//! An in memory implementation of [BaoMap] and [BaoReadonlyDb], useful for
//! testing and short lived nodes.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::RwLock;

use bao_tree::io::fsm::Outboard;
use bao_tree::io::outboard::PreOrderMemOutboard;
use bao_tree::io::outboard::PreOrderOutboard;
use bytes::Bytes;
use bytes::BytesMut;
use futures::future::{self, BoxFuture};
use futures::FutureExt;
use iroh_bytes::provider::BaoDb;
use iroh_bytes::provider::BaoMapEntryMut;
use iroh_bytes::provider::BaoMapMut;
use iroh_bytes::provider::Purpose;
use iroh_bytes::provider::ValidateProgress;
use iroh_bytes::provider::{BaoMap, BaoMapEntry, BaoReadonlyDb};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::AsyncSliceReader;
use iroh_io::AsyncSliceWriter;
use range_collections::RangeSet2;
use tokio::sync::mpsc;

/// An in memory database for iroh-bytes.
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<HashMap<Hash, (PreOrderMemOutboard, Bytes)>>);

impl Database {
    /// Create a new [Database] from a sequence of entries.
    ///
    /// Returns the database and a map of names to computed blake3 hashes.
    /// In case of duplicate names, the last entry is used.
    pub fn new(
        entries: impl IntoIterator<Item = (impl Into<String>, impl AsRef<[u8]>)>,
    ) -> (Self, BTreeMap<String, blake3::Hash>) {
        let mut names = BTreeMap::new();
        let mut res = HashMap::new();
        for (name, data) in entries.into_iter() {
            let name = name.into();
            let data: &[u8] = data.as_ref();
            // compute the outboard
            let (outboard, hash) = bao_tree::io::outboard(data, IROH_BLOCK_SIZE);
            // add the name, this assumes that names are unique
            names.insert(name, hash);
            // wrap into the right types
            let outboard =
                PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, outboard.into()).unwrap();
            let data = Bytes::from(data.to_vec());
            let hash = Hash::from(hash);
            res.insert(hash, (outboard, data));
        }
        (Self(Arc::new(res)), names)
    }

    /// Insert a new entry into the database, and return the hash of the entry.
    pub fn insert(&mut self, data: impl AsRef<[u8]>) -> Hash {
        let inner = Arc::make_mut(&mut self.0);
        let data: &[u8] = data.as_ref();
        // compute the outboard
        let (outboard, hash) = bao_tree::io::outboard(data, IROH_BLOCK_SIZE);
        // wrap into the right types
        let outboard = PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, outboard.into()).unwrap();
        let data = Bytes::from(data.to_vec());
        let hash = Hash::from(hash);
        inner.insert(hash, (outboard, data));
        hash
    }

    /// Get the bytes associated with a hash, if they exist.
    pub fn get(&self, hash: &Hash) -> Option<Bytes> {
        let entry = self.0.get(hash)?;
        Some(entry.1.clone())
    }
}

/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct DbEntry {
    outboard: PreOrderMemOutboard<Bytes>,
    data: Bytes,
}

impl BaoMapEntry<Database> for DbEntry {
    fn hash(&self) -> blake3::Hash {
        self.outboard.root()
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn available(&self) -> BoxFuture<'_, io::Result<RangeSet2<bao_tree::ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

impl BaoMap for Database {
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Bytes;
    type Entry = DbEntry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let (o, d) = self.0.get(hash)?;
        Some(DbEntry {
            outboard: o.clone(),
            data: d.clone(),
        })
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(self.0.keys().cloned().collect::<Vec<_>>().into_iter())
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }

    fn validate(
        &self,
        _tx: mpsc::Sender<ValidateProgress>,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        future::ok(()).boxed()
    }
}

#[derive(Debug, Clone, Default)]
struct MemVfsInner {
    entries: BTreeMap<u64, MemVfsEntry>,
    next_id: u64,
}

///
#[derive(Debug, Clone)]
pub struct MemVfsEntry {
    #[allow(dead_code)]
    id: u64,
    purpose: Purpose,
    data: Arc<Mutex<BytesMut>>,
}

impl AsyncSliceReader for MemVfsEntry {
    type ReadAtFuture<'a> = <BytesMut as AsyncSliceReader>::ReadAtFuture<'a>;

    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        inner.read_at(offset, len)
    }

    type LenFuture<'a> = <BytesMut as AsyncSliceReader>::LenFuture<'a>;

    fn len(&mut self) -> Self::LenFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        let reference: &mut BytesMut = &mut inner;
        AsyncSliceReader::len(reference)
    }
}

impl AsyncSliceWriter for MemVfsEntry {
    type WriteAtFuture<'a> = <BytesMut as AsyncSliceWriter>::WriteAtFuture<'a>;

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Self::WriteAtFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        inner.write_at(offset, data)
    }

    type WriteBytesAtFuture<'a> = <BytesMut as AsyncSliceWriter>::WriteBytesAtFuture<'a>;

    fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        inner.write_bytes_at(offset, data)
    }

    type SetLenFuture<'a> = <BytesMut as AsyncSliceWriter>::SetLenFuture<'a>;

    fn set_len(&mut self, len: u64) -> Self::SetLenFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        let reference: &mut BytesMut = &mut inner;
        AsyncSliceWriter::set_len(reference, len)
    }

    type SyncFuture<'a> = <BytesMut as AsyncSliceWriter>::SyncFuture<'a>;

    fn sync(&mut self) -> Self::SyncFuture<'_> {
        let mut inner = self.data.lock().unwrap();
        inner.sync()
    }
}

///
#[derive(Debug, Clone, Default)]
pub struct MemVfs(Arc<RwLock<MemVfsInner>>);

#[derive(Debug, Clone, Default)]
///
pub struct MutableDatabase {
    vfs: MemVfs,
    inner: Arc<RwLock<BTreeMap<Hash, (u64, Option<u64>)>>>,
}

/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct MutableDbEntry {
    hash: blake3::Hash,
    outboard: PreOrderMemOutboard<Bytes>,
    data: MemVfsEntry,
}

impl BaoMapEntry<MutableDatabase> for MutableDbEntry {
    fn hash(&self) -> blake3::Hash {
        self.hash.into()
    }

    fn available(
        &self,
    ) -> BoxFuture<'_, io::Result<range_collections::RangeSet2<bao_tree::ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn size(&self) -> u64 {
        self.data.data.lock().unwrap().len() as u64
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<MemVfsEntry>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

impl BaoMap for MutableDatabase {
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = MemVfsEntry;
    type Entry = MutableDbEntry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let inner = self.inner.read().unwrap();
        // look up the ids
        let (data_id, outboard_id) = inner.get(hash)?;
        // get the actual entries
        let data = self.vfs.0.read().unwrap().entries.get(data_id)?.clone();
        let hash = (*hash).into();
        let outboard_bytes = if let Some(outboard_id) = outboard_id {
            let outboard = self.vfs.0.read().unwrap().entries.get(outboard_id)?.clone();
            // todo: get rid of copying here
            let data = outboard.data.lock().unwrap().to_vec();
            data
        } else {
            // we don't have an outboard - make one
            let size = data.data.lock().unwrap().len() as u64;
            size.to_le_bytes().to_vec()
        };
        let Ok(outboard) = PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, outboard_bytes.clone().into()) else {
            let size = u64::from_le_bytes(outboard_bytes[0..8].try_into().unwrap());
            let expected_outboard_size = bao_tree::io::outboard_size(size, IROH_BLOCK_SIZE);
            panic!("failed to create outboard {} {} {} {}", size, expected_outboard_size, outboard_bytes.len(), hex::encode(outboard_bytes));
        };
        Some(MutableDbEntry {
            hash,
            outboard,
            data,
        })
    }
}

impl BaoReadonlyDb for MutableDatabase {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(
            self.inner
                .read()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        todo!()
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        todo!()
    }
}

impl BaoMapEntryMut<Database> for DbEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Database as BaoMapMut>::OutboardMut>> {
        todo!()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Database as BaoMapMut>::DataWriter>> {
        todo!()
    }
}

impl BaoMapEntry<MutableDatabase> for DbEntry {
    fn hash(&self) -> blake3::Hash {
        todo!()
    }

    fn size(&self) -> u64 {
        todo!()
    }

    fn available(&self) -> BoxFuture<'_, io::Result<RangeSet2<bao_tree::ChunkNum>>> {
        todo!()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<<MutableDatabase as BaoMap>::Outboard>> {
        todo!()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<<MutableDatabase as BaoMap>::DataReader>> {
        todo!()
    }
}

impl BaoMapEntryMut<MutableDatabase> for DbEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Database as BaoMapMut>::OutboardMut>> {
        todo!()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Database as BaoMapMut>::DataWriter>> {
        todo!()
    }
}

impl BaoMapMut for MutableDatabase {
    type OutboardMut = PreOrderOutboard<BytesMut>;

    type DataWriter = BytesMut;

    type TempEntry = DbEntry;

    fn get_partial(&self, hash: &Hash) -> Option<Self::TempEntry> {
        todo!()
    }

    fn create_temp_entry(&self, hash: Hash, size: u64) -> Self::TempEntry {
        todo!()
    }

    fn insert_temp_entry(&self, entry: Self::TempEntry) -> BoxFuture<'_, anyhow::Result<()>> {
        todo!()
    }
}

impl BaoMapMut for Database {
    type OutboardMut = PreOrderOutboard<BytesMut>;

    type DataWriter = BytesMut;

    type TempEntry = DbEntry;

    fn create_temp_entry(&self, hash: Hash, size: u64) -> Self::TempEntry {
        todo!()
    }

    fn get_partial(&self, hash: &Hash) -> Option<Self::TempEntry> {
        todo!()
    }

    fn insert_temp_entry(&self, entry: Self::TempEntry) -> BoxFuture<'_, anyhow::Result<()>> {
        todo!()
    }
}

impl BaoDb for MutableDatabase {
    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let vfs = self.vfs.0.read().unwrap();
        let hashes = vfs
            .entries
            .iter()
            .filter_map(|(_, entry)| match entry.purpose {
                Purpose::PartialData(hash, _) => Some(hash),
                _ => None,
            })
            .collect::<Vec<_>>();
        Box::new(hashes.into_iter())
    }
}

impl BaoDb for Database {}
