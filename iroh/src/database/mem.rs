//! A full in memory database for iroh-bytes
//!
//! Main entry point is [Database].
use std::collections::BTreeMap;
use std::io;
use std::num::TryFromIntError;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;

use bao_tree::io::fsm::Outboard;
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::outboard_size;
use bao_tree::BaoTree;
use bao_tree::ByteNum;
use bytes::Bytes;
use bytes::BytesMut;
use derive_more::From;
use futures::future::BoxFuture;
use futures::FutureExt;
use iroh_bytes::provider::BaoDb;
use iroh_bytes::provider::BaoPartialMap;
use iroh_bytes::provider::BaoPartialMapEntry;
use iroh_bytes::provider::ImportProgress;
use iroh_bytes::provider::ValidateProgress;
use iroh_bytes::provider::{BaoMap, BaoMapEntry, BaoReadonlyDb};
use iroh_bytes::util::progress::IdGenerator;
use iroh_bytes::util::progress::ProgressSender;
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::AsyncSliceReader;
use iroh_io::AsyncSliceWriter;
use range_collections::RangeSet2;
use tokio::sync::mpsc;

use super::flatten_to_io;

/// A mutable file like object that can be used for partial entries.
#[derive(Debug, Clone, Default)]
#[repr(transparent)]
pub struct MutableMemFile(Arc<RwLock<BytesMut>>);

impl MutableMemFile {
    /// Create a new empty file
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(RwLock::new(BytesMut::with_capacity(capacity))))
    }

    /// Freeze the data, returning the content
    ///
    /// Note that this will clear other references to the data.
    pub fn freeze(self) -> Bytes {
        let mut inner = self.0.write().unwrap();
        let mut temp = BytesMut::new();
        std::mem::swap(inner.deref_mut(), &mut temp);
        temp.clone().freeze()
    }
}

impl AsyncSliceReader for MutableMemFile {
    type ReadAtFuture<'a> = <BytesMut as AsyncSliceReader>::ReadAtFuture<'a>;

    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        let mut inner = self.0.write().unwrap();
        <BytesMut as AsyncSliceReader>::read_at(&mut inner, offset, len)
    }

    type LenFuture<'a> = <BytesMut as AsyncSliceReader>::LenFuture<'a>;

    fn len(&mut self) -> Self::LenFuture<'_> {
        let inner = self.0.read().unwrap();
        futures::future::ok(inner.len() as u64)
    }
}

impl AsyncSliceWriter for MutableMemFile {
    type WriteAtFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Self::WriteAtFuture<'_> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::write_at(&mut write, offset, data)
    }

    type WriteBytesAtFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::write_bytes_at(&mut write, offset, data)
    }

    type SetLenFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn set_len(&mut self, len: u64) -> Self::SetLenFuture<'_> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::set_len(&mut write, len)
    }

    type SyncFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn sync(&mut self) -> Self::SyncFuture<'_> {
        futures::future::ok(())
    }
}

/// A file like object that can be in readonly or writeable mode.
#[derive(Debug, Clone, From)]
pub enum MemFile {
    /// immutable data, used for complete entries
    Immutable(Bytes),
    /// mutable data, used for partial entries
    Mutable(MutableMemFile),
}

impl AsyncSliceReader for MemFile {
    type ReadAtFuture<'a> = <BytesMut as AsyncSliceReader>::ReadAtFuture<'a>;

    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        match self {
            Self::Immutable(data) => AsyncSliceReader::read_at(data, offset, len),
            Self::Mutable(data) => AsyncSliceReader::read_at(data, offset, len),
        }
    }

    type LenFuture<'a> = <BytesMut as AsyncSliceReader>::LenFuture<'a>;

    fn len(&mut self) -> Self::LenFuture<'_> {
        match self {
            Self::Immutable(data) => AsyncSliceReader::len(data),
            Self::Mutable(data) => AsyncSliceReader::len(data),
        }
    }
}

impl AsyncSliceWriter for MemFile {
    type WriteAtFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Self::WriteAtFuture<'_> {
        match self {
            Self::Immutable(_) => futures::future::err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::write_at(inner, offset, data),
        }
    }

    type WriteBytesAtFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> Self::WriteBytesAtFuture<'_> {
        match self {
            Self::Immutable(_) => futures::future::err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::write_bytes_at(inner, offset, data),
        }
    }

    type SetLenFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn set_len(&mut self, len: u64) -> Self::SetLenFuture<'_> {
        match self {
            Self::Immutable(_) => futures::future::err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::set_len(inner, len),
        }
    }

    type SyncFuture<'a> = futures::future::Ready<io::Result<()>>;

    fn sync(&mut self) -> Self::SyncFuture<'_> {
        futures::future::ok(())
    }
}

#[derive(Debug, Clone, Default)]
///
pub struct Database {
    state: Arc<RwLock<State>>,
}

#[derive(Debug, Clone, Default)]
struct State {
    complete: BTreeMap<Hash, (Bytes, PreOrderOutboard<Bytes>)>,
    partial: BTreeMap<Hash, (MutableMemFile, PreOrderOutboard<MutableMemFile>)>,
}

/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct Entry {
    hash: blake3::Hash,
    outboard: PreOrderOutboard<MemFile>,
    data: MemFile,
}

impl BaoMapEntry<Database> for Entry {
    fn hash(&self) -> blake3::Hash {
        self.hash.into()
    }

    fn available(
        &self,
    ) -> BoxFuture<'_, io::Result<range_collections::RangeSet2<bao_tree::ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn size(&self) -> u64 {
        self.outboard.tree().size().0
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderOutboard<MemFile>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<MemFile>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct PartialEntry {
    hash: blake3::Hash,
    outboard: PreOrderOutboard<MutableMemFile>,
    data: MutableMemFile,
}

impl BaoMapEntry<Database> for PartialEntry {
    fn hash(&self) -> blake3::Hash {
        self.hash.into()
    }

    fn available(
        &self,
    ) -> BoxFuture<'_, io::Result<range_collections::RangeSet2<bao_tree::ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn size(&self) -> u64 {
        self.outboard.tree().size().0
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderOutboard<MemFile>>> {
        futures::future::ok(PreOrderOutboard {
            root: self.outboard.root,
            tree: self.outboard.tree,
            data: self.outboard.data.clone().into(),
        })
        .boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<MemFile>> {
        futures::future::ok(self.data.clone().into()).boxed()
    }
}

impl BaoMap for Database {
    type Outboard = PreOrderOutboard<MemFile>;
    type DataReader = MemFile;
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.state.read().unwrap();
        // look up the ids
        if let Some((data, outboard)) = state.complete.get(&hash) {
            Some(Entry {
                hash: (*hash).into(),
                outboard: PreOrderOutboard {
                    root: outboard.root,
                    tree: outboard.tree,
                    data: outboard.data.clone().into(),
                },
                data: data.clone().into(),
            })
        } else if let Some((data, outboard)) = state.partial.get(&hash) {
            Some(Entry {
                hash: (*hash).into(),
                outboard: PreOrderOutboard {
                    root: outboard.root,
                    tree: outboard.tree,
                    data: outboard.data.clone().into(),
                },
                data: data.clone().into(),
            })
        } else {
            None
        }
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(
            self.state
                .read()
                .unwrap()
                .complete
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        todo!()
    }
}

impl BaoPartialMap for Database {
    type OutboardMut = PreOrderOutboard<MutableMemFile>;

    type DataWriter = MutableMemFile;

    type PartialEntry = PartialEntry;

    fn get_partial(&self, hash: &Hash) -> Option<PartialEntry> {
        let state = self.state.read().unwrap();
        let (data, outboard) = state.partial.get(&hash)?;
        Some(PartialEntry {
            hash: (*hash).into(),
            outboard: outboard.clone(),
            data: data.clone(),
        })
    }

    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<PartialEntry> {
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        let outboard_size =
            usize::try_from(outboard_size(size, IROH_BLOCK_SIZE)).map_err(data_too_large)?;
        let size = usize::try_from(size).map_err(data_too_large)?;
        let data = MutableMemFile::with_capacity(size);
        let outboard = MutableMemFile::with_capacity(outboard_size);
        let ob2 = PreOrderOutboard {
            root: hash.into(),
            tree,
            data: outboard.clone(),
        };
        // insert into the partial map, replacing any existing entry
        self.state
            .write()
            .unwrap()
            .partial
            .insert(hash, (data.clone(), ob2.clone()));
        Ok(PartialEntry {
            hash: hash.into(),
            outboard: PreOrderOutboard {
                root: hash.into(),
                tree,
                data: outboard,
            },
            data,
        })
    }

    fn insert_complete_entry(&self, entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        tracing::info!("insert_complete_entry {:#}", entry.hash());
        async move {
            let hash = entry.hash.into();
            let data = entry.data.freeze();
            let outboard = entry.outboard.data.freeze();
            let mut state = self.state.write().unwrap();
            let outboard = PreOrderOutboard {
                root: entry.outboard.root,
                tree: entry.outboard.tree,
                data: outboard,
            };
            state.partial.remove(&hash);
            state.complete.insert(hash, (data, outboard));
            Ok(())
        }
        .boxed()
    }
}

impl BaoDb for Database {
    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let state = self.state.read().unwrap();
        let hashes = state.partial.keys().cloned().collect::<Vec<_>>();
        Box::new(hashes.into_iter())
    }

    fn import(
        &self,
        data: std::path::PathBuf,
        _stable: bool,
        _progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(Hash, u64)>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let bytes: Bytes = std::fs::read(data)?.into();
            let size = bytes.len() as u64;
            let hash = this.import_bytes_sync(bytes);
            Ok((hash, size))
        })
        .map(flatten_to_io)
        .boxed()
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        stable: bool,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.export_sync(hash, target, stable, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import_bytes(&self, bytes: Bytes) -> BoxFuture<'_, io::Result<Hash>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let hash = this.import_bytes_sync(bytes);
            Ok(hash)
        })
        .map(flatten_to_io)
        .boxed()
    }
}

impl Database {
    fn import_bytes_sync(&self, bytes: Bytes) -> Hash {
        let size = bytes.len() as u64;
        let (outboard, hash) = bao_tree::io::outboard(&bytes, IROH_BLOCK_SIZE);
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        let outboard = PreOrderOutboard {
            root: hash,
            tree,
            data: outboard.into(),
        };
        self.state
            .write()
            .unwrap()
            .complete
            .insert(hash.into(), (bytes, outboard));
        hash.into()
    }

    fn export_sync(
        &self,
        hash: Hash,
        target: PathBuf,
        _stable: bool,
        _progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        tracing::trace!("exporting {} to {}", hash, target.display());

        if !target.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target path must be absolute",
            ));
        }
        let parent = target.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "target path has no parent directory",
            )
        })?;
        // create the directory in which the target file is
        std::fs::create_dir_all(parent)?;
        let state = self.state.read().unwrap();
        let (data, _) = state
            .complete
            .get(&hash)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hash not found"))?;

        std::fs::write(target, data)?;
        Ok(())
    }
}

impl BaoPartialMapEntry<Database> for PartialEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<PreOrderOutboard<MutableMemFile>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<MutableMemFile>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

fn data_too_large(_: TryFromIntError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, "data too large to fit in memory")
}
