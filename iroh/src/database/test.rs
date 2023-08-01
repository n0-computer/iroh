//! A readonly in memory database for iroh-bytes, usable for testing and sharing static data.
//!
//! Main entry point is [Database].
use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::Arc,
};

use bao_tree::io::{
    outboard::{PreOrderMemOutboard, PreOrderOutboard},
    sync::Outboard,
};
use bytes::{Bytes, BytesMut};
use futures::{
    future::{self, BoxFuture},
    FutureExt,
};
use iroh_bytes::{
    provider::{
        BaoDb, BaoMap, BaoMapEntry, BaoPartialMap, BaoPartialMapEntry, BaoReadonlyDb, ValidateProgress,
    },
    Hash, IROH_BLOCK_SIZE,
};
use range_collections::RangeSet2;
use tokio::sync::mpsc;

/// A readonly in memory database for iroh-bytes.
///
/// This is basically just a HashMap, so it does not allow for any modifications
/// unless you have a mutable reference to it.
///
/// It is therefore useful mostly for testing and sharing static data.
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<HashMap<Hash, (PreOrderMemOutboard, Bytes)>>);

impl<K, V> FromIterator<(K, V)> for Database
where
    K: Into<String>,
    V: AsRef<[u8]>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let (db, _m) = Self::new(iter);
        db
    }
}

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
    ///
    /// If the database was shared before, this will make a copy.
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
pub struct Entry {
    outboard: PreOrderMemOutboard<Bytes>,
    data: Bytes,
}

/// The [BaoPartialMapEntry] implementation for [Database].
/// 
/// This is an unoccupied type, since [Database] is does not allow creating partial entries.
#[derive(Debug, Clone)]
pub enum PartialEntry {}

impl BaoMapEntry<Database> for Entry {
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
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let (o, d) = self.0.get(hash)?;
        Some(Entry {
            outboard: o.clone(),
            data: d.clone(),
        })
    }
}

impl BaoPartialMap for Database {
    type OutboardMut = PreOrderOutboard<BytesMut>;

    type DataWriter = BytesMut;

    type PartialEntry = PartialEntry;

    fn get_or_create_partial(&self, _hash: Hash, _size: u64) -> io::Result<PartialEntry> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "cannot create temp entry in readonly database",
        ))
    }

    fn get_partial(&self, _hash: &Hash) -> Option<PartialEntry> {
        None
    }

    fn insert_complete_entry(&self, _entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        unreachable!()
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

impl BaoMapEntry<Database> for PartialEntry {
    fn hash(&self) -> blake3::Hash {
        unreachable!()
    }

    fn available(
        &self,
    ) -> BoxFuture<'_, io::Result<range_collections::RangeSet2<bao_tree::ChunkNum>>> {
        unreachable!()
    }

    fn size(&self) -> u64 {
        unreachable!()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        unreachable!()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        unreachable!()
    }
}

impl BaoPartialMapEntry<Database> for PartialEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Database as BaoPartialMap>::OutboardMut>> {
        unreachable!()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Database as BaoPartialMap>::DataWriter>> {
        unreachable!()
    }
}

impl BaoDb for Database {}
