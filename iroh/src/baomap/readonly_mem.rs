//! A readonly in memory database for iroh-bytes, usable for testing and sharing static data.
//!
//! Main entry point is [Store].
use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::PathBuf,
    sync::Arc,
};

use bao_tree::{
    blake3,
    io::{
        outboard::{PreOrderMemOutboard, PreOrderOutboard},
        sync::Outboard,
    },
};
use bytes::{Bytes, BytesMut};
use futures::{
    future::{self, BoxFuture},
    FutureExt,
};
use iroh_bytes::{
    baomap::{
        self, ExportMode, ImportMode, ImportProgress, Map, MapEntry, PartialMap, PartialMapEntry,
        ReadableStore, ValidateProgress,
    },
    util::progress::{IdGenerator, ProgressSender},
    Hash, IROH_BLOCK_SIZE,
};
use range_collections::RangeSet2;
use tokio::sync::mpsc;

use super::flatten_to_io;

/// A readonly in memory database for iroh-bytes.
///
/// This is basically just a HashMap, so it does not allow for any modifications
/// unless you have a mutable reference to it.
///
/// It is therefore useful mostly for testing and sharing static data.
#[derive(Debug, Clone, Default)]
pub struct Store(Arc<HashMap<Hash, (PreOrderMemOutboard, Bytes)>>);

impl<K, V> FromIterator<(K, V)> for Store
where
    K: Into<String>,
    V: AsRef<[u8]>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let (db, _m) = Self::new(iter);
        db
    }
}

impl Store {
    /// Create a new [Store] from a sequence of entries.
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

    fn export_sync(
        &self,
        hash: Hash,
        target: PathBuf,
        _mode: ExportMode,
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
        let data = self
            .get(&hash)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hash not found"))?;

        std::fs::write(target, data)?;
        Ok(())
    }
}

/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct Entry {
    outboard: PreOrderMemOutboard<Bytes>,
    data: Bytes,
}

/// The [PartialMapEntry] implementation for [Store].
///
/// This is an unoccupied type, since [Store] is does not allow creating partial entries.
#[derive(Debug, Clone)]
pub enum PartialEntry {}

impl MapEntry<Store> for Entry {
    fn hash(&self) -> blake3::Hash {
        self.outboard.root()
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<bao_tree::ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

impl Map for Store {
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

impl PartialMap for Store {
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
        // return none because we do not have partial entries
        None
    }

    fn insert_complete(&self, _entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        // this is unreachable, since we cannot create partial entries
        unreachable!()
    }
}

impl ReadableStore for Store {
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
        future::err(anyhow::anyhow!("not implemented")).boxed()
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.export_sync(hash, target, mode, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }
}

impl MapEntry<Store> for PartialEntry {
    fn hash(&self) -> blake3::Hash {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn available_ranges(
        &self,
    ) -> BoxFuture<'_, io::Result<range_collections::RangeSet2<bao_tree::ChunkNum>>> {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn size(&self) -> u64 {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }
}

impl PartialMapEntry<Store> for PartialEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Store as PartialMap>::OutboardMut>> {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Store as PartialMap>::DataWriter>> {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }
}

impl baomap::Store for Store {
    fn import(
        &self,
        data: PathBuf,
        mode: ImportMode,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(Hash, u64)>> {
        let _ = (data, mode, progress);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    /// import a byte slice
    fn import_bytes(&self, bytes: Bytes) -> BoxFuture<'_, io::Result<Hash>> {
        let _ = bytes;
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }
}
