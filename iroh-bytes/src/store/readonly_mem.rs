//! A readonly in memory database for iroh-bytes, usable for testing and sharing static data.
//!
//! Main entry point is [Store].
use std::{
    collections::{BTreeMap, HashMap},
    io,
    path::PathBuf,
    sync::Arc,
};

use crate::{
    store::{
        EntryStatus, ExportMode, ImportMode, ImportProgress, Map, MapEntry, PartialMap,
        PartialMapEntry, ReadableStore, ValidateProgress,
    },
    util::{
        progress::{IdGenerator, ProgressSender},
        Tag,
    },
    BlobFormat, Hash, HashAndFormat, TempTag, IROH_BLOCK_SIZE,
};
use bao_tree::{
    blake3,
    io::{
        outboard::{PreOrderMemOutboard, PreOrderOutboard},
        sync::Outboard,
    },
    ChunkRanges,
};
use bytes::{Bytes, BytesMut};
use futures::{
    future::{self, BoxFuture},
    FutureExt, Stream,
};
use tokio::{io::AsyncWriteExt, sync::mpsc};

use super::{DbIter, PossiblyPartialEntry};

/// A readonly in memory database for iroh-bytes.
///
/// This is basically just a HashMap, so it does not allow for any modifications
/// unless you have a mutable reference to it.
///
/// It is therefore useful mostly for testing and sharing static data.
#[derive(Debug, Clone, Default)]
pub struct Store(Arc<HashMap<Hash, (PreOrderMemOutboard<Bytes>, Bytes)>>);

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
            // wrap into the right types
            let outboard = PreOrderMemOutboard::create(data, IROH_BLOCK_SIZE)
                .map_data(Bytes::from)
                .unwrap();
            let hash = outboard.root();
            // add the name, this assumes that names are unique
            names.insert(name, hash);
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
        // wrap into the right types
        let outboard = PreOrderMemOutboard::create(data, IROH_BLOCK_SIZE)
            .map_data(Bytes::from)
            .unwrap();
        let hash = outboard.root();
        let data = Bytes::from(data.to_vec());
        let hash = Hash::from(hash);
        inner.insert(hash, (outboard, data));
        hash
    }

    /// Insert multiple entries into the database, and return the hash of the last entry.
    pub fn insert_many(
        &mut self,
        items: impl IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> Option<Hash> {
        let mut hash = None;
        for item in items.into_iter() {
            hash = Some(self.insert(item));
        }
        hash
    }

    /// Get the bytes associated with a hash, if they exist.
    pub fn get(&self, hash: &Hash) -> Option<Bytes> {
        let entry = self.0.get(hash)?;
        Some(entry.1.clone())
    }

    async fn export_impl(
        &self,
        hash: Hash,
        target: PathBuf,
        _mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
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
        tokio::fs::create_dir_all(parent).await?;
        let data = self
            .get(&hash)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hash not found"))?;

        let mut offset = 0u64;
        let mut file = tokio::fs::File::create(&target).await?;
        for chunk in data.chunks(1024 * 1024) {
            progress(offset)?;
            file.write_all(chunk).await?;
            offset += chunk.len() as u64;
        }
        file.sync_all().await?;
        drop(file);
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
    fn hash(&self) -> Hash {
        self.outboard.root().into()
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<ChunkRanges>> {
        futures::future::ok(ChunkRanges::all()).boxed()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        futures::future::ok(self.data.clone()).boxed()
    }

    fn is_complete(&self) -> bool {
        true
    }
}

impl Map for Store {
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Bytes;
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> io::Result<Option<Self::Entry>> {
        Ok(self.0.get(hash).map(|(o, d)| Entry {
            outboard: o.clone(),
            data: d.clone(),
        }))
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

    fn entry_status(&self, hash: &Hash) -> io::Result<EntryStatus> {
        Ok(match self.0.contains_key(hash) {
            true => EntryStatus::Complete,
            false => EntryStatus::NotFound,
        })
    }

    fn get_possibly_partial(&self, hash: &Hash) -> io::Result<PossiblyPartialEntry<Self>> {
        // return none because we do not have partial entries
        Ok(if let Some((o, d)) = self.0.get(hash) {
            PossiblyPartialEntry::Complete(Entry {
                outboard: o.clone(),
                data: d.clone(),
            })
        } else {
            PossiblyPartialEntry::NotFound
        })
    }

    fn insert_complete(&self, _entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        // this is unreachable, since we cannot create partial entries
        unreachable!()
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> io::Result<DbIter<Hash>> {
        Ok(Box::new(
            self.0
                .keys()
                .copied()
                .map(Ok)
                .collect::<Vec<_>>()
                .into_iter(),
        ))
    }

    fn tags(&self) -> io::Result<DbIter<(Tag, HashAndFormat)>> {
        Ok(Box::new(std::iter::empty()))
    }

    fn temp_tags(&self) -> Box<dyn Iterator<Item = HashAndFormat> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'static, io::Result<()>> {
        future::ok(()).boxed()
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        self.export_impl(hash, target, mode, progress).boxed()
    }

    fn partial_blobs(&self) -> io::Result<DbIter<Hash>> {
        Ok(Box::new(std::iter::empty()))
    }
}

impl MapEntry<Store> for PartialEntry {
    fn hash(&self) -> Hash {
        // this is unreachable, since PartialEntry can not be created
        unreachable!()
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<ChunkRanges>> {
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

    fn is_complete(&self) -> bool {
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

impl super::Store for Store {
    fn import_file(
        &self,
        data: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(TempTag, u64)>> {
        let _ = (data, mode, progress, format);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    /// import a byte slice
    fn import_bytes(&self, bytes: Bytes, format: BlobFormat) -> BoxFuture<'_, io::Result<TempTag>> {
        let _ = (bytes, format);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    fn import_stream(
        &self,
        data: impl Stream<Item = io::Result<Bytes>> + Unpin + Send,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(TempTag, u64)>> {
        let _ = (data, format, progress);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    fn clear_live(&self) {}

    fn set_tag(&self, _name: Tag, _hash: Option<HashAndFormat>) -> BoxFuture<'_, io::Result<()>> {
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    fn create_tag(&self, _hash: HashAndFormat) -> BoxFuture<'_, io::Result<Tag>> {
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    fn temp_tag(&self, inner: HashAndFormat) -> TempTag {
        TempTag::new(inner, None)
    }

    fn add_live(&self, _live: impl IntoIterator<Item = Hash>) {}

    fn delete(&self, _hashes: Vec<Hash>) -> BoxFuture<'_, io::Result<()>> {
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    fn is_live(&self, _hash: &Hash) -> bool {
        true
    }
}
