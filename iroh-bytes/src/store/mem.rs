//! A full in memory database for iroh-bytes
//!
//! Main entry point is [Store].
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io;
use std::io::Write;
use std::num::TryFromIntError;
use std::ops::DerefMut;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;

use super::flatten_to_io;
use super::temp_name;
use super::CombinedBatchWriter;
use super::DbIter;
use super::PossiblyPartialEntry;
use super::TempCounterMap;
use crate::{
    store::{
        EntryStatus, ExportMode, ImportMode, ImportProgress, Map, MapEntry, PartialMap,
        PartialMapEntry, ReadableStore, ValidateProgress,
    },
    util::{
        progress::{IdGenerator, IgnoreProgressSender, ProgressSender},
        LivenessTracker,
    },
    BlobFormat, Hash, HashAndFormat, Tag, TempTag, IROH_BLOCK_SIZE,
};
use bao_tree::io::fsm::Outboard;
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::outboard_size;
use bao_tree::BaoTree;
use bao_tree::ByteNum;
use bao_tree::ChunkRanges;
use bytes::Bytes;
use bytes::BytesMut;
use derive_more::From;
use futures::future::BoxFuture;
use futures::FutureExt;
use futures::{Stream, StreamExt};
use iroh_io::{AsyncSliceReader, AsyncSliceWriter};
use tokio::sync::mpsc;

/// A mutable file like object that can be used for partial entries.
#[derive(Debug, Clone, Default)]
#[repr(transparent)]
pub struct MutableMemFile(Arc<RwLock<BytesMut>>);

impl MutableMemFile {
    /// Create a new empty file
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Arc::new(RwLock::new(BytesMut::with_capacity(capacity))))
    }

    /// Create a snapshot of the data
    pub fn snapshot(&self) -> Bytes {
        let inner = self.0.read().unwrap();
        inner.clone().freeze()
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

// we know that the impl of AsyncSliceWriter does not contain an await point.
// but due to implicit return types the compiler does not know anymore.
// Hence the #[allow(clippy::await_holding_lock)]
impl AsyncSliceReader for MutableMemFile {
    #[allow(clippy::await_holding_lock)]
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        let mut inner = self.0.write().unwrap();
        <BytesMut as AsyncSliceReader>::read_at(&mut inner, offset, len).await
    }

    async fn len(&mut self) -> io::Result<u64> {
        let inner = self.0.read().unwrap();
        Ok(inner.len() as u64)
    }
}

// we know that the impl of AsyncSliceWriter does not contain an await point.
// but due to implicit return types the compiler does not know anymore.
// Hence the #[allow(clippy::await_holding_lock)]
impl AsyncSliceWriter for MutableMemFile {
    #[allow(clippy::await_holding_lock)]
    async fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::write_at(&mut write, offset, data).await
    }

    #[allow(clippy::await_holding_lock)]
    async fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> io::Result<()> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::write_bytes_at(&mut write, offset, data).await
    }

    #[allow(clippy::await_holding_lock)]
    async fn set_len(&mut self, len: u64) -> io::Result<()> {
        let mut write = self.0.write().unwrap();
        <BytesMut as AsyncSliceWriter>::set_len(&mut write, len).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
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
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        match self {
            Self::Immutable(data) => AsyncSliceReader::read_at(data, offset, len).await,
            Self::Mutable(data) => AsyncSliceReader::read_at(data, offset, len).await,
        }
    }

    async fn len(&mut self) -> io::Result<u64> {
        match self {
            Self::Immutable(data) => AsyncSliceReader::len(data).await,
            Self::Mutable(data) => AsyncSliceReader::len(data).await,
        }
    }
}

impl AsyncSliceWriter for MemFile {
    async fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Immutable(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::write_at(inner, offset, data).await,
        }
    }

    async fn write_bytes_at(&mut self, offset: u64, data: Bytes) -> io::Result<()> {
        match self {
            Self::Immutable(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::write_bytes_at(inner, offset, data).await,
        }
    }

    async fn set_len(&mut self, len: u64) -> io::Result<()> {
        match self {
            Self::Immutable(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "cannot write to immutable data",
            )),
            Self::Mutable(inner) => AsyncSliceWriter::set_len(inner, len).await,
        }
    }

    async fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
/// A full in memory database for iroh-bytes.
pub struct Store(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    state: RwLock<State>,
}

#[derive(Debug, Clone, Default)]
struct State {
    complete: BTreeMap<Hash, (Bytes, PreOrderOutboard<Bytes>)>,
    partial: BTreeMap<Hash, (MutableMemFile, PreOrderOutboard<MutableMemFile>)>,
    tags: BTreeMap<Tag, HashAndFormat>,
    temp: TempCounterMap,
    live: BTreeSet<Hash>,
}

/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct Entry {
    hash: Hash,
    outboard: PreOrderOutboard<MemFile>,
    data: MemFile,
    is_complete: bool,
}

impl MapEntry<Store> for Entry {
    fn hash(&self) -> Hash {
        self.hash
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<ChunkRanges>> {
        futures::future::ok(ChunkRanges::all()).boxed()
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

    fn is_complete(&self) -> bool {
        self.is_complete
    }
}

/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct PartialEntry {
    hash: Hash,
    outboard: PreOrderOutboard<MutableMemFile>,
    data: MutableMemFile,
}

impl MapEntry<Store> for PartialEntry {
    fn hash(&self) -> Hash {
        self.hash
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<ChunkRanges>> {
        futures::future::ok(ChunkRanges::all()).boxed()
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

    fn is_complete(&self) -> bool {
        false
    }
}

impl Map for Store {
    type Outboard = PreOrderOutboard<MemFile>;
    type DataReader = MemFile;
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> io::Result<Option<Self::Entry>> {
        let state = self.0.state.read().unwrap();
        // look up the ids
        Ok(if let Some((data, outboard)) = state.complete.get(hash) {
            Some(Entry {
                hash: *hash,
                outboard: PreOrderOutboard {
                    root: outboard.root,
                    tree: outboard.tree,
                    data: outboard.data.clone().into(),
                },
                data: data.clone().into(),
                is_complete: true,
            })
        } else if let Some((data, outboard)) = state.partial.get(hash) {
            Some(Entry {
                hash: *hash,
                outboard: PreOrderOutboard {
                    root: outboard.root,
                    tree: outboard.tree,
                    data: outboard.data.clone().into(),
                },
                data: data.clone().into(),
                is_complete: false,
            })
        } else {
            None
        })
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> io::Result<DbIter<Hash>> {
        Ok(Box::new(
            self.0
                .state
                .read()
                .unwrap()
                .complete
                .keys()
                .copied()
                .map(Ok)
                .collect::<Vec<_>>()
                .into_iter(),
        ))
    }

    fn tags(&self) -> io::Result<DbIter<(Tag, HashAndFormat)>> {
        let tags = self
            .0
            .state
            .read()
            .unwrap()
            .tags
            .iter()
            .map(|(k, v)| Ok((k.clone(), *v)))
            .collect::<Vec<_>>();
        Ok(Box::new(tags.into_iter()))
    }

    fn temp_tags(&self) -> Box<dyn Iterator<Item = HashAndFormat> + Send + Sync + 'static> {
        let tags = self.0.state.read().unwrap().temp.keys();
        Box::new(tags)
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, io::Result<()>> {
        futures::future::ok(()).boxed()
    }

    fn partial_blobs(&self) -> io::Result<DbIter<Hash>> {
        let state = self.0.state.read().unwrap();
        let hashes = state.partial.keys().copied().map(Ok).collect::<Vec<_>>();
        Ok(Box::new(hashes.into_iter()))
    }

    async fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.export_sync(hash, target, mode, progress))
            .map(flatten_to_io)
            .await
    }
}

impl PartialMap for Store {
    type PartialEntry = PartialEntry;

    type BatchWriter = CombinedBatchWriter<MutableMemFile, PreOrderOutboard<MutableMemFile>>;

    fn entry_status(&self, hash: &Hash) -> io::Result<EntryStatus> {
        let state = self.0.state.read().unwrap();
        Ok(if state.complete.contains_key(hash) {
            EntryStatus::Complete
        } else if state.partial.contains_key(hash) {
            EntryStatus::Partial
        } else {
            EntryStatus::NotFound
        })
    }

    fn get_possibly_partial(&self, hash: &Hash) -> io::Result<PossiblyPartialEntry<Self>> {
        let state = self.0.state.read().unwrap();
        Ok(match state.partial.get(hash) {
            Some((data, outboard)) => PossiblyPartialEntry::Partial(PartialEntry {
                hash: *hash,
                outboard: outboard.clone(),
                data: data.clone(),
            }),
            None => PossiblyPartialEntry::NotFound,
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
        self.0
            .state
            .write()
            .unwrap()
            .partial
            .insert(hash, (data.clone(), ob2));
        Ok(PartialEntry {
            hash,
            outboard: PreOrderOutboard {
                root: hash.into(),
                tree,
                data: outboard,
            },
            data,
        })
    }

    fn insert_complete(&self, entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        tracing::debug!("insert_complete_entry {:#}", entry.hash());
        async move {
            let hash = entry.hash;
            let data = entry.data.freeze();
            let outboard = entry.outboard.data.freeze();
            let mut state = self.0.state.write().unwrap();
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

impl super::Store for Store {
    async fn import_file(
        &self,
        path: std::path::PathBuf,
        _mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(TempTag, u64)> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            let id = progress.new_id();
            progress.blocking_send(ImportProgress::Found {
                id,
                name: path.to_string_lossy().to_string(),
            })?;
            progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
            // todo: provide progress for reading into mem
            let bytes: Bytes = std::fs::read(path)?.into();
            let size = bytes.len() as u64;
            progress.blocking_send(ImportProgress::Size { id, size })?;
            let tag = this.import_bytes_sync(id, bytes, format, progress)?;
            Ok((tag, size))
        })
        .map(flatten_to_io)
        .await
    }

    async fn import_stream(
        &self,
        mut data: impl Stream<Item = io::Result<Bytes>> + Unpin + Send + 'static,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(TempTag, u64)> {
        let this = self.clone();
        let id = progress.new_id();
        let name = temp_name();
        progress.send(ImportProgress::Found { id, name }).await?;
        let mut bytes = BytesMut::new();
        while let Some(chunk) = data.next().await {
            bytes.extend_from_slice(&chunk?);
            progress
                .try_send(ImportProgress::CopyProgress {
                    id,
                    offset: bytes.len() as u64,
                })
                .ok();
        }
        let bytes = bytes.freeze();
        let size = bytes.len() as u64;
        progress.blocking_send(ImportProgress::Size { id, size })?;
        let tag = this.import_bytes_sync(id, bytes, format, progress)?;
        Ok((tag, size))
    }

    async fn import_bytes(&self, bytes: Bytes, format: BlobFormat) -> io::Result<TempTag> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || {
            this.import_bytes_sync(0, bytes, format, IgnoreProgressSender::default())
        })
        .map(flatten_to_io)
        .await
    }

    async fn set_tag(&self, name: Tag, value: Option<HashAndFormat>) -> io::Result<()> {
        let mut state = self.0.state.write().unwrap();
        if let Some(value) = value {
            state.tags.insert(name, value);
        } else {
            state.tags.remove(&name);
        }
        Ok(())
    }

    async fn create_tag(&self, hash: HashAndFormat) -> io::Result<Tag> {
        let mut state = self.0.state.write().unwrap();
        let tag = Tag::auto(SystemTime::now(), |x| state.tags.contains_key(x));
        state.tags.insert(tag.clone(), hash);
        Ok(tag)
    }

    fn temp_tag(&self, tag: HashAndFormat) -> TempTag {
        TempTag::new(tag, Some(self.0.clone()))
    }

    fn clear_live(&self) {
        let mut state = self.0.state.write().unwrap();
        state.live.clear();
    }

    fn add_live(&self, live: impl IntoIterator<Item = Hash>) {
        let mut state = self.0.state.write().unwrap();
        state.live.extend(live);
    }

    fn is_live(&self, hash: &Hash) -> bool {
        let state = self.0.state.read().unwrap();
        // a blob is live if it is either in the live set, or it is temp tagged
        state.live.contains(hash) || state.temp.contains(hash)
    }

    async fn delete(&self, hashes: Vec<Hash>) -> io::Result<()> {
        let mut state = self.0.state.write().unwrap();
        for hash in hashes {
            state.complete.remove(&hash);
            state.partial.remove(&hash);
        }
        Ok(())
    }
}

impl LivenessTracker for Inner {
    fn on_clone(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tagging: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.inc(inner);
    }

    fn on_drop(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tag drop: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.dec(inner);
    }
}

impl Store {
    /// Create a new in memory database, using the given runtime.
    pub fn new() -> Self {
        Self::default()
    }

    fn import_bytes_sync(
        &self,
        id: u64,
        bytes: Bytes,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<TempTag> {
        let size = bytes.len() as u64;
        progress.blocking_send(ImportProgress::OutboardProgress { id, offset: 0 })?;
        let (outboard, hash) = bao_tree::io::outboard(&bytes, IROH_BLOCK_SIZE);
        progress.blocking_send(ImportProgress::OutboardDone {
            id,
            hash: hash.into(),
        })?;
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        let outboard = PreOrderOutboard {
            root: hash,
            tree,
            data: outboard.into(),
        };
        let hash = hash.into();
        use super::Store;
        let tag = self.temp_tag(HashAndFormat { hash, format });
        self.0
            .state
            .write()
            .unwrap()
            .complete
            .insert(hash, (bytes, outboard));
        Ok(tag)
    }

    fn export_sync(
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
        std::fs::create_dir_all(parent)?;
        let state = self.0.state.read().unwrap();
        let (data, _) = state
            .complete
            .get(&hash)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "hash not found"))?;

        let mut file = std::fs::File::create(target)?;
        let mut offset = 0;
        for chunk in data.chunks(1024 * 1024) {
            progress(offset)?;
            file.write_all(chunk)?;
            offset += chunk.len() as u64;
        }
        file.flush()?;
        drop(file);
        Ok(())
    }
}

impl PartialEntry {
    fn outboard_mut(&self) -> PreOrderOutboard<MutableMemFile> {
        self.outboard.clone()
    }

    fn data_writer(&self) -> MutableMemFile {
        self.data.clone()
    }
}

impl PartialMapEntry<Store> for PartialEntry {
    fn batch_writer(
        &self,
    ) -> futures::prelude::future::BoxFuture<'_, io::Result<<Store as PartialMap>::BatchWriter>>
    {
        async move {
            let data = self.data_writer();
            let outboard = self.outboard_mut();
            Ok(CombinedBatchWriter { data, outboard })
        }
        .boxed()
    }
}

fn data_too_large(_: TryFromIntError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, "data too large to fit in memory")
}
