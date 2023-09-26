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
use bao_tree::blake3;
use bao_tree::io::fsm::Outboard;
use bao_tree::io::outboard::PreOrderOutboard;
use bao_tree::io::outboard_size;
use bao_tree::BaoTree;
use bao_tree::ByteNum;
use bao_tree::ChunkNum;
use bytes::Bytes;
use bytes::BytesMut;
use derive_more::From;
use futures::future::BoxFuture;
use futures::FutureExt;
use iroh_bytes::baomap;
use iroh_bytes::baomap::range_collections::RangeSet2;
use iroh_bytes::baomap::EntryStatus;
use iroh_bytes::baomap::ExportMode;
use iroh_bytes::baomap::ImportMode;
use iroh_bytes::baomap::ImportProgress;
use iroh_bytes::baomap::LivenessTracker;
use iroh_bytes::baomap::PartialMap;
use iroh_bytes::baomap::PartialMapEntry;
use iroh_bytes::baomap::TempTag;
use iroh_bytes::baomap::ValidateProgress;
use iroh_bytes::baomap::{Map, MapEntry, ReadableStore};
use iroh_bytes::util::progress::IdGenerator;
use iroh_bytes::util::progress::IgnoreProgressSender;
use iroh_bytes::util::progress::ProgressSender;
use iroh_bytes::util::runtime;
use iroh_bytes::util::BlobFormat;
use iroh_bytes::util::HashAndFormat;
use iroh_bytes::util::Tag;
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::AsyncSliceReader;
use iroh_io::AsyncSliceWriter;
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

#[derive(Debug, Clone)]
/// A full in memory database for iroh-bytes.
pub struct Store(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    rt: runtime::Handle,
    state: RwLock<State>,
}

#[derive(Debug, Clone, Default)]
struct State {
    complete: BTreeMap<Hash, (Bytes, PreOrderOutboard<Bytes>)>,
    partial: BTreeMap<Hash, (MutableMemFile, PreOrderOutboard<MutableMemFile>)>,
    tags: BTreeMap<Tag, HashAndFormat>,
    temp: BTreeMap<HashAndFormat, u64>,
    live: BTreeSet<Hash>,
}

/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct Entry {
    hash: blake3::Hash,
    outboard: PreOrderOutboard<MemFile>,
    data: MemFile,
    is_complete: bool,
}

impl MapEntry<Store> for Entry {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>> {
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

    fn is_complete(&self) -> bool {
        self.is_complete
    }
}

/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct PartialEntry {
    hash: blake3::Hash,
    outboard: PreOrderOutboard<MutableMemFile>,
    data: MutableMemFile,
}

impl MapEntry<Store> for PartialEntry {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<bao_tree::ChunkNum>>> {
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

    fn is_complete(&self) -> bool {
        false
    }
}

impl Map for Store {
    type Outboard = PreOrderOutboard<MemFile>;
    type DataReader = MemFile;
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.0.state.read().unwrap();
        // look up the ids
        if let Some((data, outboard)) = state.complete.get(hash) {
            Some(Entry {
                hash: (*hash).into(),
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
                hash: (*hash).into(),
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
        }
    }

    fn contains(&self, hash: &Hash) -> EntryStatus {
        let state = self.0.state.read().unwrap();
        if state.complete.contains_key(hash) {
            EntryStatus::Complete
        } else if state.partial.contains_key(hash) {
            EntryStatus::Partial
        } else {
            EntryStatus::NotFound
        }
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(
            self.0
                .state
                .read()
                .unwrap()
                .complete
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }

    fn tags(&self) -> Box<dyn Iterator<Item = (Tag, HashAndFormat)> + Send + Sync + 'static> {
        let tags = self
            .0
            .state
            .read()
            .unwrap()
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect::<Vec<_>>();
        Box::new(tags.into_iter())
    }

    fn temp_tags(&self) -> Box<dyn Iterator<Item = HashAndFormat> + Send + Sync + 'static> {
        let tags = self
            .0
            .state
            .read()
            .unwrap()
            .temp
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        Box::new(tags.into_iter())
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        futures::future::err(anyhow::anyhow!("validate not implemented")).boxed()
    }

    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let state = self.0.state.read().unwrap();
        let hashes = state.partial.keys().cloned().collect::<Vec<_>>();
        Box::new(hashes.into_iter())
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        self.0
            .rt
            .main()
            .spawn_blocking(move || this.export_sync(hash, target, mode, progress))
            .map(flatten_to_io)
            .boxed()
    }
}

impl PartialMap for Store {
    type OutboardMut = PreOrderOutboard<MutableMemFile>;

    type DataWriter = MutableMemFile;

    type PartialEntry = PartialEntry;

    fn get_partial(&self, hash: &Hash) -> Option<PartialEntry> {
        let state = self.0.state.read().unwrap();
        let (data, outboard) = state.partial.get(hash)?;
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
        self.0
            .state
            .write()
            .unwrap()
            .partial
            .insert(hash, (data.clone(), ob2));
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

    fn insert_complete(&self, entry: PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        tracing::info!("insert_complete_entry {:#}", entry.hash());
        async move {
            let hash = entry.hash.into();
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

impl baomap::Store for Store {
    fn import(
        &self,
        path: std::path::PathBuf,
        _mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(TempTag, u64)>> {
        let this = self.clone();
        self.0
            .rt
            .main()
            .spawn_blocking(move || {
                let id = progress.new_id();
                progress.blocking_send(ImportProgress::Found {
                    id,
                    path: path.clone(),
                })?;
                progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
                // todo: provide progress for reading into mem
                let bytes: Bytes = std::fs::read(path)?.into();
                progress.blocking_send(ImportProgress::Size {
                    id,
                    size: bytes.len() as u64,
                })?;
                let size = bytes.len() as u64;
                let tag = this.import_bytes_sync(id, bytes, format, progress)?;
                Ok((tag, size))
            })
            .map(flatten_to_io)
            .boxed()
    }

    fn import_bytes(&self, bytes: Bytes, format: BlobFormat) -> BoxFuture<'_, io::Result<TempTag>> {
        let this = self.clone();
        self.0
            .rt
            .main()
            .spawn_blocking(move || {
                this.import_bytes_sync(0, bytes, format, IgnoreProgressSender::default())
            })
            .map(flatten_to_io)
            .boxed()
    }

    fn set_tag(&self, name: Tag, value: Option<HashAndFormat>) -> BoxFuture<'_, io::Result<()>> {
        let mut state = self.0.state.write().unwrap();
        if let Some(value) = value {
            state.tags.insert(name, value);
        } else {
            state.tags.remove(&name);
        }
        futures::future::ok(()).boxed()
    }

    fn create_tag(&self, hash: HashAndFormat) -> BoxFuture<'_, io::Result<Tag>> {
        let mut state = self.0.state.write().unwrap();
        let tag = Tag::auto(SystemTime::now(), |x| state.tags.contains_key(x));
        state.tags.insert(tag.clone(), hash);
        futures::future::ok(tag).boxed()
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
        state.live.contains(hash)
    }

    fn delete(&self, hash: &Hash) -> BoxFuture<'_, io::Result<()>> {
        let mut state = self.0.state.write().unwrap();
        state.complete.remove(hash);
        state.partial.remove(hash);
        futures::future::ok(()).boxed()
    }
}

impl LivenessTracker for Inner {
    fn on_clone(&self, inner: &HashAndFormat) {
        tracing::info!("temp tagging: {:?}", inner);
        let mut state = self.state.write().unwrap();
        let entry = state.temp.entry(*inner).or_default();
        // panic if we overflow an u64
        *entry = entry.checked_add(1).unwrap();
    }

    fn on_drop(&self, inner: &HashAndFormat) {
        tracing::info!("temp tag drop: {:?}", inner);
        let mut state = self.state.write().unwrap();
        let entry = state.temp.entry(*inner).or_default();
        *entry = entry.saturating_sub(1);
        if *entry == 0 {
            state.temp.remove(inner);
        }
    }
}

impl Store {
    /// Create a new in memory database, using the given runtime.
    pub fn new(rt: runtime::Handle) -> Self {
        Self(Arc::new(Inner {
            rt,
            state: RwLock::new(State::default()),
        }))
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
        use baomap::Store;
        let tag = self.temp_tag(HashAndFormat(hash, format));
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

impl PartialMapEntry<Store> for PartialEntry {
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
