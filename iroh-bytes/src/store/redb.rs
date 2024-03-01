//! redb backed storage

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::SystemTime,
};

use bao_tree::io::{
    fsm::Outboard,
    outboard::PostOrderMemOutboard,
    sync::{ReadAt, Size},
};
use bytes::Bytes;
use futures::{channel::oneshot, Stream, StreamExt};
use std::str::FromStr;

use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};
use iroh_io::AsyncSliceReader;
use redb::{AccessGuard, ReadTransaction, ReadableTable, StorageError, TableDefinition};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tokio::io::AsyncWriteExt;
use tracing::trace_span;

use crate::{
    store::bao_file::{BaoFileStorage, CompleteMemOrFileStorage},
    util::{
        progress::{IdGenerator, IgnoreProgressSender, ProgressSendError, ProgressSender},
        LivenessTracker, MemOrFile,
    },
    Tag, TempTag, IROH_BLOCK_SIZE,
};

use super::{
    bao_file::{raw_outboard_size, BaoFileConfig, BaoFileHandle},
    temp_name, BaoBatchWriter, EntryStatus, ExportMode, ImportMode, ImportProgress, MapEntry,
    ReadableStore, TempCounterMap, ValidateLevel, ValidateProgress,
};

use super::BaoBlobSize;

const BLOBS_TABLE: TableDefinition<Hash, EntryState> = TableDefinition::new("blobs-0");

const TAGS_TABLE: TableDefinition<Tag, HashAndFormat> = TableDefinition::new("tags-0");

const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> = TableDefinition::new("inline-data-0");

const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-outboard-0");

/// Location of the data.
///
/// Data can be inlined in the database, a file conceptually owned by the store,
/// or a number of external files conceptually owned by the user.
///
/// Only complete data can be inlined.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum DataLocation<I = (), E = ()> {
    /// Data is in the inline_data table.
    Inline(I),
    /// Data is in the canonical location in the data directory.
    Owned(E),
    /// Data is in several external locations. This should be a non-empty list.
    External(Vec<PathBuf>, E),
}

impl<X> DataLocation<X, u64> {
    #[allow(dead_code)]
    fn size(&self) -> Option<u64> {
        match self {
            DataLocation::Inline(_) => None,
            DataLocation::Owned(size) => Some(*size),
            DataLocation::External(_, size) => Some(*size),
        }
    }
}

impl<I, E> DataLocation<I, E> {
    #[allow(dead_code)]
    fn discard_extra_data(&self) -> DataLocation<(), ()> {
        match self {
            DataLocation::Inline(_) => DataLocation::Inline(()),
            DataLocation::Owned(_) => DataLocation::Owned(()),
            DataLocation::External(paths, _) => DataLocation::External(paths.clone(), ()),
        }
    }
    fn discard_inline_data(self) -> DataLocation<(), E> {
        match self {
            DataLocation::Inline(_) => DataLocation::Inline(()),
            DataLocation::Owned(x) => DataLocation::Owned(x),
            DataLocation::External(paths, x) => DataLocation::External(paths, x),
        }
    }
}

/// Location of the outboard.
///
/// Outboard can be inlined in the database or a file conceptually owned by the store.
/// Outboards are implementation specific to the store and as such are always owned.
///
/// Only complete outboards can be inlined.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum OutboardLocation<I = ()> {
    /// Outboard is in the inline_outboard table.
    Inline(I),
    /// Outboard is in the canonical location in the data directory.
    Owned,
    /// Outboard is not needed,
    NotNeeded,
}

impl<I> OutboardLocation<I> {
    fn discard_extra_data(self) -> OutboardLocation<()> {
        match self {
            Self::Inline(_) => OutboardLocation::Inline(()),
            Self::Owned => OutboardLocation::Owned,
            Self::NotNeeded => OutboardLocation::NotNeeded,
        }
    }
}

/// The information about an entry that we keep in the entry table for quick access.
///
/// The exact info to store here is TBD, so usually you should use the accessor methods.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum EntryState<I = ()> {
    /// For a complete entry we always know the size. It does not make much sense
    /// to write to a complete entry, so they are much easier to share.
    Complete {
        /// Location of the data.
        data_location: DataLocation<I, u64>,
        /// Location of the outboard.
        outboard_location: OutboardLocation<I>,
    },
    /// Partial entries are entries for which we know the hash, but don't have
    /// all the data. They are created when syncing from somewhere else by hash.
    ///
    /// As such they are always owned. There is also no inline storage for them.
    /// Non short lived partial entries always live in the file system, and for
    /// short lived ones we never create a database entry in the first place.
    Partial {
        /// Once we get the last chunk of a partial entry, we have validated
        /// the size of the entry despite it still being incomplete.
        ///
        /// E.g. a giant file where we just requested the last chunk.
        size: Option<u64>,
    },
}

impl Default for EntryState {
    fn default() -> Self {
        Self::Partial { size: None }
    }
}

impl EntryState {
    fn union(self, that: Self) -> io::Result<Self> {
        match (self, that) {
            (a @ Self::Complete { .. }, Self::Complete { .. }) => Ok(a),
            (a @ Self::Complete { .. }, Self::Partial { .. }) => Ok(a),
            (Self::Partial { .. }, b @ Self::Complete { .. }) => Ok(b),
            (Self::Partial { size: a_size }, Self::Partial { size: b_size }) => Ok(Self::Partial {
                size: a_size.or(b_size),
            }),
        }
    }
}

impl redb::RedbValue for EntryState {
    type SelfType<'a> = EntryState;

    type AsBytes<'a> = SmallVec<[u8; 128]>;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        postcard::from_bytes(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        postcard::to_extend(value, SmallVec::new()).unwrap()
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("EntryState")
    }
}

/// Options for inlining small complete data or outboards.
#[derive(Debug, Clone)]
pub struct InlineOptions {
    /// Maximum data size to inline.
    max_data_inlined: u64,
    /// Maximum outboard size to inline.
    max_outboard_inlined: u64,
}

impl InlineOptions {
    /// Do not inline anything, ever.
    pub const NO_INLINE: Self = Self {
        max_data_inlined: 0,
        max_outboard_inlined: 0,
    };
    /// Always inline everything
    pub const ALWAYS_INLINE: Self = Self {
        max_data_inlined: u64::MAX,
        max_outboard_inlined: u64::MAX,
    };
}

impl Default for InlineOptions {
    fn default() -> Self {
        Self {
            max_data_inlined: 1024 * 16,
            max_outboard_inlined: 1024 * 16,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PathOptions {
    /// Path to the directory where data and outboard files are stored.
    data_path: PathBuf,
    /// Path to the directory where temp files are stored.
    /// This *must* be on the same device as `data_path`, since we need to
    /// atomically move temp files into place.
    temp_path: PathBuf,
}

impl PathOptions {
    fn new(root: &Path) -> Self {
        Self {
            data_path: root.join("data"),
            temp_path: root.join("temp"),
        }
    }

    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.data_path.join(format!("{}.data", hash.to_hex()))
    }

    fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.data_path.join(format!("{}.obao4", hash.to_hex()))
    }

    fn temp_file_name(&self) -> PathBuf {
        self.temp_path.join(temp_name())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Options {
    path: PathOptions,
    /// Inline storage options.
    inline: InlineOptions,
}

#[derive(derive_more::Debug)]
pub(crate) enum ImportFile {
    TempFile(PathBuf),
    External(PathBuf),
    Memory(#[debug(skip)] Bytes),
}

impl ImportFile {
    fn content(&self) -> MemOrFile<&[u8], &Path> {
        match self {
            Self::TempFile(path) => MemOrFile::File(path.as_path()),
            Self::External(path) => MemOrFile::File(path.as_path()),
            Self::Memory(data) => MemOrFile::Mem(data.as_ref()),
        }
    }

    fn len(&self) -> io::Result<u64> {
        match self {
            Self::TempFile(path) => std::fs::metadata(path).map(|m| m.len()),
            Self::External(path) => std::fs::metadata(path).map(|m| m.len()),
            Self::Memory(data) => Ok(data.len() as u64),
        }
    }
}

///
#[derive(Debug, Clone, derive_more::From)]
pub struct Entry(BaoFileHandle);

impl super::MapEntry for Entry {
    fn hash(&self) -> Hash {
        self.0.hash()
    }

    fn size(&self) -> BaoBlobSize {
        let size = self.0.current_size().unwrap();
        tracing::info!("redb::Entry::size() = {}", size);
        BaoBlobSize::new(size, self.is_complete())
    }

    fn is_complete(&self) -> bool {
        self.0.is_complete()
    }

    async fn available_ranges(&self) -> io::Result<bao_tree::ChunkRanges> {
        todo!()
    }

    async fn outboard(&self) -> io::Result<impl Outboard> {
        self.0.outboard()
    }

    async fn data_reader(&self) -> io::Result<impl AsyncSliceReader> {
        Ok(self.0.data_reader())
    }
}

impl super::MapEntryMut for Entry {
    async fn batch_writer(&self) -> io::Result<impl BaoBatchWriter> {
        Ok(self.0.writer())
    }
}

fn to_io_err(e: impl Into<redb::Error>) -> io::Error {
    let e = e.into();
    match e {
        redb::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::Other, e),
    }
}

/// Synchronously compute the outboard of a file, and return hash and outboard.
///
/// It is assumed that the file is not modified while this is running.
///
/// If it is modified while or after this is running, the outboard will be
/// invalid, so any attempt to compute a slice from it will fail.
///
/// If the size of the file is changed while this is running, an error will be
/// returned.
///
/// The computed outboard is without length prefix.
fn compute_outboard(
    read: impl Read,
    size: u64,
    progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
) -> io::Result<(Hash, Option<Vec<u8>>)> {
    // compute outboard size so we can pre-allocate the buffer.
    let outboard_size = usize::try_from(raw_outboard_size(size))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size too large"))?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader2::new(read, progress);
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    let hash =
        bao_tree::io::sync::outboard_post_order(&mut reader, size, IROH_BLOCK_SIZE, &mut outboard)?;
    let ob = PostOrderMemOutboard::load(hash, &outboard, IROH_BLOCK_SIZE)?.flip();
    tracing::trace!(%hash, "done");
    let ob = ob.into_inner();
    let ob = if !ob.is_empty() { Some(ob) } else { None };
    Ok((hash.into(), ob))
}

pub(crate) struct ProgressReader2<R, F: Fn(u64) -> io::Result<()>> {
    inner: R,
    offset: u64,
    cb: F,
}

impl<R: io::Read, F: Fn(u64) -> io::Result<()>> ProgressReader2<R, F> {
    #[allow(dead_code)]
    pub fn new(inner: R, cb: F) -> Self {
        Self {
            inner,
            offset: 0,
            cb,
        }
    }
}

impl<R: io::Read, F: Fn(u64) -> io::Result<()>> io::Read for ProgressReader2<R, F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.offset += read as u64;
        (self.cb)(self.offset)?;
        Ok(read)
    }
}

/// overwrite a file with the given data.
///
/// This is almost like `std::fs::write`, but it does not truncate the file.
///
/// So if you overwrite a file with less data than it had before, the file will
/// still have the same size as before.
///
/// Also, if you overwrite a file with the same data as it had before, the
/// file will be unchanged even if the overwrite operation is interrupted.
fn overwrite_and_sync(path: &Path, data: &[u8]) -> io::Result<std::fs::File> {
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;
    file.write_all(data)?;
    // todo: figure out the consequences of not syncing here
    file.sync_all()?;
    Ok(file)
}

/// Read a file into memory and then delete it.
fn read_and_remove(path: &Path) -> io::Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    // todo: should we fail here or just log a warning?
    // remove could fail e.g. on windows if the file is still open
    std::fs::remove_file(path)?;
    Ok(data)
}

fn dump(db: &redb::Database) -> ActorResult<()> {
    let tx = db.begin_read()?;
    let blobs = tx.open_table(BLOBS_TABLE)?;
    let tags = tx.open_table(TAGS_TABLE)?;
    let inline_data = tx.open_table(INLINE_DATA_TABLE)?;
    let inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
    for e in blobs.iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("blobs: {} -> {:?}", k.to_hex(), v);
    }
    for e in tags.iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("tags: {} -> {:?}", k, v);
    }
    for e in inline_data.iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("inline_data: {} -> {:?}", k.to_hex(), v.len());
    }
    for e in inline_outboard.iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("inline_outboard: {} -> {:?}", k.to_hex(), v.len());
    }
    Ok(())
}

fn load_data(
    options: &PathOptions,
    tx: &ReadTransaction,
    location: DataLocation<(), u64>,
    hash: &Hash,
) -> ActorResult<MemOrFile<Bytes, (std::fs::File, u64)>> {
    Ok(match location {
        DataLocation::Inline(()) => {
            let data = tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
            let Some(data) = data.get(hash).map_err(to_io_err)? else {
                return Err(ActorError::Inconsistent(format!(
                    "inconsistent database state: {} should have inline data but does not",
                    hash.to_hex()
                )));
            };
            MemOrFile::Mem(Bytes::copy_from_slice(data.value()))
        }
        DataLocation::Owned(data_size) => {
            let path = options.owned_data_path(hash);
            let Ok(file) = std::fs::File::open(&path) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("file not found: {}", path.display()),
                )
                .into());
            };
            MemOrFile::File((file, data_size))
        }
        DataLocation::External(paths, data_size) => {
            if paths.is_empty() {
                return Err(ActorError::Inconsistent(
                    "external data location must not be empty".into(),
                ));
            }
            let path = &paths[0];
            let Ok(file) = std::fs::File::open(path) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("external file not found: {}", path.display()),
                )
                .into());
            };
            MemOrFile::File((file, data_size))
        }
    })
}

fn load_outboard(
    options: &PathOptions,
    tx: &ReadTransaction,
    location: OutboardLocation,
    size: u64,
    hash: &Hash,
) -> ActorResult<MemOrFile<Bytes, (std::fs::File, u64)>> {
    Ok(match location {
        OutboardLocation::NotNeeded => MemOrFile::Mem(Bytes::new()),
        OutboardLocation::Inline(_) => {
            let outboard = tx.open_table(INLINE_OUTBOARD_TABLE).map_err(to_io_err)?;
            let Some(outboard) = outboard.get(hash).map_err(to_io_err)? else {
                return Err(ActorError::Inconsistent(format!(
                    "inconsistent database state: {} should have inline outboard but does not",
                    hash.to_hex()
                )));
            };
            MemOrFile::Mem(Bytes::copy_from_slice(outboard.value()))
        }
        OutboardLocation::Owned => {
            let outboard_size = raw_outboard_size(size);
            let path = options.owned_outboard_path(hash);
            let Ok(file) = std::fs::File::open(&path) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("file not found: {} size={}", path.display(), outboard_size),
                )
                .into());
            };
            MemOrFile::File((file, outboard_size))
        }
    })
}

/// Take a possibly incomplete storage and turn it into complete
fn complete_storage(
    storage: BaoFileStorage,
    hash: &Hash,
    path_options: &PathOptions,
    inline_options: &InlineOptions,
) -> ActorResult<std::result::Result<CompleteMemOrFileStorage, CompleteMemOrFileStorage>> {
    let (data, outboard, _sizes) = match storage {
        BaoFileStorage::Complete(c) => return Ok(Err(c)),
        BaoFileStorage::IncompleteMem(storage) => {
            let (data, outboard, sizes) = storage.into_parts();
            (
                MemOrFile::Mem(Bytes::from(data.into_parts().0)),
                MemOrFile::Mem(Bytes::from(outboard.into_parts().0)),
                MemOrFile::Mem(Bytes::from(sizes.to_vec()?)),
            )
        }
        BaoFileStorage::IncompleteFile(storage) => {
            let (data, outboard, sizes) = storage.into_parts();
            (
                MemOrFile::File(data),
                MemOrFile::File(outboard),
                MemOrFile::File(sizes),
            )
        }
    };
    let data_size = data.size()?.unwrap();
    let outboard_size = outboard.size()?.unwrap();
    // todo: perform more sanity checks if in debug mode
    debug_assert!(raw_outboard_size(data_size) == outboard_size);
    // inline data if needed, or write to file if needed
    let data = if data_size <= inline_options.max_data_inlined {
        match data {
            MemOrFile::File(data) => {
                let mut buf = vec![0; data_size as usize];
                data.read_at(0, &mut buf)?;
                let path = path_options.owned_data_path(hash);
                // this whole file removal thing is not great. It should either fail, or try
                // again until it works. Maybe have a set of stuff to delete and do it in gc?
                if let Err(cause) = std::fs::remove_file(path) {
                    tracing::error!("failed to remove file: {}", cause);
                };
                MemOrFile::Mem(Bytes::from(buf))
            }
            MemOrFile::Mem(data) => MemOrFile::Mem(data),
        }
    } else {
        match data {
            MemOrFile::Mem(data) => {
                let path = path_options.owned_data_path(hash);
                let file = overwrite_and_sync(&path, &data)?;
                MemOrFile::File((file, data_size))
            }
            MemOrFile::File(data) => MemOrFile::File((data, data_size)),
        }
    };
    // inline outboard if needed, or write to file if needed
    let outboard = if outboard_size == 0 {
        Default::default()
    } else if outboard_size <= inline_options.max_outboard_inlined {
        match outboard {
            MemOrFile::File(outboard) => {
                let mut buf = vec![0; outboard_size as usize];
                outboard.read_at(0, &mut buf)?;
                drop(outboard);
                let path: PathBuf = path_options.owned_outboard_path(hash);
                // this whole file removal thing is not great. It should either fail, or try
                // again until it works. Maybe have a set of stuff to delete and do it in gc?
                if let Err(cause) = std::fs::remove_file(path) {
                    tracing::error!("failed to remove file: {}", cause);
                };
                MemOrFile::Mem(Bytes::from(buf))
            }
            MemOrFile::Mem(outboard) => MemOrFile::Mem(outboard),
        }
    } else {
        match outboard {
            MemOrFile::Mem(outboard) => {
                let path = path_options.owned_outboard_path(hash);
                let file = overwrite_and_sync(&path, &outboard)?;
                MemOrFile::File((file, outboard_size))
            }
            MemOrFile::File(outboard) => MemOrFile::File((outboard, outboard_size)),
        }
    };
    Ok(Ok(CompleteMemOrFileStorage { data, outboard }))
}

#[derive(derive_more::Debug)]
pub(crate) enum RedbActorMessage {
    // Query method: get a file handle for a hash, if it exists.
    // This will produce a file handle even for entries that are not yet in redb at all.
    Get {
        hash: Hash,
        tx: oneshot::Sender<Option<BaoFileHandle>>,
    },
    /// Query method: get the full entry state for a hash, both in memory and in redb.
    /// This is everything we got about the entry, including the actual inline outboard and data.
    EntryState {
        hash: Hash,
        tx: flume::Sender<EntryStateResponse>,
    },
    /// Modification method: get or create a file handle for a hash.
    ///
    /// If the entry exists in redb, either partial or complete, the corresponding
    /// data will be returned. If it does not yet exist, a new partial file handle
    /// will be created, but not yet written to redb.
    GetOrCreate {
        hash: Hash,
        tx: oneshot::Sender<BaoFileHandle>,
    },
    /// Modification method: inline size was exceeded for a partial entry.
    /// If the entry is complete, this is a no-op. If the entry is partial and in
    /// memory, it will be written to a file and created in redb.
    OnInlineSizeExceeded { hash: Hash },
    /// Modification method: marks a partial entry as complete.
    /// Calling this on a complete entry is a no-op.
    OnComplete { hash: Hash },
    ImportEntry {
        content: HashAndFormat,
        file: ImportFile,
        data_size: u64,
        #[debug("{:?}", outboard.as_ref().map(|x| x.len()))]
        outboard: Option<Vec<u8>>,
        tx: flume::Sender<ActorResult<(TempTag, u64)>>,
    },
    /// Modification method: import an entire flat store into the redb store.
    ImportFlatStore {
        paths: FlatStorePaths,
        tx: oneshot::Sender<()>,
    },
    /// Update options
    UpdateOptions {
        inline_options: InlineOptions,
        reapply: bool,
        tx: oneshot::Sender<()>,
    },
    /// Bulk query method: get entries from the blobs table
    Blobs {
        #[debug(skip)]
        filter: FilterPredicate<Hash, EntryState>,
        tx: oneshot::Sender<Vec<std::result::Result<(Hash, EntryState), StorageError>>>,
    },
    /// Bulk query method: get the entire tags table
    Tags {
        #[debug(skip)]
        filter: FilterPredicate<Tag, HashAndFormat>,
        tx: oneshot::Sender<Vec<std::result::Result<(Tag, HashAndFormat), StorageError>>>,
    },
    /// Modification method: set a tag to a value, or remove it.
    SetTag {
        tag: Tag,
        value: Option<HashAndFormat>,
        tx: oneshot::Sender<ActorResult<()>>,
    },
    /// Modification method: create a new unique tag and set it to a value.
    CreateTag {
        hash: HashAndFormat,
        tx: oneshot::Sender<ActorResult<Tag>>,
    },
    /// Modification method: unconditional delete the data for a number of hashes
    Delete {
        hashes: Vec<Hash>,
        tx: oneshot::Sender<()>,
    },
    /// Sync the entire database to disk.
    Sync { tx: oneshot::Sender<()> },
    /// Internal method: dump the entire database to stdout.
    Dump,
    /// Internal method: validate the entire database.
    ///
    /// Note that this will block the actor until it is done, so don't use it
    /// on a node under load.
    Validate {
        progress: tokio::sync::mpsc::Sender<ValidateProgress>,
        tx: oneshot::Sender<()>,
    },
    /// Internal method: shutdown the actor.
    Shutdown,
}

pub(crate) type FilterPredicate<K, V> =
    Box<dyn Fn(u64, AccessGuard<K>, AccessGuard<V>) -> Option<(K, V)> + Send + Sync>;

/// Paramerers for importing from a flat store
#[derive(Debug)]
pub struct FlatStorePaths {
    ///
    pub complete: PathBuf,
    ///
    pub partial: PathBuf,
    ///
    pub meta: PathBuf,
}

#[derive(Debug)]
pub(crate) struct EntryStateResponse {
    mem: Option<BaoFileHandle>,
    db: Option<EntryState<Bytes>>,
}

impl EntryStateResponse {
    fn status(&self) -> EntryStatus {
        match (&self.db, &self.mem) {
            (None, None) => EntryStatus::NotFound,
            (None, Some(_)) => EntryStatus::Partial,
            (Some(EntryState::Partial { .. }), _) => EntryStatus::Partial,
            (Some(EntryState::Complete { .. }), _) => EntryStatus::Complete,
        }
    }
}

///
#[derive(Debug, Clone)]
pub struct Store(Arc<StoreInner>);

impl Store {
    ///
    pub async fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        let path = root.as_ref();
        let db_path = path.join("meta").join("blobs.db");
        let options = Options {
            path: PathOptions::new(path),
            inline: Default::default(),
        };
        Self::new(db_path, options).await
    }

    async fn new(path: PathBuf, options: Options) -> io::Result<Self> {
        // spawn_blocking because StoreInner::new creates directories
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "no tokio runtime"))?;
        let inner =
            tokio::task::spawn_blocking(move || StoreInner::new_sync(path, options, rt)).await??;
        Ok(Self(Arc::new(inner)))
    }

    ///
    pub async fn update_inline_options(
        &self,
        inline_options: InlineOptions,
        reapply: bool,
    ) -> io::Result<()> {
        Ok(self
            .0
            .update_inline_options(inline_options, reapply)
            .await?)
    }

    ///
    pub async fn dump(&self) -> io::Result<()> {
        Ok(self.0.dump().await?)
    }

    ///
    pub async fn sync(&self) -> io::Result<()> {
        Ok(self.0.sync().await?)
    }

    /// Import from a v0 or v1 flat store, for backwards compatibility.
    pub async fn import_flat_store(&self, paths: FlatStorePaths) -> io::Result<()> {
        Ok(self.0.import_flat_store(paths).await?)
    }
}

#[derive(Debug)]
struct StoreInner {
    tx: flume::Sender<RedbActorMessage>,
    temp: Arc<RwLock<TempCounterMap>>,
    handle: Option<std::thread::JoinHandle<()>>,
    path_options: Arc<PathOptions>,
}

impl LivenessTracker for RwLock<TempCounterMap> {
    fn on_clone(&self, content: &HashAndFormat) {
        self.write().unwrap().inc(content);
    }

    fn on_drop(&self, content: &HashAndFormat) {
        self.write().unwrap().dec(content);
    }
}

impl StoreInner {
    pub fn new_sync(
        path: PathBuf,
        options: Options,
        rt: tokio::runtime::Handle,
    ) -> io::Result<Self> {
        std::fs::create_dir_all(&options.path.data_path)?;
        std::fs::create_dir_all(&options.path.temp_path)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        let temp: Arc<RwLock<TempCounterMap>> = Default::default();
        let (actor, tx) = RedbActor::new(&path, options.clone(), temp.clone(), rt)?;
        let handle = std::thread::spawn(move || {
            if let Err(cause) = actor.run() {
                tracing::error!("redb actor failed: {}", cause);
            }
        });
        Ok(Self {
            tx,
            temp,
            handle: Some(handle),
            path_options: Arc::new(options.path),
        })
    }

    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.path_options.owned_data_path(hash)
    }

    pub async fn get(&self, hash: Hash) -> OuterResult<Option<BaoFileHandle>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::Get { hash, tx })
            .await?;
        Ok(rx.await?)
    }

    pub async fn entry_state(&self, hash: Hash) -> OuterResult<EntryStateResponse> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(RedbActorMessage::EntryState { hash, tx })
            .await?;
        Ok(rx.recv_async().await?)
    }

    pub async fn get_or_create(&self, hash: Hash) -> OuterResult<BaoFileHandle> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::GetOrCreate { hash, tx })
            .await?;
        Ok(rx.await?)
    }

    pub async fn blobs(&self) -> OuterResult<Vec<io::Result<Hash>>> {
        let (tx, rx) = oneshot::channel();
        let filter: FilterPredicate<Hash, EntryState> = Box::new(|_i, k, v| {
            let v = v.value();
            if let EntryState::Complete { .. } = &v {
                Some((k.value(), v))
            } else {
                None
            }
        });
        self.tx
            .send_async(RedbActorMessage::Blobs { filter, tx })
            .await?;
        let blobs = rx.await?;
        // filter only complete blobs, and transform the internal error type into io::Error
        let complete = blobs
            .into_iter()
            .filter_map(|r| {
                r.map(|(hash, state)| {
                    if let EntryState::Complete { .. } = state {
                        Some(hash)
                    } else {
                        None
                    }
                })
                .map_err(|e| ActorError::from(e).into())
                .transpose()
            })
            .collect::<Vec<_>>();
        Ok(complete)
    }

    pub async fn partial_blobs(&self) -> OuterResult<Vec<io::Result<Hash>>> {
        let (tx, rx) = oneshot::channel();
        let filter: FilterPredicate<Hash, EntryState> = Box::new(|_i, k, v| {
            let v = v.value();
            if let EntryState::Partial { .. } = &v {
                Some((k.value(), v))
            } else {
                None
            }
        });
        self.tx
            .send_async(RedbActorMessage::Blobs { filter, tx })
            .await?;
        let blobs = rx.await?;
        // filter only partial blobs, and transform the internal error type into io::Error
        let complete = blobs
            .into_iter()
            .filter_map(|r| {
                r.map(|(hash, state)| {
                    if let EntryState::Partial { .. } = state {
                        Some(hash)
                    } else {
                        None
                    }
                })
                .map_err(|e| ActorError::from(e).into())
                .transpose()
            })
            .collect::<Vec<_>>();
        Ok(complete)
    }

    pub async fn tags(&self) -> OuterResult<Vec<io::Result<(Tag, HashAndFormat)>>> {
        let (tx, rx) = oneshot::channel();
        let filter: FilterPredicate<Tag, HashAndFormat> =
            Box::new(|_i, k, v| Some((k.value(), v.value())));
        self.tx
            .send_async(RedbActorMessage::Tags { filter, tx })
            .await?;
        let tags = rx.await?;
        // transform the internal error type into io::Error
        let tags = tags
            .into_iter()
            .map(|r| r.map_err(|e| ActorError::from(e).into()))
            .collect();
        Ok(tags)
    }

    pub async fn set_tag(&self, tag: Tag, value: Option<HashAndFormat>) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::SetTag { tag, value, tx })
            .await?;
        Ok(rx.await??)
    }

    pub async fn create_tag(&self, hash: HashAndFormat) -> OuterResult<Tag> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::CreateTag { hash, tx })
            .await?;
        Ok(rx.await??)
    }

    pub async fn delete(&self, hashes: Vec<Hash>) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::Delete { hashes, tx })
            .await?;
        Ok(rx.await?)
    }

    pub async fn entry_status(&self, hash: &Hash) -> OuterResult<EntryStatus> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(RedbActorMessage::EntryState { hash: *hash, tx })
            .await?;
        Ok(rx.into_recv_async().await?.status())
    }

    pub fn entry_status_sync(&self, hash: &Hash) -> OuterResult<EntryStatus> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send(RedbActorMessage::EntryState { hash: *hash, tx })?;
        Ok(rx.recv()?.status())
    }

    pub async fn complete(&self, hash: Hash) -> OuterResult<()> {
        self.tx
            .send_async(RedbActorMessage::OnComplete { hash })
            .await?;
        Ok(())
    }

    ///
    #[allow(dead_code)]
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(handle) = self.handle.take() {
            self.tx.send_async(RedbActorMessage::Shutdown).await?;
            handle
                .join()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "redb actor thread panicked"))?
        };
        Ok(())
    }

    pub async fn validate(
        &self,
        progress: tokio::sync::mpsc::Sender<ValidateProgress>,
    ) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::Validate { progress, tx })
            .await?;
        Ok(rx.await?)
    }

    pub async fn import_flat_store(&self, paths: FlatStorePaths) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::ImportFlatStore { paths, tx })
            .await?;
        Ok(rx.await?)
    }

    pub async fn update_inline_options(
        &self,
        inline_options: InlineOptions,
        reapply: bool,
    ) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(RedbActorMessage::UpdateOptions {
                inline_options,
                reapply,
                tx,
            })
            .await?;
        Ok(rx.await?)
    }

    pub async fn dump(&self) -> OuterResult<()> {
        self.tx.send_async(RedbActorMessage::Dump).await?;
        Ok(())
    }

    pub async fn sync(&self) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx.send_async(RedbActorMessage::Sync { tx }).await?;
        Ok(rx.await?)
    }

    pub fn temp_tag(&self, content: HashAndFormat) -> TempTag {
        TempTag::new(content, Some(self.temp.clone()))
    }

    fn import_file_sync(
        &self,
        path: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> OuterResult<(TempTag, u64)> {
        if !path.is_absolute() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "path must be absolute").into(),
            );
        }
        if !path.is_file() && !path.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is not a file or symlink",
            )
            .into());
        }
        let id = progress.new_id();
        progress.blocking_send(ImportProgress::Found {
            id,
            name: path.to_string_lossy().to_string(),
        })?;
        let file = match mode {
            ImportMode::TryReference => ImportFile::External(path),
            ImportMode::Copy => {
                let temp_path = self.temp_file_path();
                // copy the data, since it is not stable
                progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
                if reflink_copy::reflink_or_copy(&path, &temp_path)?.is_none() {
                    tracing::debug!("reflinked {} to {}", path.display(), temp_path.display());
                } else {
                    tracing::debug!("copied {} to {}", path.display(), temp_path.display());
                }
                ImportFile::TempFile(temp_path)
            }
        };
        let (tag, size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok((tag, size))
    }

    fn import_bytes_sync(&self, data: Bytes, format: BlobFormat) -> OuterResult<TempTag> {
        let id = 0;
        let file = ImportFile::Memory(data);
        let progress = IgnoreProgressSender::default();
        let (tag, _size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok(tag)
    }

    fn finalize_import_sync(
        &self,
        file: ImportFile,
        format: BlobFormat,
        id: u64,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> OuterResult<(TempTag, u64)> {
        let data_size = file.len()?;
        tracing::info!("finalize_import_sync {:?} {}", file, data_size);
        progress.blocking_send(ImportProgress::Size {
            id,
            size: data_size,
        })?;
        let progress2 = progress.clone();
        let (hash, outboard) = match file.content() {
            MemOrFile::File(path) => {
                let span = trace_span!("outboard.compute", path = %path.display());
                let _guard = span.enter();
                let file = std::fs::File::open(path)?;
                compute_outboard(file, data_size, move |offset| {
                    Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
                })?
            }
            MemOrFile::Mem(bytes) => {
                // todo: progress? usually this is will be small enough that progress might not be needed.
                compute_outboard(bytes, data_size, |_| Ok(()))?
            }
        };
        progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
        // from here on, everything related to the hash is protected by the temp tag
        let tag = self.temp_tag(HashAndFormat { hash, format });
        let hash = *tag.hash();
        // blocking send for the import
        let (tx, rx) = flume::bounded(1);
        self.tx.send(RedbActorMessage::ImportEntry {
            content: HashAndFormat { hash, format },
            file,
            outboard,
            data_size,
            tx,
        })?;
        Ok(rx.recv()??)
    }

    fn temp_file_path(&self) -> PathBuf {
        self.path_options.temp_file_name()
    }
}

impl Drop for StoreInner {
    fn drop(&mut self) {
        println!("store inner drop");
        if let Some(handle) = self.handle.take() {
            self.tx.send(RedbActorMessage::Shutdown).ok();
            handle.join().ok();
        }
    }
}

struct RedbActor {
    db: redb::Database,
    state: BTreeMap<Hash, BaoFileHandle>,
    temp: Arc<RwLock<TempCounterMap>>,
    msgs: flume::Receiver<RedbActorMessage>,
    path_options: PathOptions,
    inline_options: InlineOptions,
    create_options: Arc<BaoFileConfig>,
    #[allow(dead_code)]
    rt: tokio::runtime::Handle,
}

// impl RedbActor {
//     fn recv_batch(&self, n: usize) -> (Vec<RedbActorMessage>, bool) {
//         let mut res = Vec::new();
//         match self.msgs.recv() {
//             Ok(msg) => res.push(msg),
//             Err(flume::RecvError::Disconnected) => return (res, true),
//         }
//         let mut done = false;
//         for _ in 1..n {
//             if let Ok(msg) = self.msgs.try_recv() {
//                 res.push(msg);
//             } else {
//                 done = true;
//                 break;
//             }
//         }
//         (res, done)
//     }
// }

/// Error type for message handler functions of the redb actor.
///
/// What can go wrong are various things with redb, as well as io errors related
/// to files other than redb.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ActorError {
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("transaction error: {0}")]
    Transaction(#[from] redb::TransactionError),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("storage error: {0}")]
    Storage(#[from] redb::StorageError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("inconsistent database state: {0}")]
    Inconsistent(String),
}

impl From<ActorError> for io::Error {
    fn from(e: ActorError) -> Self {
        match e {
            ActorError::Io(e) => e,
            e => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

/// Result type for handler functions of the redb actor.
///
/// See [`ActorError`] for what can go wrong.
pub(crate) type ActorResult<T> = std::result::Result<T, ActorError>;

/// Error type for calling the redb actor from the store.
///
/// What can go wrong is all the things in [`ActorError`] and in addition
/// sending and receiving messages.
#[derive(Debug, thiserror::Error)]
pub(crate) enum OuterError {
    #[error("inner error: {0}")]
    Inner(#[from] ActorError),
    #[error("send error: {0}")]
    Send(#[from] flume::SendError<RedbActorMessage>),
    #[error("progress send error: {0}")]
    ProgressSend(#[from] ProgressSendError),
    #[error("recv error: {0}")]
    Recv(#[from] oneshot::Canceled),
    #[error("recv error: {0}")]
    FlumeRecv(#[from] flume::RecvError),
    #[error("join error: {0}")]
    JoinTask(#[from] tokio::task::JoinError),
}

/// Result type for calling the redb actor from the store.
///
/// See [`OuterError`] for what can go wrong.
pub(crate) type OuterResult<T> = std::result::Result<T, OuterError>;

impl From<io::Error> for OuterError {
    fn from(e: io::Error) -> Self {
        OuterError::Inner(ActorError::Io(e))
    }
}

impl From<OuterError> for io::Error {
    fn from(e: OuterError) -> Self {
        match e {
            OuterError::Inner(ActorError::Io(e)) => e,
            e => io::Error::new(io::ErrorKind::Other, e),
        }
    }
}

impl crate::store::traits::Map for Store {
    type Entry = Entry;

    async fn get(&self, hash: &Hash) -> io::Result<Option<Self::Entry>> {
        Ok(self.0.get(*hash).await?.map(From::from))
    }
}

impl crate::store::traits::MapMut for Store {
    type EntryMut = Entry;

    async fn get_or_create(&self, hash: Hash, _size: u64) -> io::Result<Self::EntryMut> {
        Ok(self.0.get_or_create(hash).await?.into())
    }

    async fn entry_status(&self, hash: &Hash) -> io::Result<EntryStatus> {
        Ok(self.0.entry_status(hash).await?)
    }

    async fn get_possibly_partial(
        &self,
        hash: &Hash,
    ) -> io::Result<super::PossiblyPartialEntry<Self>> {
        match self.0.get(*hash).await? {
            Some(entry) => Ok({
                if entry.is_complete() {
                    super::PossiblyPartialEntry::Complete(entry.into())
                } else {
                    super::PossiblyPartialEntry::Partial(entry.into())
                }
            }),
            None => Ok(super::PossiblyPartialEntry::NotFound),
        }
    }

    async fn insert_complete(&self, entry: Self::EntryMut) -> io::Result<()> {
        Ok(self.0.complete(entry.hash()).await?)
    }

    fn entry_status_sync(&self, hash: &Hash) -> io::Result<EntryStatus> {
        Ok(self.0.entry_status_sync(hash)?)
    }
}

impl ReadableStore for Store {
    async fn blobs(&self) -> io::Result<super::DbIter<Hash>> {
        Ok(Box::new(self.0.blobs().await?.into_iter()))
    }

    async fn partial_blobs(&self) -> io::Result<super::DbIter<Hash>> {
        Ok(Box::new(self.0.partial_blobs().await?.into_iter()))
    }

    async fn tags(&self) -> io::Result<super::DbIter<(Tag, HashAndFormat)>> {
        Ok(Box::new(self.0.tags().await?.into_iter()))
    }

    fn temp_tags(&self) -> Box<dyn Iterator<Item = HashAndFormat> + Send + Sync + 'static> {
        Box::new(self.0.temp.read().unwrap().keys())
    }

    async fn validate(&self, tx: tokio::sync::mpsc::Sender<ValidateProgress>) -> io::Result<()> {
        self.0.validate(tx).await?;
        Ok(())
    }

    async fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        let tt = self.0.temp_tag(HashAndFormat::raw(hash));
        let Some(state) = self.0.entry_state(hash).await?.db else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("hash not found in db: {}", hash.to_hex()),
            ));
        };
        // source is either mem (bytes) or (path, size, owned)
        let source = match state {
            EntryState::Partial { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "hash is partial",
                ));
            }
            EntryState::Complete { data_location, .. } => match data_location {
                DataLocation::Inline(data) => MemOrFile::Mem(data),
                DataLocation::Owned(size) => {
                    let path = self.0.owned_data_path(&hash);
                    MemOrFile::File((path, size, true))
                }
                DataLocation::External(paths, size) => {
                    let path = &paths[0];
                    MemOrFile::File((path.clone(), size, false))
                }
            },
        };
        tokio::task::spawn_blocking(move || {
            tracing::trace!("exporting {} to {} ({:?})", hash, target.display(), mode);

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
            let stable = mode == ExportMode::TryReference;
            match source {
                MemOrFile::Mem(data) => {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&target)?;
                    file.write_all(&data)?;
                }
                MemOrFile::File((source, size, _)) => {
                    // todo
                    let owned = false;
                    if stable && owned {
                        tracing::debug!("moving {} to {}", source.display(), target.display());
                        // we need to atomically move the file to the new location and update the redb entry.
                        // we can't do this here! That's why owned is set to false for now.
                        std::fs::rename(source, &target)?;
                    } else {
                        tracing::debug!("copying {} to {}", source.display(), target.display());
                        progress(0)?;
                        // todo: progress? not needed if the file is small
                        if reflink_copy::reflink_or_copy(&source, &target)?.is_none() {
                            tracing::debug!(
                                "reflinked {} to {}",
                                source.display(),
                                target.display()
                            );
                        } else {
                            tracing::debug!("copied {} to {}", source.display(), target.display());
                        }
                        progress(size)?;
                        // todo: should we add the new location to the entry if it was already non-owned?
                    }
                }
            };
            Ok(())
        })
        .await??;
        drop(tt);
        Ok(())
    }
}

impl crate::store::traits::Store for Store {
    async fn import_file(
        &self,
        path: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(crate::TempTag, u64)> {
        let this = self.0.clone();
        Ok(
            tokio::task::spawn_blocking(move || {
                this.import_file_sync(path, mode, format, progress)
            })
            .await??,
        )
    }

    async fn import_bytes(
        &self,
        data: bytes::Bytes,
        format: iroh_base::hash::BlobFormat,
    ) -> io::Result<crate::TempTag> {
        let this = self.0.clone();
        Ok(tokio::task::spawn_blocking(move || this.import_bytes_sync(data, format)).await??)
    }

    async fn import_stream(
        &self,
        mut data: impl Stream<Item = io::Result<Bytes>> + Unpin + Send + 'static,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(TempTag, u64)> {
        let this = self.clone();
        let id = progress.new_id();
        // write to a temp file
        let temp_data_path = this.0.temp_file_path();
        let name = temp_data_path
            .file_name()
            .expect("just created")
            .to_string_lossy()
            .to_string();
        progress.send(ImportProgress::Found { id, name }).await?;
        let mut writer = tokio::fs::File::create(&temp_data_path).await?;
        let mut offset = 0;
        while let Some(chunk) = data.next().await {
            let chunk = chunk?;
            writer.write_all(&chunk).await?;
            offset += chunk.len() as u64;
            progress.try_send(ImportProgress::CopyProgress { id, offset })?;
        }
        writer.flush().await?;
        drop(writer);
        let file = ImportFile::TempFile(temp_data_path);
        Ok(tokio::task::spawn_blocking(move || {
            this.0.finalize_import_sync(file, format, id, progress)
        })
        .await??)
    }

    async fn set_tag(&self, name: Tag, hash: Option<HashAndFormat>) -> io::Result<()> {
        Ok(self.0.set_tag(name, hash).await?)
    }

    async fn create_tag(&self, hash: HashAndFormat) -> io::Result<Tag> {
        Ok(self.0.create_tag(hash).await?)
    }

    async fn delete(&self, hashes: Vec<Hash>) -> io::Result<()> {
        Ok(self.0.delete(hashes).await?)
    }

    fn temp_tag(&self, value: HashAndFormat) -> TempTag {
        self.0.temp_tag(value)
    }
}

impl RedbActor {
    fn new(
        path: &Path,
        options: Options,
        temp: Arc<RwLock<TempCounterMap>>,
        rt: tokio::runtime::Handle,
    ) -> ActorResult<(Self, flume::Sender<RedbActorMessage>)> {
        let db = redb::Database::create(path)?;
        let tx = db.begin_write()?;
        {
            let _blobs = tx.open_table(BLOBS_TABLE)?;
            let _inline_data = tx.open_table(INLINE_DATA_TABLE)?;
            let _inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
            let _tags = tx.open_table(TAGS_TABLE)?;
        }
        tx.commit()?;
        let (tx, rx) = flume::unbounded();
        let tx2 = tx.clone();
        let create_options = BaoFileConfig::new(
            Arc::new(options.path.data_path.clone()),
            16 * 1024,
            Some(Arc::new(move |hash| {
                // todo: make the callback allow async
                tx2.send(RedbActorMessage::OnInlineSizeExceeded { hash: *hash })
                    .ok();
                Ok(())
            })),
        );
        Ok((
            Self {
                db,
                temp,
                state: BTreeMap::new(),
                msgs: rx,
                inline_options: options.inline,
                path_options: options.path,
                create_options: Arc::new(create_options),
                rt,
            },
            tx,
        ))
    }

    fn entry_state(&mut self, hash: Hash) -> ActorResult<EntryStateResponse> {
        let mem = self.state.get(&hash).cloned();
        let tx = self.db.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let db = match blobs.get(hash)? {
            Some(entry) => Some({
                match entry.value() {
                    EntryState::Complete {
                        data_location,
                        outboard_location,
                    } => {
                        let data_location = match data_location {
                            DataLocation::Inline(()) => {
                                let data = tx.open_table(INLINE_DATA_TABLE)?;
                                let data = data.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline data missing".to_owned())
                                })?;
                                DataLocation::Inline(Bytes::copy_from_slice(data.value()))
                            }
                            DataLocation::Owned(x) => DataLocation::Owned(x),
                            DataLocation::External(p, s) => DataLocation::External(p, s),
                        };
                        let outboard_location = match outboard_location {
                            OutboardLocation::Inline(()) => {
                                let outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
                                let outboard = outboard.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline outboard missing".to_owned())
                                })?;
                                OutboardLocation::Inline(Bytes::copy_from_slice(outboard.value()))
                            }
                            OutboardLocation::Owned => OutboardLocation::Owned,
                            OutboardLocation::NotNeeded => OutboardLocation::NotNeeded,
                        };
                        EntryState::Complete {
                            data_location,
                            outboard_location,
                        }
                    }
                    EntryState::Partial { size } => EntryState::Partial { size },
                }
            }),
            None => None,
        };
        Ok(EntryStateResponse { mem, db })
    }

    fn get(&mut self, hash: Hash) -> ActorResult<Option<BaoFileHandle>> {
        if let Some(entry) = self.state.get(&hash) {
            return Ok(Some(entry.clone()));
        }
        let tx = self.db.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let Some(entry) = blobs.get(hash)? else {
            tracing::debug!("redb get not found {}", hash.to_hex());
            return Ok(None);
        };
        // todo: if complete, load inline data and/or outboard into memory if needed,
        // and return a complete entry.
        let entry = entry.value();
        let config = self.create_options.clone();
        let handle = match entry {
            EntryState::Complete {
                data_location,
                outboard_location,
            } => {
                let data = load_data(&self.path_options, &tx, data_location, &hash)?;
                let outboard = load_outboard(
                    &self.path_options,
                    &tx,
                    outboard_location,
                    data.size(),
                    &hash,
                )?;
                BaoFileHandle::new_complete(config, hash, data, outboard)
            }
            EntryState::Partial { .. } => BaoFileHandle::incomplete_file(config, hash)?,
        };
        self.state.insert(hash, handle.clone());
        Ok(Some(handle))
    }

    fn import_entry(
        &mut self,
        content: HashAndFormat,
        file: ImportFile,
        data_size: u64,
        outboard: Option<Vec<u8>>,
    ) -> ActorResult<(TempTag, u64)> {
        let outboard_size = outboard.as_ref().map(|x| x.len() as u64).unwrap_or(0);
        let inline_data = data_size <= self.inline_options.max_data_inlined;
        let inline_outboard =
            outboard_size <= self.inline_options.max_outboard_inlined && outboard_size != 0;
        // from here on, everything related to the hash is protected by the temp tag
        let tag = TempTag::new(content, Some(self.temp.clone()));
        let hash = *tag.hash();
        // move the data file into place, or create a reference to it
        let data_location = match file {
            ImportFile::External(external_path) => {
                tracing::info!("stored external reference {}", external_path.display());
                if inline_data {
                    tracing::info!(
                        "reading external data to inline it: {}",
                        external_path.display()
                    );
                    let data = Bytes::from(std::fs::read(&external_path)?);
                    DataLocation::Inline(data)
                } else {
                    DataLocation::External(vec![external_path], data_size)
                }
            }
            ImportFile::TempFile(temp_data_path) => {
                if inline_data {
                    tracing::info!(
                        "reading and deleting temp file to inline it: {}",
                        temp_data_path.display()
                    );
                    let data = Bytes::from(read_and_remove(&temp_data_path)?);
                    DataLocation::Inline(data)
                } else {
                    let data_path = self.path_options.owned_data_path(&hash);
                    std::fs::rename(&temp_data_path, &data_path)?;
                    tracing::info!("created file {}", data_path.display());
                    DataLocation::Owned(data_size)
                }
            }
            ImportFile::Memory(data) => {
                if inline_data {
                    DataLocation::Inline(data)
                } else {
                    let data_path = self.path_options.owned_data_path(&hash);
                    overwrite_and_sync(&data_path, &data)?;
                    tracing::info!("created file {}", data_path.display());
                    DataLocation::Owned(data_size)
                }
            }
        };
        let outboard_location = if let Some(outboard) = outboard {
            if inline_outboard {
                OutboardLocation::Inline(Bytes::from(outboard))
            } else {
                let outboard_path = self.path_options.owned_outboard_path(&hash);
                // todo: this blocks the actor when writing a large outboard
                overwrite_and_sync(&outboard_path, &outboard)?;
                OutboardLocation::Owned
            }
        } else {
            OutboardLocation::NotNeeded
        };
        let tx = self.db.begin_write()?;
        {
            let mut blobs = tx.open_table(BLOBS_TABLE)?;
            let mut inline_data = tx.open_table(INLINE_DATA_TABLE)?;
            let mut inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
            if let DataLocation::Inline(data) = &data_location {
                inline_data.insert(hash, data.as_ref())?;
            }
            if let OutboardLocation::Inline(outboard) = &outboard_location {
                inline_outboard.insert(hash, outboard.as_ref())?;
            }
            let entry = blobs.get(hash)?;
            let entry = entry.map(|x| x.value()).unwrap_or_default();
            let entry = entry.union(EntryState::Complete {
                data_location: data_location.discard_inline_data(),
                outboard_location: outboard_location.discard_extra_data(),
            })?;
            blobs.insert(hash, entry)?;
        }
        tx.commit()?;
        Ok((tag, data_size))
    }

    fn get_or_create(&mut self, hash: Hash) -> ActorResult<BaoFileHandle> {
        if let Some(entry) = self.state.get(&hash) {
            return Ok(entry.clone());
        }
        let tx = self.db.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let entry = blobs.get(hash)?;
        let handle = if let Some(entry) = entry {
            let entry = entry.value();
            match entry {
                EntryState::Complete {
                    data_location,
                    outboard_location,
                    ..
                } => {
                    let data = load_data(&self.path_options, &tx, data_location, &hash)?;
                    let outboard = load_outboard(
                        &self.path_options,
                        &tx,
                        outboard_location,
                        data.size(),
                        &hash,
                    )?;
                    println!("creating complete entry for {}", hash.to_hex());
                    BaoFileHandle::new_complete(self.create_options.clone(), hash, data, outboard)
                }
                EntryState::Partial { .. } => {
                    println!("creating partial entry for {}", hash.to_hex());
                    BaoFileHandle::incomplete_file(self.create_options.clone(), hash)?
                }
            }
        } else {
            BaoFileHandle::incomplete_mem(self.create_options.clone(), hash)
        };
        self.state.insert(hash, handle.clone());
        Ok(handle)
    }

    /// Read the entire blobs table. Callers can then sift through the results to find what they need
    fn blobs(
        &mut self,
        filter: FilterPredicate<Hash, EntryState>,
    ) -> ActorResult<Vec<std::result::Result<(Hash, EntryState), StorageError>>> {
        let tx = self.db.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let mut res = Vec::new();
        let mut index = 0u64;
        #[allow(clippy::explicit_counter_loop)]
        for item in blobs.iter()? {
            match item {
                Ok((k, v)) => {
                    if let Some(item) = filter(index, k, v) {
                        res.push(Ok(item));
                    }
                }
                Err(e) => {
                    res.push(Err(e));
                }
            }
            index += 1;
        }
        Ok(res)
    }

    /// Read the entire tags table. Callers can then sift through the results to find what they need
    fn tags(
        &mut self,
        filter: FilterPredicate<Tag, HashAndFormat>,
    ) -> ActorResult<Vec<std::result::Result<(Tag, HashAndFormat), StorageError>>> {
        let tx = self.db.begin_read()?;
        let tags = tx.open_table(TAGS_TABLE)?;
        let mut res = Vec::new();
        let mut index = 0u64;
        #[allow(clippy::explicit_counter_loop)]
        for item in tags.iter()? {
            match item {
                Ok((k, v)) => {
                    if let Some(item) = filter(index, k, v) {
                        res.push(Ok(item));
                    }
                }
                Err(e) => {
                    res.push(Err(e));
                }
            }
            index += 1;
        }
        Ok(res)
    }

    fn create_tag(&mut self, content: HashAndFormat) -> ActorResult<Tag> {
        let tx = self.db.begin_write()?;
        let tag = {
            let mut tags = tx.open_table(TAGS_TABLE)?;
            let tag = Tag::auto(SystemTime::now(), |x| {
                matches!(tags.get(Tag(Bytes::copy_from_slice(x))), Ok(Some(_)))
            });
            tags.insert(tag.clone(), content)?;
            tag
        };
        tx.commit()?;
        Ok(tag)
    }

    fn set_tag(&self, tag: Tag, value: Option<HashAndFormat>) -> ActorResult<()> {
        let tx = self.db.begin_write()?;
        {
            let mut tags = tx.open_table(TAGS_TABLE)?;
            match value {
                Some(value) => {
                    tags.insert(tag, value)?;
                }
                None => {
                    tags.remove(tag)?;
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn on_inline_size_exceeded(&mut self, hash: Hash) -> ActorResult<()> {
        let tx = self.db.begin_write()?;
        {
            let mut blobs = tx.open_table(BLOBS_TABLE)?;
            let entry = blobs.get(hash)?.map(|x| x.value()).unwrap_or_default();
            let entry = entry.union(EntryState::Partial { size: None })?;
            blobs.insert(hash, entry)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn update_options(&mut self, options: InlineOptions, reapply: bool) -> ActorResult<()> {
        self.inline_options = options;
        if reapply {
            let mut delete_after_commit = Vec::new();
            let mut delete_on_fail = Vec::new();
            let tx = self.db.begin_write()?;
            {
                let mut blobs = tx.open_table(BLOBS_TABLE)?;
                let mut inline_data = tx.open_table(INLINE_DATA_TABLE)?;
                let mut inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
                let hashes = blobs
                    .iter()?
                    .map(|x| x.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for hash in hashes {
                    let guard = blobs
                        .get(hash)?
                        .ok_or_else(|| ActorError::Inconsistent("hash not found".to_owned()))?;
                    let entry = guard.value();
                    if let EntryState::Complete {
                        data_location,
                        outboard_location,
                    } = entry
                    {
                        let (data_location, data_size, data_location_changed) = match data_location
                        {
                            DataLocation::Owned(size) => {
                                // inline
                                if size <= self.inline_options.max_data_inlined {
                                    let path = self.path_options.owned_data_path(&hash);
                                    let data = std::fs::read(&path)?;
                                    delete_after_commit.push(path);
                                    inline_data.insert(hash, data.as_slice())?;
                                    (DataLocation::Inline(()), size, true)
                                } else {
                                    (DataLocation::Owned(size), size, false)
                                }
                            }
                            DataLocation::Inline(()) => {
                                let guard = inline_data.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline data missing".to_owned())
                                })?;
                                let data = guard.value();
                                let size = data.len() as u64;
                                if size > self.inline_options.max_data_inlined {
                                    let path = self.path_options.owned_data_path(&hash);
                                    std::fs::write(&path, data)?;
                                    drop(guard);
                                    inline_data.remove(hash)?;
                                    delete_on_fail.push(path);
                                    (DataLocation::Owned(size), size, true)
                                } else {
                                    (DataLocation::Inline(()), size, false)
                                }
                            }
                            DataLocation::External(paths, size) => {
                                (DataLocation::External(paths, size), size, false)
                            }
                        };
                        let outboard_size = raw_outboard_size(data_size);
                        let (outboard_location, outboard_location_changed) = match outboard_location
                        {
                            OutboardLocation::Owned
                                if outboard_size <= self.inline_options.max_outboard_inlined =>
                            {
                                let path = self.path_options.owned_outboard_path(&hash);
                                let outboard = std::fs::read(&path)?;
                                delete_after_commit.push(path);
                                inline_outboard.insert(hash, outboard.as_slice())?;
                                (OutboardLocation::Inline(()), true)
                            }
                            OutboardLocation::Inline(())
                                if outboard_size > self.inline_options.max_outboard_inlined =>
                            {
                                let guard = inline_outboard.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline outboard missing".to_owned())
                                })?;
                                let outboard = guard.value();
                                let path = self.path_options.owned_outboard_path(&hash);
                                std::fs::write(&path, outboard)?;
                                drop(guard);
                                inline_outboard.remove(hash)?;
                                delete_on_fail.push(path);
                                (OutboardLocation::Owned, true)
                            }
                            x => (x, false),
                        };
                        drop(guard);
                        if data_location_changed || outboard_location_changed {
                            blobs.insert(
                                hash,
                                EntryState::Complete {
                                    data_location,
                                    outboard_location,
                                },
                            )?;
                        }
                    }
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    fn import_flat_store(&mut self, paths: FlatStorePaths) -> ActorResult<()> {
        /// A file name that indicates the purpose of the file.
        #[derive(Clone, PartialEq, Eq)]
        pub enum FileName {
            /// Incomplete data for the hash, with an unique id
            PartialData(Hash, [u8; 16]),
            /// File is storing data for the hash
            Data(Hash),
            /// File is storing a partial outboard
            PartialOutboard(Hash, [u8; 16]),
            /// File is storing an outboard
            ///
            /// We can have multiple files with the same outboard, in case the outboard
            /// does not contain hashes. But we don't store those outboards.
            Outboard(Hash),
            #[allow(dead_code)]
            /// Temporary paths file
            TempPaths(Hash, [u8; 16]),
            /// External paths for the hash
            Paths(Hash),
            /// File is going to be used to store metadata
            Meta(Vec<u8>),
        }

        impl FileName {
            /// Get the file purpose from a path, handling weird cases
            pub fn from_path(path: impl AsRef<Path>) -> std::result::Result<Self, &'static str> {
                let path = path.as_ref();
                let name = path.file_name().ok_or("no file name")?;
                let name = name.to_str().ok_or("invalid file name")?;
                let purpose = Self::from_str(name).map_err(|_| "invalid file name")?;
                Ok(purpose)
            }
        }

        impl FromStr for FileName {
            type Err = ();

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                const OUTBOARD_EXT: &str = "obao4";
                // split into base and extension
                let Some((base, ext)) = s.rsplit_once('.') else {
                    return Err(());
                };
                // strip optional leading dot
                let base = base.strip_prefix('.').unwrap_or(base);
                let mut hash = [0u8; 32];
                if let Some((base, uuid_text)) = base.split_once('-') {
                    let mut uuid = [0u8; 16];
                    hex::decode_to_slice(uuid_text, &mut uuid).map_err(|_| ())?;
                    if ext == "data" {
                        hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
                        Ok(Self::PartialData(hash.into(), uuid))
                    } else if ext == OUTBOARD_EXT {
                        hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
                        Ok(Self::PartialOutboard(hash.into(), uuid))
                    } else {
                        Err(())
                    }
                } else if ext == "meta" {
                    let data = hex::decode(base).map_err(|_| ())?;
                    Ok(Self::Meta(data))
                } else {
                    hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
                    if ext == "data" {
                        Ok(Self::Data(hash.into()))
                    } else if ext == OUTBOARD_EXT {
                        Ok(Self::Outboard(hash.into()))
                    } else if ext == "paths" {
                        Ok(Self::Paths(hash.into()))
                    } else {
                        Err(())
                    }
                }
            }
        }

        #[derive(Debug, Default)]
        struct EntryPaths {
            data: Option<(PathBuf, u64)>,
            outboard: Option<(PathBuf, u64)>,
            external: Vec<(PathBuf, u64)>,
            #[allow(clippy::type_complexity)]
            partial: BTreeMap<[u8; 16], (Option<(PathBuf, u64)>, Option<(PathBuf, u64)>)>,
        }

        fn copy_outboard(src: &Path, tgt: &Path) -> io::Result<()> {
            let mut data = std::fs::read(src)?;
            if data.len() % 64 != 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outboard without length prefix",
                ));
            }
            data.splice(0..8, []);
            std::fs::write(tgt, data)
        }

        let FlatStorePaths {
            complete: complete_path,
            partial: partial_path,
            meta: meta_path,
        } = &paths;
        tracing::info!("importing flat store from {:?}", paths);
        let mut index = BTreeMap::<Hash, EntryPaths>::new();
        let mut have_partial = false;
        let mut have_complete = false;
        let mut have_meta = false;
        if partial_path.exists() {
            for entry in std::fs::read_dir(partial_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let Ok(meta) = entry.metadata() else {
                        tracing::warn!("unable to open file {}", path.display());
                        continue;
                    };
                    let size = meta.len();
                    if let Ok(purpose) = FileName::from_path(&path) {
                        match purpose {
                            FileName::PartialData(hash, uuid) => {
                                let m = index.entry(hash).or_default();
                                m.partial.entry(uuid).or_default().0 = Some((path, size));
                            }
                            FileName::PartialOutboard(hash, uuid) => {
                                let m = index.entry(hash).or_default();
                                m.partial.entry(uuid).or_default().0 = Some((path, size));
                            }
                            _ => {
                                // silently ignore other files, there could be a valid reason for them
                            }
                        }
                    }
                }
            }
            have_partial = true;
        }

        if complete_path.exists() {
            for entry in std::fs::read_dir(complete_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let Ok(meta) = entry.metadata() else {
                        tracing::warn!("unable to open file {}", path.display());
                        continue;
                    };
                    let size = meta.len();
                    if let Ok(purpose) = FileName::from_path(&path) {
                        match purpose {
                            FileName::Data(hash) => {
                                let m = index.entry(hash).or_default();
                                m.data = Some((path, size));
                            }
                            FileName::Outboard(hash) => {
                                let m = index.entry(hash).or_default();
                                m.outboard = Some((path, size));
                            }
                            FileName::Paths(hash) => {
                                let m = index.entry(hash).or_default();
                                let paths = std::fs::read(path)?;
                                let paths: BTreeSet<PathBuf> = postcard::from_bytes(&paths)
                                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                                for path in paths {
                                    let Ok(meta) = path.metadata() else {
                                        tracing::warn!(
                                            "unable to open external file {}",
                                            path.display()
                                        );
                                        continue;
                                    };
                                    m.external.push((path, meta.len()));
                                }
                            }
                            _ => {
                                // silently ignore other files, there could be a valid reason for them
                            }
                        }
                    }
                }
            }
            have_complete = true;
        }

        let tx = self.db.begin_write()?;
        let mut blobs_table = tx.open_table(BLOBS_TABLE)?;
        let mut tags_table = tx.open_table(TAGS_TABLE)?;
        for (hash, entry) in index {
            if blobs_table.get(hash)?.is_some() {
                tracing::info!("hash {} already exists in the db", hash.to_hex());
                continue;
            }
            if let Some((data_path, data_size)) = entry.data {
                let needs_outboard = data_size >= IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, outboard_size)) = entry.outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    if outboard_size != raw_outboard_size(data_size) + 8 {
                        tracing::warn!("outboard file has wrong size for {}", hash.to_hex());
                        continue;
                    }
                    Some(outboard_path)
                } else {
                    None
                };
                if let Err(cause) =
                    std::fs::rename(data_path, self.path_options.owned_data_path(&hash))
                {
                    tracing::error!("failed to move data file: {}", cause);
                    continue;
                }
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let entry = EntryState::Complete {
                    data_location: DataLocation::Owned(data_size),
                    outboard_location: if needs_outboard {
                        OutboardLocation::Owned
                    } else {
                        OutboardLocation::NotNeeded
                    },
                };
                blobs_table.insert(hash, entry)?;
                continue;
            }
            if !entry.external.is_empty() {
                let sizes = entry.external.iter().map(|x| x.1).collect::<Vec<_>>();
                if sizes.iter().min() != sizes.iter().max() {
                    tracing::warn!("external files for {} have different sizes", hash.to_hex());
                    continue;
                }
                let size = sizes[0];
                let needs_outboard = size >= IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, outboard_size)) = entry.outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    if outboard_size != raw_outboard_size(size) + 8 {
                        tracing::warn!("outboard file has wrong size for {}", hash.to_hex());
                        continue;
                    }
                    Some(outboard_path)
                } else {
                    None
                };
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let paths = entry
                    .external
                    .into_iter()
                    .map(|(path, _size)| path)
                    .collect();
                let entry = EntryState::Complete {
                    data_location: DataLocation::External(paths, size),
                    outboard_location: if needs_outboard {
                        OutboardLocation::Owned
                    } else {
                        OutboardLocation::NotNeeded
                    },
                };
                blobs_table.insert(hash, entry)?;
                continue;
            }
            // partial entries that have data
            let partial_with_data = entry.partial.into_iter().filter_map(|(_k, (d, o))| {
                if let Some(d) = d {
                    Some((d, o))
                } else {
                    None
                }
            });
            let largest_partial = partial_with_data.max_by_key(|((_, size), _o)| *size);
            if let Some(((data_path, data_size), outboard)) = largest_partial {
                let needs_outboard = data_size >= IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, _)) = outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    Some(outboard_path)
                } else {
                    None
                };
                if let Err(cause) =
                    std::fs::rename(data_path, self.path_options.owned_data_path(&hash))
                {
                    tracing::error!("failed to move data file: {}", cause);
                    continue;
                }
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let entry = EntryState::Partial { size: None };
                blobs_table.insert(hash, entry)?;
                continue;
            }
        }
        // import tags, this is pretty straightforward
        if meta_path.exists() {
            let tags_path = meta_path.join("tags.meta");
            if tags_path.exists() {
                let data = std::fs::read(&tags_path)?;
                #[allow(clippy::mutable_key_type)]
                let tags: BTreeMap<Tag, HashAndFormat> = postcard::from_bytes(&data)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                tracing::debug!("loaded tags. {} entries", tags.len());
                for (tag, content) in tags {
                    tags_table.insert(tag, content)?;
                }
                std::fs::remove_file(tags_path).ok();
            };
            have_meta = true;
        }

        drop(blobs_table);
        drop(tags_table);
        tx.commit()?;

        if have_partial {
            if let Err(cause) = std::fs::remove_dir_all(partial_path) {
                tracing::error!("failed to remove partial path: {}", cause);
            }
        }
        if have_complete {
            if let Err(cause) = std::fs::remove_dir_all(complete_path) {
                tracing::error!("failed to remove complete path: {}", cause);
            }
        }
        if have_meta {
            if let Err(cause) = std::fs::remove_dir_all(meta_path) {
                tracing::error!("failed to remove meta path: {}", cause);
            }
        }
        Ok(())
    }

    fn delete(&mut self, hashes: Vec<Hash>) -> ActorResult<()> {
        let tx = self.db.begin_write()?;
        {
            let mut blobs = tx.open_table(BLOBS_TABLE)?;
            let mut inline_data = tx.open_table(INLINE_DATA_TABLE)?;
            let mut inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
            for hash in hashes {
                if self.temp.as_ref().read().unwrap().contains(&hash) {
                    continue;
                }
                self.state.remove(&hash);
                // if let Some(entry) = self.state.remove(&hash) {
                //     if Arc::strong_count(&entry.storage) > 1 {
                //         tracing::info!(
                //             "not removing entry for {} because it is still in use",
                //             hash
                //         );
                //         continue;
                //     }
                // }
                if let Some(entry) = blobs.remove(hash)? {
                    match entry.value() {
                        EntryState::Complete {
                            data_location,
                            outboard_location,
                        } => {
                            match data_location {
                                DataLocation::Inline(_) => {
                                    inline_data.remove(hash)?;
                                }
                                DataLocation::Owned(_) => {
                                    let path = self.path_options.owned_data_path(&hash);
                                    if let Err(cause) = std::fs::remove_file(&path) {
                                        tracing::error!("failed to remove file: {}", cause);
                                    };
                                }
                                DataLocation::External(_, _) => {}
                            }
                            match outboard_location {
                                OutboardLocation::Inline(_) => {
                                    inline_outboard.remove(hash)?;
                                }
                                OutboardLocation::Owned => {
                                    let path = self.path_options.owned_outboard_path(&hash);
                                    if let Err(cause) = std::fs::remove_file(&path) {
                                        tracing::error!("failed to remove file: {}", cause);
                                    };
                                }
                                OutboardLocation::NotNeeded => {}
                            }
                        }
                        EntryState::Partial { .. } => {
                            let data_path = self.path_options.owned_data_path(&hash);
                            if let Err(cause) = std::fs::remove_file(&data_path) {
                                tracing::error!("failed to remove data file: {}", cause);
                            };
                            let outboard_path = self.path_options.owned_outboard_path(&hash);
                            if let Err(cause) = std::fs::remove_file(&outboard_path) {
                                tracing::error!("failed to remove outboard file: {}", cause);
                            };
                        }
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn on_complete(&mut self, hash: Hash) -> ActorResult<()> {
        tracing::trace!("on_complete({})", hash.to_hex());
        let Some(entry) = self.state.get(&hash) else {
            println!("entry does not exist");
            return Ok(());
        };
        let mut info = None;
        entry.transform(|state| {
            tracing::trace!("on_complete transform {:?}", state);
            let entry =
                match complete_storage(state, &hash, &self.path_options, &self.inline_options)? {
                    Ok(entry) => {
                        // store the info so we can insert it into the db later
                        info = Some((
                            entry.data_size(),
                            entry.data.mem().cloned(),
                            entry.outboard_size(),
                            entry.outboard.mem().cloned(),
                        ));
                        entry
                    }
                    Err(entry) => {
                        // the entry was already complete, nothing to do
                        entry
                    }
                };
            Ok(BaoFileStorage::Complete(entry))
        })?;
        if let Some((data_size, data, outboard_size, outboard)) = info {
            let data_location = if data.is_some() {
                DataLocation::Inline(())
            } else {
                DataLocation::Owned(data_size)
            };
            let outboard_location = if outboard_size == 0 {
                OutboardLocation::NotNeeded
            } else if outboard.is_some() {
                OutboardLocation::Inline(())
            } else {
                OutboardLocation::Owned
            };
            // todo: just mark the entry for batch write if it is a mem entry?
            let tx = self.db.begin_write()?;
            {
                let mut blobs = tx.open_table(BLOBS_TABLE)?;
                tracing::info!(
                    "inserting complete entry for {}, {} bytes",
                    hash.to_hex(),
                    data_size,
                );
                blobs.insert(
                    hash,
                    EntryState::Complete {
                        data_location,
                        outboard_location,
                    },
                )?;
                if let Some(data) = data {
                    let mut inline_data = tx.open_table(INLINE_DATA_TABLE)?;
                    inline_data.insert(hash, data.as_ref())?;
                }
                if let Some(outboard) = outboard {
                    let mut inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
                    inline_outboard.insert(hash, outboard.as_ref())?;
                }
            }
            tx.commit()?;
        }
        Ok(())
    }

    fn validate(
        &mut self,
        progress: tokio::sync::mpsc::Sender<ValidateProgress>,
    ) -> ActorResult<()> {
        let tx = self.db.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let inline_data = tx.open_table(INLINE_DATA_TABLE)?;
        let inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
        let tags = tx.open_table(TAGS_TABLE)?;
        macro_rules! send {
            ($level:expr, $entry:expr, $($arg:tt)*) => {
                if let Err(_) = progress.blocking_send(ValidateProgress::ConsistencyCheckUpdate { message: format!($($arg)*), level: $level, entry: $entry }) {
                    return Ok(());
                }
            };
        }
        macro_rules! trace {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Trace, None, $($arg)*)
            };
        }
        macro_rules! info {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Info, None, $($arg)*)
            };
        }
        macro_rules! warn {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Warn, None, $($arg)*)
            };
        }
        macro_rules! entry_warn {
            ($hash:expr, $($arg:tt)*) => {
                send!(ValidateLevel::Warn, Some($hash), $($arg)*)
            };
        }
        macro_rules! entry_info {
            ($hash:expr, $($arg:tt)*) => {
                send!(ValidateLevel::Info, Some($hash), $($arg)*)
            };
        }
        macro_rules! error {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Error, None, $($arg)*)
            };
        }
        macro_rules! entry_error {
            ($hash:expr, $($arg:tt)*) => {
                send!(ValidateLevel::Error, Some($hash), $($arg)*)
            };
        }
        // first, dump the entire data content at trace level
        trace!("dumping blobs");
        match blobs.iter() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((k, v)) => {
                            let hash = k.value();
                            let entry = v.value();
                            trace!("blob {} -> {:?}", hash.to_hex(), entry);
                        }
                        Err(cause) => {
                            error!("failed to access blob item: {}", cause);
                        }
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate blobs: {}", cause);
            }
        }
        trace!("dumping inline_data");
        match inline_data.iter() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((k, v)) => {
                            let hash = k.value();
                            let data = v.value();
                            trace!("inline_data {} -> {:?}", hash.to_hex(), data.len());
                        }
                        Err(cause) => {
                            error!("failed to access inline data item: {}", cause);
                        }
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate inline_data: {}", cause);
            }
        }
        trace!("dumping inline_outboard");
        match inline_outboard.iter() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((k, v)) => {
                            let hash = k.value();
                            let data = v.value();
                            trace!("inline_outboard {} -> {:?}", hash.to_hex(), data.len());
                        }
                        Err(cause) => {
                            error!("failed to access inline outboard item: {}", cause);
                        }
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate inline_outboard: {}", cause);
            }
        }
        trace!("dumping tags");
        match tags.iter() {
            Ok(iter) => {
                for item in iter {
                    match item {
                        Ok((k, v)) => {
                            let tag = k.value();
                            let value = v.value();
                            trace!("tags {} -> {:?}", tag, value);
                        }
                        Err(cause) => {
                            error!("failed to access tag item: {}", cause);
                        }
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate tags: {}", cause);
            }
        }

        // perform consistency check for each entry
        info!("validating blobs");
        // set of a all hashes that are referenced by the blobs table
        let mut entries = BTreeSet::new();
        match blobs.iter() {
            Ok(iter) => {
                for item in iter {
                    let Ok((hash, entry)) = item else {
                        error!("failed to access blob item");
                        continue;
                    };
                    let hash = hash.value();
                    entries.insert(hash);
                    entry_info!(hash, "validating blob");
                    let entry = entry.value();
                    match entry {
                        EntryState::Complete {
                            data_location,
                            outboard_location,
                        } => {
                            let data_size = match data_location {
                                DataLocation::Inline(_) => {
                                    let Ok(inline_data) = inline_data.get(hash) else {
                                        entry_error!(hash, "inline data can not be accessed");
                                        continue;
                                    };
                                    let Some(inline_data) = inline_data else {
                                        entry_error!(hash, "inline data missing");
                                        continue;
                                    };
                                    inline_data.value().len() as u64
                                }
                                DataLocation::Owned(size) => {
                                    let path = self.path_options.owned_data_path(&hash);
                                    let Ok(metadata) = path.metadata() else {
                                        entry_error!(hash, "owned data file does not exist");
                                        continue;
                                    };
                                    if metadata.len() != size {
                                        entry_error!(
                                            hash,
                                            "owned data file size mismatch: {}",
                                            path.display()
                                        );
                                        continue;
                                    }
                                    size
                                }
                                DataLocation::External(paths, size) => {
                                    for path in paths {
                                        let Ok(metadata) = path.metadata() else {
                                            entry_error!(
                                                hash,
                                                "external data file does not exist: {}",
                                                path.display()
                                            );
                                            continue;
                                        };
                                        if metadata.len() != size {
                                            entry_error!(
                                                hash,
                                                "external data file size mismatch: {}",
                                                path.display()
                                            );
                                            continue;
                                        }
                                    }
                                    size
                                }
                            };
                            match outboard_location {
                                OutboardLocation::Inline(_) => {
                                    let Ok(inline_outboard) = inline_outboard.get(hash) else {
                                        entry_error!(hash, "inline outboard can not be accessed");
                                        continue;
                                    };
                                    let Some(inline_outboard) = inline_outboard else {
                                        entry_error!(hash, "inline outboard missing");
                                        continue;
                                    };
                                    let outboard_size = inline_outboard.value().len() as u64;
                                    if outboard_size != raw_outboard_size(data_size) {
                                        entry_error!(hash, "inline outboard size mismatch");
                                    }
                                }
                                OutboardLocation::Owned => {
                                    let Ok(metadata) =
                                        self.path_options.owned_outboard_path(&hash).metadata()
                                    else {
                                        entry_error!(hash, "owned outboard file does not exist");
                                        continue;
                                    };
                                    let outboard_size = metadata.len();
                                    if outboard_size != raw_outboard_size(data_size) {
                                        entry_error!(hash, "owned outboard size mismatch");
                                    }
                                }
                                OutboardLocation::NotNeeded => {
                                    if raw_outboard_size(data_size) != 0 {
                                        entry_error!(
                                            hash,
                                            "outboard not needed but data size is not zero"
                                        );
                                    }
                                }
                            }
                        }
                        EntryState::Partial { .. } => {
                            if !self.path_options.owned_data_path(&hash).exists() {
                                entry_error!(hash, "persistent partial entry has no data");
                            }
                            if !self.path_options.owned_outboard_path(&hash).exists() {
                                entry_error!(hash, "persistent partial entry has no outboard");
                            }
                        }
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate blobs: {}", cause);
            }
        };
        info!("checking for orphaned inline data");
        match inline_data.iter() {
            Ok(iter) => {
                for item in iter {
                    let Ok((hash, _)) = item else {
                        error!("failed to access inline data item");
                        continue;
                    };
                    let hash = hash.value();
                    if !entries.contains(&hash) {
                        entry_error!(hash, "orphaned inline data");
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate inline_data: {}", cause);
            }
        };
        info!("checking for orphaned inline outboard data");
        match inline_outboard.iter() {
            Ok(iter) => {
                for item in iter {
                    let Ok((hash, _)) = item else {
                        error!("failed to access inline outboard item");
                        continue;
                    };
                    let hash = hash.value();
                    if !entries.contains(&hash) {
                        entry_error!(hash, "orphaned inline outboard");
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate inline_outboard: {}", cause);
            }
        };
        info!("checking for unexpected or orphaned files");
        for entry in self.path_options.data_path.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                warn!("unexpected entry in data directory: {}", path.display());
                continue;
            }
            match path.extension().and_then(|x| x.to_str()) {
                Some("data") => match path.file_stem().and_then(|x| x.to_str()) {
                    Some(stem) => {
                        let mut hash = [0u8; 32];
                        let Ok(_) = hex::decode_to_slice(stem, &mut hash) else {
                            warn!("unexpected data file in data directory: {}", path.display());
                            continue;
                        };
                        let hash = Hash::from(hash);
                        if !entries.contains(&hash) {
                            entry_warn!(hash, "orphaned data file");
                        }
                    }
                    None => {
                        warn!("unexpected data file in data directory: {}", path.display());
                    }
                },
                Some("obao4") => match path.file_stem().and_then(|x| x.to_str()) {
                    Some(stem) => {
                        let mut hash = [0u8; 32];
                        let Ok(_) = hex::decode_to_slice(stem, &mut hash) else {
                            warn!(
                                "unexpected outboard file in data directory: {}",
                                path.display()
                            );
                            continue;
                        };
                        let hash = Hash::from(hash);
                        if !entries.contains(&hash) {
                            entry_warn!(hash, "orphaned outboard file");
                        }
                    }
                    None => {
                        warn!(
                            "unexpected outboard file in data directory: {}",
                            path.display()
                        );
                    }
                },
                _ => {
                    warn!("unexpected file in data directory: {}", path.display());
                }
            }
        }
        Ok(())
    }

    fn run(mut self) -> ActorResult<()> {
        while let Ok(msg) = self.msgs.recv() {
            match msg {
                RedbActorMessage::GetOrCreate { hash, tx } => {
                    tx.send(self.get_or_create(hash)?).ok();
                }
                RedbActorMessage::ImportEntry {
                    content,
                    file,
                    data_size,
                    outboard,
                    tx,
                } => {
                    tx.send(self.import_entry(content, file, data_size, outboard))
                        .ok();
                }
                RedbActorMessage::Get { hash, tx } => {
                    tx.send(self.get(hash)?).ok();
                }
                RedbActorMessage::EntryState { hash, tx } => {
                    tx.send(self.entry_state(hash)?).ok();
                }
                RedbActorMessage::Blobs { filter, tx } => {
                    tx.send(self.blobs(filter)?).ok();
                }
                RedbActorMessage::Tags { filter, tx } => {
                    tx.send(self.tags(filter)?).ok();
                }
                RedbActorMessage::CreateTag { hash, tx } => {
                    tx.send(self.create_tag(hash)).ok();
                }
                RedbActorMessage::SetTag { tag, value, tx } => {
                    tx.send(self.set_tag(tag, value)).ok();
                }
                RedbActorMessage::OnInlineSizeExceeded { hash } => {
                    self.on_inline_size_exceeded(hash)?;
                }
                RedbActorMessage::OnComplete { hash } => {
                    self.on_complete(hash)?;
                }
                RedbActorMessage::Dump => {
                    dump(&self.db)?;
                }
                RedbActorMessage::Validate { progress, tx } => {
                    self.validate(progress)?;
                    tx.send(()).ok();
                }
                RedbActorMessage::Sync { tx } => {
                    tx.send(()).ok();
                }
                RedbActorMessage::Delete { hashes, tx } => {
                    self.delete(hashes)?;
                    tx.send(()).ok();
                }
                RedbActorMessage::ImportFlatStore { paths, tx } => {
                    self.import_flat_store(paths)?;
                    tx.send(()).ok();
                }
                RedbActorMessage::UpdateOptions {
                    inline_options,
                    reapply,
                    tx,
                } => {
                    self.update_options(inline_options, reapply)?;
                    tx.send(()).ok();
                }
                RedbActorMessage::Shutdown => {
                    tracing::info!("got shutdown");
                    break;
                }
            }
        }
        tracing::info!("redb actor done");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::store::bao_file::test_support::{
        decode_response_into_batch, make_wire_data, random_test_data, validate,
    };

    use crate::store::{MapEntryMut, MapMut};

    use super::*;

    #[tokio::test]
    async fn actor_store_smoke() {
        let testdir = tempfile::tempdir().unwrap();
        let db_path = testdir.path().join("test.redb");
        let options = Options {
            path: PathOptions::new(testdir.path()),
            inline: Default::default(),
        };
        let db = Store::new(db_path, options).await.unwrap();
        db.dump().await.unwrap();
        let data = random_test_data(1024 * 1024);
        #[allow(clippy::single_range_in_vec_init)]
        let ranges = [0..data.len() as u64];
        let (hash, chunk_ranges, wire_data) = make_wire_data(&data, &ranges);
        let handle = db.get_or_create(hash, 0).await.unwrap();
        decode_response_into_batch(
            hash,
            IROH_BLOCK_SIZE,
            chunk_ranges.clone(),
            Cursor::new(wire_data),
            handle.batch_writer().await.unwrap(),
        )
        .await
        .unwrap();
        validate(&handle.0, &data, &ranges).await;
        db.insert_complete(handle).await.unwrap();
        db.sync().await.unwrap();
        db.dump().await.unwrap();
    }
}
