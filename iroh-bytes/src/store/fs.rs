//! redb backed storage
//!
//! Data can get into the store in two ways:
//!
//! 1. import from local data
//! 2. sync from a remote
//!
//! These two cases are very different. In the first case, we have the data
//! completely and don't know the hash yet. We compute the outboard and hash,
//! and only then move/reference the data into the store.
//!
//! The entry for the hash comes into existence already complete.
//!
//! In the second case, we know the hash, but don't have the data yet. We create
//! a partial entry, and then request the data from the remote. This is the more
//! complex case.
//!
//! Partial entries always start as pure in memory entries without a database
//! entry. Only once we receive enough data, we convert them into a persistent
//! partial entry. This is necessary because we can't trust the size given
//! by the remote side before receiving data. It is also an optimization,
//! because for small blobs it is not worth it to create a partial entry.
//!
//! A persistent partial entry is always stored as three files in the file
//! system: The data file, the outboard file, and a sizes file that contains
//! the most up to date information about the size of the data.
//!
//! The redb database entry for a persistent partial entry does not contain
//! any information about the size of the data until the size is exactly known.
//!
//! Updating this information on each write would be too costly.
//!
//! Marking a partial entry as complete is done from the outside. At this point
//! the size is taken as validated. Depending on the size we decide whether to
//! store data and outboard inline or to keep storing it in external files.
//!
//! Data can get out of the store in two ways:
//!
//! 1. the data and outboard of both partial and complete entries can be read
//! at any time and shared over the network. Only data that is complete will
//! be shared, everything else will lead to validation errors.
//!
//! 2. entries can be exported to the file system. This currently only works
//! for complete entries.
//!
//! Tables:
//!
//! The blobs table contains a mapping from hash to rough entry state.
//! The inline_data table contains the actual data for complete entries.
//! The inline_outboard table contains the actual outboard for complete entries.
//! The tags table contains a mapping from tag to hash.
//!
//! Design:
//!
//! The redb store is accessed in a single threaded way by an actor that runs
//! on its own std thread. Communication with this actor is via a flume channel,
//! with oneshot channels for the return values if needed.
//!
//! Errors:
//!
//! ActorError is an enum containing errors that can happen inside message
//! handlers of the actor. This includes various redb related errors and io
//! errors when reading or writing non-inlined data or outboard files.
//!
//! OuterError is an enum containing all the actor errors and in addition
//! errors when communicating with the actor.
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, SystemTime},
};

use bao_tree::io::{
    fsm::Outboard,
    outboard::PreOrderOutboard,
    sync::{ReadAt, Size},
};
use bytes::Bytes;
use futures::{channel::oneshot, Stream, StreamExt};

use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};
use iroh_io::AsyncSliceReader;
use redb::{AccessGuard, DatabaseError, ReadableTable, StorageError};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tokio::io::AsyncWriteExt;
use tracing::trace_span;

mod import_flat_store;
mod migrate_redb_v1_v2;
mod tables;
#[doc(hidden)]
pub mod test_support;
#[cfg(test)]
mod tests;
mod util;
mod validate;

use crate::{
    store::{
        bao_file::{BaoFileStorage, CompleteStorage},
        fs::{
            tables::BaoFilePart,
            util::{overwrite_and_sync, read_and_remove, ProgressReader},
        },
    },
    util::{
        progress::{
            BoxedProgressSender, IdGenerator, IgnoreProgressSender, ProgressSendError,
            ProgressSender,
        },
        raw_outboard_size, LivenessTracker, MemOrFile,
    },
    Tag, TempTag, IROH_BLOCK_SIZE,
};
use tables::{ReadOnlyTables, ReadableTables, Tables};

use self::{tables::DeleteSet, util::PeekableFlumeReceiver};

use self::test_support::EntryData;

use super::{
    bao_file::{BaoFileConfig, BaoFileHandle, BaoFileHandleWeak, CreateCb},
    temp_name, BaoBatchWriter, BaoBlobSize, ConsistencyCheckProgress, EntryStatus, ExportMode,
    ExportProgressCb, ImportMode, ImportProgress, Map, TempCounterMap,
};

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
    fn union(self, that: DataLocation<X, u64>) -> ActorResult<Self> {
        Ok(match (self, that) {
            (
                DataLocation::External(mut paths, a_size),
                DataLocation::External(b_paths, b_size),
            ) => {
                if a_size != b_size {
                    return Err(ActorError::Inconsistent(format!(
                        "complete size mismatch {} {}",
                        a_size, b_size
                    )));
                }
                paths.extend(b_paths);
                paths.sort();
                paths.dedup();
                DataLocation::External(paths, a_size)
            }
            (_, b @ DataLocation::Owned(_)) => {
                // owned needs to win, since it has an associated file. Choosing
                // external would orphan the file.
                b
            }
            (a @ DataLocation::Owned(_), _) => {
                // owned needs to win, since it has an associated file. Choosing
                // external would orphan the file.
                a
            }
            (_, b @ DataLocation::Inline(_)) => {
                // inline needs to win, since it has associated data. Choosing
                // external would orphan the file.
                b
            }
            (a @ DataLocation::Inline(_), _) => {
                // inline needs to win, since it has associated data. Choosing
                // external would orphan the file.
                a
            }
        })
    }
}

impl<I, E> DataLocation<I, E> {
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
    /// Outboard is not needed
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    fn union(self, that: Self) -> ActorResult<Self> {
        match (self, that) {
            (
                Self::Complete {
                    data_location,
                    outboard_location,
                },
                Self::Complete {
                    data_location: b_data_location,
                    ..
                },
            ) => Ok(Self::Complete {
                // combine external paths if needed
                data_location: data_location.union(b_data_location)?,
                outboard_location,
            }),
            (a @ Self::Complete { .. }, Self::Partial { .. }) =>
            // complete wins over partial
            {
                Ok(a)
            }
            (Self::Partial { .. }, b @ Self::Complete { .. }) =>
            // complete wins over partial
            {
                Ok(b)
            }
            (Self::Partial { size: a_size }, Self::Partial { size: b_size }) =>
            // keep known size from either entry
            {
                let size = match (a_size, b_size) {
                    (Some(a_size), Some(b_size)) => {
                        // validated sizes are different. this means that at
                        // least one validation was wrong, which would be a bug
                        // in bao-tree.
                        if a_size != b_size {
                            return Err(ActorError::Inconsistent(format!(
                                "validated size mismatch {} {}",
                                a_size, b_size
                            )));
                        }
                        Some(a_size)
                    }
                    (Some(a_size), None) => Some(a_size),
                    (None, Some(b_size)) => Some(b_size),
                    (None, None) => None,
                };
                Ok(Self::Partial { size })
            }
        }
    }
}

impl redb::Value for EntryState {
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
    pub max_data_inlined: u64,
    /// Maximum outboard size to inline.
    pub max_outboard_inlined: u64,
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

/// Options for directories used by the file store.
#[derive(Debug, Clone)]
pub struct PathOptions {
    /// Path to the directory where data and outboard files are stored.
    pub data_path: PathBuf,
    /// Path to the directory where temp files are stored.
    /// This *must* be on the same device as `data_path`, since we need to
    /// atomically move temp files into place.
    pub temp_path: PathBuf,
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

    fn owned_sizes_path(&self, hash: &Hash) -> PathBuf {
        self.data_path.join(format!("{}.sizes4", hash.to_hex()))
    }

    fn temp_file_name(&self) -> PathBuf {
        self.temp_path.join(temp_name())
    }
}

/// Options for transaction batching.
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Maximum number of actor messages to batch before creating a new read transaction.
    pub max_read_batch: usize,
    /// Maximum duration to wait before committing a read transaction.
    pub max_read_duration: Duration,
    /// Maximum number of actor messages to batch before committing write transaction.
    pub max_write_batch: usize,
    /// Maximum duration to wait before committing a write transaction.
    pub max_write_duration: Duration,
}

impl Default for BatchOptions {
    fn default() -> Self {
        Self {
            max_read_batch: 10000,
            max_read_duration: Duration::from_secs(1),
            max_write_batch: 1000,
            max_write_duration: Duration::from_millis(500),
        }
    }
}

/// Options for the file store.
#[derive(Debug, Clone)]
pub struct Options {
    /// Path options.
    pub path: PathOptions,
    /// Inline storage options.
    pub inline: InlineOptions,
    /// Transaction batching options.
    pub batch: BatchOptions,
}

#[derive(derive_more::Debug)]
pub(crate) enum ImportSource {
    TempFile(PathBuf),
    External(PathBuf),
    Memory(#[debug(skip)] Bytes),
}

impl ImportSource {
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

/// Use BaoFileHandle as the entry type for the map.
pub type Entry = BaoFileHandle;

impl super::MapEntry for Entry {
    fn hash(&self) -> Hash {
        self.hash()
    }

    fn size(&self) -> BaoBlobSize {
        let size = self.current_size().unwrap();
        tracing::trace!("redb::Entry::size() = {}", size);
        BaoBlobSize::new(size, self.is_complete())
    }

    fn is_complete(&self) -> bool {
        self.is_complete()
    }

    async fn outboard(&self) -> io::Result<impl Outboard> {
        self.outboard()
    }

    async fn data_reader(&self) -> io::Result<impl AsyncSliceReader> {
        Ok(self.data_reader())
    }
}

impl super::MapEntryMut for Entry {
    async fn batch_writer(&self) -> io::Result<impl BaoBatchWriter> {
        Ok(self.writer())
    }
}

#[derive(derive_more::Debug)]
pub(crate) struct Import {
    /// The hash and format of the data to import
    content_id: HashAndFormat,
    /// The source of the data to import, can be a temp file, external file, or memory
    source: ImportSource,
    /// Data size
    data_size: u64,
    /// Outboard without length prefix
    #[debug("{:?}", outboard.as_ref().map(|x| x.len()))]
    outboard: Option<Vec<u8>>,
}

#[derive(derive_more::Debug)]
pub(crate) struct Export {
    /// A temp tag to keep the entry alive while exporting. This also
    /// contains the hash to be exported.
    temp_tag: TempTag,
    /// The target path for the export.
    target: PathBuf,
    /// The export mode to use.
    mode: ExportMode,
    /// The progress callback to use.
    #[debug(skip)]
    progress: ExportProgressCb,
}

#[derive(derive_more::Debug)]
pub(crate) enum ActorMessage {
    // Query method: get a file handle for a hash, if it exists.
    // This will produce a file handle even for entries that are not yet in redb at all.
    Get {
        hash: Hash,
        tx: oneshot::Sender<ActorResult<Option<BaoFileHandle>>>,
    },
    /// Query method: get the rough entry status for a hash. Just complete, partial or not found.
    EntryStatus {
        hash: Hash,
        tx: flume::Sender<ActorResult<EntryStatus>>,
    },
    #[cfg(test)]
    /// Query method: get the full entry state for a hash, both in memory and in redb.
    /// This is everything we got about the entry, including the actual inline outboard and data.
    EntryState {
        hash: Hash,
        tx: flume::Sender<ActorResult<test_support::EntryStateResponse>>,
    },
    /// Query method: get the full entry state for a hash.
    GetFullEntryState {
        hash: Hash,
        tx: flume::Sender<ActorResult<Option<EntryData>>>,
    },
    /// Modification method: set the full entry state for a hash.
    SetFullEntryState {
        hash: Hash,
        entry: Option<EntryData>,
        tx: flume::Sender<ActorResult<()>>,
    },
    /// Modification method: get or create a file handle for a hash.
    ///
    /// If the entry exists in redb, either partial or complete, the corresponding
    /// data will be returned. If it does not yet exist, a new partial file handle
    /// will be created, but not yet written to redb.
    GetOrCreate {
        hash: Hash,
        tx: oneshot::Sender<ActorResult<BaoFileHandle>>,
    },
    /// Modification method: inline size was exceeded for a partial entry.
    /// If the entry is complete, this is a no-op. If the entry is partial and in
    /// memory, it will be written to a file and created in redb.
    OnMemSizeExceeded { hash: Hash },
    /// Modification method: marks a partial entry as complete.
    /// Calling this on a complete entry is a no-op.
    OnComplete { handle: BaoFileHandle },
    /// Modification method: import data into a redb store
    ///
    /// At this point the size, hash and outboard must already be known.
    Import {
        cmd: Import,
        tx: flume::Sender<ActorResult<(TempTag, u64)>>,
    },
    /// Modification method: export data from a redb store
    ///
    /// In most cases this will not modify the store. Only when using
    /// [`ExportMode::TryReference`] and the entry is large enough to not be
    /// inlined.
    Export {
        cmd: Export,
        tx: oneshot::Sender<ActorResult<()>>,
    },
    /// Modification method: import an entire flat store into the redb store.
    ImportFlatStore {
        paths: FlatStorePaths,
        tx: oneshot::Sender<bool>,
    },
    /// Update inline options
    UpdateInlineOptions {
        /// The new inline options
        inline_options: InlineOptions,
        /// Whether to reapply the new options to existing entries
        reapply: bool,
        tx: oneshot::Sender<()>,
    },
    /// Bulk query method: get entries from the blobs table
    Blobs {
        #[debug(skip)]
        filter: FilterPredicate<Hash, EntryState>,
        #[allow(clippy::type_complexity)]
        tx: oneshot::Sender<
            ActorResult<Vec<std::result::Result<(Hash, EntryState), StorageError>>>,
        >,
    },
    /// Bulk query method: get the entire tags table
    Tags {
        #[debug(skip)]
        filter: FilterPredicate<Tag, HashAndFormat>,
        #[allow(clippy::type_complexity)]
        tx: oneshot::Sender<
            ActorResult<Vec<std::result::Result<(Tag, HashAndFormat), StorageError>>>,
        >,
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
        tx: oneshot::Sender<ActorResult<()>>,
    },
    /// Sync the entire database to disk.
    ///
    /// This just makes sure that there is no write transaction open.
    Sync { tx: oneshot::Sender<()> },
    /// Internal method: dump the entire database to stdout.
    Dump,
    /// Internal method: validate the entire database.
    ///
    /// Note that this will block the actor until it is done, so don't use it
    /// on a node under load.
    Fsck {
        repair: bool,
        progress: BoxedProgressSender<ConsistencyCheckProgress>,
        tx: oneshot::Sender<ActorResult<()>>,
    },
    /// Internal method: notify the actor that a new gc epoch has started.
    ///
    /// This will be called periodically and can be used to do misc cleanups.
    GcStart { tx: oneshot::Sender<()> },
    /// Internal method: shutdown the actor.
    ///
    /// Can have an optional oneshot sender to signal when the actor has shut down.
    Shutdown { tx: Option<oneshot::Sender<()>> },
}

impl ActorMessage {
    fn category(&self) -> MessageCategory {
        match self {
            Self::Get { .. }
            | Self::GetOrCreate { .. }
            | Self::EntryStatus { .. }
            | Self::Blobs { .. }
            | Self::Tags { .. }
            | Self::GcStart { .. }
            | Self::GetFullEntryState { .. }
            | Self::Dump => MessageCategory::ReadOnly,
            Self::Import { .. }
            | Self::Export { .. }
            | Self::OnMemSizeExceeded { .. }
            | Self::OnComplete { .. }
            | Self::SetTag { .. }
            | Self::CreateTag { .. }
            | Self::SetFullEntryState { .. }
            | Self::Delete { .. } => MessageCategory::ReadWrite,
            Self::UpdateInlineOptions { .. }
            | Self::Sync { .. }
            | Self::Shutdown { .. }
            | Self::Fsck { .. }
            | Self::ImportFlatStore { .. } => MessageCategory::TopLevel,
            #[cfg(test)]
            Self::EntryState { .. } => MessageCategory::ReadOnly,
        }
    }
}

enum MessageCategory {
    ReadOnly,
    ReadWrite,
    TopLevel,
}

/// Predicate for filtering entries in a redb table.
pub(crate) type FilterPredicate<K, V> =
    Box<dyn Fn(u64, AccessGuard<K>, AccessGuard<V>) -> Option<(K, V)> + Send + Sync>;

/// Parameters for importing from a flat store
#[derive(Debug)]
pub struct FlatStorePaths {
    /// Complete data files
    pub complete: PathBuf,
    /// Partial data files
    pub partial: PathBuf,
    /// Metadata files such as the tags table
    pub meta: PathBuf,
}

/// Storage that is using a redb database for small files and files for
/// large files.
#[derive(Debug, Clone)]
pub struct Store(Arc<StoreInner>);

impl Store {
    /// Load or create a new store.
    pub async fn load(root: impl AsRef<Path>) -> io::Result<Self> {
        let path = root.as_ref();
        let db_path = path.join("blobs.db");
        let options = Options {
            path: PathOptions::new(path),
            inline: Default::default(),
            batch: Default::default(),
        };
        Self::new(db_path, options).await
    }

    /// Create a new store with custom options.
    pub async fn new(path: PathBuf, options: Options) -> io::Result<Self> {
        // spawn_blocking because StoreInner::new creates directories
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "no tokio runtime"))?;
        let inner =
            tokio::task::spawn_blocking(move || StoreInner::new_sync(path, options, rt)).await??;
        Ok(Self(Arc::new(inner)))
    }

    /// Update the inline options.
    ///
    /// When reapply is true, the new options will be applied to all existing
    /// entries.
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

    /// Dump the entire content of the database to stdout.
    pub async fn dump(&self) -> io::Result<()> {
        Ok(self.0.dump().await?)
    }

    /// Ensure that all operations before the sync are processed and persisted.
    ///
    /// This is done by closing any open write transaction.
    pub async fn sync(&self) -> io::Result<()> {
        Ok(self.0.sync().await?)
    }

    /// Import from a v0 or v1 flat store, for backwards compatibility.
    pub async fn import_flat_store(&self, paths: FlatStorePaths) -> io::Result<bool> {
        Ok(self.0.import_flat_store(paths).await?)
    }
}

#[derive(Debug)]
struct StoreInner {
    tx: flume::Sender<ActorMessage>,
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
    fn new_sync(path: PathBuf, options: Options, rt: tokio::runtime::Handle) -> io::Result<Self> {
        tracing::trace!(
            "creating data directory: {}",
            options.path.data_path.display()
        );
        std::fs::create_dir_all(&options.path.data_path)?;
        tracing::trace!(
            "creating temp directory: {}",
            options.path.temp_path.display()
        );
        std::fs::create_dir_all(&options.path.temp_path)?;
        tracing::trace!(
            "creating parent directory for db file{}",
            path.parent().unwrap().display()
        );
        std::fs::create_dir_all(path.parent().unwrap())?;
        let temp: Arc<RwLock<TempCounterMap>> = Default::default();
        let (actor, tx) = Actor::new(&path, options.clone(), temp.clone(), rt)?;
        let handle = std::thread::Builder::new()
            .name("redb-actor".to_string())
            .spawn(move || {
                if let Err(cause) = actor.run_batched() {
                    tracing::error!("redb actor failed: {}", cause);
                }
            })
            .expect("failed to spawn thread");
        Ok(Self {
            tx,
            temp,
            handle: Some(handle),
            path_options: Arc::new(options.path),
        })
    }

    pub async fn get(&self, hash: Hash) -> OuterResult<Option<BaoFileHandle>> {
        let (tx, rx) = oneshot::channel();
        self.tx.send_async(ActorMessage::Get { hash, tx }).await?;
        Ok(rx.await??)
    }

    async fn get_or_create(&self, hash: Hash) -> OuterResult<BaoFileHandle> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::GetOrCreate { hash, tx })
            .await?;
        Ok(rx.await??)
    }

    async fn blobs(&self) -> OuterResult<Vec<io::Result<Hash>>> {
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
            .send_async(ActorMessage::Blobs { filter, tx })
            .await?;
        let blobs = rx.await?;
        let res = blobs?
            .into_iter()
            .map(|r| {
                r.map(|(hash, _)| hash)
                    .map_err(|e| ActorError::from(e).into())
            })
            .collect::<Vec<_>>();
        Ok(res)
    }

    async fn partial_blobs(&self) -> OuterResult<Vec<io::Result<Hash>>> {
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
            .send_async(ActorMessage::Blobs { filter, tx })
            .await?;
        let blobs = rx.await?;
        let res = blobs?
            .into_iter()
            .map(|r| {
                r.map(|(hash, _)| hash)
                    .map_err(|e| ActorError::from(e).into())
            })
            .collect::<Vec<_>>();
        Ok(res)
    }

    async fn tags(&self) -> OuterResult<Vec<io::Result<(Tag, HashAndFormat)>>> {
        let (tx, rx) = oneshot::channel();
        let filter: FilterPredicate<Tag, HashAndFormat> =
            Box::new(|_i, k, v| Some((k.value(), v.value())));
        self.tx
            .send_async(ActorMessage::Tags { filter, tx })
            .await?;
        let tags = rx.await?;
        // transform the internal error type into io::Error
        let tags = tags?
            .into_iter()
            .map(|r| r.map_err(|e| ActorError::from(e).into()))
            .collect();
        Ok(tags)
    }

    async fn set_tag(&self, tag: Tag, value: Option<HashAndFormat>) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::SetTag { tag, value, tx })
            .await?;
        Ok(rx.await??)
    }

    async fn create_tag(&self, hash: HashAndFormat) -> OuterResult<Tag> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::CreateTag { hash, tx })
            .await?;
        Ok(rx.await??)
    }

    async fn delete(&self, hashes: Vec<Hash>) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::Delete { hashes, tx })
            .await?;
        Ok(rx.await??)
    }

    async fn gc_start(&self) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx.send_async(ActorMessage::GcStart { tx }).await?;
        Ok(rx.await?)
    }

    async fn entry_status(&self, hash: &Hash) -> OuterResult<EntryStatus> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(ActorMessage::EntryStatus { hash: *hash, tx })
            .await?;
        Ok(rx.into_recv_async().await??)
    }

    fn entry_status_sync(&self, hash: &Hash) -> OuterResult<EntryStatus> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send(ActorMessage::EntryStatus { hash: *hash, tx })?;
        Ok(rx.recv()??)
    }

    async fn complete(&self, entry: Entry) -> OuterResult<()> {
        self.tx
            .send_async(ActorMessage::OnComplete { handle: entry })
            .await?;
        Ok(())
    }

    async fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: ExportProgressCb,
    ) -> OuterResult<()> {
        tracing::info!(
            "exporting {} to {} using mode {:?}",
            hash.to_hex(),
            target.display(),
            mode
        );
        if !target.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target path must be absolute",
            )
            .into());
        }
        let parent = target.parent().ok_or_else(|| {
            OuterError::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target path has no parent directory",
            ))
        })?;
        std::fs::create_dir_all(parent)?;
        let temp_tag = self.temp_tag(HashAndFormat::raw(hash));
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::Export {
                cmd: Export {
                    temp_tag,
                    target,
                    mode,
                    progress,
                },
                tx,
            })
            .await?;
        Ok(rx.await??)
    }

    async fn consistency_check(
        &self,
        repair: bool,
        progress: BoxedProgressSender<ConsistencyCheckProgress>,
    ) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::Fsck {
                repair,
                progress,
                tx,
            })
            .await?;
        Ok(rx.await??)
    }

    async fn import_flat_store(&self, paths: FlatStorePaths) -> OuterResult<bool> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::ImportFlatStore { paths, tx })
            .await?;
        Ok(rx.await?)
    }

    async fn update_inline_options(
        &self,
        inline_options: InlineOptions,
        reapply: bool,
    ) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::UpdateInlineOptions {
                inline_options,
                reapply,
                tx,
            })
            .await?;
        Ok(rx.await?)
    }

    async fn dump(&self) -> OuterResult<()> {
        self.tx.send_async(ActorMessage::Dump).await?;
        Ok(())
    }

    async fn sync(&self) -> OuterResult<()> {
        let (tx, rx) = oneshot::channel();
        self.tx.send_async(ActorMessage::Sync { tx }).await?;
        Ok(rx.await?)
    }

    fn temp_tag(&self, content: HashAndFormat) -> TempTag {
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
            ImportMode::TryReference => ImportSource::External(path),
            ImportMode::Copy => {
                if std::fs::metadata(&path)?.len() < 16 * 1024 {
                    // we don't know if the data will be inlined since we don't
                    // have the inline options here. But still for such a small file
                    // it does not seem worth it do to the temp file ceremony.
                    let data = std::fs::read(&path)?;
                    ImportSource::Memory(data.into())
                } else {
                    let temp_path = self.temp_file_name();
                    // copy the data, since it is not stable
                    progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
                    if reflink_copy::reflink_or_copy(&path, &temp_path)?.is_none() {
                        tracing::debug!("reflinked {} to {}", path.display(), temp_path.display());
                    } else {
                        tracing::debug!("copied {} to {}", path.display(), temp_path.display());
                    }
                    // copy progress for size will be called in finalize_import_sync
                    ImportSource::TempFile(temp_path)
                }
            }
        };
        let (tag, size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok((tag, size))
    }

    fn import_bytes_sync(&self, data: Bytes, format: BlobFormat) -> OuterResult<TempTag> {
        let id = 0;
        let file = ImportSource::Memory(data);
        let progress = IgnoreProgressSender::default();
        let (tag, _size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok(tag)
    }

    fn finalize_import_sync(
        &self,
        file: ImportSource,
        format: BlobFormat,
        id: u64,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> OuterResult<(TempTag, u64)> {
        let data_size = file.len()?;
        tracing::debug!("finalize_import_sync {:?} {}", file, data_size);
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
        self.tx.send(ActorMessage::Import {
            cmd: Import {
                content_id: HashAndFormat { hash, format },
                source: file,
                outboard,
                data_size,
            },
            tx,
        })?;
        Ok(rx.recv()??)
    }

    fn temp_file_name(&self) -> PathBuf {
        self.path_options.temp_file_name()
    }

    async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send_async(ActorMessage::Shutdown { tx: Some(tx) })
            .await
            .ok();
        rx.await.ok();
    }
}

impl Drop for StoreInner {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            self.tx.send(ActorMessage::Shutdown { tx: None }).ok();
            handle.join().ok();
        }
    }
}

struct ActorState {
    handles: BTreeMap<Hash, BaoFileHandleWeak>,
    protected: BTreeSet<Hash>,
    temp: Arc<RwLock<TempCounterMap>>,
    msgs: flume::Receiver<ActorMessage>,
    create_options: Arc<BaoFileConfig>,
    options: Options,
    rt: tokio::runtime::Handle,
}

/// The actor for the redb store.
///
/// It is split into the database and the rest of the state to allow for split
/// borrows in the message handlers.
struct Actor {
    db: redb::Database,
    state: ActorState,
}

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
    #[error("error during database migration: {0}")]
    Migration(#[source] anyhow::Error),
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
    Send(#[from] flume::SendError<ActorMessage>),
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

impl super::Map for Store {
    type Entry = Entry;

    async fn get(&self, hash: &Hash) -> io::Result<Option<Self::Entry>> {
        Ok(self.0.get(*hash).await?.map(From::from))
    }
}

impl super::MapMut for Store {
    type EntryMut = Entry;

    async fn get_or_create(&self, hash: Hash, _size: u64) -> io::Result<Self::EntryMut> {
        Ok(self.0.get_or_create(hash).await?)
    }

    async fn entry_status(&self, hash: &Hash) -> io::Result<EntryStatus> {
        Ok(self.0.entry_status(hash).await?)
    }

    async fn get_mut(&self, hash: &Hash) -> io::Result<Option<Self::EntryMut>> {
        self.get(hash).await
    }

    async fn insert_complete(&self, entry: Self::EntryMut) -> io::Result<()> {
        Ok(self.0.complete(entry).await?)
    }

    fn entry_status_sync(&self, hash: &Hash) -> io::Result<EntryStatus> {
        Ok(self.0.entry_status_sync(hash)?)
    }
}

impl super::ReadableStore for Store {
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

    async fn consistency_check(
        &self,
        repair: bool,
        tx: BoxedProgressSender<ConsistencyCheckProgress>,
    ) -> io::Result<()> {
        self.0.consistency_check(repair, tx.clone()).await?;
        Ok(())
    }

    async fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: ExportProgressCb,
    ) -> io::Result<()> {
        Ok(self.0.export(hash, target, mode, progress).await?)
    }
}

impl super::Store for Store {
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
        let temp_data_path = this.0.temp_file_name();
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
        let file = ImportSource::TempFile(temp_data_path);
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

    async fn gc_start(&self) -> io::Result<()> {
        self.0.gc_start().await?;
        Ok(())
    }

    fn temp_tag(&self, value: HashAndFormat) -> TempTag {
        self.0.temp_tag(value)
    }

    async fn shutdown(&self) {
        self.0.shutdown().await;
    }
}

impl Actor {
    fn new(
        path: &Path,
        options: Options,
        temp: Arc<RwLock<TempCounterMap>>,
        rt: tokio::runtime::Handle,
    ) -> ActorResult<(Self, flume::Sender<ActorMessage>)> {
        let db = match redb::Database::create(path) {
            Ok(db) => db,
            Err(DatabaseError::UpgradeRequired(1)) => {
                migrate_redb_v1_v2::run(path).map_err(ActorError::Migration)?
            }
            Err(err) => return Err(err.into()),
        };

        let txn = db.begin_write()?;
        // create tables and drop them just to create them.
        let mut t = Default::default();
        let tables = Tables::new(&txn, &mut t)?;
        drop(tables);
        txn.commit()?;
        // make the channel relatively large. there are some messages that don't
        // require a response, it's fine if they pile up a bit.
        let (tx, rx) = flume::bounded(1024);
        let tx2 = tx.clone();
        let on_file_create: CreateCb = Arc::new(move |hash| {
            // todo: make the callback allow async
            tx2.send(ActorMessage::OnMemSizeExceeded { hash: *hash })
                .ok();
            Ok(())
        });
        let create_options = BaoFileConfig::new(
            Arc::new(options.path.data_path.clone()),
            16 * 1024,
            Some(on_file_create),
        );
        Ok((
            Self {
                db,
                state: ActorState {
                    temp,
                    handles: BTreeMap::new(),
                    protected: BTreeSet::new(),
                    msgs: rx,
                    options,
                    create_options: Arc::new(create_options),
                    rt,
                },
            },
            tx,
        ))
    }

    fn run_batched(mut self) -> ActorResult<()> {
        let mut msgs = PeekableFlumeReceiver::new(self.state.msgs.clone());
        while let Some(msg) = msgs.recv() {
            if let ActorMessage::Shutdown { tx } = msg {
                if let Some(tx) = tx {
                    tx.send(()).ok();
                }
                break;
            }
            match msg.category() {
                MessageCategory::TopLevel => {
                    self.state.handle_toplevel(&self.db, msg)?;
                }
                MessageCategory::ReadOnly => {
                    msgs.push_back(msg).expect("just recv'd");
                    tracing::debug!("starting read transaction");
                    let txn = self.db.begin_read()?;
                    let tables = ReadOnlyTables::new(&txn)?;
                    let count = self.state.options.batch.max_read_batch;
                    let timeout = self.state.options.batch.max_read_duration;
                    for msg in msgs.batch_iter(count, timeout) {
                        if let Err(msg) = self.state.handle_readonly(&tables, msg)? {
                            msgs.push_back(msg).expect("just recv'd");
                            break;
                        }
                    }
                    tracing::debug!("done with read transaction");
                }
                MessageCategory::ReadWrite => {
                    msgs.push_back(msg).expect("just recv'd");
                    tracing::debug!("starting write transaction");
                    let txn = self.db.begin_write()?;
                    let mut delete_after_commit = Default::default();
                    let mut tables = Tables::new(&txn, &mut delete_after_commit)?;
                    let count = self.state.options.batch.max_write_batch;
                    let timeout = self.state.options.batch.max_write_duration;
                    for msg in msgs.batch_iter(count, timeout) {
                        if let Err(msg) = self.state.handle_readwrite(&mut tables, msg)? {
                            msgs.push_back(msg).expect("just recv'd");
                            break;
                        }
                    }
                    drop(tables);
                    txn.commit()?;
                    delete_after_commit.apply_and_clear(&self.state.options.path);
                    tracing::debug!("write transaction committed");
                }
            }
        }
        tracing::debug!("redb actor done");
        Ok(())
    }
}

impl ActorState {
    fn entry_status(
        &mut self,
        tables: &impl ReadableTables,
        hash: Hash,
    ) -> ActorResult<EntryStatus> {
        let status = match tables.blobs().get(hash)? {
            Some(guard) => match guard.value() {
                EntryState::Complete { .. } => EntryStatus::Complete,
                EntryState::Partial { .. } => EntryStatus::Partial,
            },
            None => EntryStatus::NotFound,
        };
        Ok(status)
    }

    fn get(
        &mut self,
        tables: &impl ReadableTables,
        hash: Hash,
    ) -> ActorResult<Option<BaoFileHandle>> {
        if let Some(handle) = self.handles.get(&hash).and_then(|weak| weak.upgrade()) {
            return Ok(Some(handle));
        }
        let Some(entry) = tables.blobs().get(hash)? else {
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
                let data = load_data(tables, &self.options.path, data_location, &hash)?;
                let outboard = load_outboard(
                    tables,
                    &self.options.path,
                    outboard_location,
                    data.size(),
                    &hash,
                )?;
                BaoFileHandle::new_complete(config, hash, data, outboard)
            }
            EntryState::Partial { .. } => BaoFileHandle::incomplete_file(config, hash)?,
        };
        self.handles.insert(hash, handle.downgrade());
        Ok(Some(handle))
    }

    fn export(
        &mut self,
        tables: &mut Tables,
        cmd: Export,
        tx: oneshot::Sender<ActorResult<()>>,
    ) -> ActorResult<()> {
        let Export {
            temp_tag,
            target,
            mode,
            progress,
        } = cmd;
        let guard = tables
            .blobs
            .get(temp_tag.hash())?
            .ok_or_else(|| ActorError::Inconsistent("entry not found".to_owned()))?;
        let entry = guard.value();
        match entry {
            EntryState::Complete {
                data_location,
                outboard_location,
            } => {
                match data_location {
                    DataLocation::Inline(()) => {
                        // ignore export mode, just copy. For inline data we can not reference anyway.
                        let data = tables.inline_data.get(temp_tag.hash())?.ok_or_else(|| {
                            ActorError::Inconsistent("inline data not found".to_owned())
                        })?;
                        tracing::trace!("exporting inline data to {}", target.display());
                        tx.send(std::fs::write(&target, data.value()).map_err(|e| e.into()))
                            .ok();
                    }
                    DataLocation::Owned(size) => {
                        let path = self.options.path.owned_data_path(temp_tag.hash());
                        if mode == ExportMode::Copy {
                            // copy in an external thread
                            self.rt.spawn_blocking(move || {
                                tx.send(export_file_copy(temp_tag, path, size, target, progress))
                                    .ok();
                            });
                        } else {
                            match std::fs::rename(&path, &target) {
                                Ok(()) => {
                                    let entry = EntryState::Complete {
                                        data_location: DataLocation::External(vec![target], size),
                                        outboard_location,
                                    };
                                    drop(guard);
                                    tables.blobs.insert(temp_tag.hash(), entry)?;
                                    drop(temp_tag);
                                    tx.send(Ok(())).ok();
                                }
                                Err(e) => {
                                    drop(temp_tag);
                                    tx.send(Err(e.into())).ok();
                                }
                            }
                        }
                    }
                    DataLocation::External(paths, size) => {
                        let path = paths
                            .first()
                            .ok_or_else(|| {
                                ActorError::Inconsistent("external path missing".to_owned())
                            })?
                            .to_owned();
                        // we can not reference external files, so we just copy them. But this does not have to happen in the actor.
                        if path == target {
                            // export to the same path, nothing to do
                            tx.send(Ok(())).ok();
                        } else {
                            // copy in an external thread
                            self.rt.spawn_blocking(move || {
                                tx.send(export_file_copy(temp_tag, path, size, target, progress))
                                    .ok();
                            });
                        }
                    }
                }
            }
            EntryState::Partial { .. } => {
                return Err(io::Error::new(io::ErrorKind::Unsupported, "partial entry").into());
            }
        }
        Ok(())
    }

    fn import(&mut self, tables: &mut Tables, cmd: Import) -> ActorResult<(TempTag, u64)> {
        let Import {
            content_id,
            source: file,
            outboard,
            data_size,
        } = cmd;
        let outboard_size = outboard.as_ref().map(|x| x.len() as u64).unwrap_or(0);
        let inline_data = data_size <= self.options.inline.max_data_inlined;
        let inline_outboard =
            outboard_size <= self.options.inline.max_outboard_inlined && outboard_size != 0;
        // from here on, everything related to the hash is protected by the temp tag
        let tag = TempTag::new(content_id, Some(self.temp.clone()));
        let hash = *tag.hash();
        self.protected.insert(hash);
        // move the data file into place, or create a reference to it
        let data_location = match file {
            ImportSource::External(external_path) => {
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
            ImportSource::TempFile(temp_data_path) => {
                if inline_data {
                    tracing::info!(
                        "reading and deleting temp file to inline it: {}",
                        temp_data_path.display()
                    );
                    let data = Bytes::from(read_and_remove(&temp_data_path)?);
                    DataLocation::Inline(data)
                } else {
                    let data_path = self.options.path.owned_data_path(&hash);
                    std::fs::rename(&temp_data_path, &data_path)?;
                    tracing::info!("created file {}", data_path.display());
                    DataLocation::Owned(data_size)
                }
            }
            ImportSource::Memory(data) => {
                if inline_data {
                    DataLocation::Inline(data)
                } else {
                    let data_path = self.options.path.owned_data_path(&hash);
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
                let outboard_path = self.options.path.owned_outboard_path(&hash);
                // todo: this blocks the actor when writing a large outboard
                overwrite_and_sync(&outboard_path, &outboard)?;
                OutboardLocation::Owned
            }
        } else {
            OutboardLocation::NotNeeded
        };
        if let DataLocation::Inline(data) = &data_location {
            tables.inline_data.insert(hash, data.as_ref())?;
        }
        if let OutboardLocation::Inline(outboard) = &outboard_location {
            tables.inline_outboard.insert(hash, outboard.as_ref())?;
        }
        if let DataLocation::Owned(_) = &data_location {
            tables.delete_after_commit.remove(hash, [BaoFilePart::Data]);
        }
        if let OutboardLocation::Owned = &outboard_location {
            tables
                .delete_after_commit
                .remove(hash, [BaoFilePart::Outboard]);
        }
        let entry = tables.blobs.get(hash)?;
        let entry = entry.map(|x| x.value()).unwrap_or_default();
        let data_location = data_location.discard_inline_data();
        let outboard_location = outboard_location.discard_extra_data();
        let entry = entry.union(EntryState::Complete {
            data_location,
            outboard_location,
        })?;
        tables.blobs.insert(hash, entry)?;
        Ok((tag, data_size))
    }

    fn get_or_create(
        &mut self,
        tables: &impl ReadableTables,
        hash: Hash,
    ) -> ActorResult<BaoFileHandle> {
        self.protected.insert(hash);
        if let Some(handle) = self.handles.get(&hash).and_then(|x| x.upgrade()) {
            return Ok(handle);
        }
        let entry = tables.blobs().get(hash)?;
        let handle = if let Some(entry) = entry {
            let entry = entry.value();
            match entry {
                EntryState::Complete {
                    data_location,
                    outboard_location,
                    ..
                } => {
                    let data = load_data(tables, &self.options.path, data_location, &hash)?;
                    let outboard = load_outboard(
                        tables,
                        &self.options.path,
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
        self.handles.insert(hash, handle.downgrade());
        Ok(handle)
    }

    /// Read the entire blobs table. Callers can then sift through the results to find what they need
    fn blobs(
        &mut self,
        tables: &impl ReadableTables,
        filter: FilterPredicate<Hash, EntryState>,
    ) -> ActorResult<Vec<std::result::Result<(Hash, EntryState), StorageError>>> {
        let mut res = Vec::new();
        let mut index = 0u64;
        #[allow(clippy::explicit_counter_loop)]
        for item in tables.blobs().iter()? {
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
        tables: &impl ReadableTables,
        filter: FilterPredicate<Tag, HashAndFormat>,
    ) -> ActorResult<Vec<std::result::Result<(Tag, HashAndFormat), StorageError>>> {
        let mut res = Vec::new();
        let mut index = 0u64;
        #[allow(clippy::explicit_counter_loop)]
        for item in tables.tags().iter()? {
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

    fn create_tag(&mut self, tables: &mut Tables, content: HashAndFormat) -> ActorResult<Tag> {
        let tag = {
            let tag = Tag::auto(SystemTime::now(), |x| {
                matches!(tables.tags.get(Tag(Bytes::copy_from_slice(x))), Ok(Some(_)))
            });
            tables.tags.insert(tag.clone(), content)?;
            tag
        };
        Ok(tag)
    }

    fn set_tag(
        &self,
        tables: &mut Tables,
        tag: Tag,
        value: Option<HashAndFormat>,
    ) -> ActorResult<()> {
        match value {
            Some(value) => {
                tables.tags.insert(tag, value)?;
            }
            None => {
                tables.tags.remove(tag)?;
            }
        }
        Ok(())
    }

    fn on_mem_size_exceeded(&mut self, tables: &mut Tables, hash: Hash) -> ActorResult<()> {
        let entry = tables
            .blobs
            .get(hash)?
            .map(|x| x.value())
            .unwrap_or_default();
        let entry = entry.union(EntryState::Partial { size: None })?;
        tables.blobs.insert(hash, entry)?;
        // protect all three parts of the entry
        tables.delete_after_commit.remove(
            hash,
            [BaoFilePart::Data, BaoFilePart::Outboard, BaoFilePart::Sizes],
        );
        Ok(())
    }

    fn update_inline_options(
        &mut self,
        db: &redb::Database,
        options: InlineOptions,
        reapply: bool,
    ) -> ActorResult<()> {
        self.options.inline = options;
        if reapply {
            let mut delete_after_commit = Default::default();
            let tx = db.begin_write()?;
            {
                let mut tables = Tables::new(&tx, &mut delete_after_commit)?;
                let hashes = tables
                    .blobs
                    .iter()?
                    .map(|x| x.map(|(k, _)| k.value()))
                    .collect::<Result<Vec<_>, _>>()?;
                for hash in hashes {
                    let guard = tables
                        .blobs
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
                                if size <= self.options.inline.max_data_inlined {
                                    let path = self.options.path.owned_data_path(&hash);
                                    let data = std::fs::read(&path)?;
                                    tables.delete_after_commit.insert(hash, [BaoFilePart::Data]);
                                    tables.inline_data.insert(hash, data.as_slice())?;
                                    (DataLocation::Inline(()), size, true)
                                } else {
                                    (DataLocation::Owned(size), size, false)
                                }
                            }
                            DataLocation::Inline(()) => {
                                let guard = tables.inline_data.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline data missing".to_owned())
                                })?;
                                let data = guard.value();
                                let size = data.len() as u64;
                                if size > self.options.inline.max_data_inlined {
                                    let path = self.options.path.owned_data_path(&hash);
                                    std::fs::write(&path, data)?;
                                    drop(guard);
                                    tables.inline_data.remove(hash)?;
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
                                if outboard_size <= self.options.inline.max_outboard_inlined =>
                            {
                                let path = self.options.path.owned_outboard_path(&hash);
                                let outboard = std::fs::read(&path)?;
                                tables
                                    .delete_after_commit
                                    .insert(hash, [BaoFilePart::Outboard]);
                                tables.inline_outboard.insert(hash, outboard.as_slice())?;
                                (OutboardLocation::Inline(()), true)
                            }
                            OutboardLocation::Inline(())
                                if outboard_size > self.options.inline.max_outboard_inlined =>
                            {
                                let guard = tables.inline_outboard.get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline outboard missing".to_owned())
                                })?;
                                let outboard = guard.value();
                                let path = self.options.path.owned_outboard_path(&hash);
                                std::fs::write(&path, outboard)?;
                                drop(guard);
                                tables.inline_outboard.remove(hash)?;
                                (OutboardLocation::Owned, true)
                            }
                            x => (x, false),
                        };
                        drop(guard);
                        if data_location_changed || outboard_location_changed {
                            tables.blobs.insert(
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
            delete_after_commit.apply_and_clear(&self.options.path);
        }
        Ok(())
    }

    fn delete(&mut self, tables: &mut Tables, hashes: Vec<Hash>) -> ActorResult<()> {
        for hash in hashes {
            if self.temp.as_ref().read().unwrap().contains(&hash) {
                continue;
            }
            if self.protected.contains(&hash) {
                tracing::info!("protected hash, continuing {}", &hash.to_hex()[..8]);
                continue;
            }
            tracing::info!("deleting {}", &hash.to_hex()[..8]);
            self.handles.remove(&hash);
            if let Some(entry) = tables.blobs.remove(hash)? {
                match entry.value() {
                    EntryState::Complete {
                        data_location,
                        outboard_location,
                    } => {
                        match data_location {
                            DataLocation::Inline(_) => {
                                tables.inline_data.remove(hash)?;
                            }
                            DataLocation::Owned(_) => {
                                // mark the data for deletion
                                tables.delete_after_commit.insert(hash, [BaoFilePart::Data]);
                            }
                            DataLocation::External(_, _) => {}
                        }
                        match outboard_location {
                            OutboardLocation::Inline(_) => {
                                tables.inline_outboard.remove(hash)?;
                            }
                            OutboardLocation::Owned => {
                                // mark the outboard for deletion
                                tables
                                    .delete_after_commit
                                    .insert(hash, [BaoFilePart::Outboard]);
                            }
                            OutboardLocation::NotNeeded => {}
                        }
                    }
                    EntryState::Partial { .. } => {
                        // mark all parts for deletion
                        tables.delete_after_commit.insert(
                            hash,
                            [BaoFilePart::Outboard, BaoFilePart::Data, BaoFilePart::Sizes],
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn on_complete(&mut self, tables: &mut Tables, entry: BaoFileHandle) -> ActorResult<()> {
        let hash = entry.hash();
        let mut info = None;
        tracing::trace!("on_complete({})", hash.to_hex());
        entry.transform(|state| {
            tracing::trace!("on_complete transform {:?}", state);
            let entry = match complete_storage(
                state,
                &hash,
                &self.options.path,
                &self.options.inline,
                tables.delete_after_commit,
            )? {
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
            {
                tracing::info!(
                    "inserting complete entry for {}, {} bytes",
                    hash.to_hex(),
                    data_size,
                );
                let entry = tables
                    .blobs()
                    .get(hash)?
                    .map(|x| x.value())
                    .unwrap_or_default();
                let entry = entry.union(EntryState::Complete {
                    data_location,
                    outboard_location,
                })?;
                tables.blobs.insert(hash, entry)?;
                if let Some(data) = data {
                    tables.inline_data.insert(hash, data.as_ref())?;
                }
                if let Some(outboard) = outboard {
                    tables.inline_outboard.insert(hash, outboard.as_ref())?;
                }
            }
        }
        Ok(())
    }

    fn handle_toplevel(&mut self, db: &redb::Database, msg: ActorMessage) -> ActorResult<()> {
        match msg {
            ActorMessage::ImportFlatStore { paths, tx } => {
                let res = self.import_flat_store(db, paths);
                tx.send(res?).ok();
            }
            ActorMessage::UpdateInlineOptions {
                inline_options,
                reapply,
                tx,
            } => {
                let res = self.update_inline_options(db, inline_options, reapply);
                tx.send(res?).ok();
            }
            ActorMessage::Fsck {
                repair,
                progress,
                tx,
            } => {
                let res = self.consistency_check(db, repair, progress);
                tx.send(res).ok();
            }
            ActorMessage::Sync { tx } => {
                tx.send(()).ok();
            }
            x => {
                return Err(ActorError::Inconsistent(format!(
                    "unexpected message for handle_toplevel: {:?}",
                    x
                )))
            }
        }
        Ok(())
    }

    fn handle_readonly(
        &mut self,
        tables: &impl ReadableTables,
        msg: ActorMessage,
    ) -> ActorResult<std::result::Result<(), ActorMessage>> {
        match msg {
            ActorMessage::Get { hash, tx } => {
                let res = self.get(tables, hash);
                tx.send(res).ok();
            }
            ActorMessage::GetOrCreate { hash, tx } => {
                let res = self.get_or_create(tables, hash);
                tx.send(res).ok();
            }
            ActorMessage::EntryStatus { hash, tx } => {
                let res = self.entry_status(tables, hash);
                tx.send(res).ok();
            }
            ActorMessage::Blobs { filter, tx } => {
                let res = self.blobs(tables, filter);
                tx.send(res).ok();
            }
            ActorMessage::Tags { filter, tx } => {
                let res = self.tags(tables, filter);
                tx.send(res).ok();
            }
            ActorMessage::GcStart { tx } => {
                self.protected.clear();
                self.handles.retain(|_, weak| weak.is_live());
                tx.send(()).ok();
            }
            ActorMessage::Dump => {
                dump(tables).ok();
            }
            #[cfg(test)]
            ActorMessage::EntryState { hash, tx } => {
                tx.send(self.entry_state(tables, hash)).ok();
            }
            ActorMessage::GetFullEntryState { hash, tx } => {
                let res = self.get_full_entry_state(tables, hash);
                tx.send(res).ok();
            }
            x => return Ok(Err(x)),
        }
        Ok(Ok(()))
    }

    fn handle_readwrite(
        &mut self,
        tables: &mut Tables,
        msg: ActorMessage,
    ) -> ActorResult<std::result::Result<(), ActorMessage>> {
        match msg {
            ActorMessage::Import { cmd, tx } => {
                let res = self.import(tables, cmd);
                tx.send(res).ok();
            }
            ActorMessage::SetTag { tag, value, tx } => {
                let res = self.set_tag(tables, tag, value);
                tx.send(res).ok();
            }
            ActorMessage::CreateTag { hash, tx } => {
                let res = self.create_tag(tables, hash);
                tx.send(res).ok();
            }
            ActorMessage::Delete { hashes, tx } => {
                let res = self.delete(tables, hashes);
                tx.send(res).ok();
            }
            ActorMessage::OnComplete { handle } => {
                let res = self.on_complete(tables, handle);
                res.ok();
            }
            ActorMessage::Export { cmd, tx } => {
                self.export(tables, cmd, tx)?;
            }
            ActorMessage::OnMemSizeExceeded { hash } => {
                let res = self.on_mem_size_exceeded(tables, hash);
                res.ok();
            }
            ActorMessage::Dump => {
                let res = dump(tables);
                res.ok();
            }
            ActorMessage::SetFullEntryState { hash, entry, tx } => {
                let res = self.set_full_entry_state(tables, hash, entry);
                tx.send(res).ok();
            }
            msg => {
                // try to handle it as readonly
                if let Err(msg) = self.handle_readonly(tables, msg)? {
                    return Ok(Err(msg));
                }
            }
        }
        Ok(Ok(()))
    }
}

/// Export a file by copyign out its content to a new location
fn export_file_copy(
    temp_tag: TempTag,
    path: PathBuf,
    size: u64,
    target: PathBuf,
    progress: ExportProgressCb,
) -> ActorResult<()> {
    progress(0)?;
    // todo: fine grained copy progress
    reflink_copy::reflink_or_copy(path, target)?;
    progress(size)?;
    drop(temp_tag);
    Ok(())
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
    use bao_tree::io::sync::CreateOutboard;

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader::new(read, progress);
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let buf_size = usize::try_from(size).unwrap_or(usize::MAX).min(1024 * 1024);
    let reader = BufReader::with_capacity(buf_size, reader);

    let ob = PreOrderOutboard::<Vec<u8>>::create_sized(reader, size, IROH_BLOCK_SIZE)?;
    let root = ob.root.into();
    let data = ob.data;
    tracing::trace!(%root, "done");
    let data = if !data.is_empty() { Some(data) } else { None };
    Ok((root, data))
}

fn dump(tables: &impl ReadableTables) -> ActorResult<()> {
    for e in tables.blobs().iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("blobs: {} -> {:?}", k.to_hex(), v);
    }
    for e in tables.tags().iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("tags: {} -> {:?}", k, v);
    }
    for e in tables.inline_data().iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("inline_data: {} -> {:?}", k.to_hex(), v.len());
    }
    for e in tables.inline_outboard().iter()? {
        let (k, v) = e?;
        let k = k.value();
        let v = v.value();
        println!("inline_outboard: {} -> {:?}", k.to_hex(), v.len());
    }
    Ok(())
}

fn load_data(
    tables: &impl ReadableTables,
    options: &PathOptions,
    location: DataLocation<(), u64>,
    hash: &Hash,
) -> ActorResult<MemOrFile<Bytes, (std::fs::File, u64)>> {
    Ok(match location {
        DataLocation::Inline(()) => {
            let Some(data) = tables.inline_data().get(hash)? else {
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
    tables: &impl ReadableTables,
    options: &PathOptions,
    location: OutboardLocation,
    size: u64,
    hash: &Hash,
) -> ActorResult<MemOrFile<Bytes, (std::fs::File, u64)>> {
    Ok(match location {
        OutboardLocation::NotNeeded => MemOrFile::Mem(Bytes::new()),
        OutboardLocation::Inline(_) => {
            let Some(outboard) = tables.inline_outboard().get(hash)? else {
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
    delete_after_commit: &mut DeleteSet,
) -> ActorResult<std::result::Result<CompleteStorage, CompleteStorage>> {
    let (data, outboard, _sizes) = match storage {
        BaoFileStorage::Complete(c) => return Ok(Err(c)),
        BaoFileStorage::IncompleteMem(storage) => {
            let (data, outboard, sizes) = storage.into_parts();
            (
                MemOrFile::Mem(Bytes::from(data.into_parts().0)),
                MemOrFile::Mem(Bytes::from(outboard.into_parts().0)),
                MemOrFile::Mem(Bytes::from(sizes.to_vec())),
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
                // mark data for deletion after commit
                delete_after_commit.insert(*hash, [BaoFilePart::Data]);
                MemOrFile::Mem(Bytes::from(buf))
            }
            MemOrFile::Mem(data) => MemOrFile::Mem(data),
        }
    } else {
        // protect the data from previous deletions
        delete_after_commit.remove(*hash, [BaoFilePart::Data]);
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
                // mark outboard for deletion after commit
                delete_after_commit.insert(*hash, [BaoFilePart::Outboard]);
                MemOrFile::Mem(Bytes::from(buf))
            }
            MemOrFile::Mem(outboard) => MemOrFile::Mem(outboard),
        }
    } else {
        // protect the outboard from previous deletions
        delete_after_commit.remove(*hash, [BaoFilePart::Outboard]);
        match outboard {
            MemOrFile::Mem(outboard) => {
                let path = path_options.owned_outboard_path(hash);
                let file = overwrite_and_sync(&path, &outboard)?;
                MemOrFile::File((file, outboard_size))
            }
            MemOrFile::File(outboard) => MemOrFile::File((outboard, outboard_size)),
        }
    };
    // mark sizes for deletion after commit in any case - a complete entry
    // does not need sizes.
    delete_after_commit.insert(*hash, [BaoFilePart::Sizes]);
    Ok(Ok(CompleteStorage { data, outboard }))
}
