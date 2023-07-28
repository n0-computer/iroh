//! The concrete database used by the iroh binary.
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::{fmt, io, result};

use anyhow::Context;
use bao_tree::io::outboard::{PostOrderMemOutboard, PreOrderMemOutboard};
use bao_tree::ChunkNum;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::future::Either;
use futures::{Future, FutureExt, StreamExt};
use iroh_bytes::protocol::MAX_MESSAGE_SIZE;
use iroh_bytes::provider::{BaoDb, BaoMap, BaoMapEntry, BaoReadonlyDb, LocalFs};
use iroh_bytes::provider::{ProvideProgress, ValidateProgress};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::File;
use range_collections::RangeSet2;
use tokio::sync::mpsc;
use tracing::{trace, trace_span};
use walkdir::WalkDir;

use crate::collection::Blob;
use crate::collection::Collection;
use crate::util::io::canonicalize_path;
use crate::util::io::validate_bao;
use crate::util::io::BaoValidationError;
use crate::util::progress::{Progress, ProgressReader, ProgressReaderUpdate};

/// File name of directory inside `IROH_DATA_DIR` where outboards are stored.
const FNAME_OUTBOARDS: &str = "outboards";

/// File name of directory inside `IROH_DATA_DIR` where collections are stored.
///
/// This is now used not just for collections but also for internally generated blobs.
const FNAME_COLLECTIONS: &str = "collections";

/// File name inside `IROH_DATA_DIR` where paths to data are stored.
pub const FNAME_PATHS: &str = "paths.bin";

/// Database containing content-addressed data (blobs or collections).
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<RwLock<HashMap<Hash, DbEntry>>>);
/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct DbPair {
    hash: blake3::Hash,
    entry: DbEntry,
}

impl BaoMapEntry<Database> for DbPair {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn size(&self) -> u64 {
        match &self.entry {
            DbEntry::External { size, .. } => *size,
            DbEntry::Internal { data, .. } => data.len() as u64,
        }
    }

    fn available(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard>> {
        async move {
            let bytes = self.entry.outboard_reader().await?;
            let hash = self.hash;
            PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, bytes)
        }
        .boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Either<Bytes, File>>> {
        self.entry.data_reader().boxed()
    }
}

/// A [`Database`] entry.
///
/// This is either stored externally in the file system, or internally in the database.
///
/// Internally stored entries are stored in the iroh home directory when the database is
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbEntry {
    /// A blob.
    External {
        /// The bao outboard data.
        outboard: Bytes,
        /// Path to the original data, which must not change while in use.
        ///
        /// Note that when adding multiple files with the same content, only one of them
        /// will get added to the store. So the path is not that useful for information.  It
        /// is just a place to look for the data correspoding to the hash and outboard.
        // TODO: Change this to a list of paths.
        path: PathBuf,
        /// Size of the original data.
        size: u64,
    },
    /// A collection.
    Internal {
        /// The bao outboard data.
        outboard: Bytes,
        /// The inline data.
        data: Bytes,
    },
}

impl DbEntry {
    /// True if this is an entry that is stored externally.
    pub fn is_external(&self) -> bool {
        matches!(self, DbEntry::External { .. })
    }

    /// Path to the external data, or `None` if this is an internal entry.
    pub fn blob_path(&self) -> Option<&Path> {
        match self {
            DbEntry::External { path, .. } => Some(path),
            DbEntry::Internal { .. } => None,
        }
    }

    /// Get the outboard data for this entry, as a `Bytes`.
    pub fn outboard_reader(&self) -> impl Future<Output = io::Result<Bytes>> + 'static {
        futures::future::ok(match self {
            DbEntry::External { outboard, .. } => outboard.clone(),
            DbEntry::Internal { outboard, .. } => outboard.clone(),
        })
    }

    /// A reader for the data.
    pub fn data_reader(&self) -> impl Future<Output = io::Result<Either<Bytes, File>>> + 'static {
        let this = self.clone();
        async move {
            Ok(match this {
                DbEntry::External { path, .. } => Either::Right(File::open(path).await?),
                DbEntry::Internal { data, .. } => Either::Left(data),
            })
        }
    }

    /// Returns the size of the blob or collection.
    ///
    /// For collections this is the size of the serialized collection.
    /// For blobs it is the blob size.
    pub async fn size(&self) -> u64 {
        match self {
            DbEntry::External { size, .. } => *size,
            DbEntry::Internal { data, .. } => data.len() as u64,
        }
    }
}

impl BaoMap for Database {
    type Entry = DbPair;
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Either<Bytes, File>;
    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let entry = self.get(hash)?;
        Some(DbPair {
            hash: blake3::Hash::from(*hash),
            entry,
        })
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let inner = self.0.read().unwrap();
        let items = inner.iter().map(|(hash, _)| *hash).collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let inner = self.0.read().unwrap();
        let items = inner
            .iter()
            .filter(|(_, entry)| !entry.is_external())
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        self.validate0(tx).boxed()
    }
}

impl BaoDb for Database {
    type Vfs = LocalFs;

    fn vfs(&self) -> &Self::Vfs {
        &LocalFs
    }

    fn insert_entry(
        &self,
        hash: Hash,
        data: PathBuf,
        outboard: Option<PathBuf>,
    ) -> BoxFuture<'_, io::Result<()>> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            let outboard = std::fs::read(outboard.unwrap())?.into();
            let size = std::fs::metadata(data.as_path())?.len();
            let entry = DbEntry::External {
                outboard,
                path: data,
                size,
            };
            let mut inner = db.0.write().unwrap();
            inner.insert(hash, entry);
            Ok(())
        })
        .map(make_io_error)
        .boxed()
    }
}

fn make_io_error<T>(
    r: std::result::Result<io::Result<T>, tokio::task::JoinError>,
) -> io::Result<T> {
    match r {
        Ok(Ok(t)) => Ok(t),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
    }
}

impl From<HashMap<Hash, DbEntry>> for Database {
    fn from(map: HashMap<Hash, DbEntry>) -> Self {
        Self(Arc::new(RwLock::new(map)))
    }
}

/// A snapshot of the database.
///
/// `E` can be `Infallible` if we take a snapshot from an in memory database,
/// or `io::Error` if we read a database from disk.
pub(crate) struct Snapshot<E> {
    /// list of paths we have, hash is the hash of the blob or collection
    paths: Box<dyn Iterator<Item = (Hash, u64, Option<PathBuf>)>>,
    /// map of hash to outboard, hash is the hash of the outboard and is unique
    outboards: Box<dyn Iterator<Item = result::Result<(Hash, Bytes), E>>>,
    /// map of hash to collection, hash is the hash of the collection and is unique
    collections: Box<dyn Iterator<Item = result::Result<(Hash, Bytes), E>>>,
}

impl<E> fmt::Debug for Snapshot<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot").finish()
    }
}

/// An error that can never happen
#[derive(Debug)]
pub enum NoError {}

impl From<NoError> for io::Error {
    fn from(_: NoError) -> Self {
        unreachable!()
    }
}

struct DataPaths {
    #[allow(dead_code)]
    data_dir: PathBuf,
    outboards_dir: PathBuf,
    collections_dir: PathBuf,
    paths_file: PathBuf,
}

impl DataPaths {
    fn new(data_dir: PathBuf) -> Self {
        Self {
            outboards_dir: data_dir.join(FNAME_OUTBOARDS),
            collections_dir: data_dir.join(FNAME_COLLECTIONS),
            paths_file: data_dir.join(FNAME_PATHS),
            data_dir,
        }
    }
}

/// Using base64 you have all those weird characters like + and /.
/// So we use hex for file names.
fn format_hash(hash: &Hash) -> String {
    hex::encode(hash.as_ref())
}

/// Parse a hash from a string, e.g. a file name.
fn parse_hash(hash: &str) -> anyhow::Result<Hash> {
    let hash = hex::decode(hash)?;
    let hash: [u8; 32] = hash.try_into().ok().context("wrong size for hash")?;
    Ok(Hash::from(hash))
}

impl Snapshot<io::Error> {
    /// Load a snapshot from disk.
    pub fn load(data_dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        use std::fs;
        let DataPaths {
            outboards_dir,
            collections_dir,
            paths_file,
            ..
        } = DataPaths::new(data_dir.as_ref().to_path_buf());
        let paths = fs::read(&paths_file)
            .with_context(|| format!("Failed reading {}", paths_file.display()))?;
        let paths = postcard::from_bytes::<Vec<(Hash, u64, Option<PathBuf>)>>(&paths)?;
        let hashes = paths
            .iter()
            .map(|(hash, _, _)| *hash)
            .collect::<BTreeSet<_>>();
        let outboards = hashes.clone().into_iter().map(move |hash| {
            let path = outboards_dir.join(format_hash(&hash));
            fs::read(path).map(|x| (hash, Bytes::from(x)))
        });
        let collections = fs::read_dir(&collections_dir)
            .with_context(|| {
                format!(
                    "Failed reading collections directory {}",
                    collections_dir.display()
                )
            })?
            .map(move |entry| {
                let entry = entry?;
                let path = entry.path();
                // skip directories
                if entry.file_type()?.is_dir() {
                    tracing::debug!("skipping directory: {:?}", path);
                    return Ok(None);
                }
                // try to get the file name as an OsStr
                let name = if let Some(name) = path.file_name() {
                    name
                } else {
                    tracing::debug!("skipping unexpected path: {:?}", path);
                    return Ok(None);
                };
                // try to convert into a std str
                let name = if let Some(name) = name.to_str() {
                    name
                } else {
                    tracing::debug!("skipping unexpected path: {:?}", path);
                    return Ok(None);
                };
                // try to parse the file name as a hash
                let hash = match parse_hash(name) {
                    Ok(hash) => hash,
                    Err(err) => {
                        tracing::debug!("skipping unexpected path: {:?}: {}", path, err);
                        return Ok(None);
                    }
                };
                // skip files that are not in the paths file
                if !hashes.contains(&hash) {
                    tracing::debug!("skipping unexpected hash: {:?}", hash);
                    return Ok(None);
                }
                // read the collection data and turn it into a Bytes
                let collection = Bytes::from(fs::read(path)?);
                io::Result::Ok(Some((hash, collection)))
            })
            .filter_map(|x| x.transpose());
        Ok(Self {
            paths: Box::new(paths.into_iter()),
            outboards: Box::new(outboards),
            collections: Box::new(collections),
        })
    }
}

impl<E> Snapshot<E>
where
    io::Error: From<E>,
{
    /// Persist the snapshot to disk.
    pub fn persist(self, data_dir: impl AsRef<Path>) -> io::Result<()> {
        use std::fs;
        let DataPaths {
            outboards_dir,
            collections_dir,
            paths_file,
            ..
        } = DataPaths::new(data_dir.as_ref().to_path_buf());
        fs::create_dir_all(&data_dir)?;
        fs::create_dir_all(&outboards_dir)?;
        fs::create_dir_all(&collections_dir)?;
        for item in self.outboards {
            let (hash, outboard) = item.map_err(Into::into)?;
            let path = outboards_dir.join(format_hash(&hash));
            fs::write(path, &outboard)?;
        }
        for item in self.collections {
            let (hash, collection) = item.map_err(Into::into)?;
            let path = collections_dir.join(format_hash(&hash));
            fs::write(path, &collection)?;
        }
        let mut paths = self.paths.collect::<Vec<_>>();
        paths.sort_by_key(|(path, _, _)| *path);
        let paths_content = postcard::to_stdvec(&paths).expect("failed to serialize paths file");
        fs::write(paths_file, paths_content)?;
        Ok(())
    }
}

impl Database {
    /// Load a database from disk for testing. Synchronous.
    pub fn load_test(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        Self::load_internal(dir)
    }

    /// Save a database to disk for testing. Synchronous.
    pub fn save_test(&self, dir: impl AsRef<Path>) -> io::Result<()> {
        let dir = dir.as_ref().to_path_buf();
        self.save_internal(dir)
    }

    fn load_internal(dir: PathBuf) -> anyhow::Result<Self> {
        tracing::info!("Loading snapshot from {}...", dir.display());
        let snapshot = Snapshot::load(dir)?;
        let db = Self::from_snapshot(snapshot)?;
        tracing::info!("Database loaded");
        anyhow::Ok(db)
    }

    fn save_internal(&self, dir: PathBuf) -> io::Result<()> {
        tracing::info!("Persisting database to {}...", dir.display());
        let snapshot = self.snapshot();
        snapshot.persist(dir)?;
        tracing::info!("Database stored");
        io::Result::Ok(())
    }

    /// Load a database from disk.
    pub async fn load(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let db = tokio::task::spawn_blocking(|| Self::load_internal(dir)).await??;
        Ok(db)
    }

    /// Save a database to disk.
    pub async fn save(&self, dir: impl AsRef<Path>) -> io::Result<()> {
        let dir = dir.as_ref().to_path_buf();
        let db = self.clone();
        tokio::task::spawn_blocking(move || db.save_internal(dir)).await??;
        Ok(())
    }

    /// Load a database from disk.
    pub(crate) fn from_snapshot<E: Into<io::Error>>(snapshot: Snapshot<E>) -> anyhow::Result<Self> {
        let Snapshot {
            outboards,
            collections,
            paths,
        } = snapshot;
        let outboards = outboards
            .collect::<result::Result<HashMap<_, _>, E>>()
            .map_err(Into::into)
            .context("Failed reading outboards")?;
        let collections = collections
            .collect::<result::Result<HashMap<_, _>, E>>()
            .map_err(Into::into)
            .context("Failed reading collections")?;
        let mut db = HashMap::new();
        for (hash, size, path) in paths {
            if let (Some(path), Some(outboard)) = (path, outboards.get(&hash)) {
                db.insert(
                    hash,
                    DbEntry::External {
                        outboard: outboard.clone(),
                        path,
                        size,
                    },
                );
            }
        }
        for (hash, data) in collections {
            if let Some(outboard) = outboards.get(&hash) {
                db.insert(
                    hash,
                    DbEntry::Internal {
                        outboard: outboard.clone(),
                        data,
                    },
                );
            }
        }

        Ok(Self(Arc::new(RwLock::new(db))))
    }

    /// Validate the entire database, including collections.
    ///
    /// This works by taking a snapshot of the database, and then validating. So anything you add after this call will not be validated.
    async fn validate0(&self, tx: mpsc::Sender<ValidateProgress>) -> anyhow::Result<()> {
        // This makes a copy of the db, but since the outboards are Bytes, it's not expensive.
        let mut data = self
            .0
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        data.sort_by_key(|(k, e)| (e.is_external(), e.blob_path().map(ToOwned::to_owned), *k));
        tx.send(ValidateProgress::Starting {
            total: data.len() as u64,
        })
        .await?;
        futures::stream::iter(data)
            .enumerate()
            .map(|(id, (hash, boc))| {
                let id = id as u64;
                let path = if let DbEntry::External { path, .. } = &boc {
                    Some(path.clone())
                } else {
                    None
                };
                let entry_tx = tx.clone();
                let done_tx = tx.clone();
                async move {
                    let size = boc.size().await;
                    entry_tx
                        .send(ValidateProgress::Entry {
                            id,
                            hash,
                            path: path.map(|x| x.display().to_string()),
                            size,
                        })
                        .await?;
                    let error = tokio::task::spawn_blocking(move || {
                        let progress_tx = entry_tx.clone();
                        let progress = |offset| {
                            progress_tx
                                .try_send(ValidateProgress::Progress { id, offset })
                                .ok();
                        };
                        let res = match boc {
                            DbEntry::External { outboard, path, .. } => {
                                match std::fs::File::open(&path) {
                                    Ok(data) => {
                                        tracing::info!("validating {}", path.display());
                                        let res = validate_bao(hash, data, outboard, progress);
                                        tracing::info!("done validating {}", path.display());
                                        res
                                    }
                                    Err(cause) => Err(BaoValidationError::from(cause)),
                                }
                            }
                            DbEntry::Internal { outboard, data } => {
                                validate_bao(hash, data.as_ref(), outboard, progress)
                            }
                        };
                        res.err()
                    })
                    .await?;
                    let error = error.map(|x| x.to_string());
                    done_tx.send(ValidateProgress::Done { id, error }).await?;
                    anyhow::Ok(())
                }
            })
            .buffer_unordered(num_cpus::get())
            .map(|item| {
                // unwrapping is fine here, because it will only happen if the task panicked
                // basically we are just moving the panic on this task.
                item.expect("task panicked");
                Ok(())
            })
            .forward(futures::sink::drain())
            .await?;
        Ok(())
    }

    /// take a snapshot of the database
    pub(crate) fn snapshot(&self) -> Snapshot<NoError> {
        let this = self.0.read().unwrap();
        let outboards = this
            .iter()
            .map(|(k, v)| match v {
                DbEntry::External { outboard, .. } => (*k, outboard.clone()),
                DbEntry::Internal { outboard, .. } => (*k, outboard.clone()),
            })
            .collect::<Vec<_>>();

        let collections = this
            .iter()
            .filter_map(|(k, v)| match v {
                DbEntry::External { .. } => None,
                DbEntry::Internal { data, .. } => Some((*k, data.clone())),
            })
            .collect::<Vec<_>>();

        let paths = this
            .iter()
            .map(|(k, v)| match v {
                DbEntry::External { path, size, .. } => (*k, *size, Some(path.clone())),
                DbEntry::Internal { data, .. } => (*k, data.len() as u64, None),
            })
            .collect::<Vec<_>>();

        Snapshot {
            outboards: Box::new(outboards.into_iter().map(Ok)),
            collections: Box::new(collections.into_iter().map(Ok)),
            paths: Box::new(paths.into_iter()),
        }
    }

    /// Get the entry for a given hash.
    pub fn get(&self, key: &Hash) -> Option<DbEntry> {
        self.0.read().unwrap().get(key).cloned()
    }

    /// Compute the union of this database with another.
    pub fn union_with(&self, db: HashMap<Hash, DbEntry>) {
        let mut inner = self.0.write().unwrap();
        for (k, v) in db {
            inner.entry(k).or_insert(v);
        }
    }

    /// Iterate over all blobs that are stored externally.
    pub fn external(&self) -> impl Iterator<Item = (Hash, PathBuf, u64)> + 'static {
        let items = self
            .0
            .read()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| match v {
                DbEntry::External { path, size, .. } => Some((*k, path.clone(), *size)),
                DbEntry::Internal { .. } => None,
            })
            .collect::<Vec<_>>();
        // todo: make this a proper lazy iterator at some point
        // e.g. by using an immutable map or a real database that supports snapshots.
        items.into_iter()
    }

    /// Iterate over all collections in the database.
    pub fn internal(&self) -> impl Iterator<Item = (Hash, Bytes)> + 'static {
        let items = self
            .0
            .read()
            .unwrap()
            .iter()
            .filter_map(|(hash, v)| match v {
                DbEntry::External { .. } => None,
                DbEntry::Internal { data, .. } => Some((*hash, data.clone())),
            })
            .collect::<Vec<_>>();
        // todo: make this a proper lazy iterator at some point
        // e.g. by using an immutable map or a real database that supports snapshots.
        items.into_iter()
    }

    /// Unwrap into the inner HashMap
    pub fn to_inner(&self) -> HashMap<Hash, DbEntry> {
        self.0.read().unwrap().clone()
    }
}

/// Data for a blob
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobData {
    /// Outboard data from bao.
    outboard: Bytes,
    /// Path to the original data, which must not change while in use.
    ///
    /// Note that when adding multiple files with the same content, only one of them
    /// will get added to the store. So the path is not that useful for information.
    /// It is just a place to look for the data correspoding to the hash and outboard.
    path: PathBuf,
    /// Size of the original data.
    size: u64,
}

/// A data source
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DataSource {
    /// Custom name
    name: String,
    /// Path to the file
    path: PathBuf,
}

impl DataSource {
    /// Creates a new [`DataSource`] from a [`PathBuf`].
    pub fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        DataSource { path, name }
    }
    /// Creates a new [`DataSource`] from a [`PathBuf`] and a custom name.
    pub fn with_name(path: PathBuf, name: String) -> Self {
        DataSource { path, name }
    }

    /// Returns blob name for this data source.
    ///
    /// If no name was provided when created it is derived from the path name.
    pub(crate) fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }

    /// Returns the path of this data source.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl From<PathBuf> for DataSource {
    fn from(value: PathBuf) -> Self {
        DataSource::new(value)
    }
}

impl From<&std::path::Path> for DataSource {
    fn from(value: &std::path::Path) -> Self {
        DataSource::new(value.to_path_buf())
    }
}

/// Create data sources from a path.
pub fn create_data_sources(root: PathBuf) -> anyhow::Result<Vec<DataSource>> {
    Ok(if root.is_dir() {
        let files = WalkDir::new(&root).into_iter();
        let data_sources = files
            .map(|entry| {
                let entry = entry?;
                let root = root.clone();
                if !entry.file_type().is_file() {
                    // Skip symlinks. Directories are handled by WalkDir.
                    return Ok(None);
                }
                let path = entry.into_path();
                let name = canonicalize_path(path.strip_prefix(&root)?)?;
                anyhow::Ok(Some(DataSource { name, path }))
            })
            .filter_map(Result::transpose);
        let data_sources: Vec<anyhow::Result<DataSource>> = data_sources.collect::<Vec<_>>();
        data_sources
            .into_iter()
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        // A single file, use the file name as the name of the blob.
        vec![DataSource {
            name: canonicalize_path(root.file_name().context("path must be a file")?)?,
            path: root,
        }]
    })
}

/// Outboard data for a blob.
struct BlobWithOutboard {
    /// The path of the file containing the original blob data.
    path: PathBuf,
    /// The blob name.
    // TODO: This is not optional!  crate::blobs::Blob::name is String.
    name: String,
    /// The size of the original data.
    size: u64,
    /// The hash of the blob.
    hash: Hash,
    /// The bao outboard data.
    outboard: Bytes,
}

/// Computes all the outboards, using parallelism.
async fn compute_all_outboards(
    data_sources: Vec<DataSource>,
    progress: Progress<ProvideProgress>,
) -> anyhow::Result<Vec<BlobWithOutboard>> {
    let outboards: Vec<_> = futures::stream::iter(data_sources)
        .enumerate()
        .map(|(id, data)| {
            let progress = progress.clone();
            tokio::task::spawn_blocking(move || outboard_from_datasource(id as u64, data, progress))
        })
        // Allow at most num_cpus tasks at a time, otherwise we might get too many open
        // files.
        // TODO: this assumes that this is 100% cpu bound, which is likely not true.  we
        // might get better performance by using a larger number here.
        .buffer_unordered(num_cpus::get())
        .collect()
        .await;

    // Flatten JoinError and computation error, then bail on any error.
    outboards
        .into_iter()
        .map(|join_res| {
            join_res
                .map_err(|_| anyhow::Error::msg("Task JoinError"))
                .and_then(|res| res)
        })
        .collect::<anyhow::Result<Vec<BlobWithOutboard>>>()
}

/// Computes a single outboard synchronously.
///
/// This includes the file access and sending progress reports.  Moving all file access here
/// is simpler and faster to do on the sync pool anyway.
fn outboard_from_datasource(
    id: u64,
    data_source: DataSource,
    progress: Progress<ProvideProgress>,
) -> anyhow::Result<BlobWithOutboard> {
    let file_meta = data_source.path().metadata().with_context(|| {
        format!(
            "Failed to read file size from {}",
            data_source.path().display()
        )
    })?;
    let size = file_meta.len();
    // TODO: Found should really send the PathBuf, not the name?
    progress.blocking_send(ProvideProgress::Found {
        name: data_source.name().to_string(),
        id,
        size,
    });
    let (hash, outboard) = {
        let progress = progress.clone();
        compute_outboard(data_source.path(), size, move |offset| {
            progress.try_send(ProvideProgress::Progress { id, offset })
        })?
    };
    progress.blocking_send(ProvideProgress::Done { id, hash });
    Ok(BlobWithOutboard {
        path: data_source.path().to_path_buf(),
        name: data_source.name().to_string(),
        size,
        hash,
        outboard: Bytes::from(outboard),
    })
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
fn compute_outboard(
    path: &Path,
    size: u64,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> anyhow::Result<(Hash, Vec<u8>)> {
    anyhow::ensure!(
        path.is_file(),
        "can only transfer blob data: {}",
        path.display()
    );
    let span = trace_span!("outboard.compute", path = %path.display());
    let _guard = span.enter();
    let file = std::fs::File::open(path)?;
    // compute outboard size so we can pre-allocate the buffer.
    //
    // outboard is ~1/16 of data size, so this will fail for really large files
    // on really small devices. E.g. you want to transfer a 1TB file from a pi4 with 1gb ram.
    //
    // The way to solve this would be to have larger blocks than the blake3 chunk size of 1024.
    // I think we really want to keep the outboard in memory for simplicity.
    let outboard_size = usize::try_from(bao_tree::io::outboard_size(size, IROH_BLOCK_SIZE))
        .context("outboard too large to fit in memory")?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader::new(file, |p| {
        if let ProgressReaderUpdate::Progress(offset) = p {
            progress(offset);
        }
    });
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    let hash =
        bao_tree::io::sync::outboard_post_order(&mut reader, size, IROH_BLOCK_SIZE, &mut outboard)?;
    let ob = PostOrderMemOutboard::load(hash, &outboard, IROH_BLOCK_SIZE)?.flip();
    trace!(%hash, "done");

    Ok((hash.into(), ob.into_inner()))
}

/// Creates a collection blob and returns all blobs in a hashmap.
///
/// Returns the hashmap with all blobs, including the created collection blob itself, as
/// well as the [`iroh_bytes::Hash`] of the collection blob.
pub async fn create_collection_inner(
    data_sources: Vec<DataSource>,
    progress: Progress<ProvideProgress>,
) -> anyhow::Result<(HashMap<Hash, DbEntry>, Hash)> {
    let mut outboards = compute_all_outboards(data_sources, progress.clone()).await?;

    // TODO: Don't sort on async runtime?
    outboards.sort_by_key(|o| (o.name.clone(), o.hash));

    let mut map = HashMap::with_capacity(outboards.len() + 1);
    let mut blobs = Vec::with_capacity(outboards.len());
    let mut total_blobs_size: u64 = 0;

    for BlobWithOutboard {
        path,
        name,
        size,
        hash,
        outboard,
    } in outboards
    {
        debug_assert!(outboard.len() >= 8, "outboard must at least contain size");
        map.insert(
            hash,
            DbEntry::External {
                outboard,
                path,
                size,
            },
        );
        total_blobs_size += size;
        blobs.push(Blob { name, hash });
    }

    let collection = Collection::new(blobs, total_blobs_size)?;
    let data = postcard::to_stdvec(&collection).context("collection blob encoding")?;
    if data.len() > MAX_MESSAGE_SIZE {
        anyhow::bail!("Serialised collection exceeds {MAX_MESSAGE_SIZE}");
    }
    let (outboard, hash) = bao_tree::io::outboard(&data, IROH_BLOCK_SIZE);
    let hash = Hash::from(hash);
    map.insert(
        hash,
        DbEntry::Internal {
            outboard: Bytes::from(outboard),
            data: Bytes::from(data.to_vec()),
        },
    );
    progress.send(ProvideProgress::AllDone { hash }).await?;
    Ok((map, hash))
}

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_collection(data_sources: Vec<DataSource>) -> anyhow::Result<(Database, Hash)> {
    let (db, hash) = create_collection_inner(data_sources, Progress::none()).await?;
    Ok((Database::from(db), hash))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::str::FromStr;
    use testdir::testdir;

    use crate::database::flat::Snapshot;

    use super::*;

    fn blob(size: usize) -> impl Strategy<Value = Bytes> {
        proptest::collection::vec(any::<u8>(), 0..size).prop_map(Bytes::from)
    }

    fn blobs(count: usize, size: usize) -> impl Strategy<Value = Vec<Bytes>> {
        proptest::collection::vec(blob(size), 0..count)
    }

    fn db(blob_count: usize, blob_size: usize) -> impl Strategy<Value = Database> {
        let blobs = blobs(blob_count, blob_size);
        blobs.prop_map(|blobs| {
            let mut map = HashMap::new();
            let mut cblobs = Vec::new();
            let mut total_blobs_size = 0u64;
            for blob in blobs {
                let size = blob.len() as u64;
                total_blobs_size += size;
                let (outboard, hash) = bao_tree::io::outboard(&blob, IROH_BLOCK_SIZE);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                let path = PathBuf::from_str(&hash.to_string()).unwrap();
                cblobs.push(Blob {
                    name: hash.to_string(),
                    hash,
                });
                map.insert(
                    hash,
                    DbEntry::External {
                        outboard,
                        size,
                        path,
                    },
                );
            }
            let collection = Collection::new(cblobs, total_blobs_size).unwrap();
            // encode collection and add it
            {
                let data = Bytes::from(postcard::to_stdvec(&collection).unwrap());
                let (outboard, hash) = bao_tree::io::outboard(&data, IROH_BLOCK_SIZE);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                map.insert(hash, DbEntry::Internal { outboard, data });
            }
            let db = Database::default();
            db.union_with(map);
            db
        })
    }

    proptest! {
        #[test]
        fn database_snapshot_roundtrip(db in db(10, 1024 * 64)) {
            let snapshot = db.snapshot();
            let db2 = Database::from_snapshot(snapshot).unwrap();
            prop_assert_eq!(db.to_inner(), db2.to_inner());
        }

        #[test]
        fn database_persistence_roundtrip(db in db(10, 1024 * 64)) {
            let dir = tempfile::tempdir().unwrap();
            let snapshot = db.snapshot();
            snapshot.persist(&dir).unwrap();
            let snapshot2 = Snapshot::load(&dir).unwrap();
            let db2 = Database::from_snapshot(snapshot2).unwrap();
            let db = db.to_inner();
            let db2 = db2.to_inner();
            prop_assert_eq!(db, db2);
        }
    }

    #[tokio::test]
    async fn test_create_collection() -> anyhow::Result<()> {
        let dir: PathBuf = testdir!();
        let mut expect_blobs = vec![];
        let hash = blake3::hash(&[]);
        let hash = Hash::from(hash);

        // DataSource::File
        let foo = dir.join("foo");
        tokio::fs::write(&foo, vec![]).await?;
        let foo = DataSource::new(foo);
        expect_blobs.push(Blob {
            name: "foo".to_string(),
            hash,
        });

        // DataSource::NamedFile
        let bar = dir.join("bar");
        tokio::fs::write(&bar, vec![]).await?;
        let bar = DataSource::with_name(bar, "bat".to_string());
        expect_blobs.push(Blob {
            name: "bat".to_string(),
            hash,
        });

        // DataSource::NamedFile, empty string name
        let baz = dir.join("baz");
        tokio::fs::write(&baz, vec![]).await?;
        let baz = DataSource::with_name(baz, "".to_string());
        expect_blobs.push(Blob {
            name: "".to_string(),
            hash,
        });

        let expect_collection = Collection::new(expect_blobs, 0).unwrap();

        let (db, hash) = create_collection(vec![foo, bar, baz]).await?;

        let collection = {
            let c = db.get(&hash).unwrap();
            if let DbEntry::Internal { data, .. } = c {
                Collection::from_bytes(&data)?
            } else {
                panic!("expected hash to correspond with a `Collection`, found `Blob` instead");
            }
        };

        assert_eq!(expect_collection, collection);

        Ok(())
    }
}
