use super::BlobOrCollection;
use crate::{
    rpc_protocol::ValidateProgress,
    util::{validate_bao, BaoValidationError},
    Hash,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt, io,
    path::{Path, PathBuf},
    result,
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;

/// Data for a (possibly very large) blob
///
/// This can be used for both outboards and content. Be careful, this could
/// point to a file that is a terabyte in size. So loading it into memory
/// could be a problem.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
enum BlobData {
    /// Data is stored inline in the db and exists in memory.
    Inline(Bytes),
    /// Data is stored in a file can be optionally cached in memory.
    File {
        /// Path to the file. We assume that this file does not change.
        ///
        /// None means the file is in the default location.
        custom_path: Option<PathBuf>,
        /// Possibly cached file data in memory.
        cached: Option<Bytes>,
    },
}

impl BlobData {
    fn path(&self) -> Option<Option<&PathBuf>> {
        match self {
            Self::Inline(_) => None,
            Self::File { custom_path, .. } => Some(custom_path.as_ref()),
        }
    }
}

/// Data for a (possibly very large) mutable blob
#[derive(Debug, Serialize, Deserialize)]
enum MutableBlobData {
    Inline(Vec<u8>),
    File(PathBuf),
}

impl MutableBlobData {
    fn exists(&self) -> bool {
        match self {
            Self::Inline(_) => true,
            Self::File(path) => path.exists(),
        }
    }
}

enum DataReader {
    Memory(std::io::Cursor<Bytes>),
    File(std::fs::File),
}

impl std::io::Read for DataReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Memory(data) => data.read(buf),
            Self::File(file) => file.read(buf),
        }
    }
}

impl std::io::Seek for DataReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> io::Result<u64> {
        match self {
            Self::Memory(data) => data.seek(pos),
            Self::File(file) => file.seek(pos),
        }
    }
}

enum DataWriter<'a> {
    Memory(std::io::Cursor<&'a mut Vec<u8>>),
    File(std::fs::File),
}

impl<'a> std::io::Read for DataWriter<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Memory(data) => data.read(buf),
            Self::File(file) => file.read(buf),
        }
    }
}

impl<'a> std::io::Write for DataWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Memory(data) => data.write(buf),
            Self::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Memory(data) => Ok(()),
            Self::File(file) => file.flush(),
        }
    }
}

impl<'a> std::io::Seek for DataWriter<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> io::Result<u64> {
        match self {
            Self::Memory(data) => data.seek(pos),
            Self::File(file) => file.seek(pos),
        }
    }
}

impl BlobData {
    fn new_inline(data: Bytes) -> Self {
        Self::Inline(data)
    }

    fn new_from_path(custom_path: Option<PathBuf>) -> Self {
        Self::File {
            custom_path,
            cached: None,
        }
    }

    fn reader(&self, default_path: impl Fn() -> PathBuf) -> io::Result<DataReader> {
        Ok(match self {
            Self::Inline(data) => DataReader::Memory(std::io::Cursor::new(data.clone())),
            Self::File {
                custom_path,
                cached,
                ..
            } => {
                if let Some(cached) = cached {
                    DataReader::Memory(std::io::Cursor::new(cached.clone()))
                } else {
                    DataReader::File(match custom_path {
                        Some(path) => std::fs::File::open(path)?,
                        None => std::fs::File::open(default_path())?,
                    })
                }
            }
        })
    }

    fn cached_memory_reader(
        &mut self,
        default_path: impl Fn() -> PathBuf,
    ) -> io::Result<DataReader> {
        Ok(match self {
            Self::Inline(data) => DataReader::Memory(std::io::Cursor::new(data.clone())),
            Self::File {
                cached: Some(cached),
                ..
            } => DataReader::Memory(std::io::Cursor::new(cached.clone())),
            Self::File {
                custom_path,
                cached,
                ..
            } => {
                let data = if let Some(path) = custom_path {
                    std::fs::read(path)?
                } else {
                    std::fs::read(default_path())?
                };
                let bytes = Bytes::from(data);
                *cached = Some(bytes.clone());
                DataReader::Memory(std::io::Cursor::new(bytes))
            }
        })
    }

    fn exists(&self, default_path: impl Fn() -> PathBuf) -> bool {
        match self {
            Self::Inline(_) => true,
            Self::File {
                custom_path: Some(path),
                ..
            } => path.exists(),
            Self::File {
                custom_path: None, ..
            } => default_path().exists(),
        }
    }
}

impl MutableBlobData {
    fn new_inline(data: Vec<u8>) -> Self {
        Self::Inline(data)
    }

    fn new_from_file(path: PathBuf) -> io::Result<Self> {
        Ok(Self::File(path))
    }

    fn open(&mut self) -> io::Result<DataWriter> {
        Ok(match self {
            Self::Inline(data) => DataWriter::Memory(std::io::Cursor::new(data)),
            Self::File(path) => {
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .open(path)?;
                DataWriter::File(file)
            }
        })
    }
}

/// A bao file consists of outboard and content.
///
/// Either of them can stored inline or in a file in the file system.
///
/// Under some circumstances, we can have multiple content files. We will
/// however not keep track of multiple outboard files.
#[derive(Debug, Serialize, Deserialize)]
struct BaoFile {
    outboard: BlobData,
    content: Vec<BlobData>,
}

/// An incomplete bao file consists of outboard and content.
///
/// They are related to each other.
#[derive(Debug, Serialize, Deserialize)]
struct IncompleteBaoFile {
    outboard: MutableBlobData,
    content: MutableBlobData,
}

/// The data we retain for each hash
#[derive(Debug, Default, Serialize, Deserialize)]
struct HashData {
    /// complete files (usually just 1)
    complete: Option<BaoFile>,
    /// a list of incomplete files
    incomplete: Vec<IncompleteBaoFile>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ValidateMode {
    None,
    Exists,
}

struct DatabaseInner {
    hashes: BTreeMap<Hash, HashData>,
    data_dir: PathBuf,
}

impl DatabaseInner {
    fn save(&self, data_dir: impl AsRef<Path>) -> io::Result<()> {
        let data_dir = data_dir.as_ref();
        let db_file = data_dir.join("db.bin");
        let db_file_tmp = data_dir.join("db.bin.tmp");
        let db = postcard::to_stdvec(&self.hashes)
            .map_err(|cause| io::Error::new(io::ErrorKind::Other, cause))?;
        std::fs::write(&db_file_tmp, db)?;
        std::fs::rename(&db_file_tmp, &db_file)?;
        Ok(())
    }

    fn load(data_dir: PathBuf, validate: ValidateMode) -> io::Result<Self> {
        let complete_dir = data_dir.join("data");
        let db_file = data_dir.join("db.bin");
        let db_bytes = std::fs::read(db_file)?;
        let mut hashes =
            postcard::from_bytes::<BTreeMap<Hash, HashData>>(&db_bytes).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to deserialize database: {}", e),
                )
            })?;
        let mut errors = Vec::new();
        let mut add_error = |hash: Hash, cause: String| {
            tracing::error!("error for {}: {}", hash, cause);
            errors.push((hash, cause));
        };
        // only keep hashes for which we have either complete or incomplete data
        hashes.retain(|hash, hash_data| {
            let content_name = || complete_dir.join(format!("{}.data", hex::encode(hash)));
            let outboard_name = || complete_dir.join(format!("{}.obao", hex::encode(hash)));
            hash_data.incomplete.retain_mut(|x| {
                let data_exists = x.content.exists();
                let outboard_exists = x.outboard.exists();
                if !data_exists {
                    add_error(*hash, format!("incomplete data {:?} is missing", x.content));
                }
                if !outboard_exists {
                    add_error(
                        *hash,
                        format!("incomplete outboard {:?} is missing", x.outboard),
                    );
                }
                data_exists && outboard_exists
            });
            if let Some(mut complete) = hash_data.complete.take() {
                complete.content.retain_mut(|content| {
                    let exists = content.exists(content_name);
                    if !exists {
                        add_error(*hash, format!("complete data {:?} is missing", content));
                    }
                    exists
                });
                let outboard_exists = complete.outboard.exists(outboard_name);
                if !outboard_exists {
                    add_error(
                        *hash,
                        format!("complete outboard {:?} is missing", complete.outboard),
                    );
                }
                if outboard_exists && !complete.content.is_empty() {
                    hash_data.complete = Some(complete);
                } else {
                    add_error(*hash, "lacking complete data".to_string());
                }
            }
            let retain = hash_data.complete.is_some() || !hash_data.incomplete.is_empty();
            if !retain {
                add_error(*hash, "lacking any data".to_string());
            }
            retain
        });
        if !errors.is_empty() && validate >= ValidateMode::Exists {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} errors", errors.len()),
            ));
        }
        Ok(Self { hashes, data_dir })
    }

    fn get_complete(&mut self, hash: Hash) -> io::Result<Option<(DataReader, DataReader)>> {
        let content_name = || {
            self.data_dir
                .join("data")
                .join(format!("{}.data", hex::encode(hash)))
        };
        let outboard_name = || {
            self.data_dir
                .join("data")
                .join(format!("{}.obao", hex::encode(hash)))
        };
        // do we have something for the hash
        let data = match self.hashes.get_mut(&hash) {
            Some(data) => data,
            None => return Ok(None),
        };
        // do we have a complete file
        let complete = match data.complete {
            Some(ref mut complete) => complete,
            None => return Ok(None),
        };
        // do we have any content (we should have at least one)
        let content = match complete.content.get(0) {
            Some(content) => content,
            None => return Ok(None),
        };
        // grab the outboard and cache it
        let outboard = complete.outboard.cached_memory_reader(outboard_name)?;
        // grab the content and do not! cache it
        let content = content.reader(content_name)?;
        Ok(Some((outboard, content)))
    }

    /// Insert a complete file (outboard and content)
    fn insert_complete(&mut self, hash: Hash, outboard: BlobData, content: BlobData) {
        let data = self.hashes.entry(hash).or_default();
        let complete = data.complete.get_or_insert_with(|| BaoFile {
            outboard,
            content: Vec::with_capacity(1),
        });
        // do not add the same path twice
        // do not add the default path twice
        // do not add inline twice
        if !complete.content.iter().any(|x| x.path() == content.path()) {
            // if we have to add, canonicalize the order
            complete.content.push(content);
            complete.content.sort();
        }
    }
}

pub struct Database2(Arc<RwLock<DatabaseInner>>);

/// Database containing content-addressed data (blobs or collections).
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<RwLock<HashMap<Hash, BlobOrCollection>>>);

impl From<HashMap<Hash, BlobOrCollection>> for Database {
    fn from(map: HashMap<Hash, BlobOrCollection>) -> Self {
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
            outboards_dir: data_dir.join("outboards"),
            collections_dir: data_dir.join("collections"),
            paths_file: data_dir.join("paths.bin"),
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
fn parse_hash(hash: &str) -> Result<Hash> {
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
        let paths = fs::read(paths_file)?;
        let paths = postcard::from_bytes::<Vec<(Hash, u64, Option<PathBuf>)>>(&paths)?;
        let hashes = paths
            .iter()
            .map(|(hash, _, _)| *hash)
            .collect::<BTreeSet<_>>();
        let outboards = hashes.clone().into_iter().map(move |hash| {
            let path = outboards_dir.join(format_hash(&hash));
            fs::read(path).map(|x| (hash, Bytes::from(x)))
        });
        let collections = fs::read_dir(collections_dir)?
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
    #[cfg(feature = "cli")]
    pub fn load_test(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        Self::load_internal(dir)
    }

    /// Save a database to disk for testing. Synchronous.
    #[cfg(feature = "cli")]
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
    pub(crate) fn from_snapshot<E: Into<io::Error>>(snapshot: Snapshot<E>) -> io::Result<Self> {
        let Snapshot {
            outboards,
            collections,
            paths,
        } = snapshot;
        let outboards = outboards
            .collect::<result::Result<HashMap<_, _>, E>>()
            .map_err(Into::into)?;
        let collections = collections
            .collect::<result::Result<HashMap<_, _>, E>>()
            .map_err(Into::into)?;
        let mut db = HashMap::new();
        for (hash, size, path) in paths {
            if let (Some(path), Some(outboard)) = (path, outboards.get(&hash)) {
                db.insert(
                    hash,
                    BlobOrCollection::Blob {
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
                    BlobOrCollection::Collection {
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
    pub(crate) async fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> anyhow::Result<()> {
        // This makes a copy of the db, but since the outboards are Bytes, it's not expensive.
        let mut data = self
            .0
            .read()
            .unwrap()
            .clone()
            .into_iter()
            .collect::<Vec<_>>();
        data.sort_by_key(|(k, e)| (e.is_blob(), e.blob_path().map(ToOwned::to_owned), *k));
        tx.send(ValidateProgress::Starting {
            total: data.len() as u64,
        })
        .await?;
        futures::stream::iter(data)
            .enumerate()
            .map(|(id, (hash, boc))| {
                let id = id as u64;
                let path = if let BlobOrCollection::Blob { path, .. } = &boc {
                    Some(path.clone())
                } else {
                    None
                };
                let size = boc.size();
                let entry_tx = tx.clone();
                let done_tx = tx.clone();
                async move {
                    entry_tx
                        .send(ValidateProgress::Entry {
                            id,
                            hash,
                            path: path.clone(),
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
                            BlobOrCollection::Blob { outboard, path, .. } => {
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
                            BlobOrCollection::Collection { outboard, data } => {
                                let data = std::io::Cursor::new(data);
                                validate_bao(hash, data, outboard, progress)
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
                BlobOrCollection::Blob { outboard, .. } => (*k, outboard.clone()),
                BlobOrCollection::Collection { outboard, .. } => (*k, outboard.clone()),
            })
            .collect::<Vec<_>>();

        let collections = this
            .iter()
            .filter_map(|(k, v)| match v {
                BlobOrCollection::Blob { .. } => None,
                BlobOrCollection::Collection { data, .. } => Some((*k, data.clone())),
            })
            .collect::<Vec<_>>();

        let paths = this
            .iter()
            .map(|(k, v)| match v {
                BlobOrCollection::Blob { path, size, .. } => (*k, *size, Some(path.clone())),
                BlobOrCollection::Collection { data, .. } => (*k, data.len() as u64, None),
            })
            .collect::<Vec<_>>();

        Snapshot {
            outboards: Box::new(outboards.into_iter().map(Ok)),
            collections: Box::new(collections.into_iter().map(Ok)),
            paths: Box::new(paths.into_iter()),
        }
    }

    pub(crate) fn get(&self, key: &Hash) -> Option<BlobOrCollection> {
        self.0.read().unwrap().get(key).cloned()
    }

    pub(crate) fn union_with(&self, db: HashMap<Hash, BlobOrCollection>) {
        let mut inner = self.0.write().unwrap();
        for (k, v) in db {
            inner.entry(k).or_insert(v);
        }
    }

    /// Iterate over all blobs in the database.
    pub fn blobs(&self) -> impl Iterator<Item = (Hash, PathBuf, u64)> + 'static {
        let items = self
            .0
            .read()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| match v {
                BlobOrCollection::Blob { path, size, .. } => Some((*k, path.clone(), *size)),
                BlobOrCollection::Collection { .. } => None,
            })
            .collect::<Vec<_>>();
        // todo: make this a proper lazy iterator at some point
        // e.g. by using an immutable map or a real database that supports snapshots.
        items.into_iter()
    }

    #[cfg(test)]
    pub(crate) fn to_inner(&self) -> HashMap<Hash, BlobOrCollection> {
        self.0.read().unwrap().clone()
    }
}
