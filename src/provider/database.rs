use super::BlobOrCollection;
use crate::{
    rpc_protocol::ValidateProgress,
    util::{validate_bao, BaoValidationError},
    Hash,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::StreamExt;
use std::{
    collections::{BTreeSet, HashMap},
    fmt, io,
    path::{Path, PathBuf},
    result,
    sync::{Arc, RwLock},
};
use tokio::sync::mpsc;

/// File name of directory inside `IROH_DATA_DIR` where outboards are stored.
const FNAME_OUTBOARDS: &str = "outboards";

/// File name of directory inside `IROH_DATA_DIR` where collections are stored.
const FNAME_COLLECTIONS: &str = "collections";

/// File name inside `IROH_DATA_DIR` where paths to data are stored.
pub const FNAME_PATHS: &str = "paths.bin";

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
    pub(crate) fn from_snapshot<E: Into<io::Error>>(snapshot: Snapshot<E>) -> Result<Self> {
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

    /// Unwrap into the inner HashMap
    pub fn to_inner(&self) -> HashMap<Hash, BlobOrCollection> {
        self.0.read().unwrap().clone()
    }
}
