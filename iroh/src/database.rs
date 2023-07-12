//! The concrete database used by the iroh binary.
use std::path::{PathBuf, Path};
use std::sync::{Arc, RwLock};
use std::collections::{HashMap, BTreeSet};
use std::{io, result, fmt};
use anyhow::Context;
use bao_tree::io::outboard::PreOrderMemOutboard;
use bytes::Bytes;
use futures::{FutureExt, StreamExt};
use futures::future::BoxFuture;
use iroh_bytes::provider::{ValidateProgress, DbEntry, DataSource, collection};
use iroh_bytes::util::io::{validate_bao, BaoValidationError};
use iroh_bytes::util::progress::Progress;
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_bytes::provider::database::{BaoMapEntry, BaoMap, BaoReadonlyDb};
use iroh_io::File;
use tokio::sync::mpsc;
use futures::future::Either;

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

    fn validate(
        &self,
        tx: mpsc::Sender<ValidateProgress>,
    ) -> BoxFuture<'_, anyhow::Result<()>> {
        self.validate0(tx).boxed()
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
        let paths_content =
            postcard::to_stdvec(&paths).expect("failed to serialize paths file");
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

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_collection(data_sources: Vec<DataSource>) -> anyhow::Result<(Database, Hash)> {
    let (db, hash) = collection::create_collection(data_sources, Progress::none()).await?;
    Ok((Database::from(db), hash))
}

#[cfg(test)]
mod tests {
    use iroh_bytes::blobs::{Blob, Collection};
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::str::FromStr;
    use testdir::testdir;

    use crate::database::Snapshot;

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
