//! The concrete database used by the iroh binary.
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bao_tree::io::outboard::PreOrderMemOutboard;
use bytes::Bytes;
use futures::future::Either;
use futures::future::{self, BoxFuture};
use futures::{Future, FutureExt};
use iroh_bytes::provider::ValidateProgress;
use iroh_bytes::provider::{BaoDb, BaoMap, BaoMapEntry, BaoReadonlyDb, LocalFs, Purpose, Vfs};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::File;
use rand::Rng;
use tokio::sync::mpsc;

/// File name inside `IROH_DATA_DIR` where paths to data are stored.
pub const FNAME_PATHS: &str = "paths.bin";

///
#[derive(Debug, Clone)]
pub struct RedbFs(Arc<RwLock<DatabaseInner>>);

impl Vfs for RedbFs {
    type Id = std::path::PathBuf;
    type ReadRaw = iroh_io::File;
    type WriteRaw = iroh_io::File;

    fn create_temp_pair(
        &self,
        hash: Hash,
        outboard: bool,
    ) -> BoxFuture<'_, io::Result<(Self::Id, Option<Self::Id>)>> {
        let mut lock = self.0.write().unwrap();
        let uuid = rand::thread_rng().gen::<[u8; 16]>();
        let data_path = lock
            .partial_path
            .join(Purpose::PartialData(hash, uuid).to_string());
        let outboard_path = if outboard {
            Some(
                lock.partial_path
                    .join(Purpose::PartialOutboard(hash, uuid).to_string()),
            )
        } else {
            None
        };
        // store the paths in the database. Note that this overwrites any existing entry.
        if let Some(outboard_path) = &outboard_path {
            lock.incomplete
                .insert(hash, (data_path.clone(), outboard_path.clone()));
        }
        future::ready(Ok((data_path, outboard_path))).boxed()
    }

    fn open_read(&self, handle: &Self::Id) -> BoxFuture<'_, io::Result<Self::ReadRaw>> {
        let handle = handle.clone();
        iroh_io::File::create(move || std::fs::File::open(handle.as_path())).boxed()
    }

    fn open_write(&self, handle: &std::path::PathBuf) -> BoxFuture<'_, io::Result<Self::WriteRaw>> {
        let handle = handle.clone();
        iroh_io::File::create(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(handle.as_path())
        })
        .boxed()
    }

    fn delete(&self, handle: &Self::Id) -> BoxFuture<'_, io::Result<()>> {
        let handle = handle.clone();
        tokio::fs::remove_file(handle).boxed()
    }
}

#[derive(Debug, Default)]
struct DatabaseInner {
    complete_path: PathBuf,
    partial_path: PathBuf,
    complete: BTreeMap<Hash, DbEntry>,
    incomplete: BTreeMap<Hash, (PathBuf, PathBuf)>,
}

/// Database containing content-addressed data (blobs or collections).
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<RwLock<DatabaseInner>>);
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
        let bytes = self.entry.outboard.clone();
        let hash = self.hash;
        future::ready(PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, bytes)).boxed()
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
#[derive(Debug, Clone)]
pub struct DbEntry {
    /// The bao outboard data.
    outboard: Bytes,
    /// The
    data: Either<Bytes, (PathBuf, u64)>,
}

impl DbEntry {
    /// Get the outboard data for this entry, as a `Bytes`.
    pub fn outboard_reader(&self) -> impl Future<Output = io::Result<Bytes>> + 'static {
        futures::future::ok(self.outboard.clone())
    }

    /// A reader for the data.
    pub fn data_reader(&self) -> impl Future<Output = io::Result<Either<Bytes, File>>> + 'static {
        let this = self.clone();
        async move {
            Ok(match &this.data {
                Either::Left(mem) => Either::Left(mem.clone()),
                Either::Right((path, _)) => Either::Right(File::open(path.clone()).await?),
            })
        }
    }

    /// Returns the size of the blob
    pub async fn size(&self) -> u64 {
        match &self.data {
            Either::Left(mem) => mem.len() as u64,
            Either::Right((_, size)) => *size,
        }
    }
}

impl BaoMap for Database {
    type Entry = DbPair;
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Either<Bytes, File>;
    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let entry = self.0.read().unwrap().complete.get(hash)?.clone();
        Some(DbPair {
            hash: blake3::Hash::from(*hash),
            entry,
        })
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let inner = self.0.read().unwrap();
        let items = inner
            .complete
            .iter()
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        unimplemented!()
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        unimplemented!()
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
        temp_data_path: PathBuf,
        temp_outboard_path: Option<PathBuf>,
    ) -> BoxFuture<'_, io::Result<()>> {
        let db = self.clone();
        tokio::task::spawn_blocking(move || {
            // remove incomplete
            // from here on, if something fails we lost the incomplete entry
            db.0.write().unwrap().incomplete.remove(&hash);
            // first rename the file - this is atomic
            let data_path =
                db.0.read()
                    .unwrap()
                    .complete_path
                    .join(Purpose::Data(hash).to_string());
            std::fs::rename(temp_data_path, &data_path)?;
            // then rename the outboard file
            let outboard_path = if let Some(temp_outboard_path) = temp_outboard_path {
                let outboard_path =
                    db.0.read()
                        .unwrap()
                        .complete_path
                        .join(Purpose::Outboard(hash).to_string());
                std::fs::rename(&temp_outboard_path, &outboard_path)?;
                Some(outboard_path)
            } else {
                None
            };
            let data_size = std::fs::metadata(&data_path)?.len();
            let outboard = Bytes::from(if let Some(outboard_path) = outboard_path {
                std::fs::read(outboard_path)?
            } else {
                data_size.to_be_bytes().to_vec()
            });
            let mut inner = db.0.write().unwrap();
            let entry = DbEntry {
                outboard,
                data: Either::Right((data_path, data_size)),
            };
            inner.complete.insert(hash, entry);
            Ok(())
        })
        .map(make_io_error)
        .boxed()
    }

    fn get_partial_entry(
        &self,
        hash: &Hash,
    ) -> BoxFuture<
        '_,
        io::Result<
            Option<(
                iroh_bytes::provider::VfsId<Self>,
                iroh_bytes::provider::VfsId<Self>,
            )>,
        >,
    > {
        let lock = self.0.read().unwrap();
        futures::future::ok(
            if let Some((data_path, outboard_path)) = lock.incomplete.get(hash) {
                Some((data_path.clone(), outboard_path.clone()))
            } else {
                None
            },
        )
        .boxed()
    }

    fn partial_blobs(
        &self,
    ) -> Box<dyn Iterator<Item = (Hash, iroh_bytes::provider::VfsId<Self>)> + Send + Sync + 'static>
    {
        let lock = self.0.read().unwrap();
        let res = lock
            .incomplete
            .iter()
            .map(|(hash, (data_path, _))| (*hash, data_path.clone()))
            .collect::<Vec<_>>();
        Box::new(res.into_iter())
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

impl Database {
    /// scan a directory for data
    pub fn load_internal(complete_path: PathBuf, partial_path: PathBuf) -> anyhow::Result<Self> {
        let mut partial_index =
            BTreeMap::<Hash, BTreeMap<[u8; 16], (Option<PathBuf>, Option<PathBuf>)>>::new();
        let mut full_index = BTreeMap::<Hash, (Option<PathBuf>, Option<PathBuf>)>::new();
        for entry in std::fs::read_dir(&partial_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let Some(name) = path.file_name() else {
                    tracing::warn!("skipping unexpected partial file: {:?}", path);
                    continue;
                };
                let Some(name) = name.to_str() else {
                    tracing::warn!("skipping unexpected partial file: {:?}", path);
                    continue;
                };
                if let Ok(purpose) = Purpose::from_str(name) {
                    match purpose {
                        Purpose::PartialData(hash, uuid) => {
                            let m = partial_index.entry(hash).or_default();
                            let (data, _) = m.entry(uuid).or_default();
                            *data = Some(path);
                        }
                        Purpose::PartialOutboard(hash, uuid) => {
                            let m = partial_index.entry(hash).or_default();
                            let (_, outboard) = m.entry(uuid).or_default();
                            *outboard = Some(path);
                        }
                        _ => {
                            tracing::warn!("skipping unexpected partial file: {:?}", path);
                        }
                    }
                }
            }
        }

        for entry in std::fs::read_dir(&complete_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let Some(name) = path.file_name() else {
                    tracing::warn!("skipping unexpected complete file: {:?}", path);
                    continue;
                };
                let Some(name) = name.to_str() else {
                    tracing::warn!("skipping unexpected complete file: {:?}", path);
                    continue;
                };
                if let Ok(purpose) = Purpose::from_str(name) {
                    match purpose {
                        Purpose::Data(hash) => {
                            let (data, _outboard) = full_index.entry(hash).or_default();
                            *data = Some(path);
                        }
                        Purpose::Outboard(hash) => {
                            let (_data, outboard) = full_index.entry(hash).or_default();
                            *outboard = Some(path);
                        }
                        _ => {
                            tracing::warn!("skipping unexpected complete file: {:?}", path);
                        }
                    }
                }
            }
        }
        // retain only entries for which we have both outboard and data
        partial_index.retain(|hash, entries| {
            entries.retain(|uuid, (data, outboard)| {
                if !data.is_some() {
                    tracing::warn!(
                        "missing partial data file for {} {}",
                        hex::encode(hash),
                        hex::encode(uuid)
                    );
                    return false;
                }
                if !outboard.is_some() {
                    tracing::warn!(
                        "missing partial outboard file for {} {}",
                        hex::encode(hash),
                        hex::encode(uuid)
                    );
                    return false;
                }
                true
            });
            !entries.is_empty()
        });
        let mut complete = BTreeMap::new();
        for (hash, (data_path, outboard_path)) in full_index {
            let Some(data_path) = data_path else {
                tracing::error!("missing data file for {}", hex::encode(hash));
                continue;
            };
            let Ok(metadata) = std::fs::metadata(&data_path) else {
                tracing::error!("unable to open path {}", data_path.display());
                continue;
            };
            let size = metadata.len();
            if outboard_path.is_none() && size > IROH_BLOCK_SIZE.bytes() as u64 {
                tracing::error!("missing outboard file for {}", hex::encode(hash));
                continue;
            }
            // only store data in mem if it is small
            let data_bytes = if size <= IROH_BLOCK_SIZE.bytes() as u64 {
                Some(Bytes::from(std::fs::read(&data_path)?))
            } else {
                None
            };
            // always store the outboard bytes in memory
            let outboard = Bytes::from(if let Some(outboard) = outboard_path {
                std::fs::read(outboard)?
            } else {
                size.to_be_bytes().to_vec().into()
            });
            complete.insert(
                hash,
                DbEntry {
                    outboard,
                    data: if let Some(data_bytes) = data_bytes {
                        Either::Left(data_bytes)
                    } else {
                        Either::Right((data_path, size))
                    },
                },
            );
        }
        let mut incomplete = BTreeMap::new();
        for (hash, entries) in partial_index {
            let best = entries.into_iter().filter_map(|(_, (data_path, outboard_path))| {
                let data_path = data_path?;
                let outboard_path = outboard_path?;
                let Ok(data_meta) = std::fs::metadata(&data_path) else {
                    tracing::warn!("unable to open partial data file {}", data_path.display());
                    return None
                };
                let Ok(_outboard_meta) = std::fs::metadata(&outboard_path) else {
                    tracing::warn!("unable to open partial outboard file {}", outboard_path.display());
                    return None
                };
                let data_size = data_meta.len();
                Some((data_size, data_path, outboard_path))
            }).max_by_key(|x| x.0);
            if let Some((size, data, outboard)) = best {
                if size > 0 {
                    incomplete.insert(hash, (data, outboard));
                }
            }
        }
        Ok(Self(Arc::new(RwLock::new(DatabaseInner {
            complete_path,
            partial_path,
            complete,
            incomplete,
        }))))
    }

    /// Load a database from disk.
    pub async fn load(dir: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let db =
            tokio::task::spawn_blocking(move || Self::load_internal(dir.clone(), dir)).await??;
        Ok(db)
    }
}
