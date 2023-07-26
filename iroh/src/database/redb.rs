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
use iroh_bytes::provider::{BaoDb, BaoMap, BaoMapEntry, BaoReadonlyDb, Purpose, Vfs};
use iroh_bytes::provider::{ValidateProgress, VfsId};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::File;
use rand::Rng;
use tokio::sync::mpsc;

/// File name inside `IROH_DATA_DIR` where paths to data are stored.
pub const FNAME_PATHS: &str = "paths.bin";

impl Vfs for Database {
    type Id = std::path::PathBuf;
    type ReadRaw = iroh_io::File;
    type WriteRaw = iroh_io::File;

    fn create_temp_pair(
        &self,
        hash: Hash,
        outboard: bool,
        _location_hint: Option<&[u8]>,
    ) -> BoxFuture<'_, io::Result<(Self::Id, Option<Self::Id>)>> {
        let mut lock = self.0.state.write().unwrap();
        let uuid = rand::thread_rng().gen::<[u8; 16]>();
        let data_path = self
            .0
            .options
            .partial_path
            .join(Purpose::PartialData(hash, uuid).to_string());
        let outboard_path = if outboard {
            Some(
                self.0
                    .options
                    .partial_path
                    .join(Purpose::PartialOutboard(hash, uuid).to_string()),
            )
        } else {
            None
        };
        // store the paths in the database. Note that this overwrites any existing entry.
        if let Some(outboard_path) = &outboard_path {
            lock.partial
                .insert(hash, (data_path.clone(), outboard_path.clone()));
        }
        tracing::info!("creating temp pair: {:?} {:?}", data_path, outboard_path);
        future::ready(Ok((data_path, outboard_path))).boxed()
    }

    fn move_temp_pair(
        &self,
        temp_data_id: Self::Id,
        temp_outboard_id: Option<Self::Id>,
        _location_hint: Option<&[u8]>,
    ) -> BoxFuture<'_, io::Result<(Self::Id, Option<Self::Id>)>> {
        async move {
            let dir = &self.0.options.complete_path;
            let data_purpose = Purpose::from_path(&temp_data_id).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid temp file name")
            })?;
            let Purpose::PartialData(data_hash, data_uuid) = data_purpose else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid temp file name",
                ));
            };
            let outboard_id = if let Some(temp_outboard_id) = &temp_outboard_id {
                let outboard_purpose = Purpose::from_path(temp_outboard_id).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid temp file name")
                })?;
                let Purpose::PartialData(outboard_hash, outboard_uuid) = outboard_purpose else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid temp file name",
                    ));
                };
                if data_hash != outboard_hash || data_uuid != outboard_uuid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid temp file pair",
                    ));
                }
                Some(dir.join(Purpose::Outboard(data_hash).to_string()))
            } else {
                None
            };
            let data_id = dir.join(Purpose::Data(data_hash).to_string());
            tokio::fs::rename(temp_data_id, &data_id).await?;
            if let (Some(temp_outboard_id), Some(outboard_id)) = (temp_outboard_id, &outboard_id) {
                tokio::fs::rename(temp_outboard_id, &outboard_id).await?;
            };
            Ok((data_id, outboard_id))
        }
        .boxed()
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
struct State {
    complete: BTreeMap<Hash, CompleteEntry>,
    partial: BTreeMap<Hash, (PathBuf, PathBuf)>,
}

#[derive(Debug, Default)]
struct CompleteEntry {
    // true means we own the data, false means it is stored externally
    owned_data: bool,
    // external storage locations
    external: Vec<PathBuf>,
    // outboard data, in memory
    outboard: Option<Bytes>,
    // data, in memory
    data: Option<Bytes>,
    // size of the data
    size: u64,
}

#[derive(Debug)]
struct Options {
    complete_path: PathBuf,
    partial_path: PathBuf,
    move_threshold: u64,
    inline_threshold: u64,
}

#[derive(Debug)]
struct Inner {
    options: Options,
    state: RwLock<State>,
}

/// Database containing content-addressed data (blobs or collections).
#[derive(Debug, Clone)]
pub struct Database(Arc<Inner>);
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
        let state = self.0.state.read().unwrap();
        let entry = state.complete.get(hash)?;
        let outboard = entry.outboard.as_ref()?.clone();
        Some(DbPair {
            hash: blake3::Hash::from(*hash),
            entry: DbEntry {
                data: if let Some(data) = entry.data.as_ref() {
                    Either::Left(data.clone())
                } else {
                    let path = if entry.owned_data {
                        let name = Purpose::Data(*hash).to_string();
                        self.0.options.complete_path.join(name)
                    } else {
                        entry.external.get(0)?.clone()
                    };
                    Either::Right((path, entry.size))
                },
                outboard,
            },
        })
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let inner = self.0.state.read().unwrap();
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
    type Vfs = Self;

    fn vfs(&self) -> &Self::Vfs {
        &self
    }

    fn insert_entry(
        &self,
        hash: Hash,
        data_id: PathBuf,
        outboard_id: Option<PathBuf>,
    ) -> BoxFuture<'_, io::Result<()>> {
        let db = self.clone();
        async move {
            // remove incomplete
            // from here on, if something fails we lost the incomplete entry
            db.0.state.write().unwrap().partial.remove(&hash);
            let size = std::fs::metadata(&data_id)?.len();
            let outboard = Some(Bytes::from(if let Some(outboard_id) = outboard_id {
                tokio::fs::read(outboard_id).await?
            } else {
                size.to_be_bytes().to_vec()
            }));
            let data = if size < self.0.options.inline_threshold {
                Some(Bytes::from(tokio::fs::read(data_id).await?))
            } else {
                None
            };
            let mut inner: std::sync::RwLockWriteGuard<'_, State> = db.0.state.write().unwrap();
            let entry = inner.complete.entry(hash).or_default();
            entry.data = data;
            entry.outboard = outboard;
            entry.owned_data = true;
            entry.size = size;
            Ok(())
        }
        .boxed()
    }

    fn get_partial_entry(
        &self,
        hash: &Hash,
    ) -> BoxFuture<'_, io::Result<Option<(VfsId<Self>, VfsId<Self>)>>> {
        let lock = self.0.state.read().unwrap();
        futures::future::ok(
            if let Some((data_path, outboard_path)) = lock.partial.get(hash) {
                Some((data_path.clone(), outboard_path.clone()))
            } else {
                None
            },
        )
        .boxed()
    }

    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let lock = self.0.state.read().unwrap();
        let res = lock
            .partial
            .iter()
            .map(|(hash, _)| *hash)
            .collect::<Vec<_>>();
        Box::new(res.into_iter())
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        stable: bool,
        _progress: impl Fn(u64),
    ) -> BoxFuture<'_, io::Result<()>> {
        self.clone().export_blob(hash, target, stable).boxed()
    }

    fn import_bytes<'a>(&'a self, data: &'a [u8]) -> BoxFuture<'a, io::Result<Hash>> {
        let (outboard, hash) = bao_tree::io::outboard(data, IROH_BLOCK_SIZE);
        let hash = hash.into();
        async move {
            let data_path = self
                .0
                .options
                .complete_path
                .join(Purpose::Data(hash).to_string());
            tokio::fs::write(data_path, data).await?;
            if outboard.len() > 8 {
                let outboard_path = self
                    .0
                    .options
                    .complete_path
                    .join(Purpose::Outboard(hash).to_string());
                tokio::fs::write(outboard_path, &outboard).await?;
            }
            let mut state = self.0.state.write().unwrap();
            let entry = state.complete.entry(hash).or_default();
            let size = data.len() as u64;
            entry.owned_data = true;
            entry.outboard = Some(outboard.into());
            entry.data = if size < self.0.options.inline_threshold {
                Some(data.to_vec().into())
            } else {
                None
            };
            entry.size = size;
            Ok(hash)
        }
        .boxed()
    }
}

impl Database {
    async fn export_blob(self, hash: Hash, target: PathBuf, stable: bool) -> io::Result<()> {
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
        let (source, size) = {
            let state = self.0.state.read().unwrap();
            let entry = state.complete.get(&hash).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "hash not found in database")
            })?;
            let source = if entry.owned_data {
                let name = Purpose::Data(hash).to_string();
                self.0.options.complete_path.join(name)
            } else {
                entry
                    .external
                    .get(0)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "hash not found in database")
                    })?
                    .clone()
            };
            let size = entry.size;
            drop(state);
            (source, size)
        };
        // copy all the things
        if size > self.0.options.move_threshold && stable {
            tokio::fs::rename(source, &target).await?;
            let mut state = self.0.state.write().unwrap();
            let Some(entry) = state.complete.get_mut(&hash) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "hash not found in database",
                ));
            };
            entry.owned_data = false;
            entry.external.retain(|x| x != &target);
            entry.external.insert(0, target);
        } else {
            // todo: progress
            tokio::fs::copy(source, &target).await?;
            let mut state = self.0.state.write().unwrap();
            let Some(entry) = state.complete.get_mut(&hash) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "hash not found in database",
                ));
            };
            entry.external.retain(|x| x != &target);
            entry.external.insert(0, target.to_owned());
        }
        Ok(())
    }

    /// scan a directory for data
    pub(crate) fn load_internal(
        complete_path: PathBuf,
        partial_path: PathBuf,
    ) -> anyhow::Result<Self> {
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
                            // silently ignore other files, there could be a valid reason for them
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
                            // silently ignore other files, there could be a valid reason for them
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
                CompleteEntry {
                    outboard: Some(outboard),
                    data: data_bytes,
                    owned_data: true,
                    external: vec![],
                    size,
                },
            );
        }
        let mut partial = BTreeMap::new();
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
                    partial.insert(hash, (data, outboard));
                }
            }
        }
        for hash in complete.keys() {
            tracing::info!("complete {}", hash);
            partial.remove(hash);
        }
        for hash in partial.keys() {
            tracing::info!("partial {}", hash);
        }
        Ok(Self(Arc::new(Inner {
            state: RwLock::new(State { complete, partial }),
            options: Options {
                complete_path,
                partial_path,
                move_threshold: 1024 * 128,
                inline_threshold: 1024 * 16,
            },
        })))
    }

    /// Load a database from disk.
    pub async fn load(
        complete_path: impl AsRef<Path>,
        partial_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let complete_path = complete_path.as_ref().to_path_buf();
        let partial_path = partial_path.as_ref().to_path_buf();
        let db =
            tokio::task::spawn_blocking(move || Self::load_internal(complete_path, partial_path))
                .await??;
        Ok(db)
    }
}
