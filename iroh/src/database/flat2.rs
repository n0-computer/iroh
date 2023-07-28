//! The concrete database used by the iroh binary.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bao_tree::io::outboard::{PostOrderMemOutboard, PreOrderMemOutboard};
use bao_tree::ChunkNum;
use bytes::Bytes;
use futures::future::Either;
use futures::future::{self, BoxFuture};
use futures::{Future, FutureExt};
use iroh_bytes::provider::{
    BaoDb, BaoMap, BaoMapEntry, BaoReadonlyDb, ImportProgress, Purpose, Vfs,
};
use iroh_bytes::provider::{ValidateProgress, VfsId};
use iroh_bytes::util::progress::ProgressSender;
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::File;
use rand::Rng;
use range_collections::RangeSet2;
use tokio::sync::mpsc;
use tracing::trace_span;

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
    outboard: BTreeMap<Hash, Bytes>,
    data: BTreeMap<Hash, Bytes>,
    partial: BTreeMap<Hash, (PathBuf, PathBuf)>,
}

#[derive(Debug, Default)]
struct CompleteEntry {
    // size of the data
    size: u64,
    // true means we own the data, false means it is stored externally
    owned_data: bool,
    // external storage locations
    external: BTreeSet<PathBuf>,
}

impl CompleteEntry {
    fn external_path(&self) -> Option<&PathBuf> {
        self.external.iter().next()
    }

    fn external_to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(&self.external).unwrap()
    }

    // create a new complete entry with the given size
    //
    // the generated entry will have no data or outboard data yet
    fn new_default(size: u64) -> Self {
        Self {
            owned_data: true,
            external: Default::default(),
            size,
        }
    }

    /// create a new complete entry with the given size and path
    ///
    /// the generated entry will have no data or outboard data yet
    fn new_external(size: u64, path: PathBuf) -> Self {
        Self {
            owned_data: false,
            external: [path].into_iter().collect(),
            size,
        }
    }

    // /// load the cache parts
    // async fn load(size: u64, data_id: Option<PathBuf>, outboard_id: Option<PathBuf>) -> io::Result<Self> {
    //     let outboard = Some(if let Some(outboard_id) = outboard_id {
    //         Bytes::from(tokio::fs::read(outboard_id).await?)
    //     } else {
    //         size.to_le_bytes().to_vec().into()
    //     });
    //     let data = if let Some(data_id) = data_id {
    //         Some(Bytes::from(tokio::fs::read(data_id).await?))
    //     } else {
    //         None
    //     };
    //     Ok(Self {
    //         owned_data: false,
    //         external: Default::default(),
    //         size,
    //     })
    // }

    fn is_valid(&self) -> bool {
        !self.external.is_empty() || self.owned_data
    }

    fn union_with(&mut self, new: CompleteEntry) -> io::Result<()> {
        if self.size != 0 && self.size != new.size {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "size mismatch"));
        }
        self.size = new.size;
        self.owned_data |= new.owned_data;
        self.external.extend(new.external.into_iter());
        Ok(())
    }
}

#[derive(Debug)]
struct Options {
    complete_path: PathBuf,
    partial_path: PathBuf,
    move_threshold: u64,
    inline_threshold: u64,
}

impl Options {
    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path.join(Purpose::Data(*hash).to_string())
    }

    fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path
            .join(Purpose::Outboard(*hash).to_string())
    }

    fn paths_path(&self, hash: Hash) -> PathBuf {
        self.complete_path.join(Purpose::Paths(hash).to_string())
    }
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
    /// the hash is not part of the entry itself
    hash: blake3::Hash,
    entry: DbEntry,
}

impl BaoMapEntry<Database> for DbPair {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn size(&self) -> u64 {
        match &self.entry.data {
            Either::Left(bytes) => bytes.len() as u64,
            Either::Right((_, size)) => *size,
        }
    }

    fn available(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
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

fn needs_outboard(size: u64) -> bool {
    size > (IROH_BLOCK_SIZE.bytes() as u64)
}

impl BaoMap for Database {
    type Entry = DbPair;
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Either<Bytes, File>;
    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.0.state.read().unwrap();
        let entry = state.complete.get(hash)?;
        let outboard = state.load_outboard(entry.size, hash)?;
        // check if we have the data cached
        let data = state.data.get(hash).cloned();
        Some(DbPair {
            hash: blake3::Hash::from(*hash),
            entry: DbEntry {
                data: if let Some(data) = data {
                    Either::Left(data)
                } else {
                    // get the data path
                    let path = if entry.owned_data {
                        // use the path for the data in the default location
                        self.owned_data_path(hash)
                    } else {
                        // use the first external path. if we don't have any
                        // we don't have a valid entry
                        entry.external_path()?.clone()
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
        temp_data_id: PathBuf,
        temp_outboard_id: Option<PathBuf>,
    ) -> BoxFuture<'_, io::Result<()>> {
        async move {
            let res = self
                .insert_entry_inner(hash, temp_data_id, temp_outboard_id)
                .await;
            if let Err(err) = res.as_ref() {
                tracing::error!("insert entry failed: {}", err);
            }
            res
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
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.export0(hash, target, stable, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import(
        &self,
        path: PathBuf,
        stable: bool,
        progress: impl ProgressSender<Msg = ImportProgress>,
    ) -> BoxFuture<'_, io::Result<(Hash, u64)>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.import0(path, stable, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import_bytes(&self, data: Bytes) -> BoxFuture<'_, io::Result<Hash>> {
        async move {
            let (outboard, hash) = bao_tree::io::outboard(&data, IROH_BLOCK_SIZE);
            let hash = hash.into();
            let data_path = self.owned_data_path(&hash);
            std::fs::write(data_path, &data)?;
            if outboard.len() > 8 {
                let outboard_path = self.owned_outboard_path(&hash);
                std::fs::write(outboard_path, &outboard)?;
            }
            let size = data.len() as u64;
            let mut state = self.0.state.write().unwrap();
            let entry = state.complete.entry(hash).or_default();
            entry.union_with(CompleteEntry::new_default(size))?;
            state.outboard.insert(hash, outboard.into());
            if size < self.0.options.inline_threshold {
                state.data.insert(hash, data.to_vec().into());
            }
            Ok(hash)
        }
        .boxed()
    }
}

impl State {
    fn load_outboard(&self, size: u64, hash: &Hash) -> Option<Bytes> {
        if needs_outboard(size) {
            self.outboard.get(hash).cloned()
        } else {
            Some(Bytes::from(size.to_le_bytes().to_vec()))
        }
    }

    fn update_entry(
        &mut self,
        hash: Hash,
        new: CompleteEntry,
        options: &Options,
    ) -> io::Result<()> {
        let entry = self.complete.entry(hash).or_default();
        let n = entry.external.len();
        entry.union_with(new)?;
        if entry.external.len() != n {
            let path = options.paths_path(hash);
            std::fs::write(path, entry.external_to_bytes())?;
        }
        Ok(())
    }
}

impl Database {
    fn update_entry(&self, hash: Hash, new: CompleteEntry) -> io::Result<()> {
        self.0
            .state
            .write()
            .unwrap()
            .update_entry(hash, new, &self.0.options)
    }

    async fn insert_entry_inner(
        &self,
        hash: Hash,
        temp_data_id: PathBuf,
        temp_outboard_id: Option<PathBuf>,
    ) -> io::Result<()> {
        let db = self;
        tracing::info!(
            "inserting entry: {} {} {:?}",
            hash,
            temp_data_id.display(),
            temp_outboard_id.as_ref().map(|x| x.display())
        );
        let (data_id, outboard_id) = self
            .move_temp_pair(temp_data_id, temp_outboard_id, hash)
            .await?;
        tracing::info!(
            "moved to permanent location: {} {:?} {:?}",
            hash,
            data_id.display(),
            outboard_id.as_ref().map(|x| x.display())
        );
        // remove incomplete
        // from here on, if something fails we lost the incomplete entry
        {
            db.0.state.write().unwrap().partial.remove(&hash);
        }
        // create the entry
        let (needs_data, needs_outboard) = {
            let size = tokio::fs::metadata(&data_id).await?.len();
            tracing::info!("size: {}", size);
            let mut state = db.0.state.write().unwrap();
            let entry = state.complete.entry(hash).or_default();
            entry.union_with(CompleteEntry::new_default(size))?;
            tracing::debug!("{:?}", entry);
            let needs_data =
                size < db.0.options.inline_threshold && !state.data.contains_key(&hash);
            let needs_outboard =
                size > (IROH_BLOCK_SIZE.bytes() as u64) && !state.outboard.contains_key(&hash);
            (needs_data, needs_outboard)
        };
        // trigger outboard load
        if needs_outboard {
            tracing::info!("loading outboard");
            let path = self.owned_outboard_path(&hash);
            let db = db.clone();
            tokio::task::spawn_blocking(move || {
                let outboard = Bytes::from(std::fs::read(path)?);
                let mut state = db.0.state.write().unwrap();
                state.outboard.insert(hash, outboard);
                io::Result::Ok(())
            })
            .await
            .unwrap()?;
        }
        // trigger data load
        if needs_data {
            tracing::info!("loading data");
            let path = self.owned_data_path(&hash);
            let db = db.clone();
            tokio::task::spawn_blocking(move || {
                let data = Bytes::from(std::fs::read(path)?);
                let mut state = db.0.state.write().unwrap();
                state.data.insert(hash, data);
                io::Result::Ok(())
            });
        }
        tracing::info!("done: {}", hash);
        Ok(())
    }

    fn move_temp_pair(
        &self,
        temp_data_id: PathBuf,
        temp_outboard_id: Option<PathBuf>,
        hash: Hash,
    ) -> BoxFuture<'_, io::Result<(PathBuf, Option<PathBuf>)>> {
        async move {
            let data_purpose = Purpose::from_path(&temp_data_id).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid temp file name")
            })?;
            let Purpose::PartialData(data_hash, data_uuid) = data_purpose else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid temp file name",
                ));
            };
            if data_hash != hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid temp file name",
                ));
            }
            let outboard_id = if let Some(temp_outboard_id) = &temp_outboard_id {
                let outboard_purpose = Purpose::from_path(temp_outboard_id).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid temp file name")
                })?;
                let Purpose::PartialOutboard(outboard_hash, outboard_uuid) = outboard_purpose else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid temp outboard file name",
                    ));
                };
                if data_hash != outboard_hash || data_uuid != outboard_uuid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid temp file pair",
                    ));
                }
                Some(self.owned_outboard_path(&data_hash))
            } else {
                None
            };
            let data_id = self.owned_data_path(&data_hash);
            tokio::fs::rename(temp_data_id, &data_id).await?;
            if let (Some(temp_outboard_id), Some(outboard_id)) = (temp_outboard_id, &outboard_id) {
                tokio::fs::rename(temp_outboard_id, &outboard_id).await?;
            };
            Ok((data_id, outboard_id))
        }
        .boxed()
    }

    fn import0(
        self,
        path: PathBuf,
        stable: bool,
        progress: impl ProgressSender<Msg = ImportProgress>,
    ) -> io::Result<(Hash, u64)> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must be absolute",
            ));
        }
        if !path.is_file() && !path.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path is not a file or symlink",
            ));
        }
        let id = progress.new_id();
        progress.blocking_send(ImportProgress::Found {
            id,
            path: path.clone(),
            stable,
        })?;
        let (hash, entry) = if stable {
            // compute outboard and hash from the data in place, since we assume that it is stable
            let size = path.metadata()?.len();
            progress.blocking_send(ImportProgress::Size { id, size })?;
            let progress2 = progress.clone();
            let (hash, data) = compute_outboard(&path, size, move |offset| {
                Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
            })?;
            let outboard_path = self.owned_outboard_path(&hash);
            std::fs::write(outboard_path, data)?;
            progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
            (hash, CompleteEntry::new_external(size, path))
        } else {
            let uuid = rand::thread_rng().gen::<[u8; 16]>();
            let temp_data_path = self
                .0
                .options
                .partial_path
                .join(format!("{}.temp", hex::encode(uuid)));
            // copy the data, since it is not stable
            progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
            let size = std::fs::copy(&path, &temp_data_path)?;
            // report the size only after the copy is done
            progress.blocking_send(ImportProgress::Size { id, size })?;
            // compute outboard and hash from the temp file that we own
            let progress2 = progress.clone();
            let (hash, data) = compute_outboard(&temp_data_path, size, move |offset| {
                Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
            })?;
            progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
            let outboard_path = self.owned_outboard_path(&hash);
            std::fs::write(outboard_path, data)?;
            let data_path = self.owned_data_path(&hash);
            std::fs::rename(temp_data_path, data_path)?;
            (hash, CompleteEntry::new_default(size))
        };
        let size = entry.size;
        self.update_entry(hash, entry)?;
        Ok((hash, size))
    }

    fn export0(
        &self,
        hash: Hash,
        target: PathBuf,
        stable: bool,
        _progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        tracing::info!("exporting {} to {} ({})", hash, target.display(), stable);

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
        let (source, size, owned) = {
            let state = self.0.state.read().unwrap();
            let entry = state.complete.get(&hash).ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "hash not found in database")
            })?;
            let source = if entry.owned_data {
                self.owned_data_path(&hash)
            } else {
                entry
                    .external
                    .iter()
                    .next()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no valid path found"))?
                    .clone()
            };
            let size = entry.size;
            (source, size, entry.owned_data)
        };
        // copy all the things
        let path_bytes = if size >= self.0.options.move_threshold && stable && owned {
            tracing::info!("moving {} to {}", source.display(), target.display());
            if let Err(e) = std::fs::rename(source, &target) {
                tracing::error!("rename failed: {}", e);
                return Err(e)?;
            }
            let mut state = self.0.state.write().unwrap();
            let Some(entry) = state.complete.get_mut(&hash) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "hash not found in database",
                ));
            };
            entry.owned_data = false;
            entry.external.insert(target);
            Some(entry.external_to_bytes())
        } else {
            tracing::info!("{} {} {}", size, stable, owned);
            tracing::info!("copying {} to {}", source.display(), target.display());
            // todo: progress
            std::fs::copy(&source, &target)?;
            let mut state = self.0.state.write().unwrap();
            let Some(entry) = state.complete.get_mut(&hash) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "hash not found in database",
                ));
            };
            if stable {
                entry.external.insert(target);
                Some(entry.external_to_bytes())
            } else {
                None
            }
        };
        if let Some(path_bytes) = path_bytes {
            let pp = self.paths_path(hash);
            println!("writing paths {}", pp.display());
            std::fs::write(pp, path_bytes)?;
        }
        Ok(())
    }

    /// scan a directory for data
    pub(crate) fn load0(complete_path: PathBuf, partial_path: PathBuf) -> anyhow::Result<Self> {
        let mut partial_index =
            BTreeMap::<Hash, BTreeMap<[u8; 16], (Option<PathBuf>, Option<PathBuf>)>>::new();
        let mut full_index =
            BTreeMap::<Hash, (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>)>::new();
        let mut outboard = BTreeMap::new();
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
                            let (data, _, _) = full_index.entry(hash).or_default();
                            *data = Some(path);
                        }
                        Purpose::Outboard(hash) => {
                            let (_, outboard, _) = full_index.entry(hash).or_default();
                            *outboard = Some(path);
                        }
                        Purpose::Paths(hash) => {
                            let (_, _, paths) = full_index.entry(hash).or_default();
                            *paths = Some(path);
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
        for (hash, (data_path, outboard_path, paths_path)) in full_index {
            let external: BTreeSet<PathBuf> = if let Some(paths_path) = paths_path {
                let paths = std::fs::read(paths_path)?;
                postcard::from_bytes(&paths)?
            } else {
                Default::default()
            };
            let owned_data = data_path.is_some();
            let size = if let Some(data_path) = &data_path {
                let Ok(meta) = std::fs::metadata(data_path) else {
                    tracing::warn!("unable to open owned data file {}. removing {}", data_path.display(), hex::encode(hash));
                    continue
                };
                meta.len()
            } else if let Some(external) = external.iter().next() {
                let Ok(meta) = std::fs::metadata(external) else {
                    tracing::warn!("unable to open external data file {}. removing {}", external.display(), hex::encode(hash));
                    continue
                };
                meta.len()
            } else {
                tracing::error!(
                    "neither internal nor external file exists. removing {}",
                    hex::encode(hash)
                );
                continue;
            };
            if needs_outboard(size) {
                if let Some(outboard_path) = outboard_path {
                    let outboard_data = std::fs::read(outboard_path)?;
                    outboard.insert(hash, outboard_data.into());
                } else {
                    tracing::error!("missing outboard file for {}", hex::encode(hash));
                    continue;
                }
            }
            complete.insert(
                hash,
                CompleteEntry {
                    owned_data,
                    external,
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
            state: RwLock::new(State {
                complete,
                partial,
                outboard,
                data: Default::default(),
            }),
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
            tokio::task::spawn_blocking(move || Self::load0(complete_path, partial_path)).await??;
        Ok(db)
    }

    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.0.options.owned_data_path(hash)
    }

    fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.0.options.owned_outboard_path(hash)
    }

    fn paths_path(&self, hash: Hash) -> PathBuf {
        self.0.options.paths_path(hash)
    }
}

// hardlink or copy a file
fn hardlink_or_copy_sync(src: &Path, dst: &Path) -> io::Result<()> {
    if src == dst {
        tracing::info!(
            "skipping hardlinking {} to {}",
            src.display(),
            dst.display()
        );
        return Ok(());
    }
    if let Err(e) = std::fs::remove_file(dst) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::info!("remove failed {}", e);
            return Err(e);
        }
    }
    tracing::info!("hardlinking {} to {}", src.display(), dst.display());
    Ok(match std::fs::hard_link(src, dst) {
        Ok(_) => {}
        Err(e) => {
            tracing::info!("hard link failed {}", e);
            tracing::info!("copying {} to {}", src.display(), dst.display());
            std::fs::copy(src, dst)?;
        }
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
    progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
) -> io::Result<(Hash, Vec<u8>)> {
    let span = trace_span!("outboard.compute", path = %path.display());
    let _guard = span.enter();
    let file = std::fs::File::open(path)?;
    // compute outboard size so we can pre-allocate the buffer.
    let outboard_size = usize::try_from(bao_tree::io::outboard_size(size, IROH_BLOCK_SIZE))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size too large"))?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader2::new(file, progress);
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    let hash =
        bao_tree::io::sync::outboard_post_order(&mut reader, size, IROH_BLOCK_SIZE, &mut outboard)?;
    let ob = PostOrderMemOutboard::load(hash, &outboard, IROH_BLOCK_SIZE)?.flip();
    tracing::trace!(%hash, "done");

    Ok((hash.into(), ob.into_inner()))
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

fn flatten_to_io<T>(
    e: std::result::Result<io::Result<T>, tokio::task::JoinError>,
) -> io::Result<T> {
    match e {
        Ok(x) => x,
        Err(cause) => Err(io::Error::new(io::ErrorKind::Other, cause)),
    }
}
