//! A flat file database implementation.
//!
//! This is a simple database implementation that stores all data in the file system.
//! It is used by the iroh binary.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bao_tree::io::outboard::{PostOrderMemOutboard, PreOrderOutboard};
use bao_tree::io::sync::ReadAt;
use bao_tree::{BaoTree, ByteNum, ChunkNum};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::future::Either;
use futures::{Future, FutureExt};
use iroh_bytes::provider::ValidateProgress;
use iroh_bytes::provider::{
    BaoDb, BaoMap, BaoMapEntry, BaoPartialMap, BaoPartialMapEntry, BaoReadonlyDb, ImportProgress,
};
use iroh_bytes::util::progress::{IdGenerator, ProgressSender};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::{AsyncSliceReader, AsyncSliceWriter, File};
use rand::Rng;
use range_collections::RangeSet2;
use tokio::sync::mpsc;
use tracing::trace_span;

use super::flatten_to_io;

#[derive(Debug, Default)]
struct State {
    // complete entries
    complete: BTreeMap<Hash, CompleteEntry>,
    // partial entries
    partial: BTreeMap<Hash, PartialEntry>,
    // outboard data, cached for all complete entries
    outboard: BTreeMap<Hash, Bytes>,
    // data, cached for all complete entries that are small enough
    data: BTreeMap<Hash, Bytes>,
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

    #[allow(dead_code)]
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

#[derive(Debug, Clone, Default)]
struct PartialEntry {
    // size of the data
    #[allow(dead_code)]
    size: u64,
    // unique id for this entry
    uuid: [u8; 16],
}

impl PartialEntry {
    fn new(size: u64, uuid: [u8; 16]) -> Self {
        Self { size, uuid }
    }
}

impl BaoPartialMapEntry<Database> for Entry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Database as BaoPartialMap>::OutboardMut>> {
        let hash = self.hash;
        let size = self.entry.size();
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        let outboard = self.entry.outboard.clone();
        async move {
            if let Either::Right(path) = outboard {
                let mut writer = iroh_io::File::create(move || {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(path.clone())
                })
                .await?;
                writer.write_at(0, &size.to_le_bytes()).await?;
                Ok(PreOrderOutboard {
                    root: hash,
                    tree,
                    data: writer,
                })
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot write to in-memory outboard",
                ))
            }
        }
        .boxed()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Database as BaoPartialMap>::DataWriter>> {
        let data = self.entry.data.clone();
        async move {
            if let Either::Right((path, _)) = data {
                let writer = iroh_io::File::create(move || {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .open(path.clone())
                })
                .await?;
                Ok(writer)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot write to in-memory data",
                ))
            }
        }
        .boxed()
    }
}

impl BaoPartialMap for Database {
    type OutboardMut = PreOrderOutboard<File>;

    type DataWriter = iroh_io::File;

    type PartialEntry = Entry;

    fn get_partial(&self, hash: &Hash) -> Option<Self::PartialEntry> {
        let entry = self.0.state.read().unwrap().partial.get(hash)?.clone();
        Some(Entry {
            hash: blake3::Hash::from(*hash),
            entry: EntryData {
                data: Either::Right((
                    self.0.options.partial_data_path(*hash, &entry.uuid),
                    entry.size,
                )),
                outboard: Either::Right(self.0.options.partial_outboard_path(*hash, &entry.uuid)),
            },
        })
    }

    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Entry> {
        let mut state = self.0.state.write().unwrap();
        let entry = state.partial.entry(hash).or_insert_with(|| {
            let uuid = rand::thread_rng().gen::<[u8; 16]>();
            PartialEntry::new(size, uuid)
        });
        let data_path = self.0.options.partial_data_path(hash, &entry.uuid);
        let outboard_path = self.0.options.partial_outboard_path(hash, &entry.uuid);
        Ok(Entry {
            hash: blake3::Hash::from(hash),
            entry: EntryData {
                data: Either::Right((data_path, size)),
                outboard: Either::Right(outboard_path),
            },
        })
    }

    fn insert_complete_entry(&self, entry: Entry) -> BoxFuture<'_, io::Result<()>> {
        let hash = entry.hash.into();
        let Either::Right((temp_data_path, size)) = entry.entry.data else {
            todo!()
        };
        let Either::Right(temp_outboard_path) = entry.entry.outboard else {
            todo!()
        };
        let data_path = self.0.options.owned_data_path(&hash);
        async move {
            // for a short time we will have neither partial nor complete
            self.0.state.write().unwrap().partial.remove(&hash);
            tokio::fs::rename(temp_data_path, &data_path).await?;
            let outboard = if tokio::fs::try_exists(&temp_outboard_path).await? {
                let outboard_path = self.0.options.owned_outboard_path(&hash);
                tokio::fs::rename(temp_outboard_path, &outboard_path).await?;
                Some(tokio::fs::read(&outboard_path).await?.into())
            } else {
                None
            };
            let mut state = self.0.state.write().unwrap();
            let entry = state.complete.entry(hash).or_default();
            entry.union_with(CompleteEntry::new_default(size))?;
            if let Some(outboard) = outboard {
                state.outboard.insert(hash, outboard);
            }
            Ok(())
        }
        .boxed()
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
    fn partial_data_path(&self, hash: Hash, uuid: &[u8; 16]) -> PathBuf {
        self.partial_path
            .join(FileName::PartialData(hash, *uuid).to_string())
    }

    fn partial_outboard_path(&self, hash: Hash, uuid: &[u8; 16]) -> PathBuf {
        self.partial_path
            .join(FileName::PartialOutboard(hash, *uuid).to_string())
    }

    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path.join(FileName::Data(*hash).to_string())
    }

    fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path
            .join(FileName::Outboard(*hash).to_string())
    }

    fn paths_path(&self, hash: Hash) -> PathBuf {
        self.complete_path.join(FileName::Paths(hash).to_string())
    }
}

#[derive(Debug)]
struct Inner {
    options: Options,
    state: RwLock<State>,
}

/// Flat file database implementation.
///
/// This
#[derive(Debug, Clone)]
pub struct Database(Arc<Inner>);
/// The [BaoMapEntry] and [BaoPartialMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct Entry {
    /// the hash is not part of the entry itself
    hash: blake3::Hash,
    entry: EntryData,
}

impl BaoMapEntry<Database> for Entry {
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

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderOutboard<MemOrFile>>> {
        async move {
            let size = self.entry.size();
            let data = self.entry.outboard_reader().await?;
            Ok(PreOrderOutboard {
                root: self.hash,
                tree: BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE),
                data,
            })
        }
        .boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<MemOrFile>> {
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
struct EntryData {
    /// The bao outboard data.
    outboard: Either<Bytes, PathBuf>,
    /// The data itself.
    data: Either<Bytes, (PathBuf, u64)>,
}

/// A reader for either a file or a byte slice.
///
/// This is used to read small data from memory, and large data from disk.
#[derive(Debug)]
pub enum MemOrFile {
    /// We got it all in memory
    Mem(Bytes),
    /// An iroh_io::File
    File(File),
}

impl AsyncSliceReader for MemOrFile {
    type ReadAtFuture<'a> = futures::future::Either<
        <Bytes as AsyncSliceReader>::ReadAtFuture<'a>,
        <File as AsyncSliceReader>::ReadAtFuture<'a>,
    >;

    fn read_at(&mut self, offset: u64, len: usize) -> Self::ReadAtFuture<'_> {
        match self {
            MemOrFile::Mem(mem) => Either::Left(mem.read_at(offset, len)),
            MemOrFile::File(file) => Either::Right(file.read_at(offset, len)),
        }
    }

    type LenFuture<'a> = futures::future::Either<
        <Bytes as AsyncSliceReader>::LenFuture<'a>,
        <File as AsyncSliceReader>::LenFuture<'a>,
    >;

    fn len(&mut self) -> Self::LenFuture<'_> {
        match self {
            MemOrFile::Mem(mem) => Either::Left(mem.len()),
            MemOrFile::File(file) => Either::Right(file.len()),
        }
    }
}

impl EntryData {
    /// Get the outboard data for this entry, as a `Bytes`.
    pub fn outboard_reader(&self) -> impl Future<Output = io::Result<MemOrFile>> + 'static {
        let outboard = self.outboard.clone();
        async move {
            Ok(match outboard {
                Either::Left(mem) => MemOrFile::Mem(mem),
                Either::Right(path) => MemOrFile::File(File::open(path).await?),
            })
        }
    }

    /// A reader for the data.
    pub fn data_reader(&self) -> impl Future<Output = io::Result<MemOrFile>> + 'static {
        let data = self.data.clone();
        async move {
            Ok(match data {
                Either::Left(mem) => MemOrFile::Mem(mem),
                Either::Right((path, _)) => MemOrFile::File(File::open(path).await?),
            })
        }
    }

    /// Returns the size of the blob
    pub fn size(&self) -> u64 {
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
    type Entry = Entry;
    type Outboard = PreOrderOutboard<MemOrFile>;
    type DataReader = MemOrFile;
    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.0.state.read().unwrap();
        if let Some(entry) = state.complete.get(hash) {
            println!("got complete: {} {}", hash, entry.size);
            let outboard = state.load_outboard(entry.size, hash)?;
            // check if we have the data cached
            let data = state.data.get(hash).cloned();
            Some(Entry {
                hash: blake3::Hash::from(*hash),
                entry: EntryData {
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
                    outboard: Either::Left(outboard),
                },
            })
        } else if let Some(entry) = state.partial.get(hash) {
            let data_path = self.0.options.partial_data_path(*hash, &entry.uuid);
            let outboard_path = self.0.options.partial_outboard_path(*hash, &entry.uuid);
            println!(
                "got partial: {} {} {}",
                hash,
                entry.size,
                hex::encode(entry.uuid)
            );
            Some(Entry {
                hash: blake3::Hash::from(*hash),
                entry: EntryData {
                    data: Either::Right((data_path, entry.size)),
                    outboard: Either::Right(outboard_path),
                },
            })
        } else {
            println!("got none {}", hash);
            None
        }
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
    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let lock = self.0.state.read().unwrap();
        let res = lock.partial.keys().cloned().collect::<Vec<_>>();
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
        tokio::task::spawn_blocking(move || this.export_sync(hash, target, stable, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import(
        &self,
        path: PathBuf,
        stable: bool,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(Hash, u64)>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.import_sync(path, stable, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import_bytes(&self, data: Bytes) -> BoxFuture<'_, io::Result<Hash>> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.import_bytes_sync(data))
            .map(flatten_to_io)
            .boxed()
    }
}

impl State {
    /// Gets or creates the outboard data for the given hash.
    ///
    /// For small entries the outboard consists of just the le encoded size,
    /// so we create it on demand.
    fn load_outboard(&self, size: u64, hash: &Hash) -> Option<Bytes> {
        if needs_outboard(size) {
            self.outboard.get(hash).cloned()
        } else {
            Some(Bytes::from(size.to_le_bytes().to_vec()))
        }
    }
}

impl Database {
    fn import_sync(
        self,
        path: PathBuf,
        stable: bool,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
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
        let (hash, new, outboard) = if stable {
            // compute outboard and hash from the data in place, since we assume that it is stable
            let size = path.metadata()?.len();
            progress.blocking_send(ImportProgress::Size { id, size })?;
            let progress2 = progress.clone();
            let (hash, outboard) = compute_outboard(&path, size, move |offset| {
                Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
            })?;
            progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
            (hash, CompleteEntry::new_external(size, path), outboard)
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
            let (hash, outboard) = compute_outboard(&temp_data_path, size, move |offset| {
                Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
            })?;
            progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
            let data_path = self.owned_data_path(&hash);
            std::fs::rename(temp_data_path, data_path)?;
            (hash, CompleteEntry::new_default(size), outboard)
        };
        if let Some(outboard) = outboard.as_ref() {
            let outboard_path = self.owned_outboard_path(&hash);
            std::fs::write(outboard_path, &outboard)?;
        }
        let size = new.size;
        let mut state = self.0.state.write().unwrap();
        let entry = state.complete.entry(hash).or_default();
        let n = entry.external.len();
        entry.union_with(new)?;
        if entry.external.len() != n {
            let path = self.0.options.paths_path(hash);
            std::fs::write(path, entry.external_to_bytes())?;
        }
        if let Some(outboard) = outboard {
            state.outboard.insert(hash, outboard.into());
        }
        Ok((hash, size))
    }

    fn import_bytes_sync(&self, data: Bytes) -> io::Result<Hash> {
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

    fn export_sync(
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
    pub(crate) fn load_sync(complete_path: PathBuf, partial_path: PathBuf) -> anyhow::Result<Self> {
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
                if let Ok(purpose) = FileName::from_str(name) {
                    match purpose {
                        FileName::PartialData(hash, uuid) => {
                            let m = partial_index.entry(hash).or_default();
                            let (data, _) = m.entry(uuid).or_default();
                            *data = Some(path);
                        }
                        FileName::PartialOutboard(hash, uuid) => {
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
                if let Ok(purpose) = FileName::from_str(name) {
                    match purpose {
                        FileName::Data(hash) => {
                            let (data, _, _) = full_index.entry(hash).or_default();
                            *data = Some(path);
                        }
                        FileName::Outboard(hash) => {
                            let (_, outboard, _) = full_index.entry(hash).or_default();
                            *outboard = Some(path);
                        }
                        FileName::Paths(hash) => {
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
        // figure out what we have completely
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
                    // we could delete the data file here
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
        // retain only entries for which we have both outboard and data
        partial_index.retain(|hash, entries| {
            entries.retain(|uuid, (data, outboard)| match (data, outboard) {
                (Some(_), Some(_)) => true,
                (Some(data), None) => {
                    tracing::warn!(
                        "missing partial outboard file for {} {}",
                        hex::encode(hash),
                        hex::encode(uuid)
                    );
                    std::fs::remove_file(data).ok();
                    false
                }
                (None, Some(outboard)) => {
                    tracing::warn!(
                        "missing partial data file for {} {}",
                        hex::encode(hash),
                        hex::encode(uuid)
                    );
                    std::fs::remove_file(outboard).ok();
                    false
                }
                _ => false,
            });
            !entries.is_empty()
        });
        let mut partial = BTreeMap::new();
        for (hash, entries) in partial_index {
            let best = if !complete.contains_key(&hash) {
                entries.iter().filter_map(|(uuid, (data_path, outboard_path))| {
                let data_path = data_path.as_ref()?;
                let outboard_path = outboard_path.as_ref()?;
                let Ok(data_meta) = std::fs::metadata(&data_path) else {
                    tracing::warn!("unable to open partial data file {}", data_path.display());
                    return None
                };
                let Ok(outboard_file) = std::fs::File::open(&outboard_path) else {
                    tracing::warn!("unable to open partial outboard file {}", outboard_path.display());
                    return None
                };
                let mut expected_size = [0u8; 8];
                let Ok(_) = outboard_file.read_at(0, &mut expected_size) else {
                    tracing::warn!("partial outboard file is missing length {}", outboard_path.display());
                    return None
                };
                let current_size = data_meta.len();
                let expected_size = u64::from_le_bytes(expected_size);
                Some((current_size, expected_size, uuid))
            }).max_by_key(|x| x.0)
            } else {
                None
            };
            if let Some((current_size, expected_size, uuid)) = best {
                if current_size > 0 {
                    partial.insert(
                        hash,
                        PartialEntry {
                            size: expected_size,
                            uuid: *uuid,
                        },
                    );
                }
            }
            // remove all other entries
            let keep = partial.get(&hash).map(|x| x.uuid);
            for (uuid, (data_path, outboard_path)) in entries {
                if Some(uuid) != keep {
                    if let Some(data_path) = data_path {
                        tracing::info!("removing partial data file {}", data_path.display());
                        std::fs::remove_file(data_path)?;
                    }
                    if let Some(outboard_path) = outboard_path {
                        tracing::info!(
                            "removing partial outboard file {}",
                            outboard_path.display()
                        );
                        std::fs::remove_file(outboard_path)?;
                    }
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

    /// Blocking load a database from disk.
    pub fn load_blocking(
        complete_path: impl AsRef<Path>,
        partial_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let complete_path = complete_path.as_ref().to_path_buf();
        let partial_path = partial_path.as_ref().to_path_buf();
        let db = Self::load_sync(complete_path, partial_path)?;
        Ok(db)
    }

    /// Load a database from disk.
    pub async fn load(
        complete_path: impl AsRef<Path>,
        partial_path: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let complete_path = complete_path.as_ref().to_path_buf();
        let partial_path = partial_path.as_ref().to_path_buf();
        let db = tokio::task::spawn_blocking(move || Self::load_sync(complete_path, partial_path))
            .await??;
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
) -> io::Result<(Hash, Option<Vec<u8>>)> {
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
    let ob = ob.into_inner();
    let ob = if ob.len() > 8 { Some(ob) } else { None };
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

/// A file name that indicates the purpose of the file.
#[derive(Clone)]
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

// todo: use "obao4" instead to indicate that it is pre order bao like in the spec,
// but with a chunk group size of 2^4?
const OUTBOARD_EXT: &str = "outboard";

impl fmt::Display for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialData(hash, uuid) => {
                write!(f, "{}-{}.data", hex::encode(hash), hex::encode(uuid))
            }
            Self::PartialOutboard(hash, uuid) => {
                write!(
                    f,
                    "{}-{}.{}",
                    hex::encode(hash),
                    hex::encode(uuid),
                    OUTBOARD_EXT
                )
            }
            Self::Paths(hash) => {
                write!(f, "{}.paths", hex::encode(hash))
            }
            Self::Data(hash) => write!(f, "{}.data", hex::encode(hash)),
            Self::Outboard(hash) => write!(f, "{}.{}", hex::encode(hash), OUTBOARD_EXT),
            Self::Meta(name) => write!(f, "{}.meta", hex::encode(name)),
        }
    }
}

impl FromStr for FileName {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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
        } else {
            hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
            if ext == "data" {
                Ok(Self::Data(hash.into()))
            } else if ext == OUTBOARD_EXT {
                Ok(Self::Outboard(hash.into()))
            } else if ext == "paths" {
                Ok(Self::Paths(hash.into()))
            } else if ext == "meta" {
                Ok(Self::Meta(hash.into()))
            } else {
                Err(())
            }
        }
    }
}

struct DD<T: fmt::Display>(T);

impl<T: fmt::Display> fmt::Debug for DD<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for FileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PartialData(hash, guid) => f
                .debug_tuple("PartialData")
                .field(&DD(hash))
                .field(&DD(hex::encode(guid)))
                .finish(),
            Self::Data(hash) => f.debug_tuple("Data").field(&DD(hash)).finish(),
            Self::PartialOutboard(hash, guid) => f
                .debug_tuple("PartialOutboard")
                .field(&DD(hash))
                .field(&DD(hex::encode(guid)))
                .finish(),
            Self::Outboard(hash) => f.debug_tuple("Outboard").field(&DD(hash)).finish(),
            Self::Meta(arg0) => f.debug_tuple("Meta").field(&DD(hex::encode(arg0))).finish(),
            Self::Paths(arg0) => f
                .debug_tuple("Paths")
                .field(&DD(hex::encode(arg0)))
                .finish(),
        }
    }
}

impl FileName {
    /// true if the purpose is for a temporary file
    pub fn temporary(&self) -> bool {
        match self {
            FileName::PartialData(_, _) => true,
            FileName::Data(_) => false,
            FileName::PartialOutboard(_, _) => true,
            FileName::Outboard(_) => false,
            FileName::Meta(_) => false,
            FileName::Paths(_) => false,
        }
    }

    /// some bytes that can be used as a hint for the name of the file
    pub fn name_hint(&self) -> &[u8] {
        match self {
            FileName::PartialData(hash, _) => hash.as_bytes(),
            FileName::Data(hash) => hash.as_bytes(),
            FileName::PartialOutboard(hash, _) => hash.as_bytes(),
            FileName::Meta(data) => data.as_slice(),
            FileName::Outboard(_) => &[],
            FileName::Paths(_) => &[],
        }
    }
}
