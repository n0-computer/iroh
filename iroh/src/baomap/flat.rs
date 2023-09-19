//! A flat file database implementation.
//!
//! This is a simple database implementation that stores all data in the file system.
//! It is used by the iroh binary.
//!
//! # File format
//!
//! The flat file database stores data and outboards in a directory structure.
//! Partial and complete entries can be stored in the same directory, or in different
//! directories. The purpose of a file is always clear from the file name.
//!
//! Currently a single directory is used to store all entries, but
//! in the future we might want to use a directory tree for file systems that don't
//! support a large number of files in a single directory.
//!
//! ## Files
//!
//! ### Complete data files
//!
//! Complete files have as name the hex encoded blake3 hash of the data, and the extension
//! `.data`. There can only ever be one complete file for a given hash. If the file does
//! not contain the data corresponding to the hash, this is considered an error that should
//! be reported during validation.
//!
//! They will not *change* during the lifetime of the database, but might be deleted.
//!
//! These files can become quite large and make up the vast majority of the disk usage.
//!
//! ### Path files
//!
//! Path files have as name the hex encoded blake3 hash of the data, and the extension
//! `.paths`. They contain a postcard serialized list of absolute paths to the data file.
//! The paths are stored in sorted order and do not contain duplicates.
//!
//! Path files are used for when data is stored externally. If any of the files listed in
//! the path file is missing, or does not contain exactly the data corresponding to the
//! hash, this is considered an error that should be reported during validation.
//!
//! External storage will only be used for large files.
//!
//! Postcard encoding of strings is just adding a varint encoded length prefix, followed
//! by the utf8 encoded string. See the [postcard wire format spec](https://postcard.jamesmunns.com/).
//!
//! ### Complete outboard files
//!
//! Complete outboard files have as name the hex encoded blake3 hash of the data, and the
//! extension `.obao4`. `obao` stands for pre-order bao, and `4` describes the block size.
//! So `obao4` means that the outboard data is stored in a pre-order bao tree with a block
//! size of 1024*2^4=16384 bytes, which is the default block size for iroh.
//!
//! They will not *change* during the lifetime of the database, but might be deleted.
//!
//! The first 8 bytes of the file are the little endian encoded size of the data.
//!
//! In the future we might support other block sizes as well as in-order or post-order
//! encoded trees. The file extension will then change accordingly. E.g. `obao` for
//! pre-order outboard files with a block size of 1024*2^0=1024 bytes.
//!
//! For files that are smaller than the block size, the outboard file would just contain
//! the size. Storing these outboard files is not necessary, and therefore they are not
//! stored.
//!
//! ### Partial data files
//!
//! There can be multiple partial data files for a given hash. E.g. you could have one
//! partial data file containing valid bytes 0..16384 of a file, and another containing
//! valid bytes 32768..49152 of the same file.
//!
//! To allow for this, partial data files have as name the hex encoded blake3 hash of the
//! complete data, followed by a -, followed by a hex encoded 16 byte random uuid, followed
//! by the extension `.data`.
//!
//! ### Partial outboard files
//!
//! There can be multiple partial outboard files for a given hash. E.g. you could have one
//! partial outboard file containing the outboard for blocks 0..2 of a file and a second
//! partial outboard file containing the outboard for blocks 2..4 of the same file.
//!
//! To allow for this, partial outboard files have as name the hex encoded blake3 hash of
//! the complete data, followed by a -, followed by a hex encoded 16 byte random uuid,
//!
//! Partial outboard files are not stored for small files, since the outboard is just the
//! size of the data.
//!
//! Pairs of partial data and partial outboard files belong together, and are correlated
//! by the uuid.
//!
//! It is unusual but not impossible to have multiple partial data files for the same
//! hash. In that case the best partial data file should be chosen on startup.
//!
//! ### Temp files
//!
//! When copying data into the database, we first copy the data into a temporary file to
//! ensure that the data is not modified while we compute the outboard. These files have
//! just a hex encoded 16 byte random uuid as name, and the extension `.temp`.
//!
//! We don't know the hash of the data yet. These files are fully ephemeral, and can
//! be deleted on restart.
//!
//! # File lifecycle
//!
//! ## Import from local storage
//!
//! When a file is imported from local storage in copy mode, the file in question is first
//! copied to a temporary file. The temporary file is then used to compute the outboard.
//!
//! Once the outboard is computed, the temporary file is renamed to the final data file,
//! and the outboard is written to the final outboard file.
//!
//! When importing in reference mode, the outboard is computed directly from the file in
//! question. Once the outboard is computed, the file path is added to the paths file,
//! and the outboard is written to the outboard file.
//!
//! ## Download from the network
//!
//! When a file is downloaded from the network, a pair of partial data and partial outboard
//! files is created. The partial data file is filled with the downloaded data, and the
//! partial outboard file is filled at the same time. Note that a partial data file is
//! worthless without the corresponding partial outboard file, since only the outboard
//! can be used to verify the downloaded parts of the data.
//!
//! Once the download is complete, the partial data and partial outboard files are renamed
//! to the final partial data and partial outboard files.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};

use bao_tree::io::outboard::{PostOrderMemOutboard, PreOrderOutboard};
use bao_tree::io::sync::ReadAt;
use bao_tree::{blake3, ChunkNum};
use bao_tree::{BaoTree, ByteNum};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::future::Either;
use futures::{Future, FutureExt};
use iroh_bytes::baomap::range_collections::RangeSet2;
use iroh_bytes::baomap::{
    self, EntryStatus, ExportMode, ImportMode, ImportProgress, LivenessTracker, Map, MapEntry,
    PartialMap, PartialMapEntry, PinnedCid, ReadableStore, ValidateProgress,
};
use iroh_bytes::util::progress::{IdGenerator, ProgressSender};
use iroh_bytes::util::{Cid, Format};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use iroh_io::{AsyncSliceReader, AsyncSliceWriter, File};
use rand::Rng;
use tokio::sync::mpsc;
use tracing::trace_span;

use super::flatten_to_io;

#[derive(Debug, Default)]
struct State {
    // complete entries
    complete: BTreeMap<Hash, CompleteEntry>,
    // partial entries
    partial: BTreeMap<Hash, PartialEntryData>,
    // outboard data, cached for all complete entries
    outboard: BTreeMap<Hash, Bytes>,
    // data, cached for all complete entries that are small enough
    data: BTreeMap<Hash, Bytes>,
    // in memory tracking of live set
    live: BTreeSet<Hash>,
    // temp pins
    temp: BTreeMap<Cid, u64>,
    // roots
    roots: BTreeMap<Bytes, Cid>,
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
        self.external.extend(new.external);
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct PartialEntryData {
    // size of the data
    #[allow(dead_code)]
    size: u64,
    // unique id for this entry
    uuid: [u8; 16],
}

impl PartialEntryData {
    fn new(size: u64, uuid: [u8; 16]) -> Self {
        Self { size, uuid }
    }
}

impl MapEntry<Store> for PartialEntry {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>> {
        futures::future::ok(RangeSet2::all()).boxed()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<<Store as Map>::Outboard>> {
        async move {
            let file = File::open(self.outboard_path.clone()).await?;
            Ok(PreOrderOutboard {
                root: self.hash,
                tree: BaoTree::new(ByteNum(self.size), IROH_BLOCK_SIZE),
                data: MemOrFile::File(file),
            })
        }
        .boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<<Store as Map>::DataReader>> {
        async move {
            let file = File::open(self.data_path.clone()).await?;
            Ok(MemOrFile::File(file))
        }
        .boxed()
    }

    fn is_complete(&self) -> bool {
        false
    }
}

impl PartialMapEntry<Store> for PartialEntry {
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<<Store as PartialMap>::OutboardMut>> {
        let hash = self.hash;
        let size = self.size;
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        let path = self.outboard_path.clone();
        async move {
            let mut writer = iroh_io::File::create(move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(path)
            })
            .await?;
            writer.write_at(0, &size.to_le_bytes()).await?;
            Ok(PreOrderOutboard {
                root: hash,
                tree,
                data: writer,
            })
        }
        .boxed()
    }

    fn data_writer(&self) -> BoxFuture<'_, io::Result<<Store as PartialMap>::DataWriter>> {
        let path = self.data_path.clone();
        iroh_io::File::create(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
        })
        .boxed()
    }
}

impl PartialMap for Store {
    type OutboardMut = PreOrderOutboard<File>;

    type DataWriter = iroh_io::File;

    type PartialEntry = PartialEntry;

    fn get_partial(&self, hash: &Hash) -> Option<Self::PartialEntry> {
        let entry = self.0.state.read().unwrap().partial.get(hash)?.clone();
        Some(PartialEntry {
            hash: blake3::Hash::from(*hash),
            size: entry.size,
            data_path: self.0.options.partial_data_path(*hash, &entry.uuid),
            outboard_path: self.0.options.partial_outboard_path(*hash, &entry.uuid),
        })
    }

    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Self::PartialEntry> {
        let mut state = self.0.state.write().unwrap();
        // this protects the entry from being deleted until the next mark phase
        //
        // example: a collection containing this hash is temp pinned, but
        // we did not have the collection at the time of the mark phase.
        //
        // now we get the collection and it's child between the mark and the sweep
        // phase. the child is not in the live set and will be deleted.
        //
        // this prevents this from happening until the live set is cleared at the
        // beginning of the next mark phase, at which point this hash is normally
        // reachable.
        tracing::info!("protecting partial hash {}", hash);
        state.live.insert(hash);
        let entry = state.partial.entry(hash).or_insert_with(|| {
            let uuid = rand::thread_rng().gen::<[u8; 16]>();
            PartialEntryData::new(size, uuid)
        });
        let data_path = self.0.options.partial_data_path(hash, &entry.uuid);
        let outboard_path = self.0.options.partial_outboard_path(hash, &entry.uuid);
        Ok(PartialEntry {
            hash: blake3::Hash::from(hash),
            size: entry.size,
            data_path,
            outboard_path,
        })
    }

    fn insert_complete(&self, entry: Self::PartialEntry) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        self.0
            .options
            .rt
            .spawn_blocking(move || this.insert_complete_sync(entry))
            .map(flatten_to_io)
            .boxed()
    }
}

#[derive(Debug)]
struct Options {
    complete_path: PathBuf,
    partial_path: PathBuf,
    move_threshold: u64,
    inline_threshold: u64,
    rt: tokio::runtime::Handle,
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
    // mutex for async access to complete files
    //
    // complete files are never written to. They come into existence when a partial
    // entry is completed, and are deleted as a whole.
    complete_io_mutex: Mutex<()>,
}

/// Flat file database implementation.
///
/// This
#[derive(Debug, Clone)]
pub struct Store(Arc<Inner>);
/// The [MapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct Entry {
    /// the hash is not part of the entry itself
    hash: blake3::Hash,
    entry: EntryData,
    is_complete: bool,
}

impl MapEntry<Store> for Entry {
    fn hash(&self) -> blake3::Hash {
        self.hash
    }

    fn size(&self) -> u64 {
        match &self.entry.data {
            Either::Left(bytes) => bytes.len() as u64,
            Either::Right((_, size)) => *size,
        }
    }

    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>> {
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

    fn is_complete(&self) -> bool {
        self.is_complete
    }
}

/// A [`Store`] entry.
///
/// This is either stored externally in the file system, or internally in the database.
///
/// Internally stored entries are stored in the iroh home directory when the database is
/// persisted.
#[derive(Debug, Clone)]
struct EntryData {
    /// The data itself.
    data: Either<Bytes, (PathBuf, u64)>,
    /// The bao outboard data.
    outboard: Either<Bytes, PathBuf>,
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

/// The [PartialMapEntry] implementation for [Store].
#[derive(Debug, Clone)]
pub struct PartialEntry {
    hash: blake3::Hash,
    size: u64,
    data_path: PathBuf,
    outboard_path: PathBuf,
}

impl Map for Store {
    type Entry = Entry;
    type Outboard = PreOrderOutboard<MemOrFile>;
    type DataReader = MemOrFile;
    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.0.state.read().unwrap();
        if let Some(entry) = state.complete.get(hash) {
            tracing::trace!("got complete: {} {}", hash, entry.size);
            let outboard = state.load_outboard(entry.size, hash)?;
            // check if we have the data cached
            let data = state.data.get(hash).cloned();
            Some(Entry {
                hash: blake3::Hash::from(*hash),
                is_complete: true,
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
            tracing::trace!(
                "got partial: {} {} {}",
                hash,
                entry.size,
                hex::encode(entry.uuid)
            );
            Some(Entry {
                hash: blake3::Hash::from(*hash),
                is_complete: false,
                entry: EntryData {
                    data: Either::Right((data_path, entry.size)),
                    outboard: Either::Right(outboard_path),
                },
            })
        } else {
            tracing::trace!("got none {}", hash);
            None
        }
    }

    fn contains(&self, hash: &Hash) -> EntryStatus {
        let state = self.0.state.read().unwrap();
        if state.complete.contains_key(hash) {
            EntryStatus::Complete
        } else if state.partial.contains_key(hash) {
            EntryStatus::Partial
        } else {
            EntryStatus::NotFound
        }
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let inner = self.0.state.read().unwrap();
        let items = inner.complete.keys().copied().collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn temp_pins(&self) -> Box<dyn Iterator<Item = Cid> + Send + Sync + 'static> {
        let inner = self.0.state.read().unwrap();
        let items = inner.temp.keys().copied().collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn roots(&self) -> Box<dyn Iterator<Item = (Bytes, Cid)> + Send + Sync + 'static> {
        let inner = self.0.state.read().unwrap();
        let items = inner
            .roots
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        Box::new(items.into_iter())
    }

    fn validate(&self, _tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>> {
        unimplemented!()
    }

    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        let lock = self.0.state.read().unwrap();
        let res = lock.partial.keys().cloned().collect::<Vec<_>>();
        Box::new(res.into_iter())
    }

    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let this = self.clone();
        self.0
            .options
            .rt
            .spawn_blocking(move || this.export_sync(hash, target, mode, progress))
            .map(flatten_to_io)
            .boxed()
    }
}

impl baomap::Store for Store {
    fn import(
        &self,
        path: PathBuf,
        mode: ImportMode,
        format: Format,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(PinnedCid, u64)>> {
        let this = self.clone();
        self.0
            .options
            .rt
            .spawn_blocking(move || this.import_sync(path, mode, format, progress))
            .map(flatten_to_io)
            .boxed()
    }

    fn import_bytes(&self, data: Bytes, format: Format) -> BoxFuture<'_, io::Result<PinnedCid>> {
        let this = self.clone();
        self.0
            .options
            .rt
            .spawn_blocking(move || this.import_bytes_sync(data, format))
            .map(flatten_to_io)
            .boxed()
    }

    fn set_root(&self, name: &[u8], value: Option<Cid>) -> BoxFuture<io::Result<()>> {
        let name_debug = if let Ok(text) = std::str::from_utf8(&name) {
            format!("\"{}\"", text)
        } else {
            hex::encode(&name)
        };
        tracing::info!("set_root {} {:?}", name_debug, value);
        let mut state = self.0.state.write().unwrap();
        if let Some(item) = value {
            state.roots.insert(name.to_vec().into(), item);
        } else {
            state.roots.remove(name);
        }
        async move { Ok(()) }.boxed()
    }

    fn temp_pin(&self, cid: Cid) -> PinnedCid {
        PinnedCid::new(cid, Some(self.0.clone()))
    }

    fn clear_live(&self) {
        let mut state = self.0.state.write().unwrap();
        state.live.clear();
    }

    fn add_live(&self, elements: impl IntoIterator<Item = Hash>) {
        let mut state = self.0.state.write().unwrap();
        state.live.extend(elements);
    }

    fn is_live(&self, hash: &Hash) -> bool {
        let state = self.0.state.read().unwrap();
        let res = state.live.contains(hash);
        println!("is_live: {:?} {} {}", hash, state.live.len(), res);
        res
    }

    fn delete(&self, hash: &Hash) -> BoxFuture<'_, io::Result<()>> {
        println!("delete: {:?}", hash);
        let this = self.clone();
        let hash = *hash;
        self.0
            .options
            .rt
            .spawn_blocking(move || this.delete_sync(hash))
            .map(flatten_to_io)
            .boxed()
    }
}

impl LivenessTracker for Inner {
    fn on_clone(&self, cid: &Cid) {
        tracing::info!("temp pinning: {:?}", cid);
        let mut state = self.state.write().unwrap();
        let entry = state.temp.entry(*cid).or_default();
        // panic if we overflow an u64
        *entry = entry.checked_add(1).unwrap();
    }

    fn on_drop(&self, cid: &Cid) {
        tracing::info!("temp pin drop: {:?}", cid);
        let mut state = self.state.write().unwrap();
        let entry = state.temp.entry(*cid).or_default();
        *entry = entry.saturating_sub(1);
        if *entry == 0 {
            state.temp.remove(cid);
        }
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

impl Store {
    fn import_sync(
        self,
        path: PathBuf,
        mode: ImportMode,
        format: Format,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(PinnedCid, u64)> {
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
        let complete_io_guard = self.0.complete_io_mutex.lock().unwrap();
        let id = progress.new_id();
        progress.blocking_send(ImportProgress::Found {
            id,
            path: path.clone(),
        })?;
        let (cid, new, outboard) = match mode {
            ImportMode::TryReference => {
                // compute outboard and hash from the data in place, since we assume that it is stable
                let size = path.metadata()?.len();
                progress.blocking_send(ImportProgress::Size { id, size })?;
                let progress2 = progress.clone();
                let (hash, outboard) = compute_outboard(&path, size, move |offset| {
                    Ok(progress2.try_send(ImportProgress::OutboardProgress { id, offset })?)
                })?;
                progress.blocking_send(ImportProgress::OutboardDone { id, hash })?;
                use baomap::Store;
                let cid = self.temp_pin((hash, format));
                (cid, CompleteEntry::new_external(size, path), outboard)
            }
            ImportMode::Copy => {
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
                use baomap::Store;
                // the cid must be pinned before we move the file, otherwise there is a race condition
                // where it might be deleted here.
                let cid = self.temp_pin((hash, Format::Blob));
                std::fs::rename(temp_data_path, data_path)?;
                (cid, CompleteEntry::new_default(size), outboard)
            }
        };
        // all writes here are protected by the temp pin
        let hash = *cid.hash();
        if let Some(outboard) = outboard.as_ref() {
            let outboard_path = self.owned_outboard_path(&hash);
            std::fs::write(outboard_path, outboard)?;
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
        drop(complete_io_guard);
        Ok((cid, size))
    }

    fn import_bytes_sync(&self, data: Bytes, format: Format) -> io::Result<PinnedCid> {
        let complete_io_guard = self.0.complete_io_mutex.lock().unwrap();
        let (outboard, hash) = bao_tree::io::outboard(&data, IROH_BLOCK_SIZE);
        let hash = hash.into();
        use baomap::Store;
        let cid = self.temp_pin((hash, format));
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
        drop(complete_io_guard);
        Ok(cid)
    }

    fn delete_sync(&self, hash: Hash) -> io::Result<()> {
        let mut data = None;
        let mut outboard = None;
        let mut external = None;
        let mut partial_data = None;
        let mut partial_outboard = None;
        let complete_io_guard = self.0.complete_io_mutex.lock().unwrap();
        let mut state = self.0.state.write().unwrap();
        if let Some(entry) = state.complete.remove(&hash) {
            if entry.owned_data {
                data = Some(self.owned_data_path(&hash));
            }
            if needs_outboard(entry.size) {
                outboard = Some(self.owned_outboard_path(&hash));
            }
            if !entry.external.is_empty() {
                external = Some(self.0.options.paths_path(hash));
            }
        }
        if let Some(partial) = state.partial.remove(&hash) {
            partial_data = Some(self.0.options.partial_data_path(hash, &partial.uuid));
            if needs_outboard(partial.size) {
                partial_outboard = Some(self.0.options.partial_outboard_path(hash, &partial.uuid));
            }
        }
        state.outboard.remove(&hash);
        state.data.remove(&hash);
        drop(state);
        if let Some(data) = data {
            if let Err(cause) = std::fs::remove_file(data) {
                tracing::warn!("failed to delete data file: {}", cause);
            }
        }
        if let Some(external) = external {
            if let Err(cause) = std::fs::remove_file(external) {
                tracing::warn!("failed to delete partial outboard file: {}", cause);
            }
        }
        if let Some(outboard) = outboard {
            if let Err(cause) = std::fs::remove_file(outboard) {
                tracing::warn!("failed to delete outboard file: {}", cause);
            }
        }
        drop(complete_io_guard);
        // deleting the partial data and outboard files can happen at any time.
        // there is no race condition since these are unique names.
        if let Some(partial_data) = partial_data {
            if let Err(cause) = std::fs::remove_file(partial_data) {
                tracing::warn!("failed to delete partial data file: {}", cause);
            }
        }
        if let Some(partial_outboard) = partial_outboard {
            if let Err(cause) = std::fs::remove_file(partial_outboard) {
                tracing::warn!("failed to delete partial outboard file: {}", cause);
            }
        }
        Ok(())
    }

    fn insert_complete_sync(&self, entry: PartialEntry) -> io::Result<()> {
        let hash = entry.hash.into();
        let data_path = self.0.options.owned_data_path(&hash);
        let size = entry.size;
        let temp_data_path = entry.data_path;
        let temp_outboard_path = entry.outboard_path;
        let complete_io_guard = self.0.complete_io_mutex.lock().unwrap();
        // for a short time we will have neither partial nor complete
        self.0.state.write().unwrap().partial.remove(&hash);
        std::fs::rename(temp_data_path, &data_path)?;
        let outboard = if temp_outboard_path.exists() {
            let outboard_path = self.0.options.owned_outboard_path(&hash);
            std::fs::rename(temp_outboard_path, &outboard_path)?;
            Some(std::fs::read(&outboard_path)?.into())
        } else {
            None
        };
        let mut state = self.0.state.write().unwrap();
        let entry = state.complete.entry(hash).or_default();
        entry.union_with(CompleteEntry::new_default(size))?;
        if let Some(outboard) = outboard {
            state.outboard.insert(hash, outboard);
        }
        drop(complete_io_guard);
        Ok(())
    }

    fn export_sync(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
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
        let stable = mode == ExportMode::TryReference;
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
            tracing::info!("copying {} to {}", source.display(), target.display());
            progress(0)?;
            // todo: progress
            std::fs::copy(&source, &target)?;
            progress(size)?;
            let mut state = self.0.state.write().unwrap();
            let Some(entry) = state.complete.get_mut(&hash) else {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "hash not found in database",
                ));
            };
            if mode == ExportMode::TryReference {
                entry.external.insert(target);
                Some(entry.external_to_bytes())
            } else {
                None
            }
        };
        if let Some(path_bytes) = path_bytes {
            let pp = self.paths_path(hash);
            std::fs::write(pp, path_bytes)?;
        }
        Ok(())
    }

    /// scan a directory for data
    pub(crate) fn load_sync(
        complete_path: PathBuf,
        partial_path: PathBuf,
        rt: iroh_bytes::util::runtime::Handle,
    ) -> anyhow::Result<Self> {
        tracing::info!(
            "loading database from {} {}",
            complete_path.display(),
            partial_path.display()
        );
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
                    tracing::warn!(
                        "unable to open owned data file {}. removing {}",
                        data_path.display(),
                        hex::encode(hash)
                    );
                    continue;
                };
                meta.len()
            } else if let Some(external) = external.iter().next() {
                let Ok(meta) = std::fs::metadata(external) else {
                    tracing::warn!(
                        "unable to open external data file {}. removing {}",
                        external.display(),
                        hex::encode(hash)
                    );
                    continue;
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
                entries
                    .iter()
                    .filter_map(|(uuid, (data_path, outboard_path))| {
                        let data_path = data_path.as_ref()?;
                        let outboard_path = outboard_path.as_ref()?;
                        let Ok(data_meta) = std::fs::metadata(data_path) else {
                            tracing::warn!(
                                "unable to open partial data file {}",
                                data_path.display()
                            );
                            return None;
                        };
                        let Ok(outboard_file) = std::fs::File::open(outboard_path) else {
                            tracing::warn!(
                                "unable to open partial outboard file {}",
                                outboard_path.display()
                            );
                            return None;
                        };
                        let mut expected_size = [0u8; 8];
                        let Ok(_) = outboard_file.read_at(0, &mut expected_size) else {
                            tracing::warn!(
                                "partial outboard file is missing length {}",
                                outboard_path.display()
                            );
                            return None;
                        };
                        let current_size = data_meta.len();
                        let expected_size = u64::from_le_bytes(expected_size);
                        Some((current_size, expected_size, uuid))
                    })
                    .max_by_key(|x| x.0)
            } else {
                None
            };
            if let Some((current_size, expected_size, uuid)) = best {
                if current_size > 0 {
                    partial.insert(
                        hash,
                        PartialEntryData {
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
                live: Default::default(),
                roots: Default::default(),
                temp: Default::default(),
            }),
            options: Options {
                complete_path,
                partial_path,
                move_threshold: 1024 * 128,
                inline_threshold: 1024 * 16,
                rt: rt.main().clone(),
            },
            complete_io_mutex: Mutex::new(()),
        })))
    }

    /// Blocking load a database from disk.
    pub fn load_blocking(
        complete_path: impl AsRef<Path>,
        partial_path: impl AsRef<Path>,
        rt: &iroh_bytes::util::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let complete_path = complete_path.as_ref().to_path_buf();
        let partial_path = partial_path.as_ref().to_path_buf();
        let rt = rt.clone();
        let db = Self::load_sync(complete_path, partial_path, rt)?;
        Ok(db)
    }

    /// Load a database from disk.
    pub async fn load(
        complete_path: impl AsRef<Path>,
        partial_path: impl AsRef<Path>,
        rt: &iroh_bytes::util::runtime::Handle,
    ) -> anyhow::Result<Self> {
        let complete_path = complete_path.as_ref().to_path_buf();
        let partial_path = partial_path.as_ref().to_path_buf();
        let rtc = rt.clone();
        let db = rt
            .main()
            .spawn_blocking(move || Self::load_sync(complete_path, partial_path, rtc))
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

/// The extension for outboard files. We use obao4 to indicate that this is an outboard
/// in the standard pre order format (obao like in the bao crate), but with a chunk group
/// size of 4, unlike the bao crate which uses 0.
const OUTBOARD_EXT: &str = "obao4";

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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_hash() -> impl Strategy<Value = Hash> {
        any::<[u8; 32]>().prop_map(|x| x.into())
    }

    fn arb_filename() -> impl Strategy<Value = FileName> {
        prop_oneof![
            arb_hash().prop_map(FileName::Data),
            arb_hash().prop_map(FileName::Outboard),
            arb_hash().prop_map(FileName::Paths),
            (arb_hash(), any::<[u8; 16]>())
                .prop_map(|(hash, uuid)| FileName::PartialData(hash, uuid)),
            (arb_hash(), any::<[u8; 16]>())
                .prop_map(|(hash, uuid)| FileName::PartialOutboard(hash, uuid)),
            any::<Vec<u8>>().prop_map(FileName::Meta),
        ]
    }

    #[test]
    fn filename_parse_error() {
        assert!(FileName::from_str("foo").is_err());
        assert!(FileName::from_str("1234.data").is_err());
        assert!(FileName::from_str("1234ABDC.outboard").is_err());
        assert!(FileName::from_str("1234-1234.data").is_err());
        assert!(FileName::from_str("1234ABDC-1234.outboard").is_err());
    }

    proptest! {
        #[test]
        fn filename_roundtrip(name in arb_filename()) {
            let s = name.to_string();
            let name2 = super::FileName::from_str(&s).unwrap();
            prop_assert_eq!(name, name2);
        }
    }
}
