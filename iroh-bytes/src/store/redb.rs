//! redb backed storage

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::SystemTime,
};

use bao_tree::io::{
    fsm::Outboard,
    outboard::PostOrderMemOutboard,
    sync::{ReadAt, Size},
};
use bytes::Bytes;
use futures::{FutureExt, Stream, StreamExt};

use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};
use iroh_io::AsyncSliceReader;
use redb::{ReadTransaction, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use tokio::io::AsyncWriteExt;
use tracing::trace_span;

use crate::{
    store::bao_file::{BaoFileStorage, CompleteMemOrFileStorage},
    util::{
        progress::{IdGenerator, IgnoreProgressSender, ProgressSender},
        LivenessTracker, MemOrFile,
    },
    Tag, TempTag, IROH_BLOCK_SIZE,
};

use super::{
    bao_file::{self, raw_outboard_size, BaoFileConfig},
    flatten_to_io, temp_name, BaoBatchWriter, EntryStatus, ExportMode, ImportMode, ImportProgress,
    MapEntry, ReadableStore, TempCounterMap,
};

use super::{BaoBlobSize, Map};

const BLOBS_TABLE: TableDefinition<Hash, EntryState> = TableDefinition::new("blobs-0");

const TAGS_TABLE: TableDefinition<&[u8], HashAndFormat> = TableDefinition::new("tags-0");

const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> = TableDefinition::new("inline-data-0");

const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-outboard-0");

/// Location of the data.
///
/// Data can be inlined in the database, a file conceptually owned by the store,
/// or a number of external files conceptually owned by the user.
///
/// Only complete data can be inlined.
#[derive(Debug, Serialize, Deserialize)]
enum DataLocation {
    /// Data is in the inline_data table.
    Inline,
    /// Data is in the canonical location in the data directory.
    Owned,
    /// Data is in several external locations. This should be a non-empty list.
    External(Vec<PathBuf>),
}

/// Location of the outboard.
///
/// Outboard can be inlined in the database or a file conceptually owned by the store.
/// Outboards are implementation specific to the store and as such are always owned.
///
/// Only complete outboards can be inlined.
#[derive(Debug, Serialize, Deserialize)]
enum OutboardLocation {
    /// Outboard is in the inline_outboard table.
    Inline,
    /// Outboard is in the canonical location in the data directory.
    Owned,
    /// Outboard is not needed,
    NotNeeded,
}

/// The information about an entry that we keep in the entry table for quick access.
///
/// The exact info to store here is TBD, so usually you should use the accessor methods.
#[derive(Debug, Serialize, Deserialize)]
enum EntryState {
    /// For a complete entry we always know the size. It does not make much sense
    /// to write to a complete entry, so they are much easier to share.
    Complete {
        /// The validated size of the complete entry.
        size: u64,
        /// Location of the data.
        data_location: DataLocation,
        /// Location of the outboard.
        outboard_location: OutboardLocation,
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
    fn union(self, that: Self) -> io::Result<Self> {
        match (self, that) {
            (a @ Self::Complete { .. }, Self::Complete { .. }) => Ok(a),
            (a @ Self::Complete { .. }, Self::Partial { .. }) => Ok(a),
            (Self::Partial { .. }, b @ Self::Complete { .. }) => Ok(b),
            (Self::Partial { size: a_size }, Self::Partial { size: b_size }) => Ok(Self::Partial {
                size: a_size.or(b_size),
            }),
        }
    }

    fn complete(&self) -> bool {
        match self {
            Self::Complete { .. } => true,
            Self::Partial { .. } => false,
        }
    }

    /// If this is true, there should be a corresponding entry in the inline_outboard table.
    ///
    /// It is false either if there is no outboard at all, or if it in a file.
    fn inline_outboard(&self) -> bool {
        matches!(
            self,
            Self::Complete {
                outboard_location: OutboardLocation::Inline,
                ..
            }
        )
    }

    /// If this is true, there should be a corresponding entry in the inline_data table.
    ///
    /// It is false either if the data is in an owned file or in one or more external files.
    fn inline_data(&self) -> bool {
        matches!(
            self,
            Self::Complete {
                data_location: DataLocation::Inline,
                ..
            }
        )
    }

    fn owned(&self) -> bool {
        match self {
            Self::Complete { data_location, .. } => matches!(data_location, DataLocation::Owned),
            Self::Partial { .. } => true,
        }
    }
}

impl redb::RedbValue for EntryState {
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

#[derive(Debug)]
struct Inner {
    redb: redb::Database,
    state: RwLock<State>,
    options: Options,
}

impl LivenessTracker for Inner {
    fn on_clone(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tagging: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.inc(inner);
    }

    fn on_drop(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tag drop: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.dec(inner);
    }
}

#[derive(Debug)]
struct Options {
    complete_path: PathBuf,
    partial_path: PathBuf,
    max_data_inlined: u64,
    max_outboard_inlined: u64,
    move_threshold: u64,
}

impl Options {
    fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path.join(format!("{}.data", hash.to_hex()))
    }

    fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.complete_path.join(format!("{}.obao4", hash.to_hex()))
    }
}

#[derive(Debug)]
struct State {
    /// LRU cache of open bao files
    memory: BTreeMap<Hash, Entry>,
    temp: TempCounterMap,
    live: BTreeSet<Hash>,
}

///
#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
    create_options: Arc<BaoFileConfig>,
}

#[derive(derive_more::Debug)]
enum ImportFile {
    TempFile(PathBuf),
    External(PathBuf),
    Memory(#[debug(skip)] Bytes),
}

impl ImportFile {
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

impl Store {
    /// Path to the directory where complete files and outboard files are stored.
    pub(crate) fn complete_path(root: &Path) -> PathBuf {
        root.join("complete")
    }

    /// Path to the directory where partial files and outboard are stored.
    pub(crate) fn partial_path(root: &Path) -> PathBuf {
        root.join("partial")
    }

    /// Path to the directory where metadata is stored.
    pub(crate) fn meta_path(root: &Path) -> PathBuf {
        root.join("meta")
    }

    pub(crate) fn db_path(root: &Path) -> PathBuf {
        Self::meta_path(root).join("db.v1")
    }

    fn load_data(
        options: &Options,
        tx: &ReadTransaction,
        location: DataLocation,
        size: u64,
        hash: &Hash,
    ) -> io::Result<MemOrFile<Bytes, (std::fs::File, u64)>> {
        Ok(match location {
            DataLocation::Inline => {
                let data = tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
                let Some(data) = data.get(hash).map_err(to_io_err)? else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "inconsistent database state: {} should have inline data but does not",
                            hash.to_hex()
                        ),
                    ));
                };
                MemOrFile::Mem(Bytes::copy_from_slice(data.value()))
            }
            DataLocation::Owned => {
                let data_size = size;
                let path = options.owned_data_path(&hash);
                let Ok(file) = std::fs::File::open(&path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("file not found: {}", path.display()),
                    ));
                };
                MemOrFile::File((file, data_size))
            }
            DataLocation::External(_paths) => {
                unimplemented!()
            }
        })
    }

    fn load_outboard(
        options: &Options,
        tx: &ReadTransaction,
        location: OutboardLocation,
        size: u64,
        hash: &Hash,
    ) -> io::Result<MemOrFile<Bytes, (std::fs::File, u64)>> {
        Ok(match location {
            OutboardLocation::NotNeeded => MemOrFile::Mem(Bytes::new()),
            OutboardLocation::Inline => {
                let outboard = tx.open_table(INLINE_OUTBOARD_TABLE).map_err(to_io_err)?;
                let Some(outboard) = outboard.get(hash).map_err(to_io_err)? else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("inconsistent database state: {} should have inline outboard but does not", hash.to_hex()),
                    ));
                };
                MemOrFile::Mem(Bytes::copy_from_slice(outboard.value()))
            }
            OutboardLocation::Owned => {
                let outboard_size = raw_outboard_size(size);
                let path = options.owned_outboard_path(&hash);
                let Ok(file) = std::fs::File::open(&path) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("file not found: {} size={}", path.display(), outboard_size),
                    ));
                };
                MemOrFile::File((file, outboard_size))
            }
        })
    }

    fn dump(&self) -> std::result::Result<(), redb::Error> {
        let tx = self.inner.redb.begin_read()?;
        let blobs = tx.open_table(BLOBS_TABLE)?;
        let tags = tx.open_table(TAGS_TABLE)?;
        let inline_data = tx.open_table(INLINE_DATA_TABLE)?;
        let inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE)?;
        for e in blobs.iter()? {
            let (k, v) = e?;
            let k = k.value();
            let v = v.value();
            println!("blobs: {} -> {:?}", k.to_hex(), v);
        }
        for e in tags.iter()? {
            let (k, v) = e?;
            let k = Tag::from(Bytes::copy_from_slice(k.value()));
            let v = v.value();
            println!("tags: {} -> {:?}", k, v);
        }
        for e in inline_data.iter()? {
            let (k, v) = e?;
            let k = k.value();
            let v = v.value();
            println!("inline_data: {} -> {:?}", k.to_hex(), v.len());
        }
        for e in inline_outboard.iter()? {
            let (k, v) = e?;
            let k = k.value();
            let v = v.value();
            println!("inline_outboard: {} -> {:?}", k.to_hex(), v.len());
        }
        Ok(())
    }

    fn temp_path(&self) -> PathBuf {
        self.inner.options.partial_path.join(temp_name())
    }

    ///
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let db = tokio::task::spawn_blocking(move || Self::load_sync(&path)).await??;
        Ok(db)
    }

    ///
    pub fn load_sync(path: &Path) -> anyhow::Result<Self> {
        tracing::info!("loading database from {}", path.display(),);
        let complete_path = Self::complete_path(path);
        let partial_path = Self::partial_path(path);
        let meta_path = Self::meta_path(path);
        std::fs::create_dir_all(&complete_path)?;
        std::fs::create_dir_all(&partial_path)?;
        std::fs::create_dir_all(&meta_path)?;
        let db_path = Self::db_path(path);
        let redb = redb::Database::create(db_path)?;
        let tx = redb.begin_write()?;
        {
            let _ = tx.open_table(BLOBS_TABLE)?;
            let _ = tx.open_table(TAGS_TABLE)?;
            let _ = tx.open_table(INLINE_DATA_TABLE)?;
            let _ = tx.open_table(INLINE_OUTBOARD_TABLE)?;
        }
        tx.commit()?;
        let options = Options {
            complete_path: complete_path.clone(),
            partial_path,
            max_data_inlined: 1024 * 16,
            max_outboard_inlined: 1024 * 16,
            move_threshold: 1024 * 16,
        };
        let state = State {
            memory: Default::default(),
            temp: Default::default(),
            live: Default::default(),
        };
        let inner = Arc::new(Inner {
            redb,
            state: RwLock::new(state),
            options,
        });
        let inner2 = inner.clone();
        let cb: bao_file::CreateCb = Arc::new(move |hash| {
            let hash = Hash::from(*hash);
            let tx = inner2.redb.begin_write().map_err(to_io_err)?;
            {
                let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
                let entry = blobs
                    .get(hash)
                    .map_err(to_io_err)?
                    .map(|x| x.value())
                    .unwrap_or_default();
                let entry = entry.union(EntryState::Partial { size: None })?;
                blobs.insert(hash, entry).map_err(to_io_err)?;
            }
            tx.commit().map_err(to_io_err)?;
            Ok(())
        });
        let create_options = Arc::new(BaoFileConfig::new(
            Arc::new(complete_path),
            1024 * 16,
            Some(cb),
        ));
        let res = Self {
            inner,
            create_options,
        };
        // res.dump().map_err(to_io_err)?;
        Ok(res)
    }

    fn import_file_sync(
        self,
        path: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(TempTag, u64)> {
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
            name: path.to_string_lossy().to_string(),
        })?;
        let file = match mode {
            ImportMode::TryReference => ImportFile::External(path),
            ImportMode::Copy => {
                let size = path.metadata()?.len();
                if size <= self.inner.options.max_data_inlined {
                    let data = Bytes::from(std::fs::read(&path)?);
                    ImportFile::Memory(data)
                } else {
                    let temp_path = self.temp_path();
                    // copy the data, since it is not stable
                    progress.try_send(ImportProgress::CopyProgress { id, offset: 0 })?;
                    if reflink_copy::reflink_or_copy(&path, &temp_path)?.is_none() {
                        tracing::debug!("reflinked {} to {}", path.display(), temp_path.display());
                    } else {
                        tracing::debug!("copied {} to {}", path.display(), temp_path.display());
                    }
                    ImportFile::TempFile(temp_path)
                }
            }
        };
        let (tag, size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok((tag, size))
    }

    fn import_bytes_sync(&self, data: Bytes, format: BlobFormat) -> io::Result<TempTag> {
        let id = 0;
        let file = ImportFile::Memory(data);
        let progress = IgnoreProgressSender::default();
        let (tag, _size) = self.finalize_import_sync(file, format, id, progress)?;
        Ok(tag)
    }

    fn finalize_import_sync(
        &self,
        file: ImportFile,
        format: BlobFormat,
        id: u64,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> io::Result<(TempTag, u64)> {
        let data_size = file.len()?;
        let outboard_size = raw_outboard_size(data_size);
        let inline_data = data_size <= self.inner.options.max_data_inlined;
        let inline_outboard =
            outboard_size <= self.inner.options.max_outboard_inlined && outboard_size != 0;
        tracing::info!("finalize_import_sync {:?} {}", file, data_size);
        progress.blocking_send(ImportProgress::Size {
            id,
            size: data_size,
        })?;
        let progress2 = progress.clone();
        let (hash, outboard) = match file.content() {
            MemOrFile::File(path) => {
                let span = trace_span!("outboard.compute", path = %path.display());
                let _guard = span.enter();
                let file = std::fs::File::open(&path)?;
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
        use super::Store;
        // from here on, everything related to the hash is protected by the temp tag
        let tag = self.temp_tag(HashAndFormat { hash, format });
        let hash = *tag.hash();
        // move the data file into place, or create a reference to it
        //
        // todo: can I do the io ops outside of the transaction?
        let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
        {
            let (data_location, inline_data) = match file {
                ImportFile::External(external_path) => {
                    tracing::info!("stored external reference {}", external_path.display());
                    if inline_data {
                        tracing::info!(
                            "reading external data to inline it: {}",
                            external_path.display()
                        );
                        let data = Bytes::from(std::fs::read(&external_path)?);
                        (DataLocation::Inline, Some(data))
                    } else {
                        (DataLocation::External(vec![external_path]), None)
                    }
                }
                ImportFile::TempFile(temp_data_path) => {
                    if inline_data {
                        tracing::info!(
                            "reading and deleting temp file to inline it: {}",
                            temp_data_path.display()
                        );
                        let data = Bytes::from(read_and_remove(&temp_data_path)?);
                        (DataLocation::Inline, Some(data))
                    } else {
                        let data_path = self.inner.options.owned_data_path(&hash);
                        std::fs::rename(&temp_data_path, &data_path)?;
                        tracing::info!("created file {}", data_path.display());
                        (DataLocation::Owned, None)
                    }
                }
                ImportFile::Memory(data) => {
                    if inline_data {
                        (DataLocation::Inline, Some(data))
                    } else {
                        let data_path = self.inner.options.owned_data_path(&hash);
                        overwrite_and_sync(&data_path, &data)?;
                        tracing::info!("created file {}", data_path.display());
                        (DataLocation::Owned, None)
                    }
                }
            };
            let (outboard_location, inline_outboard) = if let Some(outboard) = outboard {
                if inline_outboard {
                    (OutboardLocation::Inline, Some(outboard))
                } else {
                    let outboard_path = self.inner.options.owned_outboard_path(&hash);
                    overwrite_and_sync(&outboard_path, &outboard)?;
                    (OutboardLocation::Owned, None)
                }
            } else {
                (OutboardLocation::NotNeeded, None)
            };
            let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
            let entry = blobs
                .get(&hash)
                .map_err(to_io_err)?
                .map(|x| x.value())
                .unwrap_or_default();
            let entry = entry.union(EntryState::Complete {
                size: data_size,
                data_location,
                outboard_location,
            })?;
            tracing::debug!("inserting entry for {}", hash.to_hex());
            blobs.insert(hash, entry).map_err(to_io_err)?;
            if let Some(data) = inline_data {
                let mut inline_data = tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
                inline_data.insert(hash, data.as_ref()).map_err(to_io_err)?;
            }
            if let Some(outboard) = inline_outboard {
                let mut inline_outboard =
                    tx.open_table(INLINE_OUTBOARD_TABLE).map_err(to_io_err)?;
                inline_outboard
                    .insert(hash, outboard.as_slice())
                    .map_err(to_io_err)?;
            }
        }
        tx.commit().map_err(to_io_err)?;
        tracing::debug!("finalize_import_sync committed");
        // self.dump().map_err(to_io_err)?;
        Ok((tag, data_size))
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
        // get the data or data source and info
        // for now, we don't support exporting partial data
        let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
        let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let (source, outboard_location) = {
            let entry = blobs.get(&hash).map_err(to_io_err)?.map(|x| x.value());
            match entry {
                Some(EntryState::Complete {
                    size,
                    data_location,
                    outboard_location,
                }) => (
                    match data_location {
                        DataLocation::Inline => {
                            let inline_data =
                                tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
                            let data = inline_data.get(&hash).map_err(to_io_err)?.unwrap();
                            let data = Bytes::copy_from_slice(data.value());
                            MemOrFile::Mem(data)
                        }
                        DataLocation::Owned => {
                            let path = self.inner.options.owned_data_path(&hash);
                            MemOrFile::File((path, size, true))
                        }
                        DataLocation::External(paths) => {
                            if let Some(path) = paths.get(0) {
                                MemOrFile::File((path.to_owned(), size, false))
                            } else {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "external data location is empty",
                                ));
                            }
                        }
                    },
                    outboard_location,
                ),
                Some(EntryState::Partial { .. }) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "data is not complete",
                    ));
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "hash not found in database",
                    ))
                }
            }
        };
        // copy all the things
        let stable = mode == ExportMode::TryReference;
        match source {
            MemOrFile::Mem(data) => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                file.write_all(&data)?;
            }
            MemOrFile::File((source, size, owned)) => {
                if size >= self.inner.options.move_threshold && stable && owned {
                    tracing::debug!("moving {} to {}", source.display(), target.display());
                    std::fs::rename(source, &target)?;
                    let entry = EntryState::Complete {
                        size,
                        data_location: DataLocation::External(vec![target]),
                        outboard_location,
                    };
                    blobs.insert(hash, entry).map_err(to_io_err)?;
                } else {
                    tracing::debug!("copying {} to {}", source.display(), target.display());
                    progress(0)?;
                    // todo: progress? not needed if the file is small
                    if reflink_copy::reflink_or_copy(&source, &target)?.is_none() {
                        tracing::debug!("reflinked {} to {}", source.display(), target.display());
                    } else {
                        tracing::debug!("copied {} to {}", source.display(), target.display());
                    }
                    progress(size)?;
                    // todo: should we add the new location to the entry if it was already non-owned?
                }
            }
        };
        drop(blobs);
        tx.commit().map_err(to_io_err)?;
        Ok(())
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> io::Result<super::DbIter<Hash>> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let res = blobs
            .iter()
            .map_err(to_io_err)?
            .filter_map(|r| {
                let (hash, entry) = match r {
                    Ok((k, v)) => (k, v),
                    Err(e) => return Some(Err(to_io_err(e))),
                };
                let hash = hash.value();
                let entry = entry.value();
                if entry.complete() {
                    Some(Ok(hash))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(Box::new(res.into_iter()))
    }

    fn partial_blobs(&self) -> io::Result<super::DbIter<Hash>> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let res = blobs
            .iter()
            .map_err(to_io_err)?
            .filter_map(|r| {
                let (hash, entry) = match r {
                    Ok((k, v)) => (k, v),
                    Err(e) => return Some(Err(to_io_err(e))),
                };
                let hash = hash.value();
                let entry = entry.value();
                if !entry.complete() {
                    Some(Ok(hash))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(Box::new(res.into_iter()))
    }

    fn tags(&self) -> io::Result<super::DbIter<(crate::Tag, iroh_base::hash::HashAndFormat)>> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let tags = tx.open_table(TAGS_TABLE).map_err(to_io_err)?;
        let res = tags
            .iter()
            .map_err(to_io_err)?
            .map(|r| {
                let (tag, hash) = r.map_err(to_io_err)?;
                let tag = Tag::from(Bytes::copy_from_slice(tag.value()));
                let hash = hash.value();
                Ok((tag, hash))
            })
            .collect::<Vec<_>>();
        tracing::info!("tags: {:?}", res);
        Ok(Box::new(res.into_iter()))
    }

    fn temp_tags(
        &self,
    ) -> Box<dyn Iterator<Item = iroh_base::hash::HashAndFormat> + Send + Sync + 'static> {
        let tags = self.inner.state.read().unwrap().temp.keys();
        Box::new(tags)
    }

    async fn validate(
        &self,
        _tx: tokio::sync::mpsc::Sender<super::ValidateProgress>,
    ) -> io::Result<()> {
        self.dump().map_err(to_io_err)?;
        Ok(())
    }

    async fn export(
        &self,
        hash: Hash,
        target: std::path::PathBuf,
        mode: super::ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.export_sync(hash, target, mode, progress))
            .map(flatten_to_io)
            .await
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
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.import_file_sync(path, mode, format, progress))
            .map(flatten_to_io)
            .await
    }

    async fn import_bytes(
        &self,
        data: bytes::Bytes,
        format: iroh_base::hash::BlobFormat,
    ) -> io::Result<crate::TempTag> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.import_bytes_sync(data, format))
            .map(flatten_to_io)
            .await
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
        let temp_data_path = this.temp_path();
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
        let file = ImportFile::TempFile(temp_data_path);
        tokio::task::spawn_blocking(move || this.finalize_import_sync(file, format, id, progress))
            .map(flatten_to_io)
            .await
    }

    async fn set_tag(&self, name: crate::Tag, hash: Option<HashAndFormat>) -> io::Result<()> {
        tracing::info!("set tag: {:?} -> {:?}", name, hash);
        let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
        {
            let mut tags = tx.open_table(TAGS_TABLE).map_err(to_io_err)?;
            if let Some(hash) = hash {
                tags.insert(name.0.as_ref(), hash).map_err(to_io_err)?;
            } else {
                tags.remove(name.0.as_ref()).map_err(to_io_err)?;
            }
        }
        tx.commit().map_err(to_io_err)?;
        Ok(())
    }

    async fn create_tag(&self, hash: HashAndFormat) -> io::Result<Tag> {
        tracing::info!("create tag: {:?}", hash);
        let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
        let res = {
            let mut tags = tx.open_table(TAGS_TABLE).map_err(to_io_err)?;
            let tag = Tag::auto(SystemTime::now(), |tag| match tags.get(tag) {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    tracing::error!("error checking tag: {}", e);
                    false
                }
            });
            tags.insert(tag.0.as_ref(), hash).map_err(to_io_err)?;
            tag
        };
        tx.commit().map_err(to_io_err)?;
        Ok(res)
    }

    fn temp_tag(&self, content: HashAndFormat) -> TempTag {
        TempTag::new(content, Some(self.inner.clone()))
    }

    fn clear_live(&self) {
        let mut state = self.inner.state.write().unwrap();
        state.live.clear();
    }

    fn add_live(&self, elements: impl IntoIterator<Item = Hash>) {
        let mut state = self.inner.state.write().unwrap();
        state.live.extend(elements);
        tracing::info!("add_live {:?}", state.live);
    }

    fn is_live(&self, hash: &Hash) -> bool {
        let state = self.inner.state.read().unwrap();
        // a blob is live if it is either in the live set, or it is temp tagged
        state.live.contains(hash) || state.temp.contains(hash)
    }

    async fn delete(&self, hashes: Vec<Hash>) -> io::Result<()> {
        let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
        {
            let mut state = self.inner.state.write().unwrap();
            let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
            let mut inline_data = tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
            let mut inline_outboard = tx.open_table(INLINE_OUTBOARD_TABLE).map_err(to_io_err)?;
            for hash in hashes {
                tracing::info!("deleting {}", hash.to_hex());
                state.memory.remove(&hash);
                if let Some(entry) = blobs.remove(hash).map_err(to_io_err)? {
                    let entry = entry.value();
                    if entry.inline_data() {
                        inline_data.remove(hash).map_err(to_io_err)?;
                    }
                    if entry.inline_outboard() {
                        inline_outboard.remove(hash).map_err(to_io_err)?;
                    }
                    // delete the data file if it is owned
                    if entry.owned() {
                        let data_path = self.inner.options.owned_data_path(&hash);
                        std::fs::remove_file(data_path).ok();
                    }
                    // delete the outboard file in any case, it is always owned
                    let outboard_path = self.inner.options.owned_outboard_path(&hash);
                    std::fs::remove_file(outboard_path).ok();
                }
            }
        }
        tx.commit().map_err(to_io_err)?;
        Ok(())
    }
}

///
#[derive(Debug, Clone)]
pub struct Entry {
    inner: bao_file::BaoFileHandle,
}

impl super::MapEntry for Entry {
    fn hash(&self) -> Hash {
        self.inner.hash().into()
    }

    fn size(&self) -> BaoBlobSize {
        let size = self.inner.current_size().unwrap();
        tracing::info!("redb::Entry::size() = {}", size);
        BaoBlobSize::new(size, self.is_complete())
    }

    fn is_complete(&self) -> bool {
        self.inner.is_complete()
    }

    async fn available_ranges(&self) -> io::Result<bao_tree::ChunkRanges> {
        todo!()
    }

    async fn outboard(&self) -> io::Result<impl Outboard> {
        self.inner.outboard()
    }

    async fn data_reader(&self) -> io::Result<impl AsyncSliceReader> {
        Ok(self.inner.data_reader())
    }
}

impl super::MapEntryMut for Entry {
    async fn batch_writer(&self) -> io::Result<impl BaoBatchWriter> {
        Ok(self.inner.writer())
    }
}

impl super::Map for Store {
    type Entry = Entry;

    fn get(&self, hash: &Hash) -> io::Result<Option<Entry>> {
        let hash = *hash;
        let state = self.inner.state.write().unwrap();
        let lru = state.memory.get(&hash);
        if let Some(entry) = lru {
            return Ok(Some(entry.clone()));
        }
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let Some(entry) = blobs.get(hash).map_err(to_io_err)? else {
            tracing::debug!("redb get not found {}", hash.to_hex());
            return Ok(None);
        };
        // todo: if complete, load inline data and/or outboard into memory if needed,
        // and return a complete entry.
        let entry = entry.value();
        let config = self.create_options.clone();
        let inner = match entry {
            EntryState::Complete {
                size,
                data_location,
                outboard_location,
            } => {
                let data = Self::load_data(&self.inner.options, &tx, data_location, size, &hash)?;
                let outboard =
                    Self::load_outboard(&self.inner.options, &tx, outboard_location, size, &hash)?;
                bao_file::BaoFileHandle::new_complete(config, hash.into(), data, outboard)
            }
            EntryState::Partial { .. } => {
                bao_file::BaoFileHandle::new_partial(config, hash.into())?
            }
        };
        tracing::info!("redb get found {}", hash.to_hex());
        Ok(Some(Entry { inner }))
    }
}

impl super::MapMut for Store {
    type EntryMut = Entry;

    fn get_or_create_partial(&self, hash: Hash, _size: u64) -> io::Result<Entry> {
        tracing::debug!("get_or_create_partial({})", hash.to_hex());
        let state = self.inner.state.write().unwrap();
        let lru = state.memory.get(&hash);
        if let Some(entry) = lru {
            return Ok(entry.clone());
        }
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let inner = {
            let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
            let entry = blobs.get(hash).map_err(to_io_err)?;
            if let Some(entry) = entry {
                let entry = entry.value();
                match entry {
                    EntryState::Complete {
                        size,
                        data_location,
                        outboard_location,
                        ..
                    } => {
                        let data =
                            Self::load_data(&self.inner.options, &tx, data_location, size, &hash)?;
                        let outboard = Self::load_outboard(
                            &self.inner.options,
                            &tx,
                            outboard_location,
                            size,
                            &hash,
                        )?;
                        println!("creating complete entry for {}", hash.to_hex());
                        bao_file::BaoFileHandle::new_complete(
                            self.create_options.clone(),
                            hash.into(),
                            data,
                            outboard,
                        )
                    }
                    EntryState::Partial { .. } => {
                        println!("creating partial entry for {}", hash.to_hex());
                        bao_file::BaoFileHandle::new_partial(
                            self.create_options.clone(),
                            hash.into(),
                        )?
                    }
                }
            } else {
                bao_file::BaoFileHandle::new_mem(self.create_options.clone(), hash.into())
            }
        };
        Ok(Entry { inner })
    }

    fn entry_status(&self, hash: &Hash) -> io::Result<super::EntryStatus> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let Some(guard) = blobs.get(hash).map_err(to_io_err)? else {
            return Ok(EntryStatus::NotFound);
        };
        Ok(if guard.value().complete() {
            EntryStatus::Complete
        } else {
            EntryStatus::Partial
        })
    }

    fn get_possibly_partial(&self, hash: &Hash) -> io::Result<super::PossiblyPartialEntry<Self>> {
        match self.get(hash)? {
            Some(entry) => Ok({
                if entry.is_complete() {
                    super::PossiblyPartialEntry::Complete(entry)
                } else {
                    super::PossiblyPartialEntry::Partial(entry)
                }
            }),
            None => Ok(super::PossiblyPartialEntry::NotFound),
        }
    }

    async fn insert_complete(&self, entry: Entry) -> io::Result<()> {
        tracing::info!("inserting complete entry {:?}", entry);
        let hash: Hash = entry.inner.hash().into();
        // during all of this, the entry is locked
        let res = entry.inner.transform(|storage| {
            let (data, outboard, _sizes) = match storage {
                r @ BaoFileStorage::Complete(_) => return Ok(r),
                BaoFileStorage::IncompleteMem(storage) => {
                    let (data, outboard, sizes) = storage.into_parts();
                    (
                        MemOrFile::Mem(Bytes::from(data.into_parts().0)),
                        MemOrFile::Mem(Bytes::from(outboard.into_parts().0)),
                        MemOrFile::Mem(Bytes::from(sizes.to_vec()?)),
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
            let data = if data_size <= self.inner.options.max_data_inlined {
                match data {
                    MemOrFile::File(data) => {
                        let mut buf = vec![0; data_size as usize];
                        data.read_at(0, &mut buf)?;
                        let path: PathBuf = self.inner.options.owned_data_path(&hash);
                        // this whole file removal thing is not great. It should either fail, or try
                        // again until it works. Maybe have a set of stuff to delete and do it in gc?
                        if let Err(cause) = std::fs::remove_file(path) {
                            tracing::error!("failed to remove file: {}", cause);
                        };
                        MemOrFile::Mem(Bytes::from(buf))
                    }
                    MemOrFile::Mem(data) => MemOrFile::Mem(data),
                }
            } else {
                match data {
                    MemOrFile::Mem(data) => {
                        let path = self.inner.options.owned_data_path(&hash);
                        let file = overwrite_and_sync(&path, &data)?;
                        MemOrFile::File((file, data_size))
                    }
                    MemOrFile::File(data) => MemOrFile::File((data, data_size)),
                }
            };
            let data_location = if data.is_mem() {
                DataLocation::Inline
            } else {
                DataLocation::Owned
            };
            // inline outboard if needed, or write to file if needed
            let outboard = if outboard_size == 0 {
                Default::default()
            } else if outboard_size <= self.inner.options.max_outboard_inlined {
                match outboard {
                    MemOrFile::File(outboard) => {
                        let mut buf = vec![0; outboard_size as usize];
                        outboard.read_at(0, &mut buf)?;
                        drop(outboard);
                        let path: PathBuf = self.inner.options.owned_outboard_path(&hash);
                        // this whole file removal thing is not great. It should either fail, or try
                        // again until it works. Maybe have a set of stuff to delete and do it in gc?
                        if let Err(cause) = std::fs::remove_file(path) {
                            tracing::error!("failed to remove file: {}", cause);
                        };
                        MemOrFile::Mem(Bytes::from(buf))
                    }
                    MemOrFile::Mem(outboard) => MemOrFile::Mem(outboard),
                }
            } else {
                match outboard {
                    MemOrFile::Mem(outboard) => {
                        let path = self.inner.options.owned_outboard_path(&hash);
                        let file = overwrite_and_sync(&path, &outboard)?;
                        MemOrFile::File((file, outboard_size))
                    }
                    MemOrFile::File(outboard) => MemOrFile::File((outboard, outboard_size)),
                }
            };
            let outboard_location = if outboard_size == 0 {
                OutboardLocation::NotNeeded
            } else if data.is_mem() {
                OutboardLocation::Inline
            } else {
                OutboardLocation::Owned
            };
            // todo: just mark the entry for batch write if it is a mem entry?
            let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
            {
                let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
                tracing::info!(
                    "inserting complete entry for {}, {} bytes",
                    hash.to_hex(),
                    data_size,
                );
                blobs
                    .insert(
                        hash,
                        EntryState::Complete {
                            size: data_size,
                            data_location,
                            outboard_location,
                        },
                    )
                    .map_err(to_io_err)?;
                if let MemOrFile::Mem(data) = &data {
                    let mut inline_data = tx.open_table(INLINE_DATA_TABLE).map_err(to_io_err)?;
                    inline_data.insert(hash, data.as_ref()).map_err(to_io_err)?;
                }
                if let MemOrFile::Mem(outboard) = &outboard {
                    let mut inline_outboard =
                        tx.open_table(INLINE_OUTBOARD_TABLE).map_err(to_io_err)?;
                    inline_outboard
                        .insert(hash, outboard.as_ref())
                        .map_err(to_io_err)?;
                }
            }
            tx.commit().map_err(to_io_err)?;
            Ok(BaoFileStorage::Complete(CompleteMemOrFileStorage {
                data,
                outboard,
            }))
        });
        if let Err(e) = res.as_ref() {
            tracing::error!("error inserting complete entry: {}", e);
        }
        res
    }
}

fn to_io_err(e: impl Into<redb::Error>) -> io::Error {
    let e = e.into();
    match e {
        redb::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::Other, e),
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
///
/// The computed outboard is without length prefix.
fn compute_outboard(
    read: impl Read,
    size: u64,
    progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
) -> io::Result<(Hash, Option<Vec<u8>>)> {
    // compute outboard size so we can pre-allocate the buffer.
    let outboard_size = usize::try_from(raw_outboard_size(size))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "size too large"))?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader2::new(read, progress);
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    let hash =
        bao_tree::io::sync::outboard_post_order(&mut reader, size, IROH_BLOCK_SIZE, &mut outboard)?;
    let ob = PostOrderMemOutboard::load(hash, &outboard, IROH_BLOCK_SIZE)?.flip();
    tracing::trace!(%hash, "done");
    let ob = ob.into_inner();
    let ob = if !ob.is_empty() { Some(ob) } else { None };
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

/// overwrite a file with the given data.
///
/// This is almost like `std::fs::write`, but it does not truncate the file.
///
/// So if you overwrite a file with less data than it had before, the file will
/// still have the same size as before.
///
/// Also, if you overwrite a file with the same data as it had before, the
/// file will be unchanged even if the overwrite operation is interrupted.
fn overwrite_and_sync(path: &Path, data: &[u8]) -> io::Result<std::fs::File> {
    let mut file = OpenOptions::new().write(true).create(true).open(&path)?;
    file.write_all(data)?;
    // todo: figure out the consequences of not syncing here
    file.sync_all()?;
    Ok(file)
}

/// Read a file into memory and then delete it.
fn read_and_remove(path: &Path) -> io::Result<Vec<u8>> {
    let data = std::fs::read(&path)?;
    // todo: should we fail here or just log a warning?
    // remove could fail e.g. on windows if the file is still open
    std::fs::remove_file(&path)?;
    Ok(data)
}
