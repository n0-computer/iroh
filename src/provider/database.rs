use super::BlobOrCollection;
use crate::{
    rpc_protocol::ValidateProgress,
    util::{validate_bao, BaoValidationError},
    Hash,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{Future, FutureExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt,
    io::{self, Read},
    path::{Path, PathBuf},
    pin::Pin,
    result,
    sync::{Arc, RwLock},
};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::either::Either;

/// Data for a (possibly very large) blob
///
/// This can be used for both outboards and content. Be careful, this could
/// point to a file that is a terabyte in size. So loading it into memory
/// could be a problem.
///
/// Blob data can either be inline (tiny data, stored in the db) or in a file.
/// The file can be in the default location or a custom location.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum BlobData {
    /// Data is stored inline in the db and exists in memory.
    Inline(Bytes),
    /// Data is stored in a file can be optionally cached in memory.
    File(Option<PathBuf>),
}

impl fmt::Debug for BlobData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inline(data) => f.debug_tuple("Inline").field(&data.len()).finish(),
            Self::File(path) => f.debug_tuple("File").field(path).finish(),
        }
    }
}

impl BlobData {
    fn len(&self, default_path: impl Fn() -> PathBuf) -> io::Result<u64> {
        Ok(match self {
            Self::Inline(data) => data.len() as u64,
            Self::File(custom_path) => {
                let path = custom_path.as_ref().cloned().unwrap_or_else(default_path);
                std::fs::metadata(path)?.len()
            }
        })
    }

    async fn len_async(&self, default_path: impl Fn() -> PathBuf) -> io::Result<u64> {
        Ok(match self {
            Self::Inline(data) => data.len() as u64,
            Self::File(custom_path) => {
                let path = custom_path.as_ref().cloned().unwrap_or_else(default_path);
                tokio::fs::metadata(path).await?.len()
            }
        })
    }

    fn read_as_bytes(&self, default_path: impl Fn() -> PathBuf) -> io::Result<Bytes> {
        match self {
            Self::Inline(data) => Ok(data.clone()),
            Self::File(custom_path) => {
                let path = custom_path.as_ref().cloned().unwrap_or_else(default_path);
                let mut file = std::fs::File::open(path)?;
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                Ok(Bytes::from(buf))
            }
        }
    }

    /// Canonicalize whether data is stored inline or in a file, given a maximum inline size.
    ///
    /// For files which are already in the right format (inline or file), this is a no-op.
    fn canonicalize(
        &mut self,
        default_path: impl Fn() -> PathBuf + Clone,
        max_inline: u64,
    ) -> io::Result<()> {
        match self {
            BlobData::Inline(bytes) => {
                if bytes.len() as u64 > max_inline {
                    // too big, store externally
                    let path = default_path();
                    tracing::debug!("storing inline data externally in {}", path.display());
                    std::fs::write(path, bytes)?;
                    *self = BlobData::File(None)
                }
            }
            BlobData::File(path) => {
                let path = path.as_ref().cloned();
                let size = self.len(default_path.clone())?;
                if size <= max_inline {
                    // too small, store inline
                    tracing::debug!("storing file data from {:?} inline", path);
                    *self = BlobData::Inline(self.read_as_bytes(default_path)?)
                }
            }
        };
        Ok(())
    }

    fn path(&self) -> BlobDataPath {
        match self {
            Self::Inline(_) => BlobDataPath::Inline,
            Self::File(custom_path) => custom_path
                .as_ref()
                .map(BlobDataPath::Custom)
                .unwrap_or(BlobDataPath::Default),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum BlobDataPath<'a> {
    Inline,
    Default,
    Custom(&'a PathBuf),
}

/// Data for a (possibly very large) mutable blob
///
/// This is identical to BlobData, except that there is no default location
/// for incomplete files. There can be multiple incomplete files for the same
/// hash.
///
/// This is cheap to clone, since it either contains a cheaply cloneable Bytes
/// or just a reference to a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum MutableBlobData {
    Inline(Bytes),
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

/// A synchronous reader from either a file or memory
#[derive(Debug)]
pub enum DataReader {
    Memory(std::io::Cursor<Bytes>),
    File(std::fs::File),
}

impl std::io::Read for DataReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Memory(data) => std::io::Read::read(data, buf),
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

#[derive(Debug)]
pub struct AsyncDataReader(Either<std::io::Cursor<Bytes>, tokio::fs::File>);

impl AsyncDataReader {
    fn memory(data: Bytes) -> Self {
        Self(Either::Left(std::io::Cursor::new(data)))
    }

    pub fn is_file(&self) -> bool {
        matches!(self.0, Either::Right(_))
    }

    pub fn is_memory(&self) -> bool {
        matches!(self.0, Either::Left(_))
    }

    pub fn into_bytes(self) -> Option<Bytes> {
        match self.0 {
            Either::Left(data) => Some(data.into_inner()),
            Either::Right(_) => None,
        }
    }

    pub async fn read_bytes(self) -> io::Result<Bytes> {
        Ok(match self.0 {
            Either::Left(data) => data.get_ref().clone(),
            Either::Right(mut file) => {
                let mut data = Vec::new();
                file.read_to_end(&mut data).await?;
                Bytes::from(data)
            }
        })
    }

    pub fn into_inner(self) -> Either<std::io::Cursor<Bytes>, tokio::fs::File> {
        self.0
    }
}

impl tokio::io::AsyncRead for AsyncDataReader {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncSeek for AsyncDataReader {
    fn start_seek(mut self: std::pin::Pin<&mut Self>, position: io::SeekFrom) -> io::Result<()> {
        Pin::new(&mut self.0).start_seek(position)
    }

    fn poll_complete(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<u64>> {
        Pin::new(&mut self.0).poll_complete(cx)
    }
}

impl BlobData {
    fn reader(&self, default_path: impl Fn() -> PathBuf) -> io::Result<DataReader> {
        Ok(match self {
            Self::Inline(data) => DataReader::Memory(std::io::Cursor::new(data.clone())),
            Self::File(custom_path) => DataReader::File(match custom_path {
                Some(path) => std::fs::File::open(path)?,
                None => std::fs::File::open(default_path())?,
            }),
        })
    }

    fn async_reader(
        &self,
        default_path: impl Fn() -> PathBuf,
    ) -> impl Future<Output = io::Result<AsyncDataReader>> + 'static {
        match self {
            Self::Inline(data) => {
                futures::future::ready(Ok(AsyncDataReader::memory(data.clone()))).left_future()
            }
            Self::File(custom_path) => {
                let path = match custom_path {
                    Some(path) => path.clone(),
                    None => default_path(),
                };
                async move {
                    let file = tokio::fs::File::open(path).await?;
                    Ok(AsyncDataReader(Either::Right(file)))
                }
                .right_future()
            }
        }
    }

    fn exists(&self, default_path: impl Fn() -> PathBuf) -> bool {
        match self {
            Self::Inline(_) => true,
            Self::File(Some(path)) => path.exists(),
            Self::File(None) => default_path().exists(),
        }
    }
}

/// A bao file consists of outboard and content.
///
/// Either of them can stored inline or in a file in the file system.
///
/// Under some circumstances, we can have multiple content files. We will
/// however not keep track of multiple outboard files.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaoFile {
    outboard: BlobData,
    content: Vec<BlobData>,
}

/// An incomplete bao file consists of outboard and content.
///
/// They are related to each other.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IncompleteBaoFile {
    outboard: MutableBlobData,
    content: MutableBlobData,
}

/// The data we retain for each hash
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HashData {
    /// complete files (usually just 1)
    complete: Option<BaoFile>,
    /// a list of incomplete files
    incomplete: Vec<IncompleteBaoFile>,
}

///
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValidateMode {
    /// No validation at all
    None,
    /// Validate that all files exist
    Exists,
}

#[derive(Debug, Clone)]
struct DatabaseInner {
    /// the persisted data
    hashes: BTreeMap<Hash, HashData>,
    /// the outboard cache, not persisted
    ///
    /// Each cache cell has its own lock, so we only have to lock one cell
    /// while loading an item into the cache.
    outboard_cache: BTreeMap<Hash, Arc<tokio::sync::RwLock<Option<Bytes>>>>,
    /// the path we come from
    home_dir: PathBuf,
    /// the content dir, wrapped in an Arc to make it cheap to clone
    content_dir: Arc<PathBuf>,
}

const fn iroh_header(version: u32) -> [u8; 8] {
    let mut res = [b'i', b'r', b'o', b'h', 0, 0, 0, 0];
    res[4] = (version >> 24) as u8;
    res[5] = (version >> 16) as u8;
    res[6] = (version >> 8) as u8;
    res[7] = version as u8;
    res
}

impl DatabaseInner {
    fn new(home_dir: PathBuf) -> Self {
        let content_dir = home_dir.join("data");
        Self {
            hashes: BTreeMap::new(),
            outboard_cache: BTreeMap::new(),
            home_dir,
            content_dir: Arc::new(content_dir),
        }
    }

    fn save(&self, data_dir: impl AsRef<Path>) -> io::Result<()> {
        let data_dir = data_dir.as_ref();
        let db_file = data_dir.join("db.bin");
        let db_file_tmp = data_dir.join("db.bin.tmp");
        tracing::debug!("storing database in {}", db_file_tmp.display());
        let mut db = postcard::to_stdvec(&self.hashes)
            .map_err(|cause| io::Error::new(io::ErrorKind::Other, cause))?;
        db.splice(0..0, iroh_header(0));
        // write into temp file
        std::fs::write(&db_file_tmp, db)?;
        // rename to final file somewhat atomically
        tracing::debug!(
            "replacing original db file {} with {}",
            db_file.display(),
            db_file_tmp.display()
        );
        std::fs::rename(&db_file_tmp, &db_file)?;
        Ok(())
    }

    fn load(home_dir: PathBuf, validate: ValidateMode) -> io::Result<Self> {
        tracing::debug!("loading database from {}", home_dir.display());
        let content_dir = home_dir.join("data");
        // make sure the content dir exists
        std::fs::create_dir_all(&content_dir)?;
        let content_dir = Arc::new(content_dir);
        let db_file = Database::db_path(&home_dir);
        let db_bytes = std::fs::read(db_file)?;
        const HEADER: [u8; 8] = iroh_header(0);
        if db_bytes.len() < HEADER.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "database file is too short",
            ));
        }
        if db_bytes[0..HEADER.len()] != HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "database file has invalid header",
            ));
        }
        let mut hashes =
            postcard::from_bytes::<BTreeMap<Hash, HashData>>(&db_bytes[8..]).map_err(|e| {
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
            let content_name = || content_dir.join(format!("{}.data", hex::encode(hash)));
            let outboard_name = || content_dir.join(format!("{}.obao", hex::encode(hash)));
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
        Ok(Self {
            hashes,
            home_dir,
            content_dir,
            outboard_cache: BTreeMap::new(),
        })
    }

    fn get(&mut self, hash: Hash) -> io::Result<Option<(Bytes, DataReader)>> {
        let content_path = default_content_path(&self.content_dir, hash);
        let outboard_path = default_outboard_path(&self.content_dir, hash);
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
        let outboard = self.outboard_cache.entry(hash).or_default();
        // we never cache the content
        let content_reader = content.reader(content_path)?;
        let outboard_data = if let BlobData::Inline(bytes) = content {
            // just use the inline data without cloning
            bytes.clone()
        } else {
            // block the cache cell for a possible cache write
            let mut lock = outboard.blocking_write();
            if let Some(outboard) = lock.as_ref() {
                // we got it in the cache already
                outboard.clone()
            } else {
                // keep the lock until we have the data
                let mut outboard_reader = complete.outboard.reader(outboard_path)?;
                let mut outboard = Vec::new();
                outboard_reader.read_to_end(&mut outboard)?;
                let outboard = Bytes::from(outboard);
                *lock = Some(outboard.clone());
                outboard
            }
        };
        Ok(Some((outboard_data, content_reader)))
    }

    fn get_async(
        &mut self,
        hash: Hash,
    ) -> impl Future<Output = io::Result<Option<(Bytes, AsyncDataReader)>>> + 'static {
        let nope = || nope().boxed();
        let content_path = default_content_path(&self.content_dir, hash);
        let outboard_path = default_outboard_path(&self.content_dir, hash);
        // do we have something for the hash
        let data = match self.hashes.get(&hash) {
            Some(data) => data,
            None => return nope(),
        };
        // do we have a complete file
        let complete = match data.complete {
            Some(ref complete) => complete,
            None => return nope(),
        };
        // do we have any content (we should have at least one)
        let content = match complete.content.get(0) {
            Some(content) => content,
            None => return nope(),
        };
        // we never cache the content
        let content = content.async_reader(content_path);
        // get the outboard from inline or lazy load it from the cache
        if let BlobData::Inline(outboard) = &complete.outboard {
            // got inline data
            pair_from_bytes(outboard.clone(), content).boxed()
        } else {
            // grab the cache cell and clone the outboard
            let cache_cell = self.outboard_cache.entry(hash).or_default().clone();
            let outboard = complete.outboard.clone();
            update_cache_cell(cache_cell, outboard, outboard_path, content).boxed()
        }
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

    // todo: remove
    fn blobs(&self) -> Vec<io::Result<(Hash, PathBuf, u64)>> {
        let mut res = Vec::new();
        let read_data = |hash: Hash, complete: BaoFile| -> io::Result<Vec<(Hash, PathBuf, u64)>> {
            let content_path = default_content_path(&self.content_dir, hash);
            let mut outboard = complete
                .outboard
                .reader(default_outboard_path(&self.content_dir, hash))?;
            let mut buf = [0u8; 8];
            outboard.read_exact(&mut buf)?;
            let size = u64::from_le_bytes(buf);
            Ok(complete
                .content
                .iter()
                .filter_map(|content| {
                    let path = match content.path() {
                        BlobDataPath::Inline => return None,
                        BlobDataPath::Default => content_path(),
                        BlobDataPath::Custom(path) => path.clone(),
                    };
                    // todo: read size from outboard
                    Some((hash, path, size))
                })
                .collect())
        };
        for (hash, data) in &self.hashes {
            if let Some(complete) = &data.complete {
                match read_data(*hash, complete.clone()) {
                    Ok(elems) => {
                        for elem in elems {
                            res.push(Ok(elem));
                        }
                    }
                    Err(cause) => res.push(Err(cause)),
                }
            }
        }
        res
    }
}

fn nope() -> impl Future<Output = io::Result<Option<(Bytes, AsyncDataReader)>>> {
    futures::future::ready(Ok(None))
}

async fn pair_from_bytes(
    outboard: Bytes,
    content: impl Future<Output = io::Result<AsyncDataReader>>,
) -> io::Result<Option<(Bytes, AsyncDataReader)>> {
    let content_reader = content.await?;
    Ok(Some((outboard, content_reader)))
}

/// Given a cache cell for the outboard, the outboard data, the outboard path and the content reader,
/// update the cache cell and then return the outboard and content readers.
async fn update_cache_cell(
    cache_cell: Arc<tokio::sync::RwLock<Option<Bytes>>>,
    outboard: BlobData,
    outboard_path: impl Fn() -> PathBuf,
    content: impl Future<Output = io::Result<AsyncDataReader>>,
) -> io::Result<Option<(Bytes, AsyncDataReader)>> {
    let mut lock = cache_cell.write().await;
    let outboard = if let Some(outboard) = lock.as_ref() {
        // we got it in the cache already and can release the lock immediately
        outboard.clone()
    } else {
        // keep the lock until we have the data
        // create the outboard reader
        let mut outboard_reader = outboard.async_reader(outboard_path).await?;
        // read the outboard data into a Bytes
        let mut outboard = Vec::new();
        outboard_reader.read_to_end(&mut outboard).await?;
        let outboard = Bytes::from(outboard);
        // store in cache
        *lock = Some(outboard.clone());
        outboard
    };
    // done with the lock
    drop(lock);
    pair_from_bytes(outboard, content).await
}

/// Creates a function that returns the default path to a content file
fn default_content_path(
    content_dir: &Arc<PathBuf>,
    hash: Hash,
) -> impl Fn() -> PathBuf + Clone + 'static {
    let content_dir = content_dir.clone();
    move || content_dir.join(format!("{}.data", hex::encode(hash)))
}

/// Creates a function that returns the default path to an outboard file
fn default_outboard_path(
    content_dir: &Arc<PathBuf>,
    hash: Hash,
) -> impl Fn() -> PathBuf + Clone + 'static {
    let content_dir = content_dir.clone();
    move || content_dir.join(format!("{}.obao", hex::encode(hash)))
}

///
#[derive(Debug, Clone)]
pub struct Database(Arc<RwLock<DatabaseInner>>);

impl Database {
    /// get the path of the databse file from the home dir
    pub fn db_path(data_dir: impl AsRef<Path>) -> PathBuf {
        data_dir.as_ref().join("db.bin")
    }

    /// get the path of the content dir from the home dir
    pub fn content_path(data_dir: impl AsRef<Path>) -> PathBuf {
        data_dir.as_ref().join("data")
    }

    pub(crate) fn from_blobs(blobs: HashMap<Hash, BlobOrCollection>) -> io::Result<Self> {
        let home = PathBuf::from(".");
        let db = Database::new(home);
        db.union_with(blobs)?;
        Ok(db)
    }

    // todo: remove
    pub(crate) fn union_with(&self, collection: HashMap<Hash, BlobOrCollection>) -> io::Result<()> {
        println!("unioning with {} blobs", collection.len());
        let content_dir = self.0.read().unwrap().content_dir.clone();
        for (hash, blob) in collection.into_iter() {
            let (mut outboard, mut content) = match blob {
                BlobOrCollection::Blob { outboard, path, .. } => {
                    (BlobData::Inline(outboard), BlobData::File(Some(path)))
                }
                BlobOrCollection::Collection { outboard, data } => {
                    (BlobData::Inline(outboard), BlobData::Inline(data))
                }
            };
            outboard.canonicalize(default_outboard_path(&content_dir, hash), 1024)?;
            content.canonicalize(default_content_path(&content_dir, hash), 1024)?;
            println!("unioning with blob {:?} {:?} {:?}", hash, outboard, content);
            self.insert(hash, outboard, content)
        }
        println!("{:?}", self);
        Ok(())
    }

    ///
    // todo: remove
    pub fn blobs(&self) -> impl Iterator<Item = (Hash, PathBuf, u64)> {
        self.0
            .read()
            .unwrap()
            .blobs()
            .into_iter()
            .filter_map(|x| x.ok())
    }

    fn snapshot(&self) -> (BTreeMap<Hash, HashData>, Arc<PathBuf>) {
        let reader = self.0.read().unwrap();
        (reader.hashes.clone(), reader.content_dir.clone())
    }

    pub(crate) async fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> anyhow::Result<()> {
        // This makes a copy of the db, but since the outboards are Bytes, it's not expensive.
        let (hashes, content_dir) = self.snapshot();
        // flatten to a list
        let mut data = hashes
            .into_iter()
            .flat_map(|(hash, data)| {
                let complete = data.complete?;
                Some((hash, complete))
            })
            .flat_map(|(hash, baofile)| {
                baofile
                    .content
                    .into_iter()
                    .map(move |content| (hash, baofile.outboard.clone(), content))
            })
            .collect::<Vec<_>>();
        // sort by path to make the sequence useful to humans
        let compare_data_path =
            |a: &(_, _, BlobData), b: &(_, _, BlobData)| a.2.path().cmp(&b.2.path());
        data.sort_by(compare_data_path);
        tx.send(ValidateProgress::Starting {
            total: data.len() as u64,
        })
        .await?;
        futures::stream::iter(data)
            .enumerate()
            .map(|(id, (hash, outboard, data))| {
                let id = id as u64;
                let entry_tx = tx.clone();
                let done_tx = tx.clone();
                let content_dir = content_dir.clone();
                async move {
                    let default_outboard_path = default_outboard_path(&content_dir, hash);
                    let default_content_path = default_content_path(&content_dir, hash);
                    let outboard_reader = outboard.async_reader(default_outboard_path).await?;
                    // read outboard from disk even if we have it in the cache
                    // this is validate, so we want to be sure the data on disk is correct
                    let outboard = outboard_reader.read_bytes().await?;
                    // todo: check size
                    let size = u64::from_le_bytes(outboard[0..8].try_into().unwrap());
                    let data_reader = data.reader(default_content_path.clone())?;
                    let data_text = format!("{:?}", data);
                    let path = match data {
                        BlobData::File(Some(path)) => Some(path),
                        BlobData::File(None) => Some(default_content_path()),
                        BlobData::Inline(_) => None,
                    };
                    entry_tx
                        .send(ValidateProgress::Entry {
                            id,
                            hash,
                            path,
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
                        let res = {
                            tracing::info!("validating {}", data_text);
                            let res = validate_bao(hash, data_reader, outboard, progress);
                            tracing::info!("done validating {}", data_text);
                            res
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

    ///
    pub fn new(data_dir: PathBuf) -> Self {
        let inner = DatabaseInner::new(data_dir);
        Self(Arc::new(RwLock::new(inner)))
    }

    ///
    pub async fn load(data_dir: PathBuf, validate: ValidateMode) -> io::Result<Self> {
        tokio::task::spawn_blocking(|| Self::load_internal(data_dir, validate)).await?
    }

    ///
    pub async fn save(&self, data_dir: impl AsRef<Path>) -> io::Result<()> {
        let this = self.clone();
        let data_dir = data_dir.as_ref().to_owned();
        tokio::task::spawn_blocking(move || this.save_internal(data_dir)).await?
    }

    /// Load a database from disk for testing. Synchronous.
    #[cfg(feature = "cli")]
    pub fn load_test(dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        Self::load_internal(dir, ValidateMode::None)
    }

    ///
    fn load_internal(data_dir: PathBuf, validate: ValidateMode) -> io::Result<Self> {
        let inner = DatabaseInner::load(data_dir, validate)?;
        Ok(Self(Arc::new(RwLock::new(inner))))
    }

    ///
    fn save_internal(&self, data_dir: impl AsRef<Path>) -> io::Result<()> {
        let inner = self.0.read().unwrap();
        inner.save(data_dir)
    }

    ///
    pub fn get(&self, hash: &Hash) -> io::Result<Option<(Bytes, DataReader)>> {
        // we need write access to the database to cache the outboard
        let mut inner = self.0.write().unwrap();
        inner.get(*hash)
    }

    /// Get complete data asynchronously.
    ///
    /// For outboards that are not inline and not already cached, this will block
    /// the cache cell until the outboard is loaded.
    pub fn get_async(
        &self,
        hash: &Hash,
    ) -> impl Future<Output = io::Result<Option<(Bytes, AsyncDataReader)>>> {
        // we need write access to the database to cache the outboard
        let mut inner = self.0.write().unwrap();
        inner.get_async(*hash)
    }

    /// Insert complete data. This does not do any checks about the validity of the data.
    pub fn insert(&self, hash: Hash, outboard: BlobData, content: BlobData) {
        let mut inner = self.0.write().unwrap();
        inner.insert_complete(hash, outboard, content)
    }
}

/// Database containing content-addressed data (blobs or collections).
#[derive(Debug, Clone, Default)]
pub struct DatabaseOld(Arc<RwLock<HashMap<Hash, BlobOrCollection>>>);

impl From<HashMap<Hash, BlobOrCollection>> for DatabaseOld {
    fn from(map: HashMap<Hash, BlobOrCollection>) -> Self {
        Self(Arc::new(RwLock::new(map)))
    }
}

/// A snapshot of the database.
///
/// `E` can be `Infallible` if we take a snapshot from an in memory database,
/// or `io::Error` if we read a database from disk.
pub(crate) struct SnapshotOld<E> {
    /// list of paths we have, hash is the hash of the blob or collection
    paths: Box<dyn Iterator<Item = (Hash, u64, Option<PathBuf>)>>,
    /// map of hash to outboard, hash is the hash of the outboard and is unique
    outboards: Box<dyn Iterator<Item = result::Result<(Hash, Bytes), E>>>,
    /// map of hash to collection, hash is the hash of the collection and is unique
    collections: Box<dyn Iterator<Item = result::Result<(Hash, Bytes), E>>>,
}

impl<E> fmt::Debug for SnapshotOld<E> {
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

impl SnapshotOld<io::Error> {
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

impl<E> SnapshotOld<E>
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

impl DatabaseOld {
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
        let snapshot = SnapshotOld::load(dir)?;
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
    pub(crate) fn from_snapshot<E: Into<io::Error>>(snapshot: SnapshotOld<E>) -> io::Result<Self> {
        let SnapshotOld {
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
    pub(crate) fn snapshot(&self) -> SnapshotOld<NoError> {
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

        SnapshotOld {
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
