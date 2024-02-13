use std::{
    fs::{File, OpenOptions},
    io,
    ops::{Deref, DerefMut},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use bao_tree::{
    blake3,
    io::{
        fsm::{BaoContentItem, Outboard, ResponseDecoderReadingNext, ResponseDecoderStart},
        sync::{ReadAt, WriteAt},
    },
    BaoTree, BlockSize, ByteNum, ChunkRanges, TreeNode,
};
use bytes::{Bytes, BytesMut};
use derive_more::Debug;
use futures::{future, FutureExt};
use iroh_io::AsyncSliceReader;
use tokio::io::AsyncRead;

use crate::{store::BaoBatchWriter, IROH_BLOCK_SIZE};

/// Data files are stored in 3 files. The data file, the outboard file,
/// and a sizes file. The sizes file contains the size that the remote side told us
/// when writing each data block.
///
/// For complete data files, the sizes file is not needed, since you can just
/// use the size of the data file.
///
/// For files below the chunk size, the outboard file is not needed, since
/// there is only one leaf, and the outboard file is empty.
struct DataPaths {
    /// The data file. Size is determined by the chunk with the highest offset
    /// that has been written.
    ///
    /// Gaps will be filled with zeros.
    data: PathBuf,
    /// The outboard file. This is *without* the size header, since that is not
    /// known for partial files.
    ///
    /// The size of the outboard file is therefore a multiple of a hash pair
    /// (64 bytes).
    ///
    /// The naming convention is to use obao for pre order traversal and oboa
    /// for post order traversal. The log2 of the chunk group size is appended,
    /// so for the default chunk group size in iroh of 4, the file extension
    /// is .obao4.
    outboard: PathBuf,
    /// The sizes file. This is a file with 8 byte sizes for each chunk group.
    /// The naming convention is to prepend the log2 of the chunk group size,
    /// so for the default chunk group size in iroh of 4, the file extension
    /// is .sizes4.
    ///
    /// The traversal order is not relevant for the sizes file, since it is
    /// about the data chunks, not the hash pairs.
    sizes: PathBuf,
}

/// The memory variant of a bao file. This is used before we know that the
/// size exceeds the memory limit, even when the remote advertizes a very large
/// size.
#[derive(Debug, Default)]
struct MutableMemStorage {
    /// Data file, can be any size.
    data: Vec<u8>,
    /// Outboard file, must be a multiple of 64 bytes.
    outboard: Vec<u8>,
    /// Sizes file, must be a multiple of 8 bytes. Little endian u64.
    /// Last 8 bytes is the most precise known size.
    sizes: Vec<u8>,
}

#[derive(Debug, Default)]
struct MemStorage {
    data: Bytes,
    outboard: Bytes,
    sizes: Bytes,
}

impl MemStorage {
    fn current_size(&self) -> u64 {
        let sizes = self.sizes.as_ref();
        let len = sizes.len();
        if len < 8 {
            0
        } else {
            u64::from_le_bytes(sizes[len - 8..len].try_into().unwrap())
        }
    }

    fn read_data_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.data, offset, len)
    }

    fn read_outboard_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.outboard, offset, len)
    }
}

fn create_read_write(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

impl MutableMemStorage {
    /// Persist the batch to disk, creating a FileBatch.
    fn persist(&self, paths: DataPaths) -> io::Result<FileStorage> {
        let mut data = create_read_write(&paths.data)?;
        let mut outboard = create_read_write(&paths.outboard)?;
        let mut sizes = create_read_write(&paths.sizes)?;
        data.write_all_at(0, &self.data)?;
        outboard.write_all_at(0, &self.outboard)?;
        sizes.write_all_at(0, &self.sizes)?;
        Ok(FileStorage {
            data,
            outboard,
            sizes,
        })
    }

    fn current_size(&self) -> u64 {
        let sizes = &self.sizes;
        let len = sizes.len();
        if len < 8 {
            0
        } else {
            u64::from_le_bytes(sizes[len - 8..len].try_into().unwrap())
        }
    }

    fn read_data_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.data, offset, len)
    }

    fn read_outboard_at(&self, offset: u64, len: usize) -> Bytes {
        copy_limited_slice(&self.outboard, offset, len)
    }

    fn write_batch(&mut self, size: u64, batch: &[BaoContentItem]) -> std::io::Result<()> {
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        for item in batch {
            match item {
                BaoContentItem::Parent(parent) => {
                    if let Some(offset) = tree.pre_order_offset(parent.node) {
                        let o0 = offset
                            .checked_mul(64)
                            .expect("u64 overflow multiplying to hash pair offset");
                        let o1 = (o0 + 64).try_into().expect("usize overflow in outboard");
                        let o0 = o0.try_into().expect("usize overflow in outboard");
                        let outboard = &mut self.outboard;
                        // make the outboard file big enough so the copy_from_slice works
                        if outboard.len() < o1 {
                            outboard.resize(o1, 0u8);
                        }
                        outboard[o0..o0 + 32].copy_from_slice(parent.pair.0.as_bytes().as_slice());
                        outboard[o0 + 32..o1].copy_from_slice(parent.pair.1.as_bytes().as_slice());
                    }
                }
                BaoContentItem::Leaf(leaf) => {
                    let o0 = leaf.offset.0;
                    let o1 = o0
                        .checked_add(leaf.data.len() as u64)
                        .expect("u64 overflow for leaf end offset");
                    let o0 = o0.try_into().expect("usize overflow for leaf start offset");
                    let o1 = o1.try_into().expect("usize overflow for leaf end offset");
                    let i0 = (leaf.offset.0 >> tree.block_size().0)
                        .checked_mul(8)
                        .expect("u64 overflow for sizes");
                    let i1 = i0.checked_add(8).expect("u64 overflow for sizes");
                    let i0 = i0.try_into().expect("usize overflow for size start offset");
                    let i1 = i1.try_into().expect("usize overflow for size end offset");
                    let sizes = &mut self.sizes;
                    // make the sizes file big enough so the copy_from_slice works
                    if sizes.len() < i1 {
                        sizes.resize(i1, 0);
                    }
                    sizes[i0..i1].copy_from_slice(tree.size().0.to_le_bytes().as_slice());
                    // make the data file big enough so the copy_from_slice works
                    let data = &mut self.data;
                    if data.len() < o1 {
                        data.resize(o1, 0u8);
                    }
                    data[o0..o1].copy_from_slice(leaf.data.as_ref());
                }
            }
        }
        Ok(())
    }
}

/// Read from the given file at the given offset, until end of file or max bytes.
fn read_to_end(file: impl ReadAt, offset: u64, max: usize) -> io::Result<Bytes> {
    let mut res = BytesMut::new();
    let mut buf = [0u8; 4096];
    let mut remaining = max;
    let mut offset = offset;
    while remaining > 0 {
        let end = buf.len().min(remaining);
        let read = file.read_at(offset, &mut buf[..end])?;
        if read == 0 {
            // eof
            break;
        }
        res.extend_from_slice(&buf[..read]);
        offset += read as u64;
        remaining -= read;
    }
    Ok(res.freeze())
}

fn max_offset(batch: &[BaoContentItem]) -> u64 {
    batch
        .iter()
        .filter_map(|item| match item {
            BaoContentItem::Leaf(leaf) => {
                let len = leaf.data.len().try_into().unwrap();
                let end = leaf
                    .offset
                    .0
                    .checked_add(len)
                    .expect("u64 overflow for leaf end");
                Some(end)
            }
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

#[derive(Debug)]
struct FileStorage {
    data: std::fs::File,
    outboard: std::fs::File,
    sizes: std::fs::File,
}

impl FileStorage {
    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            data: self.data.try_clone()?,
            outboard: self.outboard.try_clone()?,
            sizes: self.sizes.try_clone()?,
        })
    }

    fn current_size(&self) -> io::Result<u64> {
        let len = self.sizes.metadata()?.len();
        if len < 8 {
            Ok(0)
        } else {
            // todo: use the last full u64 in case the sizes file is not a multiple of 8
            // bytes. Not sure how that would happen, but we should handle it.
            let mut buf = [0u8; 8];
            self.sizes.read_exact_at(len - 8, &mut buf)?;
            Ok(u64::from_le_bytes(buf))
        }
    }

    fn write_batch(&mut self, size: u64, batch: &[BaoContentItem]) -> io::Result<()> {
        let tree = BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE);
        for item in batch {
            match item {
                BaoContentItem::Parent(parent) => {
                    if let Some(offset) = tree.pre_order_offset(parent.node) {
                        let o0 = offset
                            .checked_mul(64)
                            .expect("u64 overflow multiplying to hash pair offset");
                        let o0 = o0.try_into().expect("usize overflow in outboard");
                        self.outboard
                            .write_all_at(o0, parent.pair.0.as_bytes().as_slice())?;
                        self.outboard
                            .write_all_at(o0 + 32, parent.pair.1.as_bytes().as_slice())?;
                        std::io::Write::flush(&mut self.outboard)?;
                    }
                }
                BaoContentItem::Leaf(leaf) => {
                    let o0 = leaf.offset.0;
                    let index = leaf.offset.0 >> tree.block_size().0;
                    let index = index.checked_mul(8).expect("u64 overflow for block index");
                    println!(
                        "write_batch f={:?} o={} l={}",
                        self.data,
                        o0,
                        leaf.data.len()
                    );
                    self.data.write_all_at(o0, leaf.data.as_ref())?;
                    std::io::Write::flush(&mut self.data)?;
                    self.data.sync_all()?;
                    self.sizes
                        .write_all_at(index, &tree.size().0.to_le_bytes())?;
                    std::io::Write::flush(&mut self.sizes)?;
                }
            }
        }
        Ok(())
    }

    fn read_data_at(&self, offset: u64, len: usize) -> io::Result<Bytes> {
        read_to_end(&self.data, offset, len)
    }

    fn read_outboard_at(&self, offset: u64, len: usize) -> io::Result<Bytes> {
        read_to_end(&self.outboard, offset, len)
    }
}

/// The storage for a bao file. This can be either in memory or on disk.
///
/// The arc rwlock dance is done at a higher level.
///
/// Default is just an empty memory file, since that is how you always have
/// to start.
#[derive(Debug)]
enum BaoFileStorage {
    MutableMem(MutableMemStorage),
    File(FileStorage),
    Mem(MemStorage),
}

impl BaoFileStorage {
    /// Create a new mutable mem storage.
    pub fn create() -> Self {
        Self::MutableMem(Default::default())
    }

    /// Call sync_all on all the files.
    fn sync_all(&self) -> io::Result<()> {
        match self {
            BaoFileStorage::Mem(_) => Ok(()),
            BaoFileStorage::MutableMem(_) => Ok(()),
            BaoFileStorage::File(file) => {
                file.data.sync_all()?;
                file.outboard.sync_all()?;
                file.sizes.sync_all()?;
                Ok(())
            }
        }
    }
}

/// A cheaply cloneable handle to a bao file, including the hash and the configuration.
#[derive(Debug, Clone)]
pub struct BaoFileHandle {
    storage: Arc<RwLock<BaoFileStorage>>,
    config: Arc<BaoFileConfig>,
    hash: blake3::Hash,
}

type CreateCb = Arc<dyn Fn(&blake3::Hash) + Send + Sync>;

/// Configuration for the deferred batch writer. It will start writing to memory,
/// and then switch to a file when the memory limit is reached.
#[derive(derive_more::Debug, Clone)]
pub struct BaoFileConfig {
    /// Directory to store files in. Only used when memory limit is reached.
    dir: Arc<PathBuf>,
    /// Maximum data size (inclusive) before switching to file mode.
    max_mem: usize,
    /// Callback to call when we switch to file mode.
    #[debug(skip)]
    on_create: Option<CreateCb>,
}

impl BaoFileConfig {
    /// Create a new deferred batch writer configuration.
    fn new(dir: Arc<PathBuf>, max_mem: usize, on_create: Option<CreateCb>) -> Self {
        Self {
            dir,
            max_mem,
            on_create,
        }
    }

    /// Get the paths for a hash.
    fn paths(&self, hash: &blake3::Hash) -> DataPaths {
        DataPaths {
            data: self.dir.join(format!("{}.data", hash)),
            outboard: self.dir.join(format!("{}.obao4", hash)),
            sizes: self.dir.join(format!("{}.sizes4", hash)),
        }
    }
}

/// The outboard type
pub type OutboardType = PreOrderOutboard<OutboardReader>;

/// A reader for a bao file, reading just the data.
pub struct DataReader(Option<BaoFileHandle>);

async fn with_storage<T, F>(opt: &mut Option<BaoFileHandle>, f: F) -> io::Result<T>
where
    F: FnOnce(&BaoFileStorage) -> io::Result<T> + Send + 'static,
    T: Send + 'static,
{
    let handle = opt
        .take()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "deferred batch busy"))?;
    // if we can get the lock immediately, and we are in memory mode, we can
    // avoid spawning a task.
    if let Ok(storage) = handle.storage.try_read() {
        if let BaoFileStorage::MutableMem(_) = storage.deref() {
            let res = f(storage.deref());
            // clone because for some reason even when we drop storage, the
            // borrow checker still thinks handle is borrowed.
            *opt = Some(handle.clone());
            return res;
        }
    };
    // otherwise, we have to spawn a task.
    let (handle, res) = tokio::task::spawn_blocking(move || {
        let storage = handle.storage.read().unwrap();
        let res = f(storage.deref());
        drop(storage);
        (handle, res)
    })
    .await
    .expect("spawn_blocking failed");
    *opt = Some(handle);
    res
}

impl AsyncSliceReader for DataReader {
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        with_storage(&mut self.0, move |storage| match storage {
            BaoFileStorage::Mem(mem) => Ok(mem.read_data_at(offset, len)),
            BaoFileStorage::MutableMem(mem) => Ok(mem.read_data_at(offset, len)),
            BaoFileStorage::File(file) => file.read_data_at(offset, len),
        })
        .await
    }

    async fn len(&mut self) -> io::Result<u64> {
        with_storage(&mut self.0, move |storage| match storage {
            BaoFileStorage::Mem(mem) => Ok(mem.data.len() as u64),
            BaoFileStorage::MutableMem(mem) => Ok(mem.data.len() as u64),
            BaoFileStorage::File(file) => file.data.metadata().map(|m| m.len()),
        })
        .await
    }
}

pub struct OutboardReader(Option<BaoFileHandle>);

impl AsyncSliceReader for OutboardReader {
    async fn read_at(&mut self, offset: u64, len: usize) -> io::Result<Bytes> {
        with_storage(&mut self.0, move |storage| match storage {
            BaoFileStorage::Mem(mem) => Ok(mem.read_outboard_at(offset, len)),
            BaoFileStorage::MutableMem(mem) => Ok(mem.read_outboard_at(offset, len)),
            BaoFileStorage::File(file) => file.read_outboard_at(offset, len),
        })
        .await
    }

    async fn len(&mut self) -> io::Result<u64> {
        with_storage(&mut self.0, move |storage| match storage {
            BaoFileStorage::Mem(mem) => Ok(mem.outboard.len() as u64),
            BaoFileStorage::MutableMem(mem) => Ok(mem.outboard.len() as u64),
            BaoFileStorage::File(file) => file.outboard.metadata().map(|m| m.len()),
        })
        .await
    }
}

impl BaoFileHandle {
    /// Create a new bao file handle.
    ///
    /// This will create a new file handle with an empty memory storage.
    /// Since there are very likely to be many of these, we use an arc rwlock
    pub fn new(config: Arc<BaoFileConfig>, hash: blake3::Hash) -> Self {
        let storage = BaoFileStorage::create();
        Self {
            storage: Arc::new(RwLock::new(storage)),
            config,
            hash,
        }
    }

    /// An AsyncSliceReader for the data file.
    ///
    /// Caution: this is a reader for the unvalidated data file. Reading this
    /// can produce data that does not match the hash.
    pub fn data_reader(&self) -> DataReader {
        DataReader(Some(self.clone()))
    }

    /// An AsyncSliceReader for the outboard file.
    ///
    /// The outboard file is used to validate the data file. It contains the
    pub fn outboard_reader(&self) -> OutboardReader {
        OutboardReader(Some(self.clone()))
    }

    /// The most precise known total size of the data file.
    pub fn current_size(&self) -> io::Result<u64> {
        match self.storage.read().unwrap().deref() {
            BaoFileStorage::Mem(mem) => Ok(mem.current_size()),
            BaoFileStorage::MutableMem(mem) => Ok(mem.current_size()),
            BaoFileStorage::File(file) => file.current_size(),
        }
    }

    pub fn outboard(&self) -> io::Result<PreOrderOutboard<OutboardReader>> {
        let root = self.hash;
        let tree = BaoTree::new(ByteNum(self.current_size()?), IROH_BLOCK_SIZE);
        let outboard = OutboardReader(Some(self.clone()));
        Ok(PreOrderOutboard {
            root,
            tree,
            data: outboard,
        })
    }

    /// The hash of the file.
    pub fn hash(&self) -> blake3::Hash {
        self.hash
    }

    /// Create a new writer from the handle.
    pub fn writer(&self) -> BaoFileWriter {
        BaoFileWriter(Some(self.clone()))
    }

    /// This is the synchronous impl for writing a batch.
    fn write_batch(&self, size: u64, batch: &[BaoContentItem]) -> io::Result<()> {
        // TODO: try_write fast path for memory
        let mut storage = self.storage.write().unwrap();
        match storage.deref_mut() {
            BaoFileStorage::Mem(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot write to a read-only file",
                ))
            }
            BaoFileStorage::MutableMem(mem) => {
                // check if we need to switch to file mode, otherwise write to memory
                if max_offset(&batch) < self.config.max_mem as u64 {
                    mem.write_batch(size, &batch)?
                } else {
                    // create the paths. This allocates 3 pathbufs, so we do it
                    // only when we need to.
                    let paths = self.config.paths(&self.hash);
                    // *first* switch to file mode, *then* write the batch.
                    //
                    // otherwise we might allocate a lot of memory if we get
                    // a write at the end of a very large file.
                    let mut file_batch = mem.persist(paths)?;
                    if let Some(cb) = self.config.on_create.as_ref() {
                        cb(&self.hash);
                    }
                    file_batch.write_batch(size, &batch)?;
                    *storage = BaoFileStorage::File(file_batch);
                }
            }
            BaoFileStorage::File(file) => {
                // already in file mode, just write the batch
                file.write_batch(size, &batch)?;
            }
        };
        Ok(())
    }
}

/// This is finally the thing for which we can implement BaoPairMut.
///
/// It is a BaoFileHandle wrapped in an Option, so that we can take it out
/// in the future.
#[derive(Debug)]
pub struct BaoFileWriter(Option<BaoFileHandle>);

/// Decode a response into a file while updating an outboard.
///
/// If you do not want to update an outboard, use [super::outboard::EmptyOutboard] as
/// the outboard.
pub async fn decode_response_into_batch<R, W>(
    root: blake3::Hash,
    block_size: BlockSize,
    ranges: ChunkRanges,
    encoded: R,
    mut target: W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: BaoBatchWriter,
{
    let start = ResponseDecoderStart::new(root, ranges, block_size, encoded);
    let (mut reading, size) = start.next().await?;
    let mut stack = Vec::new();
    loop {
        let item = match reading.next().await {
            ResponseDecoderReadingNext::Done(_reader) => break,
            ResponseDecoderReadingNext::More((next, item)) => {
                reading = next;
                item?
            }
        };
        match item {
            BaoContentItem::Parent(_) => {
                stack.push(item);
            }
            BaoContentItem::Leaf(_) => {
                // write a batch every time we see a leaf
                // the last item will be a leaf.
                stack.push(item);
                target.write_batch(size, std::mem::take(&mut stack)).await?;
            }
        }
    }
    assert!(stack.is_empty(), "last item should be a leaf");
    Ok(())
}

impl BaoBatchWriter for BaoFileWriter {
    async fn write_batch(&mut self, size: u64, batch: Vec<BaoContentItem>) -> std::io::Result<()> {
        let Some(handle) = self.0.take() else {
            return Err(io::Error::new(io::ErrorKind::Other, "deferred batch busy"));
        };
        let (handle, res) = tokio::task::spawn_blocking(move || {
            let res = handle.write_batch(size, &batch);
            (handle, res)
        })
        .await
        .expect("spawn_blocking failed");
        self.0 = Some(handle);
        res
    }

    async fn sync(&mut self) -> io::Result<()> {
        let Some(handle) = self.0.take() else {
            return Err(io::Error::new(io::ErrorKind::Other, "deferred batch busy"));
        };
        let (handle, res) = tokio::task::spawn_blocking(move || {
            let res = handle.storage.write().unwrap().sync_all();
            (handle, res)
        })
        .await
        .expect("spawn_blocking failed");
        self.0 = Some(handle);
        res
    }
}

/// A pre order outboard without length prefix.
#[derive(Clone, PartialEq, Eq)]
pub struct PreOrderOutboard<R> {
    pub root: blake3::Hash,
    pub tree: BaoTree,
    pub data: R,
}

impl<R: AsyncSliceReader> Outboard for PreOrderOutboard<R> {
    fn root(&self) -> blake3::Hash {
        self.root
    }

    fn tree(&self) -> BaoTree {
        self.tree
    }

    async fn load(&mut self, node: TreeNode) -> io::Result<Option<(blake3::Hash, blake3::Hash)>> {
        let Some(offset) = self.tree.pre_order_offset(node) else {
            return Ok(None);
        };
        let offset = offset * 64;
        let content = self.data.read_at(offset, 64).await?;
        Ok(Some(if content.len() != 64 {
            (blake3::Hash::from([0; 32]), blake3::Hash::from([0; 32]))
        } else {
            parse_hash_pair(content)?
        }))
    }
}

pub(crate) fn parse_hash_pair(buf: Bytes) -> io::Result<(blake3::Hash, blake3::Hash)> {
    if buf.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "hash pair must be 64 bytes",
        ));
    }
    let l_hash = blake3::Hash::from(<[u8; 32]>::try_from(&buf[..32]).unwrap());
    let r_hash = blake3::Hash::from(<[u8; 32]>::try_from(&buf[32..]).unwrap());
    Ok((l_hash, r_hash))
}

pub(crate) fn limited_range(offset: u64, len: usize, buf_len: usize) -> std::ops::Range<usize> {
    if offset < buf_len as u64 {
        let start = offset as usize;
        let end = start.saturating_add(len).min(buf_len);
        start..end
    } else {
        0..0
    }
}

fn get_limited_slice(bytes: &Bytes, offset: u64, len: usize) -> Bytes {
    bytes.slice(limited_range(offset, len, bytes.len()))
}

fn copy_limited_slice(bytes: &[u8], offset: u64, len: usize) -> Bytes {
    bytes[limited_range(offset, len, bytes.len())]
        .to_vec()
        .into()
}

#[cfg(test)]
mod tests {
    use std::{ops::Range, sync::Arc};

    use bao_tree::{
        io::{outboard::PostOrderMemOutboard, round_up_to_chunks, sync::encode_ranges_validated},
        ChunkNum,
    };
    use futures::{Future, Stream, StreamExt};
    use rand::RngCore;
    use range_collections::RangeSet2;
    use tokio::task::JoinSet;
    use tokio_util::task::LocalPoolHandle;

    use super::*;

    const IROH_BLOCK_SIZE: BlockSize = BlockSize(4);

    async fn validate(handle: &BaoFileHandle, original: &[u8], ranges: &[Range<u64>]) {
        let mut r = handle.data_reader();
        for range in ranges {
            let start = range.start.try_into().unwrap();
            let len = (range.end - range.start).try_into().unwrap();
            let data = &original[limited_range(start, len, original.len())];
            let read = r.read_at(start, len).await.unwrap();
            assert_eq!(data.len(), read.as_ref().len());
            assert_eq!(data, read.as_ref());
        }
    }

    fn random_test_data(size: usize) -> Vec<u8> {
        let mut rand = rand::thread_rng();
        let mut res = vec![0u8; size];
        rand.fill_bytes(&mut res);
        res
    }

    fn to_ranges(ranges: &[Range<u64>]) -> RangeSet2<u64> {
        let mut range_set = RangeSet2::empty();
        for range in ranges.as_ref().iter().cloned() {
            range_set |= RangeSet2::from(range);
        }
        range_set
    }

    /// Simulate the send side, when asked to send bao encoded data for the given ranges.
    fn make_wire_data(
        data: &[u8],
        ranges: impl AsRef<[Range<u64>]>,
    ) -> (blake3::Hash, ChunkRanges, Vec<u8>) {
        // compute a range set from the given ranges
        let range_set = to_ranges(ranges.as_ref());
        // round up to chunks
        let chunk_ranges = round_up_to_chunks(&range_set);
        // compute the outboard
        let outboard = PostOrderMemOutboard::create(data, IROH_BLOCK_SIZE).flip();
        let mut encoded = Vec::new();
        encode_ranges_validated(data, &outboard, &chunk_ranges, &mut encoded).unwrap();
        (*outboard.hash(), chunk_ranges, encoded)
    }

    /// Helper to simulate a slow request.
    fn trickle(data: &[u8], mtu: usize, delay: std::time::Duration) -> impl Stream<Item = Bytes> {
        let parts = data
            .chunks(mtu)
            .map(Bytes::copy_from_slice)
            .collect::<Vec<_>>();
        futures::stream::iter(parts).then(move |part| async move {
            tokio::time::sleep(delay).await;
            part
        })
    }

    async fn local<F>(f: F) -> F::Output
    where
        F: Future,
    {
        tokio::task::LocalSet::new().run_until(f).await
    }

    #[tokio::test]
    async fn partial_downloads() {
        local(async move {
            let n = 1024 * 64u64;
            let test_data = random_test_data(n as usize);
            let temp_dir = tempfile::tempdir().unwrap();
            let hash = blake3::hash(&test_data);
            let handle = BaoFileHandle::new(
                Arc::new(BaoFileConfig::new(
                    Arc::new(temp_dir.as_ref().to_owned()),
                    1024 * 16,
                    None,
                )),
                hash,
            );
            let mut tasks = JoinSet::new();
            for i in 1..3 {
                let file = handle.writer();
                let range = (i * (n / 4)) as u64..((i + 1) * (n / 4)) as u64;
                println!("range: {:?}", range);
                let (hash, chunk_ranges, wire_data) = make_wire_data(&test_data, &[range]);
                let trickle = trickle(&wire_data, 1200, std::time::Duration::from_millis(10))
                    .map(io::Result::Ok)
                    .boxed();
                let trickle = tokio_util::io::StreamReader::new(trickle);
                let _task = tasks.spawn_local(async move {
                    decode_response_into_batch(hash, IROH_BLOCK_SIZE, chunk_ranges, trickle, file)
                        .await
                });
            }
            while let Some(res) = tasks.join_next().await {
                res.unwrap().unwrap();
            }
            println!(
                "len {:?} {:?}",
                handle,
                handle.data_reader().len().await.unwrap()
            );
            validate(&handle, &test_data, &[1024 * 16..1024 * 48]).await;

            // let ranges =
            // let full_chunks = bao_tree::io::full_chunk_groups();
            let encoded = Vec::new();
            bao_tree::io::fsm::encode_ranges_validated(
                handle.data_reader(),
                handle.outboard().unwrap(),
                &ChunkRanges::from(ChunkNum(16)..ChunkNum(48)),
                encoded,
            )
            .await
            .unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn concurrent_downloads() {
        let n = 1024 * 32u64;
        let test_data = random_test_data(n as usize);
        let temp_dir = tempfile::tempdir().unwrap();
        let hash = blake3::hash(&test_data);
        let handle = BaoFileHandle::new(
            Arc::new(BaoFileConfig::new(
                Arc::new(temp_dir.as_ref().to_owned()),
                1024 * 16,
                None,
            )),
            hash,
        );
        let local = LocalPoolHandle::new(4);
        let mut tasks = Vec::new();
        for i in 0..4 {
            let file = handle.writer();
            let range = (i * (n / 4)) as u64..((i + 1) * (n / 4)) as u64;
            println!("range: {:?}", range);
            let (hash, chunk_ranges, wire_data) = make_wire_data(&test_data, &[range]);
            let trickle = trickle(&wire_data, 1200, std::time::Duration::from_millis(10))
                .map(io::Result::Ok)
                .boxed();
            let trickle = tokio_util::io::StreamReader::new(trickle);
            let task = local.spawn_pinned(move || async move {
                decode_response_into_batch(hash, IROH_BLOCK_SIZE, chunk_ranges, trickle, file).await
            });
            tasks.push(task);
        }
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        println!(
            "len {:?} {:?}",
            handle,
            handle.data_reader().len().await.unwrap()
        );
        validate(&handle, &test_data, &[0..n]).await;

        let encoded = Vec::new();
        bao_tree::io::fsm::encode_ranges_validated(
            handle.data_reader(),
            handle.outboard().unwrap(),
            &ChunkRanges::all(),
            encoded,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn stay_in_mem() {
        let test_data = random_test_data(1024 * 17);
        let ranges = [0..test_data.len().try_into().unwrap()];
        let (hash, chunk_ranges, wire_data) = make_wire_data(&test_data, &ranges);
        println!("file len is {:?}", chunk_ranges);
        let temp_dir = tempfile::tempdir().unwrap();
        let handle = BaoFileHandle::new(
            Arc::new(BaoFileConfig::new(
                Arc::new(temp_dir.as_ref().to_owned()),
                1024 * 16,
                None,
            )),
            hash,
        );
        decode_response_into_batch(
            hash,
            IROH_BLOCK_SIZE,
            chunk_ranges,
            wire_data.as_slice(),
            handle.writer(),
        )
        .await
        .unwrap();
        validate(&handle, &test_data, &ranges).await;

        let encoded = Vec::new();
        bao_tree::io::fsm::encode_ranges_validated(
            handle.data_reader(),
            handle.outboard().unwrap(),
            &ChunkRanges::all(),
            encoded,
        )
        .await
        .unwrap();
        println!("{:?}", handle);
    }
}
