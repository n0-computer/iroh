//! Traits for in-memory or persistent maps of blob with bao encoded outboards.
use std::{collections::BTreeSet, io, path::PathBuf};

use bao_tree::{
    io::fsm::{BaoContentItem, Outboard},
    BaoTree, ChunkRanges,
};
use bytes::Bytes;
use futures::{Future, Stream, StreamExt};
use genawaiter::rc::{Co, Gen};
use iroh_base::rpc::RpcError;
use iroh_io::AsyncSliceReader;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncRead;
use tokio_util::task::LocalPoolHandle;

use crate::{
    hashseq::parse_hash_seq,
    protocol::RangeSpec,
    util::{
        progress::{BoxedProgressSender, IdGenerator, ProgressSender},
        Tag,
    },
    BlobFormat, Hash, HashAndFormat, TempTag, IROH_BLOCK_SIZE,
};

pub use bao_tree;
pub use range_collections;

/// A fallible but owned iterator over the entries in a store.
pub type DbIter<T> = Box<dyn Iterator<Item = io::Result<T>> + Send + Sync + 'static>;

/// Export trogress callback
pub type ExportProgressCb = Box<dyn Fn(u64) -> io::Result<()> + Send + Sync + 'static>;

/// The availability status of an entry in a store.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EntryStatus {
    /// The entry is completely available.
    Complete,
    /// The entry is partially available.
    Partial,
    /// The entry is not in the store.
    NotFound,
}

/// The size of a bao file
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BaoBlobSize {
    /// A remote side told us the size, but we have insufficient data to verify it.
    Unverified(u64),
    /// We have verified the size.
    Verified(u64),
}

impl BaoBlobSize {
    /// Create a new `BaoFileSize` with the given size and verification status.
    pub fn new(size: u64, verified: bool) -> Self {
        if verified {
            BaoBlobSize::Verified(size)
        } else {
            BaoBlobSize::Unverified(size)
        }
    }

    /// Get just the value, no matter if it is verified or not.
    pub fn value(&self) -> u64 {
        match self {
            BaoBlobSize::Unverified(size) => *size,
            BaoBlobSize::Verified(size) => *size,
        }
    }
}

/// An entry for one hash in a bao map
///
/// The entry has the ability to provide you with an (outboard, data)
/// reader pair. Creating the reader is async and may fail. The futures that
/// create the readers must be `Send`, but the readers themselves don't have to
/// be.
pub trait MapEntry: std::fmt::Debug + Clone + Send + Sync + 'static {
    /// The hash of the entry.
    fn hash(&self) -> Hash;
    /// The size of the entry.
    fn size(&self) -> BaoBlobSize;
    /// Returns `true` if the entry is complete.
    ///
    /// Note that this does not actually verify if the bytes on disk are complete,
    /// it only checks if the entry was marked as complete in the store.
    fn is_complete(&self) -> bool;
    /// A future that resolves to a reader that can be used to read the outboard
    fn outboard(&self) -> impl Future<Output = io::Result<impl Outboard>> + Send;
    /// A future that resolves to a reader that can be used to read the data
    fn data_reader(&self) -> impl Future<Output = io::Result<impl AsyncSliceReader>> + Send;
}

/// A generic map from hashes to bao blobs (blobs with bao outboards).
///
/// This is the readonly view. To allow updates, a concrete implementation must
/// also implement [`MapMut`].
///
/// Entries are *not* guaranteed to be complete for all implementations.
/// They are also not guaranteed to be immutable, since this could be the
/// readonly view of a mutable store.
pub trait Map: Clone + Send + Sync + 'static {
    /// The entry type. An entry is a cheaply cloneable handle that can be used
    /// to open readers for both the data and the outboard
    type Entry: MapEntry;
    /// Get an entry for a hash.
    ///
    /// This can also be used for a membership test by just checking if there
    /// is an entry. Creating an entry should be cheap, any expensive ops should
    /// be deferred to the creation of the actual readers.
    ///
    /// It is not guaranteed that the entry is complete.
    fn get(&self, hash: &Hash) -> impl Future<Output = io::Result<Option<Self::Entry>>> + Send;
}

/// A partial entry
pub trait MapEntryMut: MapEntry {
    /// Get a batch writer
    fn batch_writer(&self) -> impl Future<Output = io::Result<impl BaoBatchWriter>> + Send;
}

/// An async batch interface for writing bao content items to a pair of data and
/// outboard.
///
/// Details like the chunk group size and the actual storage location are left
/// to the implementation.
pub trait BaoBatchWriter {
    /// Write a batch of bao content items to the underlying storage.
    ///
    /// The batch is guaranteed to be sorted as data is received from the network.
    /// So leafs will be sorted by offset, and parents will be sorted by pre order
    /// traversal offset. There is no guarantee that they will be consecutive
    /// though.
    ///
    /// The size is the total size of the blob that the remote side told us.
    /// It is not guaranteed to be correct, but it is guaranteed to be
    /// consistent with all data in the batch. The size therefore represents
    /// an upper bound on the maximum offset of all leaf items.
    /// So it is guaranteed that `leaf.offset + leaf.size <= size` for all
    /// leaf items in the batch.
    ///
    /// Batches should not become too large. Typically, a batch is just a few
    /// parent nodes and a leaf.
    ///
    /// Batch is a vec so it can be moved into a task, which is unfortunately
    /// necessary in typical io code.
    fn write_batch(
        &mut self,
        size: u64,
        batch: Vec<BaoContentItem>,
    ) -> impl Future<Output = io::Result<()>>;

    /// Sync the written data to permanent storage, if applicable.
    /// E.g. for a file based implementation, this would call sync_data
    /// on all files.
    fn sync(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// Implement BaoBatchWriter for mutable references
impl<W: BaoBatchWriter> BaoBatchWriter for &mut W {
    async fn write_batch(&mut self, size: u64, batch: Vec<BaoContentItem>) -> io::Result<()> {
        (**self).write_batch(size, batch).await
    }

    async fn sync(&mut self) -> io::Result<()> {
        (**self).sync().await
    }
}

/// A wrapper around a batch writer that calls a progress callback for one leaf
/// per batch.
#[derive(Debug)]
pub(crate) struct FallibleProgressBatchWriter<W, F>(W, F);

impl<W: BaoBatchWriter, F: Fn(u64, usize) -> io::Result<()> + 'static>
    FallibleProgressBatchWriter<W, F>
{
    /// Create a new `FallibleProgressBatchWriter` from an inner writer and a progress callback
    ///
    /// The `on_write` function is called for each write, with the `offset` as the first and the
    /// length of the data as the second param. `on_write` must return an `io::Result`.
    /// If `on_write` returns an error, the download is aborted.
    pub fn new(inner: W, on_write: F) -> Self {
        Self(inner, on_write)
    }
}

impl<W: BaoBatchWriter, F: Fn(u64, usize) -> io::Result<()> + 'static> BaoBatchWriter
    for FallibleProgressBatchWriter<W, F>
{
    async fn write_batch(&mut self, size: u64, batch: Vec<BaoContentItem>) -> io::Result<()> {
        // find the offset and length of the first (usually only) chunk
        let chunk = batch
            .iter()
            .filter_map(|item| {
                if let BaoContentItem::Leaf(leaf) = item {
                    Some((leaf.offset, leaf.data.len()))
                } else {
                    None
                }
            })
            .next();
        self.0.write_batch(size, batch).await?;
        // call the progress callback
        if let Some((offset, len)) = chunk {
            (self.1)(offset, len)?;
        }
        Ok(())
    }

    async fn sync(&mut self) -> io::Result<()> {
        self.0.sync().await
    }
}

/// A mutable bao map.
///
/// This extends the readonly [`Map`] trait with methods to create and modify entries.
pub trait MapMut: Map {
    /// An entry that is possibly writable
    type EntryMut: MapEntryMut;

    /// Get an existing entry as an EntryMut.
    ///
    /// For implementations where EntryMut and Entry are the same type, this is just an alias for
    /// `get`.
    fn get_mut(
        &self,
        hash: &Hash,
    ) -> impl Future<Output = io::Result<Option<Self::EntryMut>>> + Send;

    /// Get an existing partial entry, or create a new one.
    ///
    /// We need to know the size of the partial entry. This might produce an
    /// error e.g. if there is not enough space on disk.
    fn get_or_create(
        &self,
        hash: Hash,
        size: u64,
    ) -> impl Future<Output = io::Result<Self::EntryMut>> + Send;

    /// Find out if the data behind a `hash` is complete, partial, or not present.
    ///
    /// Note that this does not actually verify the on-disc data, but only checks in which section
    /// of the store the entry is present.
    fn entry_status(&self, hash: &Hash) -> impl Future<Output = io::Result<EntryStatus>> + Send;

    /// Sync version of `entry_status`, for the doc sync engine until we can get rid of it.
    ///
    /// Don't count on this to be efficient.
    fn entry_status_sync(&self, hash: &Hash) -> io::Result<EntryStatus>;

    /// Upgrade a partial entry to a complete entry.
    fn insert_complete(&self, entry: Self::EntryMut)
        -> impl Future<Output = io::Result<()>> + Send;
}

/// Extension of [`Map`] to add misc methods used by the rpc calls.
pub trait ReadableStore: Map {
    /// list all blobs in the database. This includes both raw blobs that have
    /// been imported, and hash sequences that have been created internally.
    fn blobs(&self) -> impl Future<Output = io::Result<DbIter<Hash>>> + Send;
    /// list all tags (collections or other explicitly added things) in the database
    fn tags(&self) -> impl Future<Output = io::Result<DbIter<(Tag, HashAndFormat)>>> + Send;

    /// Temp tags
    fn temp_tags(&self) -> Box<dyn Iterator<Item = HashAndFormat> + Send + Sync + 'static>;

    /// Perform a consistency check on the database
    fn consistency_check(
        &self,
        repair: bool,
        tx: BoxedProgressSender<ConsistencyCheckProgress>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// list partial blobs in the database
    fn partial_blobs(&self) -> impl Future<Output = io::Result<DbIter<Hash>>> + Send;

    /// This trait method extracts a file to a local path.
    ///
    /// `hash` is the hash of the file
    /// `target` is the path to the target file
    /// `mode` is a hint how the file should be exported.
    /// `progress` is a callback that is called with the total number of bytes that have been written
    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        mode: ExportMode,
        progress: ExportProgressCb,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

/// The mutable part of a Bao store.
pub trait Store: ReadableStore + MapMut {
    /// This trait method imports a file from a local path.
    ///
    /// `data` is the path to the file.
    /// `mode` is a hint how the file should be imported.
    /// `progress` is a sender that provides a way for the importer to send progress messages
    /// when importing large files. This also serves as a way to cancel the import. If the
    /// consumer of the progress messages is dropped, subsequent attempts to send progress
    /// will fail.
    ///
    /// Returns the hash of the imported file. The reason to have this method is that some database
    /// implementations might be able to import a file without copying it.
    fn import_file(
        &self,
        data: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> impl Future<Output = io::Result<(TempTag, u64)>> + Send;

    /// Import data from memory.
    ///
    /// It is a special case of `import` that does not use the file system.
    fn import_bytes(
        &self,
        bytes: Bytes,
        format: BlobFormat,
    ) -> impl Future<Output = io::Result<TempTag>> + Send;

    /// Import data from a stream of bytes.
    fn import_stream(
        &self,
        data: impl Stream<Item = io::Result<Bytes>> + Send + Unpin + 'static,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> impl Future<Output = io::Result<(TempTag, u64)>> + Send;

    /// Import data from an async byte reader.
    fn import_reader(
        &self,
        data: impl AsyncRead + Send + Unpin + 'static,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> impl Future<Output = io::Result<(TempTag, u64)>> + Send {
        let stream = tokio_util::io::ReaderStream::new(data);
        self.import_stream(stream, format, progress)
    }

    /// Set a tag
    fn set_tag(
        &self,
        name: Tag,
        hash: Option<HashAndFormat>,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Create a new tag
    fn create_tag(&self, hash: HashAndFormat) -> impl Future<Output = io::Result<Tag>> + Send;

    /// Create a temporary pin for this store
    fn temp_tag(&self, value: HashAndFormat) -> TempTag;

    /// Notify the store that a new gc phase is about to start
    fn gc_start(&self) -> impl Future<Output = io::Result<()>> + Send;

    /// Traverse all roots recursively and mark them as live.
    ///
    /// Poll this stream to completion to perform a full gc mark phase.
    ///
    /// Not polling this stream to completion is dangerous, since it might lead
    /// to some live data being missed.
    ///
    /// The implementation of this method should do the minimum amount of work
    /// to determine the live set. Actual deletion of garbage should be done
    /// in the gc_sweep phase.
    fn gc_mark(&self, live: &mut BTreeSet<Hash>) -> impl Stream<Item = GcMarkEvent> + Unpin {
        Gen::new(|co| async move {
            if let Err(e) = gc_mark_task(self, live, &co).await {
                co.yield_(GcMarkEvent::Error(e)).await;
            }
        })
    }

    /// Remove all blobs that are not marked as live.
    ///
    /// Poll this stream to completion to perform a full gc sweep. Not polling this stream
    /// to completion just means that some garbage will remain in the database.
    ///
    /// Sweeping might take long, but it can safely be done in the background.
    fn gc_sweep(&self, live: &BTreeSet<Hash>) -> impl Stream<Item = GcSweepEvent> + Unpin {
        Gen::new(|co| async move {
            if let Err(e) = gc_sweep_task(self, live, &co).await {
                co.yield_(GcSweepEvent::Error(e)).await;
            }
        })
    }

    /// physically delete the given hashes from the store.
    fn delete(&self, hashes: Vec<Hash>) -> impl Future<Output = io::Result<()>> + Send;

    /// Shutdown the store.
    fn shutdown(&self) -> impl Future<Output = ()> + Send;

    /// Validate the database
    ///
    /// This will check that the file and outboard content is correct for all complete
    /// entries, and output valid ranges for all partial entries.
    ///
    /// It will not check the internal consistency of the database.
    fn validate(
        &self,
        repair: bool,
        tx: BoxedProgressSender<ValidateProgress>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        validate_impl(self, repair, tx)
    }
}

async fn validate_impl(
    store: &impl Store,
    repair: bool,
    tx: BoxedProgressSender<ValidateProgress>,
) -> io::Result<()> {
    use futures_buffered::BufferedStreamExt;

    let validate_parallelism: usize = num_cpus::get();
    let lp = LocalPoolHandle::new(validate_parallelism);
    let complete = store.blobs().await?.collect::<io::Result<Vec<_>>>()?;
    let partial = store
        .partial_blobs()
        .await?
        .collect::<io::Result<Vec<_>>>()?;
    tx.send(ValidateProgress::Starting {
        total: complete.len() as u64,
    })
    .await?;
    let complete_result = futures::stream::iter(complete)
        .map(|hash| {
            let store = store.clone();
            let tx = tx.clone();
            lp.spawn_pinned(move || async move {
                let entry = store
                    .get(&hash)
                    .await?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "entry not found"))?;
                let size = entry.size().value();
                let outboard = entry.outboard().await?;
                let data = entry.data_reader().await?;
                let chunk_ranges = ChunkRanges::all();
                let mut ranges = bao_tree::io::fsm::valid_ranges(outboard, data, &chunk_ranges);
                let id = tx.new_id();
                tx.send(ValidateProgress::Entry {
                    id,
                    hash,
                    path: None,
                    size,
                })
                .await?;
                let mut actual_chunk_ranges = ChunkRanges::empty();
                while let Some(item) = ranges.next().await {
                    let item = item?;
                    let offset = item.start.to_bytes();
                    actual_chunk_ranges |= ChunkRanges::from(item);
                    tx.try_send(ValidateProgress::EntryProgress { id, offset })?;
                }
                let expected_chunk_range =
                    ChunkRanges::from(..BaoTree::new(size, IROH_BLOCK_SIZE).chunks());
                let incomplete = actual_chunk_ranges == expected_chunk_range;
                let error = if incomplete {
                    None
                } else {
                    Some(format!(
                        "expected chunk ranges {:?}, got chunk ranges {:?}",
                        expected_chunk_range, actual_chunk_ranges
                    ))
                };
                tx.send(ValidateProgress::EntryDone { id, error }).await?;
                drop(ranges);
                drop(entry);
                io::Result::Ok((hash, incomplete))
            })
        })
        .buffered_unordered(validate_parallelism)
        .collect::<Vec<_>>()
        .await;
    let partial_result = futures::stream::iter(partial)
        .map(|hash| {
            let store = store.clone();
            let tx = tx.clone();
            lp.spawn_pinned(move || async move {
                let entry = store
                    .get(&hash)
                    .await?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "entry not found"))?;
                let size = entry.size().value();
                let outboard = entry.outboard().await?;
                let data = entry.data_reader().await?;
                let chunk_ranges = ChunkRanges::all();
                let mut ranges = bao_tree::io::fsm::valid_ranges(outboard, data, &chunk_ranges);
                let id = tx.new_id();
                tx.send(ValidateProgress::PartialEntry {
                    id,
                    hash,
                    path: None,
                    size,
                })
                .await?;
                let mut actual_chunk_ranges = ChunkRanges::empty();
                while let Some(item) = ranges.next().await {
                    let item = item?;
                    let offset = item.start.to_bytes();
                    actual_chunk_ranges |= ChunkRanges::from(item);
                    tx.try_send(ValidateProgress::PartialEntryProgress { id, offset })?;
                }
                tx.send(ValidateProgress::PartialEntryDone {
                    id,
                    ranges: RangeSpec::new(&actual_chunk_ranges),
                })
                .await?;
                drop(ranges);
                drop(entry);
                io::Result::Ok(())
            })
        })
        .buffered_unordered(validate_parallelism)
        .collect::<Vec<_>>()
        .await;
    let mut to_downgrade = Vec::new();
    for item in complete_result {
        let (hash, incomplete) = item??;
        if incomplete {
            to_downgrade.push(hash);
        }
    }
    for item in partial_result {
        item??;
    }
    if repair {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "repair not implemented",
        ));
    }
    Ok(())
}

/// Implementation of the gc method.
async fn gc_mark_task<'a>(
    store: &'a impl Store,
    live: &'a mut BTreeSet<Hash>,
    co: &Co<GcMarkEvent>,
) -> anyhow::Result<()> {
    macro_rules! debug {
        ($($arg:tt)*) => {
            co.yield_(GcMarkEvent::CustomDebug(format!($($arg)*))).await;
        };
    }
    macro_rules! warn {
        ($($arg:tt)*) => {
            co.yield_(GcMarkEvent::CustomWarning(format!($($arg)*), None)).await;
        };
    }
    let mut roots = BTreeSet::new();
    debug!("traversing tags");
    for item in store.tags().await? {
        let (name, haf) = item?;
        debug!("adding root {:?} {:?}", name, haf);
        roots.insert(haf);
    }
    debug!("traversing temp roots");
    for haf in store.temp_tags() {
        debug!("adding temp pin {:?}", haf);
        roots.insert(haf);
    }
    for HashAndFormat { hash, format } in roots {
        // we need to do this for all formats except raw
        if live.insert(hash) && !format.is_raw() {
            let Some(entry) = store.get(&hash).await? else {
                warn!("gc: {} not found", hash);
                continue;
            };
            if !entry.is_complete() {
                warn!("gc: {} is partial", hash);
                continue;
            }
            let Ok(reader) = entry.data_reader().await else {
                warn!("gc: {} creating data reader failed", hash);
                continue;
            };
            let Ok((mut stream, count)) = parse_hash_seq(reader).await else {
                warn!("gc: {} parse failed", hash);
                continue;
            };
            debug!("parsed collection {} {:?}", hash, count);
            loop {
                let item = match stream.next().await {
                    Ok(Some(item)) => item,
                    Ok(None) => break,
                    Err(_err) => {
                        warn!("gc: {} parse failed", hash);
                        break;
                    }
                };
                // if format != raw we would have to recurse here by adding this to current
                live.insert(item);
            }
        }
    }
    debug!("gc mark done. found {} live blobs", live.len());
    Ok(())
}

async fn gc_sweep_task<'a>(
    store: &'a impl Store,
    live: &BTreeSet<Hash>,
    co: &Co<GcSweepEvent>,
) -> anyhow::Result<()> {
    let blobs = store.blobs().await?.chain(store.partial_blobs().await?);
    let mut count = 0;
    let mut batch = Vec::new();
    for hash in blobs {
        let hash = hash?;
        if !live.contains(&hash) {
            batch.push(hash);
            count += 1;
        }
        if batch.len() >= 100 {
            store.delete(batch.clone()).await?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        store.delete(batch).await?;
    }
    co.yield_(GcSweepEvent::CustomDebug(format!(
        "deleted {} blobs",
        count
    )))
    .await;
    Ok(())
}

/// An event related to GC
#[derive(Debug)]
pub enum GcMarkEvent {
    /// A custom event (info)
    CustomDebug(String),
    /// A custom non critical error
    CustomWarning(String, Option<anyhow::Error>),
    /// An unrecoverable error during GC
    Error(anyhow::Error),
}

/// An event related to GC
#[derive(Debug)]
pub enum GcSweepEvent {
    /// A custom event (debug)
    CustomDebug(String),
    /// A custom non critical error
    CustomWarning(String, Option<anyhow::Error>),
    /// An unrecoverable error during GC
    Error(anyhow::Error),
}

/// Progress messages for an import operation
///
/// An import operation involves computing the outboard of a file, and then
/// either copying or moving the file into the database.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum ImportProgress {
    /// Found a path
    ///
    /// This will be the first message for an id
    Found { id: u64, name: String },
    /// Progress when copying the file to the store
    ///
    /// This will be omitted if the store can use the file in place
    ///
    /// There will be multiple of these messages for an id
    CopyProgress { id: u64, offset: u64 },
    /// Determined the size
    ///
    /// This will come after `Found` and zero or more `CopyProgress` messages.
    /// For unstable files, determining the size will only be done once the file
    /// is fully copied.
    Size { id: u64, size: u64 },
    /// Progress when computing the outboard
    ///
    /// There will be multiple of these messages for an id
    OutboardProgress { id: u64, offset: u64 },
    /// Done computing the outboard
    ///
    /// This comes after `Size` and zero or more `OutboardProgress` messages
    OutboardDone { id: u64, hash: Hash },
}

/// The import mode describes how files will be imported.
///
/// This is a hint to the import trait method. For some implementations, this
/// does not make any sense. E.g. an in memory implementation will always have
/// to copy the file into memory. Also, a disk based implementation might choose
/// to copy small files even if the mode is `Reference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    /// This mode will copy the file into the database before hashing.
    ///
    /// This is the safe default because the file can not be accidentally modified
    /// after it has been imported.
    #[default]
    Copy,
    /// This mode will try to reference the file in place and assume it is unchanged after import.
    ///
    /// This has a large performance and storage benefit, but it is less safe since
    /// the file might be modified after it has been imported.
    ///
    /// Stores are allowed to ignore this mode and always copy the file, e.g.
    /// if the file is very small or if the store does not support referencing files.
    TryReference,
}
/// The import mode describes how files will be imported.
///
/// This is a hint to the import trait method. For some implementations, this
/// does not make any sense. E.g. an in memory implementation will always have
/// to copy the file into memory. Also, a disk based implementation might choose
/// to copy small files even if the mode is `Reference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum ExportMode {
    /// This mode will copy the file to the target directory.
    ///
    /// This is the safe default because the file can not be accidentally modified
    /// after it has been exported.
    #[default]
    Copy,
    /// This mode will try to move the file to the target directory and then reference it from
    /// the database.
    ///
    /// This has a large performance and storage benefit, but it is less safe since
    /// the file might be modified in the target directory after it has been exported.
    ///
    /// Stores are allowed to ignore this mode and always copy the file, e.g.
    /// if the file is very small or if the store does not support referencing files.
    TryReference,
}

/// The expected format of a hash being exported.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ExportFormat {
    /// The hash refers to any blob and will be exported to a single file.
    #[default]
    Blob,
    /// The hash refers to a [`crate::format::collection::Collection`] blob
    /// and all children of the collection shall be exported to one file per child.
    ///
    /// If the blob can be parsed as a [`BlobFormat::HashSeq`], and the first child contains
    /// collection metadata, all other children of the collection will be exported to
    /// a file each, with their collection name treated as a relative path to the export
    /// destination path.
    ///
    /// If the blob cannot be parsed as a collection, the operation will fail.
    Collection,
}

#[allow(missing_docs)]
#[derive(Debug)]
pub enum ExportProgress {
    /// Starting to export to a file
    ///
    /// This will be the first message for an id
    Start {
        id: u64,
        hash: Hash,
        path: PathBuf,
        stable: bool,
    },
    /// Progress when copying the file to the target
    ///
    /// This will be omitted if the store can move the file or use copy on write
    ///
    /// There will be multiple of these messages for an id
    Progress { id: u64, offset: u64 },
    /// Done exporting
    Done { id: u64 },
}

/// Level for generic validation messages
#[derive(
    Debug, Clone, Copy, derive_more::Display, Serialize, Deserialize, PartialOrd, Ord, PartialEq, Eq,
)]
pub enum ReportLevel {
    /// Very unimportant info messages
    Trace,
    /// Info messages
    Info,
    /// Warnings, something is not quite right
    Warn,
    /// Errors, something is very wrong
    Error,
}

/// Progress updates for the validate operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ConsistencyCheckProgress {
    /// Consistency check started
    Start,
    /// Consistency check update
    Update {
        /// The message
        message: String,
        /// The entry this message is about, if any
        entry: Option<Hash>,
        /// The level of the message
        level: ReportLevel,
    },
    /// Consistency check ended
    Done,
    /// We got an error and need to abort.
    Abort(RpcError),
}

/// Progress updates for the validate operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ValidateProgress {
    /// started validating
    Starting {
        /// The total number of entries to validate
        total: u64,
    },
    /// We started validating a complete entry
    Entry {
        /// a new unique id for this entry
        id: u64,
        /// the hash of the entry
        hash: Hash,
        /// location of the entry.
        ///
        /// In case of a file, this is the path to the file.
        /// Otherwise it might be an url or something else to uniquely identify the entry.
        path: Option<String>,
        /// The size of the entry, in bytes.
        size: u64,
    },
    /// We got progress ingesting item `id`.
    EntryProgress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done with `id`
    EntryDone {
        /// The unique id of the entry.
        id: u64,
        /// An error if we failed to validate the entry.
        error: Option<String>,
    },
    /// We started validating an entry
    PartialEntry {
        /// a new unique id for this entry
        id: u64,
        /// the hash of the entry
        hash: Hash,
        /// location of the entry.
        ///
        /// In case of a file, this is the path to the file.
        /// Otherwise it might be an url or something else to uniquely identify the entry.
        path: Option<String>,
        /// The best known size of the entry, in bytes.
        size: u64,
    },
    /// We got progress ingesting item `id`.
    PartialEntryProgress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done with `id`
    PartialEntryDone {
        /// The unique id of the entry.
        id: u64,
        /// Available ranges.
        ranges: RangeSpec,
    },
    /// We are done with the whole operation.
    AllDone,
    /// We got an error and need to abort.
    Abort(RpcError),
}

/// Database events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A GC was started
    GcStarted,
    /// A GC was completed
    GcCompleted,
}
