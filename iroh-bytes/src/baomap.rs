//! Traits for in-memory or persistent maps of blob with bao encoded outboards.
use std::{collections::BTreeSet, io, path::PathBuf, sync::Arc};

use crate::{
    collection::CollectionParser,
    util::{
        progress::{IdGenerator, ProgressSender},
        BlobFormat, Cid, RpcError,
    },
    Hash,
};
use bao_tree::{blake3, ChunkNum};
use bytes::Bytes;
use futures::{future::BoxFuture, stream::LocalBoxStream, FutureExt, StreamExt};
use genawaiter::rc::{Co, Gen};
use iroh_io::AsyncSliceReader;
use range_collections::RangeSet2;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub use bao_tree;
pub use range_collections;

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

/// An entry for one hash in a bao collection
///
/// The entry has the ability to provide you with an (outboard, data)
/// reader pair. Creating the reader is async and may fail. The futures that
/// create the readers must be `Send`, but the readers themselves don't have to
/// be.
pub trait MapEntry<D: Map>: Clone + Send + Sync + 'static {
    /// The hash of the entry.
    fn hash(&self) -> blake3::Hash;
    /// The size of the entry.
    fn size(&self) -> u64;
    /// Returns `true` if the entry is complete.
    ///
    /// Note that this does not actually verify if the bytes on disk are complete, it only checks
    /// if the entry is among the partial or complete section of the [`Map`]. To verify if all
    /// bytes are actually available on disk, use [`MapEntry::available_ranges`].
    fn is_complete(&self) -> bool;
    /// Compute the available ranges.
    ///
    /// Depending on the implementation, this may be an expensive operation.
    ///
    /// It can also only ever be a best effort, since the underlying data may
    /// change at any time. E.g. somebody could flip a bit in the file, or download
    /// more chunks.
    fn available_ranges(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>>;
    /// A future that resolves to a reader that can be used to read the outboard
    fn outboard(&self) -> BoxFuture<'_, io::Result<D::Outboard>>;
    /// A future that resolves to a reader that can be used to read the data
    fn data_reader(&self) -> BoxFuture<'_, io::Result<D::DataReader>>;
}

/// A generic collection of blobs with precomputed outboards
pub trait Map: Clone + Send + Sync + 'static {
    /// The outboard type. This can be an in memory outboard or an outboard that
    /// retrieves the data asynchronously from a remote database.
    type Outboard: bao_tree::io::fsm::Outboard;
    /// The reader type.
    type DataReader: AsyncSliceReader;
    /// The entry type. An entry is a cheaply cloneable handle that can be used
    /// to open readers for both the data and the outboard
    type Entry: MapEntry<Self>;
    /// Get an entry for a hash.
    ///
    /// This can also be used for a membership test by just checking if there
    /// is an entry. Creating an entry should be cheap, any expensive ops should
    /// be deferred to the creation of the actual readers.
    ///
    /// It is not guaranteed that the entry is complete. A [PartialMap] would return
    /// here both complete and partial entries, so that you can share partial entries.
    ///
    /// This function should not block to perform io. The knowledge about
    /// existing entries must be present in memory.
    fn get(&self, hash: &Hash) -> Option<Self::Entry>;

    /// Find out if the data behind a `hash` is complete, partial, or not present.
    ///
    /// Note that this does not actually verify the on-disc data, but only checks in which section
    /// of the store the entry is present.
    fn contains(&self, hash: &Hash) -> EntryStatus;
}

/// A partial entry
pub trait PartialMapEntry<D: PartialMap>: MapEntry<D> {
    /// A future that resolves to an writeable outboard
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<D::OutboardMut>>;
    /// A future that resolves to a writer that can be used to write the data
    fn data_writer(&self) -> BoxFuture<'_, io::Result<D::DataWriter>>;
}

/// A mutable bao map
pub trait PartialMap: Map {
    /// The outboard type to write data to the partial entry.
    type OutboardMut: bao_tree::io::fsm::OutboardMut;
    /// The writer type to write data to the partial entry.
    type DataWriter: iroh_io::AsyncSliceWriter;
    /// A partial entry. This is an entry that is writeable and possibly incomplete.
    ///
    /// It must also be readable.
    type PartialEntry: PartialMapEntry<Self>;

    /// Get an existing partial entry, or create a new one.
    ///
    /// We need to know the size of the partial entry. This might produce an
    /// error e.g. if there is not enough space on disk.
    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Self::PartialEntry>;

    /// Get an existing partial entry.
    ///
    /// This will return `None` if there is no partial entry for this hash.
    ///
    /// This function should not block to perform io. The knowledge about
    /// partial entries must be present in memory.
    fn get_partial(&self, hash: &Hash) -> Option<Self::PartialEntry>;

    /// Upgrade a partial entry to a complete entry.
    fn insert_complete(&self, entry: Self::PartialEntry) -> BoxFuture<'_, io::Result<()>>;
}

/// Extension of BaoMap to add misc methods used by the rpc calls.
pub trait ReadableStore: Map {
    /// list all blobs in the database. This should include collections, since
    /// collections are blobs and can be requested as blobs.
    ///
    /// This function should not block to perform io. The knowledge about
    /// existing blobs must be present in memory.
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;
    /// list all tags (collections or other explicitly added things) in the database
    ///
    /// This function should not block to perform io. The knowledge about
    /// existing tags must be present in memory.
    fn tags(&self) -> Box<dyn Iterator<Item = (Bytes, Cid)> + Send + Sync + 'static>;

    /// Temp tags
    fn temp_tags(&self) -> Box<dyn Iterator<Item = Cid> + Send + Sync + 'static>;

    /// Validate the database
    fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>>;

    /// list partial blobs in the database
    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;

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
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>>;
}

/// The mutable part of a BaoDb
pub trait Store: ReadableStore + PartialMap {
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
    fn import(
        &self,
        data: PathBuf,
        mode: ImportMode,
        format: BlobFormat,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(TempTag, u64)>>;

    /// This trait method imports data from memory.
    ///
    /// It is a special case of `import` that does not use the file system.
    fn import_bytes(&self, bytes: Bytes, format: BlobFormat) -> BoxFuture<'_, io::Result<TempTag>>;

    /// Set a named pin
    fn set_tag(&self, name: Bytes, hash: Option<Cid>) -> BoxFuture<'_, io::Result<()>> {
        let _ = name;
        let _ = hash;
        async move { Ok(()) }.boxed()
    }

    /// Create a temporary pin for this store
    fn temp_tag(&self, cid: Cid) -> TempTag {
        TempTag {
            cid,
            liveness: None,
        }
    }

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
    fn gc_mark<'a>(
        &'a self,
        cp: impl CollectionParser + 'a,
        extra_roots: impl IntoIterator<Item = io::Result<Cid>> + 'a,
    ) -> LocalBoxStream<'a, GcMarkEvent> {
        Gen::new(|co| async move {
            if let Err(e) = gc_mark_task(self, cp, extra_roots, &co).await {
                co.yield_(GcMarkEvent::Error(e)).await;
            }
        })
        .boxed_local()
    }

    /// Remove all blobs that are not marked as live.
    ///
    /// Poll this stream to completion to perform a full gc sweep. Not polling this stream
    /// to completion just means that some garbage will remain in the database.
    ///
    /// Sweeping might take long, but it can safely be done in the background.
    fn gc_sweep(&self) -> LocalBoxStream<'_, GcSweepEvent> {
        let blobs = self.blobs();
        Gen::new(|co| async move {
            let mut count = 0;
            for hash in blobs {
                if !self.is_live(&hash) {
                    if let Err(e) = self.delete(&hash).await {
                        co.yield_(GcSweepEvent::Error(e.into())).await;
                    } else {
                        count += 1;
                    }
                }
            }
            co.yield_(GcSweepEvent::CustomInfo(format!("deleted {} blobs", count)))
                .await;
        })
        .boxed_local()
    }

    /// Clear the live set.
    fn clear_live(&self) {
        let _ = self;
    }

    /// Add the given hashes to the live set.
    ///
    /// This is used by the gc mark phase to mark roots as live.
    fn add_live(&self, live: impl IntoIterator<Item = Hash>) {
        let _ = live;
    }

    /// True if the given hash is live.
    fn is_live(&self, hash: &Hash) -> bool {
        let _ = hash;
        false
    }

    /// physically delete the given hash from the store.
    fn delete(&self, hash: &Hash) -> BoxFuture<'_, io::Result<()>> {
        let _ = hash;
        async move { Ok(()) }.boxed()
    }
}

/// A trait for things that can track liveness of cids.
///
/// A cid in iroh is just a hash and a format. This trait works together with
/// [PinnedCid] to keep track of the liveness of a cid.
///
/// It is important to include the format in the liveness tracking, since
/// pinning a blob and pinning a collection are different things.
pub trait LivenessTracker: std::fmt::Debug + Send + Sync + 'static {
    /// Called on clone
    fn on_clone(&self, cid: &Cid) {
        let _ = cid;
    }
    /// Called on drop
    fn on_drop(&self, cid: &Cid) {
        let _ = cid;
    }
}

/// A cid that is protected from garbage collection.
///
/// This contains all the information of a blake3 cid, but in addition keeps
/// the corresponding data alive.
#[derive(Debug)]
pub struct TempTag {
    /// The cid we are pinning
    cid: Cid,
    /// liveness tracker
    liveness: Option<Arc<dyn LivenessTracker>>,
}

impl TempTag {
    /// Create a new pinned cid
    pub fn new(cid: Cid, liveness: Option<Arc<dyn LivenessTracker>>) -> Self {
        if let Some(liveness) = liveness.as_ref() {
            liveness.on_clone(&cid);
        }
        Self { cid, liveness }
    }

    /// The hash of the pinned item
    pub fn cid(&self) -> &Cid {
        &self.cid
    }

    /// The hash of the pinned item
    pub fn hash(&self) -> &Hash {
        &self.cid.0
    }

    /// The format of the pinned item
    pub fn format(&self) -> BlobFormat {
        self.cid.1
    }
}

impl Clone for TempTag {
    fn clone(&self) -> Self {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.on_clone(&self.cid);
        }
        Self::new(self.cid, self.liveness.clone())
    }
}

impl Drop for TempTag {
    fn drop(&mut self) {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.on_drop(&self.cid);
        }
    }
}

/// Implementation of the gc method.
async fn gc_mark_task<'a>(
    store: &'a impl Store,
    cp: impl CollectionParser + 'a,
    extra_roots: impl IntoIterator<Item = io::Result<Cid>> + 'a,
    co: &Co<GcMarkEvent>,
) -> anyhow::Result<()> {
    macro_rules! info {
        ($($arg:tt)*) => {
            co.yield_(GcMarkEvent::CustomInfo(format!($($arg)*))).await;
        };
    }
    macro_rules! warn {
        ($($arg:tt)*) => {
            co.yield_(GcMarkEvent::CustomWarning(format!($($arg)*), None)).await;
        };
    }
    store.clear_live();
    let mut roots = BTreeSet::new();
    info!("traversing tags");
    for (name, cid) in store.tags() {
        info!("adding root {:?} {:?}", name, cid);
        roots.insert(cid);
    }
    info!("traversing temp roots");
    for cid in store.temp_tags() {
        info!("adding temp pin {:?}", cid);
        roots.insert(cid);
    }
    info!("traversing extra roots");
    for cid in extra_roots {
        let cid = cid?;
        info!("adding extra root {:?}", cid);
        roots.insert(cid);
    }
    let mut current = roots.into_iter().collect::<Vec<_>>();
    let mut live: BTreeSet<Hash> = BTreeSet::new();
    // process all current. Since we don't have nested collections, this will
    // terminate after 1 iteration.
    while !current.is_empty() {
        for (hash, format) in std::mem::take(&mut current) {
            if live.insert(hash) && format == BlobFormat::Collection {
                let Some(entry) = store.get(&hash) else {
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
                let Ok((mut iter, stats)) = cp.parse(0, reader).await else {
                    warn!("gc: {} parse failed", hash);
                    continue;
                };
                info!("parsed collection {} {:?}", hash, stats);
                loop {
                    let item = match iter.next().await {
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
    }
    info!("gc mark done. found {} live blobs", live.len());
    store.add_live(live);
    Ok(())
}

/// An event related to GC
#[derive(Debug)]
pub enum GcMarkEvent {
    /// A custom event (info)
    CustomInfo(String),
    /// A custom non critical error
    CustomWarning(String, Option<anyhow::Error>),
    /// An unrecoverable error during GC
    Error(anyhow::Error),
}

/// An event related to GC
#[derive(Debug)]
pub enum GcSweepEvent {
    /// A custom event (info)
    CustomInfo(String),
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
    Found { id: u64, path: PathBuf },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ValidateProgress {
    /// started validating
    Starting {
        /// The total number of entries to validate
        total: u64,
    },
    /// We started validating an entry
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
        /// the size of the entry
        size: u64,
    },
    /// We got progress ingesting item `id`.
    Progress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done with `id`
    Done {
        /// The unique id of the entry.
        id: u64,
        /// An error if we failed to validate the entry.
        error: Option<String>,
    },
    /// We are done with the whole operation.
    AllDone,
    /// We got an error and need to abort.
    Abort(RpcError),
}
