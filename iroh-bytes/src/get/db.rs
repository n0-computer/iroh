//! Functions that use the iroh-bytes protocol in conjunction with a bao store.
use bao_tree::ChunkNum;
use futures::{Future, StreamExt};
use iroh_base::hash::Hash;
use iroh_base::rpc::RpcError;
use serde::{Deserialize, Serialize};

use crate::protocol::RangeSpec;
use crate::store::BaoBlobSize;
use crate::store::FallibleProgressBatchWriter;
use std::io;

use crate::hashseq::parse_hash_seq;
use crate::store::BaoBatchWriter;

use crate::{
    get::{
        self,
        error::GetError,
        fsm::{AtBlobHeader, AtEndBlob, ConnectedNext, EndBlobNext},
        Stats,
    },
    protocol::{GetRequest, RangeSpecSeq},
    store::{MapEntry, MapEntryMut, MapMut, Store as BaoStore},
    util::progress::{IdGenerator, ProgressSender},
    BlobFormat, HashAndFormat,
};
use anyhow::anyhow;
use bao_tree::ChunkRanges;
use iroh_io::AsyncSliceReader;
use tracing::trace;

/// Get a blob or collection into a store.
///
/// This considers data that is already in the store, and will only request
/// the remaining data.
///
/// Progress is reported as [`DownloadProgress`] through a [`ProgressSender`]. Note that the
/// [`DownloadProgress::AllDone`] event is not emitted from here, but left to an upper layer to send,
/// if desired.
pub async fn get_to_db<
    D: BaoStore,
    C: FnOnce() -> F,
    F: Future<Output = anyhow::Result<quinn::Connection>>,
>(
    db: &D,
    get_conn: C,
    hash_and_format: &HashAndFormat,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> Result<Stats, GetError> {
    let HashAndFormat { hash, format } = hash_and_format;
    match format {
        BlobFormat::Raw => get_blob(db, get_conn, hash, sender).await,
        BlobFormat::HashSeq => get_hash_seq(db, get_conn, hash, sender).await,
    }
}

/// Get a blob that was requested completely.
///
/// We need to create our own files and handle the case where an outboard
/// is not needed.
async fn get_blob<
    D: BaoStore,
    C: FnOnce() -> F,
    F: Future<Output = anyhow::Result<quinn::Connection>>,
>(
    db: &D,
    get_conn: C,
    hash: &Hash,
    progress: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> Result<Stats, GetError> {
    let end = match db.get_mut(hash).await? {
        Some(entry) if entry.is_complete() => {
            tracing::info!("already got entire blob");
            progress
                .send(DownloadProgress::FoundLocal {
                    child: 0,
                    hash: *hash,
                    size: entry.size(),
                    valid_ranges: RangeSpec::all(),
                })
                .await?;
            return Ok(Stats::default());
        }
        Some(entry) => {
            trace!("got partial data for {}", hash);
            let valid_ranges = valid_ranges::<D>(&entry)
                .await
                .ok()
                .unwrap_or_else(ChunkRanges::all);
            progress
                .send(DownloadProgress::FoundLocal {
                    child: 0,
                    hash: *hash,
                    size: entry.size(),
                    valid_ranges: RangeSpec::new(&valid_ranges),
                })
                .await?;
            let required_ranges: ChunkRanges = ChunkRanges::all().difference(&valid_ranges);

            let request = GetRequest::new(*hash, RangeSpecSeq::from_ranges([required_ranges]));
            // full request
            let conn = get_conn().await.map_err(GetError::Io)?;
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                return Err(GetError::NoncompliantNode(anyhow!("expected StartRoot")));
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database

            get_blob_inner_partial(db, header, entry, progress).await?
        }
        None => {
            // full request
            let conn = get_conn().await.map_err(GetError::Io)?;
            let request = get::fsm::start(conn, GetRequest::single(*hash));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                return Err(GetError::NoncompliantNode(anyhow!("expected StartRoot")));
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database
            get_blob_inner(db, header, progress).await?
        }
    };

    // we have requested a single hash, so we must be at closing
    let EndBlobNext::Closing(end) = end.next() else {
        return Err(GetError::NoncompliantNode(anyhow!("expected StartRoot")));
    };
    // this closes the bidi stream. Do something with the stats?
    let stats = end.next().await?;
    Ok(stats)
}

/// Given a partial entry, get the valid ranges.
pub async fn valid_ranges<D: MapMut>(entry: &D::EntryMut) -> anyhow::Result<ChunkRanges> {
    use tracing::trace as log;
    // compute the valid range from just looking at the data file
    let mut data_reader = entry.data_reader().await?;
    let data_size = data_reader.size().await?;
    let valid_from_data = ChunkRanges::from(..ChunkNum::full_chunks(data_size));
    // compute the valid range from just looking at the outboard file
    let mut outboard = entry.outboard().await?;
    let all = ChunkRanges::all();
    let mut stream = bao_tree::io::fsm::valid_outboard_ranges(&mut outboard, &all);
    let mut valid_from_outboard = ChunkRanges::empty();
    while let Some(range) = stream.next().await {
        valid_from_outboard |= ChunkRanges::from(range?);
    }
    let valid: ChunkRanges = valid_from_data.intersection(&valid_from_outboard);
    log!("valid_from_data: {:?}", valid_from_data);
    log!("valid_from_outboard: {:?}", valid_from_data);
    Ok(valid)
}

/// Get a blob that was requested completely.
///
/// We need to create our own files and handle the case where an outboard
/// is not needed.
async fn get_blob_inner<D: BaoStore>(
    db: &D,
    at_header: AtBlobHeader,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> Result<AtEndBlob, GetError> {
    // read the size. The size we get here is not verified, but since we use
    // it for the tree traversal we are guaranteed not to get more than size.
    let (at_content, size) = at_header.next().await?;
    let hash = at_content.hash();
    let child_offset = at_content.offset();
    // get or create the partial entry
    let entry = db.get_or_create(hash, size).await?;
    // open the data file in any case
    let bw = entry.batch_writer().await?;
    // allocate a new id for progress reports for this transfer
    let id = sender.new_id();
    sender
        .send(DownloadProgress::Found {
            id,
            hash,
            size,
            child: child_offset,
        })
        .await?;
    let sender2 = sender.clone();
    let on_write = move |offset: u64, _length: usize| {
        // if try send fails it means that the receiver has been dropped.
        // in that case we want to abort the write_all_with_outboard.
        sender2
            .try_send(DownloadProgress::Progress { id, offset })
            .map_err(|e| {
                tracing::info!("aborting download of {}", hash);
                e
            })?;
        Ok(())
    };
    let mut bw = FallibleProgressBatchWriter::new(bw, on_write);
    // use the convenience method to write all to the batch writer
    let end = at_content.write_all_batch(&mut bw).await?;
    // sync the underlying storage, if needed
    bw.sync().await?;
    drop(bw);
    db.insert_complete(entry).await?;
    // notify that we are done
    sender.send(DownloadProgress::Done { id }).await?;
    Ok(end)
}

/// Get a blob that was requested partially.
///
/// We get passed the data and outboard ids. Partial downloads are only done
/// for large blobs where the outboard is present.
async fn get_blob_inner_partial<D: BaoStore>(
    db: &D,
    at_header: AtBlobHeader,
    entry: D::EntryMut,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> Result<AtEndBlob, GetError> {
    // read the size. The size we get here is not verified, but since we use
    // it for the tree traversal we are guaranteed not to get more than size.
    let (at_content, size) = at_header.next().await?;
    // create a batch writer for the bao file
    let bw = entry.batch_writer().await?;
    // allocate a new id for progress reports for this transfer
    let id = sender.new_id();
    let hash = at_content.hash();
    let child_offset = at_content.offset();
    sender
        .send(DownloadProgress::Found {
            id,
            hash,
            size,
            child: child_offset,
        })
        .await?;
    let sender2 = sender.clone();
    let on_write = move |offset: u64, _length: usize| {
        // if try send fails it means that the receiver has been dropped.
        // in that case we want to abort the write_all_with_outboard.
        sender2
            .try_send(DownloadProgress::Progress { id, offset })
            .map_err(|e| {
                tracing::info!("aborting download of {}", hash);
                e
            })?;
        Ok(())
    };
    let mut bw = FallibleProgressBatchWriter::new(bw, on_write);
    // use the convenience method to write all to the batch writer
    let at_end = at_content.write_all_batch(&mut bw).await?;
    // sync the underlying storage, if needed
    bw.sync().await?;
    drop(bw);
    // we got to the end without error, so we can mark the entry as complete
    //
    // caution: this assumes that the request filled all the gaps in our local
    // data. We can't re-check this here since that would be very expensive.
    db.insert_complete(entry).await?;
    // notify that we are done
    sender.send(DownloadProgress::Done { id }).await?;
    Ok(at_end)
}

/// Get information about a blob in a store.
///
/// This will compute the valid ranges for partial blobs, so it is somewhat expensive for those.
pub async fn blob_info<D: BaoStore>(db: &D, hash: &Hash) -> io::Result<BlobInfo<D>> {
    io::Result::Ok(match db.get_mut(hash).await? {
        Some(entry) if entry.is_complete() => BlobInfo::Complete {
            size: entry.size().value(),
        },
        Some(entry) => {
            let valid_ranges = valid_ranges::<D>(&entry)
                .await
                .ok()
                .unwrap_or_else(ChunkRanges::all);
            BlobInfo::Partial {
                entry,
                valid_ranges,
            }
        }
        None => BlobInfo::Missing,
    })
}

/// Like `get_blob_info`, but for multiple hashes
async fn blob_infos<D: BaoStore>(db: &D, hash_seq: &[Hash]) -> io::Result<Vec<BlobInfo<D>>> {
    let items = futures::stream::iter(hash_seq)
        .then(|hash| blob_info(db, hash))
        .collect::<Vec<_>>();
    items.await.into_iter().collect()
}

/// Get a sequence of hashes
async fn get_hash_seq<
    D: BaoStore,
    C: FnOnce() -> F,
    F: Future<Output = anyhow::Result<quinn::Connection>>,
>(
    db: &D,
    get_conn: C,
    root_hash: &Hash,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> Result<Stats, GetError> {
    use tracing::info as log;
    let finishing = match db.get_mut(root_hash).await? {
        Some(entry) if entry.is_complete() => {
            log!("already got collection - doing partial download");
            // send info that we have the hashseq itself entirely
            sender
                .send(DownloadProgress::FoundLocal {
                    child: 0,
                    hash: *root_hash,
                    size: entry.size(),
                    valid_ranges: RangeSpec::all(),
                })
                .await?;
            // got the collection
            let reader = entry.data_reader().await?;
            let (mut hash_seq, children) = parse_hash_seq(reader).await.map_err(|err| {
                GetError::NoncompliantNode(anyhow!("Failed to parse downloaded HashSeq: {err}"))
            })?;
            sender
                .send(DownloadProgress::FoundHashSeq {
                    hash: *root_hash,
                    children,
                })
                .await?;
            let mut children: Vec<Hash> = vec![];
            while let Some(hash) = hash_seq.next().await? {
                children.push(hash);
            }
            let missing_info = blob_infos(db, &children).await?;
            // send the info about what we have
            for (i, info) in missing_info.iter().enumerate() {
                if let Some(size) = info.size() {
                    sender
                        .send(DownloadProgress::FoundLocal {
                            child: (i as u64) + 1,
                            hash: children[i],
                            size,
                            valid_ranges: RangeSpec::new(&info.valid_ranges()),
                        })
                        .await?;
                }
            }
            if missing_info
                .iter()
                .all(|x| matches!(x, BlobInfo::Complete { .. }))
            {
                log!("nothing to do");
                return Ok(Stats::default());
            }

            let missing_iter = std::iter::once(ChunkRanges::empty())
                .chain(missing_info.iter().map(|x| x.missing_ranges()))
                .collect::<Vec<_>>();
            log!("requesting chunks {:?}", missing_iter);
            let request = GetRequest::new(*root_hash, RangeSpecSeq::from_ranges(missing_iter));
            let conn = get_conn().await.map_err(GetError::Io)?;
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            log!("connected");
            // we have not requested the root, so this must be StartChild
            let ConnectedNext::StartChild(start) = connected.next().await? else {
                return Err(GetError::NoncompliantNode(anyhow!("expected StartChild")));
            };
            let mut next = EndBlobNext::MoreChildren(start);
            // read all the children
            loop {
                let start = match next {
                    EndBlobNext::MoreChildren(start) => start,
                    EndBlobNext::Closing(finish) => break finish,
                };
                let child_offset = usize::try_from(start.child_offset())
                    .map_err(|_| GetError::NoncompliantNode(anyhow!("child offset too large")))?;
                let (child_hash, info) =
                    match (children.get(child_offset), missing_info.get(child_offset)) {
                        (Some(blob), Some(info)) => (*blob, info),
                        _ => break start.finish(),
                    };
                tracing::info!(
                    "requesting child {} {:?}",
                    child_hash,
                    info.missing_ranges()
                );
                let header = start.next(child_hash);
                let end_blob = match info {
                    BlobInfo::Missing => get_blob_inner(db, header, sender.clone()).await?,
                    BlobInfo::Partial { entry, .. } => {
                        get_blob_inner_partial(db, header, entry.clone(), sender.clone()).await?
                    }
                    BlobInfo::Complete { .. } => {
                        return Err(GetError::NoncompliantNode(anyhow!(
                            "got data we have not requested"
                        )));
                    }
                };
                next = end_blob.next();
            }
        }
        _ => {
            tracing::debug!("don't have collection - doing full download");
            // don't have the collection, so probably got nothing
            let conn = get_conn().await.map_err(GetError::Io)?;
            let request = get::fsm::start(conn, GetRequest::all(*root_hash));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                return Err(GetError::NoncompliantNode(anyhow!("expected StartRoot")));
            };
            // move to the header
            let header = start.next();
            // read the blob and add it to the database
            let end_root = get_blob_inner(db, header, sender.clone()).await?;
            // read the collection fully for now
            let entry = db
                .get(root_hash)
                .await?
                .ok_or_else(|| GetError::LocalFailure(anyhow!("just downloaded but not in db")))?;
            let reader = entry.data_reader().await?;
            let (mut collection, count) = parse_hash_seq(reader).await.map_err(|err| {
                GetError::NoncompliantNode(anyhow!("Failed to parse downloaded HashSeq: {err}"))
            })?;
            sender
                .send(DownloadProgress::FoundHashSeq {
                    hash: *root_hash,
                    children: count,
                })
                .await?;
            let mut children = vec![];
            while let Some(hash) = collection.next().await? {
                children.push(hash);
            }
            let mut next = end_root.next();
            // read all the children
            loop {
                let start = match next {
                    EndBlobNext::MoreChildren(start) => start,
                    EndBlobNext::Closing(finish) => break finish,
                };
                let child_offset = usize::try_from(start.child_offset())
                    .map_err(|_| GetError::NoncompliantNode(anyhow!("child offset too large")))?;

                let child_hash = match children.get(child_offset) {
                    Some(blob) => *blob,
                    None => break start.finish(),
                };
                let header = start.next(child_hash);
                let end_blob = get_blob_inner(db, header, sender.clone()).await?;
                next = end_blob.next();
            }
        }
    };
    // this closes the bidi stream. Do something with the stats?
    let stats = finishing.next().await?;
    Ok(stats)
}

/// Information about a the status of a blob in a store.
#[derive(Debug, Clone)]
pub enum BlobInfo<D: BaoStore> {
    /// we have the blob completely
    Complete {
        /// The size of the entry in bytes.
        size: u64,
    },
    /// we have the blob partially
    Partial {
        /// The partial entry.
        entry: D::EntryMut,
        /// The ranges that are available locally.
        valid_ranges: ChunkRanges,
    },
    /// we don't have the blob at all
    Missing,
}

impl<D: BaoStore> BlobInfo<D> {
    /// The size of the blob, if known.
    pub fn size(&self) -> Option<BaoBlobSize> {
        match self {
            BlobInfo::Complete { size } => Some(BaoBlobSize::Verified(*size)),
            BlobInfo::Partial { entry, .. } => Some(entry.size()),
            BlobInfo::Missing => None,
        }
    }

    /// Ranges that are valid locally.
    ///
    /// This will be all for complete blobs, empty for missing blobs,
    /// and a set with possibly open last range for partial blobs.
    pub fn valid_ranges(&self) -> ChunkRanges {
        match self {
            BlobInfo::Complete { .. } => ChunkRanges::all(),
            BlobInfo::Partial { valid_ranges, .. } => valid_ranges.clone(),
            BlobInfo::Missing => ChunkRanges::empty(),
        }
    }

    /// Ranges that are missing locally and need to be requested.
    ///
    /// This will be empty for complete blobs, all for missing blobs, and
    /// a set with possibly open last range for partial blobs.
    pub fn missing_ranges(&self) -> ChunkRanges {
        match self {
            BlobInfo::Complete { .. } => ChunkRanges::empty(),
            BlobInfo::Partial { valid_ranges, .. } => ChunkRanges::all().difference(valid_ranges),
            BlobInfo::Missing => ChunkRanges::all(),
        }
    }
}

/// Progress updates for the get operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DownloadProgress {
    /// Data was found locally.
    FoundLocal {
        /// child offset
        child: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: BaoBlobSize,
        /// The ranges that are available locally.
        valid_ranges: RangeSpec,
    },
    /// A new connection was established.
    Connected,
    /// An item was found with hash `hash`, from now on referred to via `id`.
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// child offset
        child: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: u64,
    },
    /// An item was found with hash `hash`, from now on referred to via `id`.
    FoundHashSeq {
        /// The name of the entry.
        hash: Hash,
        /// Number of children in the collection, if known.
        children: u64,
    },
    /// We got progress ingesting item `id`.
    Progress {
        /// The unique id of the entry.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We are done with `id`, and the hash is `hash`.
    Done {
        /// The unique id of the entry.
        id: u64,
    },
    /// All operations finished.
    ///
    /// This will be the last message in the stream.
    AllDone(Stats),
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}
