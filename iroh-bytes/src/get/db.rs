//! Functions that use the iroh-bytes protocol in conjunction with a bao store.
use std::path::PathBuf;
use std::time::Duration;

use futures::Future;
use futures::StreamExt;
use iroh_base::{hash::Hash, rpc::RpcError};
use serde::{Deserialize, Serialize};

use crate::protocol::RangeSpec;
use crate::util::progress::FallibleProgressSliceWriter;
use std::io;

use crate::hashseq::parse_hash_seq;
use crate::store::PossiblyPartialEntry;
use crate::{
    get::{
        self,
        fsm::{AtBlobHeader, AtEndBlob, ConnectedNext, EndBlobNext},
        Stats,
    },
    protocol::{GetRequest, RangeSpecSeq},
    store::{MapEntry, PartialMap, PartialMapEntry, Store as BaoStore},
    util::progress::{IdGenerator, ProgressSender},
    BlobFormat, HashAndFormat, IROH_BLOCK_SIZE,
};
use anyhow::Context;
use bao_tree::io::fsm::OutboardMut;
use bao_tree::{ByteNum, ChunkRanges};
use iroh_io::{AsyncSliceReader, AsyncSliceWriter};
use tracing::trace;

/// Get a blob or collection into a store.
///
/// This considers data that is already in the store, and will only request
/// the remaining data.
pub async fn get_to_db<
    D: BaoStore,
    C: FnOnce() -> F,
    F: Future<Output = anyhow::Result<quinn::Connection>>,
>(
    db: &D,
    get_conn: C,
    hash_and_format: &HashAndFormat,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> anyhow::Result<Stats> {
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
) -> anyhow::Result<Stats> {
    let end = match db.get_possibly_partial(hash) {
        PossiblyPartialEntry::Complete(entry) => {
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
        PossiblyPartialEntry::Partial(entry) => {
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
            let conn = get_conn().await?;
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database

            get_blob_inner_partial(db, header, entry, progress).await?
        }
        PossiblyPartialEntry::NotFound => {
            // full request
            let conn = get_conn().await?;
            let request = get::fsm::start(conn, GetRequest::single(*hash));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database
            get_blob_inner(db, header, progress).await?
        }
    };

    // we have requested a single hash, so we must be at closing
    let EndBlobNext::Closing(end) = end.next() else {
        anyhow::bail!("expected Closing");
    };
    // this closes the bidi stream. Do something with the stats?
    let stats = end.next().await?;
    anyhow::Ok(stats)
}

/// Given a partial entry, get the valid ranges.
pub async fn valid_ranges<D: PartialMap>(entry: &D::PartialEntry) -> anyhow::Result<ChunkRanges> {
    use tracing::trace as log;
    // compute the valid range from just looking at the data file
    let mut data_reader = entry.data_reader().await?;
    let data_size = data_reader.len().await?;
    let valid_from_data = ChunkRanges::from(..ByteNum(data_size).full_chunks());
    // compute the valid range from just looking at the outboard file
    let mut outboard = entry.outboard().await?;
    let valid_from_outboard = bao_tree::io::fsm::valid_ranges(&mut outboard).await?;
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
) -> anyhow::Result<AtEndBlob> {
    // read the size
    let (at_content, size) = at_header.next().await?;
    let hash = at_content.hash();
    let child_offset = at_content.offset();
    // create the temp file pair
    let entry = db.get_or_create_partial(hash, size)?;
    // open the data file in any case
    let df = entry.data_writer().await?;
    let mut of: Option<D::OutboardMut> = if needs_outboard(size) {
        Some(entry.outboard_mut().await?)
    } else {
        None
    };
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
    let mut pw = FallibleProgressSliceWriter::new(df, on_write);
    // use the convenience method to write all to the two vfs objects
    let end = at_content
        .write_all_with_outboard(of.as_mut(), &mut pw)
        .await?;
    // sync the data file
    pw.sync().await?;
    // sync the outboard file, if we wrote one
    if let Some(mut of) = of {
        of.sync().await?;
    }
    db.insert_complete(entry).await?;
    // notify that we are done
    sender.send(DownloadProgress::Done { id }).await?;
    Ok(end)
}

fn needs_outboard(size: u64) -> bool {
    size > (IROH_BLOCK_SIZE.bytes() as u64)
}

/// Get a blob that was requested partially.
///
/// We get passed the data and outboard ids. Partial downloads are only done
/// for large blobs where the outboard is present.
async fn get_blob_inner_partial<D: BaoStore>(
    db: &D,
    at_header: AtBlobHeader,
    entry: D::PartialEntry,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> anyhow::Result<AtEndBlob> {
    // TODO: the data we get is validated at this point, but we need to check
    // that it actually contains the requested ranges. Or DO WE?

    // read the size
    let (at_content, size) = at_header.next().await?;
    // open the data file in any case
    let df = entry.data_writer().await?;
    let mut of = if needs_outboard(size) {
        Some(entry.outboard_mut().await?)
    } else {
        None
    };
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
    let mut pw = FallibleProgressSliceWriter::new(df, on_write);
    // use the convenience method to write all to the two vfs objects
    let at_end = at_content
        .write_all_with_outboard(of.as_mut(), &mut pw)
        .await?;
    // sync the data file
    pw.sync().await?;
    // sync the outboard file
    if let Some(mut of) = of {
        of.sync().await?;
    }
    // actually store the data. it is up to the db to decide if it wants to
    // rename the files or not.
    db.insert_complete(entry).await?;
    // notify that we are done
    sender.send(DownloadProgress::Done { id }).await?;
    Ok(at_end)
}

/// Get information about a blob in a store.
///
/// This will compute the valid ranges for partial blobs, so it is somewhat expensive for those.
pub async fn blob_info<D: BaoStore>(db: &D, hash: &Hash) -> io::Result<BlobInfo<D>> {
    io::Result::Ok(match db.get_possibly_partial(hash) {
        PossiblyPartialEntry::Partial(entry) => {
            let valid_ranges = valid_ranges::<D>(&entry)
                .await
                .ok()
                .unwrap_or_else(ChunkRanges::all);
            BlobInfo::Partial {
                entry,
                valid_ranges,
            }
        }
        PossiblyPartialEntry::Complete(entry) => BlobInfo::Complete { size: entry.size() },
        PossiblyPartialEntry::NotFound => BlobInfo::Missing,
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
) -> anyhow::Result<Stats> {
    use tracing::info as log;
    let finishing =
        if let PossiblyPartialEntry::Complete(entry) = db.get_possibly_partial(root_hash) {
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
            let (mut hash_seq, children) = parse_hash_seq(reader).await?;
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
            let conn = get_conn().await?;
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            log!("connected");
            // we have not requested the root, so this must be StartChild
            let ConnectedNext::StartChild(start) = connected.next().await? else {
                anyhow::bail!("expected StartChild");
            };
            let mut next = EndBlobNext::MoreChildren(start);
            // read all the children
            loop {
                let start = match next {
                    EndBlobNext::MoreChildren(start) => start,
                    EndBlobNext::Closing(finish) => break finish,
                };
                let child_offset =
                    usize::try_from(start.child_offset()).context("child offset too large")?;
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
                    BlobInfo::Complete { .. } => anyhow::bail!("got data we have not requested"),
                };
                next = end_blob.next();
            }
        } else {
            tracing::info!("don't have collection - doing full download");
            // don't have the collection, so probably got nothing
            let conn = get_conn().await?;
            let request = get::fsm::start(conn, GetRequest::all(*root_hash));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // read the blob and add it to the database
            let end_root = get_blob_inner(db, header, sender.clone()).await?;
            // read the collection fully for now
            let entry = db.get(root_hash).context("just downloaded")?;
            let reader = entry.data_reader().await?;
            let (mut collection, count) = parse_hash_seq(reader).await?;
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
                let child_offset =
                    usize::try_from(start.child_offset()).context("child offset too large")?;
                let child_hash = match children.get(child_offset) {
                    Some(blob) => *blob,
                    None => break start.finish(),
                };
                let header = start.next(child_hash);
                let end_blob = get_blob_inner(db, header, sender.clone()).await?;
                next = end_blob.next();
            }
        };
    // this closes the bidi stream. Do something with the stats?
    let stats = finishing.next().await?;
    anyhow::Ok(stats)
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
        entry: D::PartialEntry,
        /// The ranges that are available locally.
        valid_ranges: ChunkRanges,
    },
    /// we don't have the blob at all
    Missing,
}

impl<D: BaoStore> BlobInfo<D> {
    /// The size of the blob, if known.
    pub fn size(&self) -> Option<u64> {
        match self {
            BlobInfo::Complete { size } => Some(*size),
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
#[derive(Debug, Serialize, Deserialize)]
pub enum DownloadProgress {
    /// Data was found locally.
    FoundLocal {
        /// child offset
        child: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: u64,
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
    /// We are done with the network part - all data is local.
    NetworkDone {
        /// The number of bytes written.
        bytes_written: u64,
        /// The number of bytes read.
        bytes_read: u64,
        /// The time it took to transfer the data.
        elapsed: Duration,
    },
    /// The download part is done for this id, we are now exporting the data
    /// to the specified out path.
    Export {
        /// Unique id of the entry.
        id: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: u64,
        /// The path to the file where the data is exported.
        target: PathBuf,
    },
    /// We have made progress exporting the data.
    ///
    /// This is only sent for large blobs.
    ExportProgress {
        /// Unique id of the entry that is being exported.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We got an error and need to abort.
    Abort(RpcError),
    /// We are done with the whole operation.
    AllDone,
}
