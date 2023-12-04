//! Functions to get blobs from peers

use std::io;

use anyhow::Context;
use bao_tree::io::fsm::OutboardMut;
use bao_tree::{ByteNum, ChunkRanges};
use iroh_bytes::hashseq::parse_hash_seq;
use iroh_bytes::store::range_collections::range_set::RangeSetRange;
use iroh_bytes::{
    get::{
        self,
        fsm::{AtBlobHeader, AtEndBlob, ConnectedNext, EndBlobNext},
        Stats,
    },
    protocol::{GetRequest, RangeSpecSeq},
    provider::DownloadProgress,
    store::{MapEntry, PartialMap, PartialMapEntry, Store as BaoStore},
    util::progress::{IdGenerator, ProgressSender},
    BlobFormat, Hash, HashAndFormat, IROH_BLOCK_SIZE,
};
use iroh_io::AsyncSliceReader;
use tracing::trace;

use crate::util::progress::ProgressSliceWriter2;

/// Get a blob or collection
pub async fn get<D: BaoStore>(
    db: &D,
    conn: quinn::Connection,
    hash_and_format: &HashAndFormat,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> anyhow::Result<Stats> {
    let HashAndFormat { hash, format } = hash_and_format;
    let res = match format {
        BlobFormat::Raw => get_blob(db, conn, hash, sender).await,
        BlobFormat::HashSeq => get_hash_seq(db, conn, hash, sender).await,
    };
    if let Err(e) = res.as_ref() {
        tracing::error!("get failed: {}", e);
    }
    res
}

/// Get a blob that was requested completely.
///
/// We need to create our own files and handle the case where an outboard
/// is not needed.
pub async fn get_blob<D: BaoStore>(
    db: &D,
    conn: quinn::Connection,
    hash: &Hash,
    progress: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> anyhow::Result<Stats> {
    let end = if let Some(entry) = db.get_partial(hash) {
        trace!("got partial data for {}", hash);
        let required_ranges = get_missing_ranges_blob::<D>(&entry)
            .await
            .ok()
            .unwrap_or_else(ChunkRanges::all);
        let request = GetRequest::new(*hash, RangeSpecSeq::from_ranges([required_ranges]));
        // full request
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
    } else {
        // full request
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
    };

    // we have requested a single hash, so we must be at closing
    let EndBlobNext::Closing(end) = end.next() else {
        anyhow::bail!("expected Closing");
    };
    // this closes the bidi stream. Do something with the stats?
    let stats = end.next().await?;
    anyhow::Ok(stats)
}

pub(crate) async fn get_missing_ranges_blob<D: PartialMap>(
    entry: &D::PartialEntry,
) -> anyhow::Result<ChunkRanges> {
    use tracing::trace as log;
    // compute the valid range from just looking at the data file
    let mut data_reader = entry.data_reader().await?;
    let data_size = data_reader.len().await?;
    let valid_from_data = ChunkRanges::from(..ByteNum(data_size).full_chunks());
    // compute the valid range from just looking at the outboard file
    let mut outboard = entry.outboard().await?;
    let valid_from_outboard = bao_tree::io::fsm::valid_ranges(&mut outboard).await?;
    let valid: ChunkRanges = valid_from_data.intersection(&valid_from_outboard);
    let total_valid: u64 = valid
        .iter()
        .map(|x| match x {
            RangeSetRange::Range(x) => x.end.to_bytes().0 - x.start.to_bytes().0,
            RangeSetRange::RangeFrom(_) => 0,
        })
        .sum();
    log!("valid_from_data: {:?}", valid_from_data);
    log!("valid_from_outboard: {:?}", valid_from_data);
    log!("total_valid: {}", total_valid);
    let invalid = ChunkRanges::all().difference(&valid);
    Ok(invalid)
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
    use iroh_io::AsyncSliceWriter;
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
    let mut pw = ProgressSliceWriter2::new(df, on_write);
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
    use iroh_io::AsyncSliceWriter;

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
    let mut pw = ProgressSliceWriter2::new(df, on_write);
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

/// Given a sequence of hashes, figure out what is missing
pub(crate) async fn get_missing_ranges_hash_seq<D: BaoStore>(
    db: &D,
    hash_seq: &[Hash],
) -> io::Result<Vec<BlobInfo<D>>> {
    let items = hash_seq.iter().map(|hash| async move {
        io::Result::Ok(if let Some(entry) = db.get_partial(hash) {
            // first look for partial
            trace!("got partial data for {}", hash,);
            let missing_chunks = get_missing_ranges_blob::<D>(&entry)
                .await
                .ok()
                .unwrap_or_else(ChunkRanges::all);
            BlobInfo::Partial {
                entry,
                missing_chunks,
            }
        } else if db.get(hash).is_some() {
            // then look for complete
            BlobInfo::Complete
        } else {
            BlobInfo::Missing
        })
    });
    let mut res = Vec::with_capacity(hash_seq.len());
    // todo: parallelize maybe?
    for item in items {
        res.push(item.await?);
    }
    Ok(res)
}

/// Get a sequence of hashes
pub async fn get_hash_seq<D: BaoStore>(
    db: &D,
    conn: quinn::Connection,
    root_hash: &Hash,
    sender: impl ProgressSender<Msg = DownloadProgress> + IdGenerator,
) -> anyhow::Result<Stats> {
    use tracing::info as log;
    let finishing = if let Some(entry) = db.get(root_hash) {
        log!("already got collection - doing partial download");
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
        let missing_info = get_missing_ranges_hash_seq(db, &children).await?;
        if missing_info.iter().all(|x| matches!(x, BlobInfo::Complete)) {
            log!("nothing to do");
            return Ok(Stats::default());
        }
        let missing_iter = std::iter::once(ChunkRanges::empty())
            .chain(missing_info.iter().map(|x| x.missing_chunks()))
            .collect::<Vec<_>>();
        log!("requesting chunks {:?}", missing_iter);
        let request = GetRequest::new(*root_hash, RangeSpecSeq::from_ranges(missing_iter));
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
                info.missing_chunks()
            );
            let header = start.next(child_hash);
            let end_blob = match info {
                BlobInfo::Missing => get_blob_inner(db, header, sender.clone()).await?,
                BlobInfo::Partial { entry, .. } => {
                    get_blob_inner_partial(db, header, entry.clone(), sender.clone()).await?
                }
                BlobInfo::Complete => anyhow::bail!("got data we have not requested"),
            };
            next = end_blob.next();
        }
    } else {
        tracing::info!("don't have collection - doing full download");
        // don't have the collection, so probably got nothing
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

#[derive(Debug, Clone)]
pub(crate) enum BlobInfo<D: BaoStore> {
    // we have the blob completely
    Complete,
    // we have the blob partially
    Partial {
        entry: D::PartialEntry,
        missing_chunks: ChunkRanges,
    },
    // we don't have the blob at all
    Missing,
}

impl<D: BaoStore> BlobInfo<D> {
    pub fn missing_chunks(&self) -> ChunkRanges {
        match self {
            BlobInfo::Complete => ChunkRanges::empty(),
            BlobInfo::Partial { missing_chunks, .. } => missing_chunks.clone(),
            BlobInfo::Missing => ChunkRanges::all(),
        }
    }
}
