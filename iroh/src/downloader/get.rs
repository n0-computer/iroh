//! [`Getter`] implementation that performs requests over [`quinn::Connection`]s.

use std::io;

use anyhow::Context;
use bao_tree::io::fsm::OutboardMut;
use bao_tree::ChunkRanges;
use futures::{FutureExt, StreamExt};
use iroh_bytes::{
    get::{
        self,
        db::{blob_info, valid_ranges, BlobInfo},
        fsm::{AtBlobHeader, AtEndBlob, ConnectedNext, EndBlobNext},
        Stats,
    },
    hashseq::parse_hash_seq,
    protocol::{GetRequest, RangeSpecSeq},
    store::{MapEntry, PartialMapEntry, PossiblyPartialEntry, Store},
    util::progress::FallibleProgressSliceWriter,
    BlobFormat, Hash, HashAndFormat, TempTag, IROH_BLOCK_SIZE,
};
#[cfg(feature = "metrics")]
use iroh_metrics::{inc, inc_by};
use tracing::trace;

#[cfg(feature = "metrics")]
use crate::metrics::Metrics;

use super::{DownloadKind, FailureAction, GetFut, Getter};

/// [`Getter`] implementation that performs requests over [`quinn::Connection`]s.
pub(crate) struct IoGetter<S: Store> {
    pub store: S,
}

impl<S: Store> Getter for IoGetter<S> {
    type Connection = quinn::Connection;

    fn get(&mut self, kind: DownloadKind, conn: Self::Connection) -> GetFut {
        let store = self.store.clone();
        let fut = async move {
            let res = get(&store, conn, kind.hash_and_format()).await;
            match res {
                Ok((_stats, tt)) => {
                    #[cfg(feature = "metrics")]
                    {
                        let Stats {
                            bytes_written,
                            bytes_read: _,
                            elapsed,
                        } = _stats;

                        inc!(Metrics, downloads_success);
                        inc_by!(Metrics, download_bytes_total, bytes_written);
                        inc_by!(Metrics, download_time_total, elapsed.as_millis() as u64);
                    }
                    Ok(tt)
                }
                Err(e) => {
                    // record metrics according to the error
                    #[cfg(feature = "metrics")]
                    {
                        match &e {
                            FailureAction::RetryLater(_) => inc!(Metrics, downloads_notfound),
                            _ => inc!(Metrics, downloads_error),
                        }
                    }
                    Err(e)
                }
            }
        };
        fut.boxed_local()
    }
}

impl From<quinn::ConnectionError> for FailureAction {
    fn from(value: quinn::ConnectionError) -> Self {
        // explicit match just to be sure we are taking everything into account
        match value {
            e @ quinn::ConnectionError::VersionMismatch => {
                // > The peer doesn't implement any supported version
                // unsupported version is likely a long time error, so this peer is not usable
                FailureAction::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::TransportError(_) => {
                // > The peer violated the QUIC specification as understood by this implementation
                // bad peer we don't want to keep around
                FailureAction::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::ConnectionClosed(_) => {
                // > The peer's QUIC stack aborted the connection automatically
                // peer might be disconnecting or otherwise unavailable, drop it
                FailureAction::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::ApplicationClosed(_) => {
                // > The peer closed the connection
                // peer might be disconnecting or otherwise unavailable, drop it
                FailureAction::DropPeer(e.into())
            }
            e @ quinn::ConnectionError::Reset => {
                // > The peer is unable to continue processing this connection, usually due to having restarted
                FailureAction::RetryLater(e.into())
            }
            e @ quinn::ConnectionError::TimedOut => {
                // > Communication with the peer has lapsed for longer than the negotiated idle timeout
                FailureAction::RetryLater(e.into())
            }
            e @ quinn::ConnectionError::LocallyClosed => {
                // > The local application closed the connection
                // TODO(@divma): don't see how this is reachable but let's just not use the peer
                FailureAction::DropPeer(e.into())
            }
        }
    }
}

impl From<quinn::ReadError> for FailureAction {
    fn from(value: quinn::ReadError) -> Self {
        match value {
            e @ quinn::ReadError::Reset(_) => FailureAction::RetryLater(e.into()),
            quinn::ReadError::ConnectionLost(conn_error) => conn_error.into(),
            quinn::ReadError::UnknownStream
            | quinn::ReadError::IllegalOrderedRead
            | quinn::ReadError::ZeroRttRejected => {
                // all these errors indicate the peer is not usable at this moment
                FailureAction::DropPeer(value.into())
            }
        }
    }
}

impl From<quinn::WriteError> for FailureAction {
    fn from(value: quinn::WriteError) -> Self {
        match value {
            e @ quinn::WriteError::Stopped(_) => FailureAction::RetryLater(e.into()),
            quinn::WriteError::ConnectionLost(conn_error) => conn_error.into(),
            quinn::WriteError::UnknownStream | quinn::WriteError::ZeroRttRejected => {
                // all these errors indicate the peer is not usable at this moment
                FailureAction::DropPeer(value.into())
            }
        }
    }
}

impl From<iroh_bytes::get::fsm::ConnectedNextError> for FailureAction {
    fn from(value: iroh_bytes::get::fsm::ConnectedNextError) -> Self {
        use iroh_bytes::get::fsm::ConnectedNextError::*;
        match value {
            e @ PostcardSer(_) => {
                // serialization errors indicate something wrong with the request itself
                FailureAction::AbortRequest(e.into())
            }
            e @ RequestTooBig => {
                // request will never be sent, drop it
                FailureAction::AbortRequest(e.into())
            }
            Write(e) => e.into(),
            e @ Io(_) => {
                // io errors are likely recoverable
                FailureAction::RetryLater(e.into())
            }
        }
    }
}

impl From<iroh_bytes::get::fsm::AtBlobHeaderNextError> for FailureAction {
    fn from(value: iroh_bytes::get::fsm::AtBlobHeaderNextError) -> Self {
        use iroh_bytes::get::fsm::AtBlobHeaderNextError::*;
        match value {
            e @ NotFound => {
                // > This indicates that the provider does not have the requested data.
                // peer might have the data later, simply retry it
                FailureAction::RetryLater(e.into())
            }
            Read(e) => e.into(),
            e @ Io(_) => {
                // io errors are likely recoverable
                FailureAction::RetryLater(e.into())
            }
        }
    }
}

impl From<iroh_bytes::get::fsm::DecodeError> for FailureAction {
    fn from(value: iroh_bytes::get::fsm::DecodeError) -> Self {
        use get::fsm::DecodeError::*;

        match value {
            e @ NotFound => FailureAction::RetryLater(e.into()),
            e @ ParentNotFound(_) => FailureAction::RetryLater(e.into()),
            e @ LeafNotFound(_) => FailureAction::RetryLater(e.into()),
            e @ ParentHashMismatch(_) => {
                // TODO(@divma): did the peer sent wrong data? is it corrupted? did we sent a wrong
                // request?
                FailureAction::AbortRequest(e.into())
            }
            e @ LeafHashMismatch(_) => {
                // TODO(@divma): did the peer sent wrong data? is it corrupted? did we sent a wrong
                // request?
                FailureAction::AbortRequest(e.into())
            }
            Read(e) => e.into(),
            Io(e) => e.into(),
        }
    }
}

impl From<std::io::Error> for FailureAction {
    fn from(value: std::io::Error) -> Self {
        // generally consider io errors recoverable
        // we might want to revisit this at some point
        FailureAction::RetryLater(value.into())
    }
}

/// Get a blob or collection
pub async fn get<D: Store>(
    db: &D,
    conn: quinn::Connection,
    hash_and_format: HashAndFormat,
) -> Result<(Stats, TempTag), FailureAction> {
    let tt = db.temp_tag(hash_and_format);
    let HashAndFormat { hash, format } = hash_and_format;
    let stats = match format {
        BlobFormat::Raw => get_blob(db, conn, &hash).await,
        BlobFormat::HashSeq => get_hash_seq(db, conn, &hash).await,
    };
    Ok((stats?, tt))
}

/// Get a blob that was requested completely.
///
/// We need to create our own files and handle the case where an outboard
/// is not needed.
pub async fn get_blob<D: Store>(
    db: &D,
    conn: quinn::Connection,
    hash: &Hash,
) -> Result<Stats, FailureAction> {
    let end = match db.get_possibly_partial(hash) {
        PossiblyPartialEntry::Complete(_) => {
            trace!("got complete data for {}", hash);
            return Ok(Stats::default());
        }
        PossiblyPartialEntry::Partial(entry) => {
            trace!("got partial data for {}", hash,);

            let valid_ranges = valid_ranges::<D>(&entry)
                .await
                .ok()
                .unwrap_or_else(ChunkRanges::all);
            let required_ranges: ChunkRanges = ChunkRanges::all().difference(&valid_ranges);
            let request = GetRequest::new(*hash, RangeSpecSeq::from_ranges([required_ranges]));
            // full request
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                return Err(FailureAction::DropPeer(anyhow::anyhow!(
                    "expected `StartRoot` in single blob request"
                )));
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database

            get_blob_inner_partial(db, header, entry).await?
        }
        PossiblyPartialEntry::NotFound => {
            // full request
            let request = get::fsm::start(conn, GetRequest::single(*hash));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                return Err(FailureAction::DropPeer(anyhow::anyhow!(
                    "expected `StartRoot` in single blob request"
                )));
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database
            get_blob_inner(db, header).await?
        }
    };

    // we have requested a single hash, so we must be at closing
    let EndBlobNext::Closing(end) = end.next() else {
        // TODO(@divma): I think this is a codign error and not a peer error
        return Err(FailureAction::DropPeer(anyhow::anyhow!(
            "peer sent extra data in single blob request"
        )));
    };
    // this closes the bidi stream. Do something with the stats?
    let stats = end.next().await?;
    Ok(stats)
}

/// Get a blob that was requested completely.
///
/// We need to create our own files and handle the case where an outboard
/// is not needed.
async fn get_blob_inner<D: Store>(
    db: &D,
    header: AtBlobHeader,
) -> Result<AtEndBlob, FailureAction> {
    use iroh_io::AsyncSliceWriter;

    let hash = header.hash();
    // read the size
    let (content, size) = header.next().await?;
    // create the temp file pair
    let entry = db.get_or_create_partial(hash, size)?;
    // open the data file in any case
    let df = entry.data_writer().await?;
    let mut of: Option<D::OutboardMut> = if needs_outboard(size) {
        Some(entry.outboard_mut().await?)
    } else {
        None
    };
    let on_write = move |_offset: u64, _length: usize| Ok(());
    let mut pw = FallibleProgressSliceWriter::new(df, on_write);
    // use the convenience method to write all to the two vfs objects
    let end = content
        .write_all_with_outboard(of.as_mut(), &mut pw)
        .await?;
    // TODO(@divma): what does this failure mean
    // sync the data file
    pw.sync().await?;
    // sync the outboard file, if we wrote one
    if let Some(mut of) = of {
        of.sync().await?;
    }
    db.insert_complete(entry).await?;
    Ok(end)
}

fn needs_outboard(size: u64) -> bool {
    size > (IROH_BLOCK_SIZE.bytes() as u64)
}

/// Get a blob that was requested partially.
///
/// We get passed the data and outboard ids. Partial downloads are only done
/// for large blobs where the outboard is present.
async fn get_blob_inner_partial<D: Store>(
    db: &D,
    header: AtBlobHeader,
    entry: D::PartialEntry,
) -> Result<AtEndBlob, FailureAction> {
    // TODO: the data we get is validated at this point, but we need to check
    // that it actually contains the requested ranges. Or DO WE?
    use iroh_io::AsyncSliceWriter;

    // read the size
    let (content, size) = header.next().await?;
    // open the data file in any case
    let df = entry.data_writer().await?;
    let mut of = if needs_outboard(size) {
        Some(entry.outboard_mut().await?)
    } else {
        None
    };
    let on_write = move |_offset: u64, _length: usize| Ok(());
    let mut pw = FallibleProgressSliceWriter::new(df, on_write);
    // use the convenience method to write all to the two vfs objects
    let end = content
        .write_all_with_outboard(of.as_mut(), &mut pw)
        .await?;

    // TODO(@divma): what does this failure mean
    // sync the data file
    pw.sync().await?;
    // sync the outboard file
    if let Some(mut of) = of {
        of.sync().await?;
    }
    // actually store the data. it is up to the db to decide if it wants to
    // rename the files or not.
    db.insert_complete(entry).await?;
    Ok(end)
}

/// Get a collection
pub async fn get_hash_seq<D: Store>(
    db: &D,
    conn: quinn::Connection,
    root_hash: &Hash,
) -> Result<Stats, FailureAction> {
    use tracing::info as log;
    let finishing =
        if let PossiblyPartialEntry::Complete(entry) = db.get_possibly_partial(root_hash) {
            log!("already got collection - doing partial download");
            // got the collection
            let reader = entry.data_reader().await?;
            let (mut collection, _) = parse_hash_seq(reader).await.map_err(|e| {
                FailureAction::DropPeer(anyhow::anyhow!(
                    "peer sent data that can't be parsed as collection : {e}"
                ))
            })?;
            let mut children: Vec<Hash> = vec![];
            while let Some(hash) = collection.next().await.map_err(|e| {
                FailureAction::DropPeer(anyhow::anyhow!(
                    "received collection data can't be iterated: {e}"
                ))
            })? {
                children.push(hash);
            }
            let missing_info = get_blob_infos(db, &children).await?;
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
            let request = get::fsm::start(conn, request);
            // create a new bidi stream
            let connected = request.next().await?;
            log!("connected");
            // we have not requested the root, so this must be StartChild
            let ConnectedNext::StartChild(start) = connected.next().await? else {
                return Err(FailureAction::DropPeer(anyhow::anyhow!(
                    "peer sent data that does not match requested info"
                )));
            };
            let mut next = EndBlobNext::MoreChildren(start);
            // read all the children
            loop {
                let start = match next {
                    EndBlobNext::MoreChildren(start) => start,
                    EndBlobNext::Closing(finish) => break finish,
                };
                let child_offset = usize::try_from(start.child_offset())
                    .context("child offset too large")
                    .map_err(|_| {
                        FailureAction::AbortRequest(anyhow::anyhow!(
                            "requested offsets surpasses platform's usize"
                        ))
                    })?;
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
                    BlobInfo::Missing => get_blob_inner(db, header).await?,
                    BlobInfo::Partial { entry, .. } => {
                        get_blob_inner_partial(db, header, entry.clone()).await?
                    }
                    BlobInfo::Complete { .. } => {
                        return Err(FailureAction::DropPeer(anyhow::anyhow!(
                            "peer sent data we did't request"
                        )))
                    }
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
                return Err(FailureAction::DropPeer(anyhow::anyhow!(
                    "expected StartRoot"
                )));
            };
            // move to the header
            let header = start.next();
            // read the blob and add it to the database
            let end_root = get_blob_inner(db, header).await?;
            // read the collection fully for now
            let entry = db.get(root_hash).context("just downloaded").map_err(|_| {
                FailureAction::RetryLater(anyhow::anyhow!("data just downloaded was not found"))
            })?;
            let reader = entry.data_reader().await?;
            let (mut collection, _) = parse_hash_seq(reader).await.map_err(|_| {
                FailureAction::DropPeer(anyhow::anyhow!(
                    "peer sent data that can't be parsed as collection"
                ))
            })?;
            let mut children = vec![];
            while let Some(hash) = collection.next().await.map_err(|e| {
                FailureAction::DropPeer(anyhow::anyhow!(
                    "received collection data can't be iterated: {e}"
                ))
            })? {
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
                    .context("child offset too large")
                    .map_err(|_| {
                        FailureAction::AbortRequest(anyhow::anyhow!(
                            "requested offsets surpasses platform's usize"
                        ))
                    })?;
                let child_hash = match children.get(child_offset) {
                    Some(blob) => *blob,
                    None => break start.finish(),
                };
                let header = start.next(child_hash);
                let end_blob = get_blob_inner(db, header).await?;
                next = end_blob.next();
            }
        };
    // this closes the bidi stream. Do something with the stats?
    let stats = finishing.next().await?;
    Ok(stats)
}

/// Like `get_blob_info`, but for multiple hashes
async fn get_blob_infos<D: Store>(db: &D, hash_seq: &[Hash]) -> io::Result<Vec<BlobInfo<D>>> {
    let items = futures::stream::iter(hash_seq)
        .then(|hash| blob_info(db, hash))
        .collect::<Vec<_>>();
    items.await.into_iter().collect()
}
