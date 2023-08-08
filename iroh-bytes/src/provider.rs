//! The server side API
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bao_tree::io::fsm::{encode_ranges_validated, Outboard};
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;

use crate::baomap::*;
use crate::collection::CollectionParser;
use crate::protocol::{
    read_lp, write_lp, CustomGetRequest, GetRequest, RangeSpec, Request, RequestToken,
};
use crate::util::RpcError;
use crate::Hash;

/// Events emitted by the provider informing about the current status.
#[derive(Debug, Clone)]
pub enum Event {
    /// A new collection has been added
    CollectionAdded {
        /// The hash of the added collection
        hash: Hash,
    },
    /// A new client connected to the node.
    ClientConnected {
        /// An unique connection id.
        connection_id: u64,
    },
    /// A request was received from a client.
    GetRequestReceived {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
        /// Token requester gve for this request, if any
        token: Option<RequestToken>,
        /// The hash for which the client wants to receive data.
        hash: Hash,
    },
    /// A request was received from a client.
    CustomGetRequestReceived {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
        /// Token requester gve for this request, if any
        token: Option<RequestToken>,
        /// The size of the custom get request.
        len: usize,
    },
    /// A collection has been found and is being transferred.
    TransferCollectionStarted {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
        /// The number of blobs in the collection.
        num_blobs: Option<u64>,
        /// The total blob size of the data.
        total_blobs_size: Option<u64>,
    },
    /// A collection request was completed and the data was sent to the client.
    TransferCollectionCompleted {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
    },
    /// A blob in a collection was transferred.
    TransferBlobCompleted {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
        /// The hash of the blob
        hash: Hash,
        /// The index of the blob in the collection.
        index: u64,
        /// The size of the blob transferred.
        size: u64,
    },
    /// A request was aborted because the client disconnected.
    TransferAborted {
        /// The quic connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this request.
        request_id: u64,
    },
}

/// Progress updates for the provide operation.
#[derive(Debug, Serialize, Deserialize)]
pub enum ProvideProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// The name of the entry.
        name: String,
        /// The size of the entry in bytes.
        size: u64,
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
        /// The hash of the entry.
        hash: Hash,
    },
    /// We are done with the whole operation.
    AllDone {
        /// The hash of the created collection.
        hash: Hash,
    },
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}

/// Progress updates for the provide operation.
#[derive(Debug, Serialize, Deserialize)]
pub enum ShareProgress {
    /// A new connection was established.
    Connected,
    /// An item was found with hash `hash`, from now on referred to via `id`.
    Found {
        /// A new unique id for this entry.
        id: u64,
        /// The name of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: u64,
    },
    /// An item was found with hash `hash`, from now on referred to via `id`.
    FoundCollection {
        /// The name of the entry.
        hash: Hash,
        /// Number of children in the collection, if known.
        num_blobs: Option<u64>,
        /// The size of the entry in bytes, if known.
        total_blobs_size: Option<u64>,
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
        target: String,
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

/// hook into the request handling to process authorization by examining
/// the request and any given token. Any error returned will abort the request,
/// and the error will be sent to the requester.
pub trait RequestAuthorizationHandler: Send + Sync + Debug + 'static {
    /// Handle the authorization request, given an opaque data blob from the requester.
    fn authorize(
        &self,
        token: Option<RequestToken>,
        request: &Request,
    ) -> BoxFuture<'static, anyhow::Result<()>>;
}

/// A custom get request handler that allows the user to make up a get request
/// on the fly.
pub trait CustomGetHandler: Send + Sync + Debug + 'static {
    /// Handle the custom request, given an opaque data blob from the requester.
    fn handle(
        &self,
        token: Option<RequestToken>,
        request: Bytes,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>>;
}

/// Read the request from the getter.
///
/// Will fail if there is an error while reading, if the reader
/// contains more data than the Request, or if no valid request is sent.
///
/// When successful, the buffer is empty after this function call.
pub async fn read_request(mut reader: quinn::RecvStream, buffer: &mut BytesMut) -> Result<Request> {
    let payload = read_lp(&mut reader, buffer)
        .await?
        .context("No request received")?;
    let request: Request = postcard::from_bytes(&payload)?;
    ensure!(
        reader.read_chunk(8, false).await?.is_none(),
        "Extra data past request"
    );
    Ok(request)
}

/// Transfers the collection & blob data.
///
/// First, it transfers the collection data & its associated outboard encoding data. Then it sequentially transfers each individual blob data & its associated outboard
/// encoding data.
///
/// Will fail if there is an error writing to the getter or reading from
/// the database.
///
/// If a blob from the collection cannot be found in the database, the transfer will gracefully
/// close the writer, and return with `Ok(SentStatus::NotFound)`.
///
/// If the transfer does _not_ end in error, the buffer will be empty and the writer is gracefully closed.
pub async fn transfer_collection<D: BaoMap, E: EventSender, C: CollectionParser>(
    request: GetRequest,
    // Store from which to fetch blobs.
    db: &D,
    // Response writer, containing the quinn stream.
    writer: &mut ResponseWriter<E>,
    // the collection to transfer
    mut outboard: D::Outboard,
    mut data: D::DataReader,
    collection_parser: C,
) -> Result<SentStatus> {
    let hash = request.hash;

    // if the request is just for the root, we don't need to deserialize the collection
    let just_root = matches!(request.ranges.single(), Some((0, _)));
    let mut c = if !just_root {
        // use the collection parser to parse the collection
        let (c, stats) = collection_parser.parse(0, &mut data).await?;
        writer
            .events
            .send(Event::TransferCollectionStarted {
                connection_id: writer.connection_id(),
                request_id: writer.request_id(),
                num_blobs: stats.num_blobs,
                total_blobs_size: stats.total_blob_size,
            })
            .await;
        Some(c)
    } else {
        None
    };

    let mut prev = 0;
    for (offset, ranges) in request.ranges.iter_non_empty() {
        if offset == 0 {
            debug!("writing ranges '{:?}' of collection {}", ranges, hash);
            // send the root
            encode_ranges_validated(
                &mut data,
                &mut outboard,
                &ranges.to_chunk_ranges(),
                &mut writer.inner,
            )
            .await?;
            debug!(
                "finished writing ranges '{:?}' of collection {}",
                ranges, hash
            );
        } else {
            let c = c.as_mut().context("collection parser not available")?;
            debug!("wrtiting ranges '{:?}' of child {}", ranges, offset);
            // skip to the next blob if there is a gap
            if prev < offset - 1 {
                c.skip(offset - prev - 1).await?;
            }
            if let Some(hash) = c.next().await? {
                tokio::task::yield_now().await;
                let (status, size) = send_blob(db, hash, ranges, &mut writer.inner).await?;
                if SentStatus::NotFound == status {
                    writer.inner.finish().await?;
                    return Ok(status);
                }

                writer
                    .events
                    .send(Event::TransferBlobCompleted {
                        connection_id: writer.connection_id(),
                        request_id: writer.request_id(),
                        hash,
                        index: offset - 1,
                        size,
                    })
                    .await;
            } else {
                // nothing more we can send
                break;
            }
            prev = offset;
        }
    }

    debug!("done writing");
    writer.inner.finish().await?;
    Ok(SentStatus::Sent)
}

/// Trait for sending events.
pub trait EventSender: Clone + Sync + Send + 'static {
    /// Send an event.
    fn send(&self, event: Event) -> BoxFuture<()>;
}

/// Handle a single connection.
pub async fn handle_connection<D: BaoMap, E: EventSender, C: CollectionParser>(
    connecting: quinn::Connecting,
    db: D,
    events: E,
    collection_parser: C,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    authorization_handler: Arc<dyn RequestAuthorizationHandler>,
    rt: crate::util::runtime::Handle,
) {
    let remote_addr = connecting.remote_address();
    let connection = match connecting.await {
        Ok(conn) => conn,
        Err(err) => {
            warn!(%remote_addr, "Error connecting: {err:#}");
            return;
        }
    };
    let connection_id = connection.stable_id() as u64;
    let span = debug_span!("connection", connection_id, %remote_addr);
    async move {
        while let Ok((writer, reader)) = connection.accept_bi().await {
            // The stream ID index is used to identify this request.  Requests only arrive in
            // bi-directional RecvStreams initiated by the client, so this uniquely identifies them.
            let request_id = reader.id().index();
            let span = debug_span!("stream", stream_id = %request_id);
            let writer = ResponseWriter {
                connection_id,
                events: events.clone(),
                inner: writer,
            };
            events.send(Event::ClientConnected { connection_id }).await;
            let db = db.clone();
            let custom_get_handler = custom_get_handler.clone();
            let authorization_handler = authorization_handler.clone();
            let collection_parser = collection_parser.clone();
            rt.local_pool().spawn_pinned(|| {
                async move {
                    if let Err(err) = handle_stream(
                        db,
                        reader,
                        writer,
                        custom_get_handler,
                        authorization_handler,
                        collection_parser,
                    )
                    .await
                    {
                        warn!("error: {err:#?}",);
                    }
                }
                .instrument(span)
            });
        }
    }
    .instrument(span)
    .await
}

async fn handle_stream<D: BaoMap, E: EventSender, C: CollectionParser>(
    db: D,
    reader: quinn::RecvStream,
    writer: ResponseWriter<E>,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    authorization_handler: Arc<dyn RequestAuthorizationHandler>,
    collection_parser: C,
) -> Result<()> {
    let mut in_buffer = BytesMut::with_capacity(1024);

    // 1. Decode the request.
    debug!("reading request");
    let request = match read_request(reader, &mut in_buffer).await {
        Ok(r) => r,
        Err(e) => {
            writer.notify_transfer_aborted().await;
            return Err(e);
        }
    };

    // 2. Authorize the request (may be a no-op)
    debug!("authorizing request");
    if let Err(e) = authorization_handler
        .authorize(request.token().cloned(), &request)
        .await
    {
        writer.notify_transfer_aborted().await;
        return Err(e);
    }

    match request {
        Request::Get(request) => handle_get(db, request, collection_parser, writer).await,
        Request::CustomGet(request) => {
            handle_custom_get(db, request, writer, custom_get_handler, collection_parser).await
        }
    }
}
async fn handle_custom_get<E: EventSender, D: BaoMap, C: CollectionParser>(
    db: D,
    request: CustomGetRequest,
    mut writer: ResponseWriter<E>,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    collection_parser: C,
) -> Result<()> {
    writer
        .events
        .send(Event::CustomGetRequestReceived {
            len: request.data.len(),
            connection_id: writer.connection_id(),
            request_id: writer.request_id(),
            token: request.token.clone(),
        })
        .await;
    // try to make a GetRequest from the custom bytes
    let request = custom_get_handler
        .handle(request.token, request.data)
        .await?;
    // write it to the requester as the first thing
    let data = postcard::to_stdvec(&request)?;
    write_lp(&mut writer.inner, &data).await?;
    // from now on just handle it like a normal get request
    handle_get(db, request, collection_parser, writer).await
}

/// Handle a single standard get request.
pub async fn handle_get<D: BaoMap, E: EventSender, C: CollectionParser>(
    db: D,
    request: GetRequest,
    collection_parser: C,
    mut writer: ResponseWriter<E>,
) -> Result<()> {
    let hash = request.hash;
    debug!(%hash, "received request");
    writer
        .events
        .send(Event::GetRequestReceived {
            hash,
            connection_id: writer.connection_id(),
            request_id: writer.request_id(),
            token: request.token().cloned(),
        })
        .await;

    // 4. Attempt to find hash
    match db.get(&hash) {
        // Collection or blob request
        Some(entry) => {
            // 5. Transfer data!
            match transfer_collection(
                request,
                &db,
                &mut writer,
                entry.outboard().await?,
                entry.data_reader().await?,
                collection_parser,
            )
            .await
            {
                Ok(SentStatus::Sent) => {
                    writer.notify_transfer_completed().await;
                }
                Ok(SentStatus::NotFound) => {
                    writer.notify_transfer_aborted().await;
                }
                Err(e) => {
                    writer.notify_transfer_aborted().await;
                    return Err(e);
                }
            }

            debug!("finished response");
        }
        None => {
            debug!("not found {}", hash);
            writer.notify_transfer_aborted().await;
            writer.inner.finish().await?;
        }
    };

    Ok(())
}

/// A helper struct that combines a quinn::SendStream with auxiliary information
#[derive(Debug)]
pub struct ResponseWriter<E> {
    inner: quinn::SendStream,
    events: E,
    connection_id: u64,
}

impl<E: EventSender> ResponseWriter<E> {
    fn connection_id(&self) -> u64 {
        self.connection_id
    }

    fn request_id(&self) -> u64 {
        self.inner.id().index()
    }

    async fn notify_transfer_completed(&self) {
        self.events
            .send(Event::TransferCollectionCompleted {
                connection_id: self.connection_id(),
                request_id: self.request_id(),
            })
            .await;
    }

    async fn notify_transfer_aborted(&self) {
        self.events
            .send(Event::TransferAborted {
                connection_id: self.connection_id(),
                request_id: self.request_id(),
            })
            .await;
    }
}

/// Status  of a send operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentStatus {
    /// The requested data was sent
    Sent,
    /// The requested data was not found
    NotFound,
}

/// Send a
pub async fn send_blob<D: BaoMap, W: AsyncWrite + Unpin + Send + 'static>(
    db: &D,
    name: Hash,
    ranges: &RangeSpec,
    writer: &mut W,
) -> Result<(SentStatus, u64)> {
    match db.get(&name) {
        Some(entry) => {
            let outboard = entry.outboard().await?;
            let size = outboard.tree().size().0;
            let mut file_reader = entry.data_reader().await?;
            let res = bao_tree::io::fsm::encode_ranges_validated(
                &mut file_reader,
                outboard,
                &ranges.to_chunk_ranges(),
                writer,
            )
            .await;
            debug!("done sending blob {} {:?}", name, res);
            res?;

            Ok((SentStatus::Sent, size))
        }
        _ => {
            debug!("blob not found {}", hex::encode(name));
            Ok((SentStatus::NotFound, 0))
        }
    }
}
