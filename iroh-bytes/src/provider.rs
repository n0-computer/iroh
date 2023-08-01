//! The server side API
use std::fmt::Debug;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use bao_tree::io::fsm::{encode_ranges_validated, Outboard};
use bao_tree::ChunkNum;
use bytes::{Bytes, BytesMut};
use futures::future::BoxFuture;
use futures::FutureExt;
use iroh_io::{AsyncSliceReader, AsyncSliceWriter};
use range_collections::RangeSet2;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;

use crate::collection::CollectionParser;
use crate::protocol::{
    read_lp, write_lp, CustomGetRequest, GetRequest, RangeSpec, Request, RequestToken,
};
use crate::util::progress::{IdGenerator, ProgressSender};
use crate::util::RpcError;
use crate::Hash;

/// An entry for one hash in a bao collection
///
/// The entry has the ability to provide you with an (outboard, data)
/// reader pair. Creating the reader is async and may fail. The futures that
/// create the readers must be `Send`, but the readers themselves don't have to
/// be.
pub trait BaoMapEntry<D: BaoMap>: Clone + Send + Sync + 'static {
    /// The hash of the entry
    fn hash(&self) -> blake3::Hash;
    /// the size of the entry
    fn size(&self) -> u64;
    /// Compute the available ranges.
    ///
    /// Depending on the implementation, this may be an expensive operation.
    ///
    /// It can also only ever be a best effort, since the underlying data may
    /// change at any time. E.g. somebody could flip a bit in the file, or download
    /// more chunks.
    fn available(&self) -> BoxFuture<'_, io::Result<RangeSet2<ChunkNum>>>;
    /// A future that resolves to a reader that can be used to read the outboard
    fn outboard(&self) -> BoxFuture<'_, io::Result<D::Outboard>>;
    /// A future that resolves to a reader that can be used to read the data
    fn data_reader(&self) -> BoxFuture<'_, io::Result<D::DataReader>>;
}

/// A generic collection of blobs with precomputed outboards
pub trait BaoMap: Clone + Send + Sync + 'static {
    /// The outboard type. This can be an in memory outboard or an outboard that
    /// retrieves the data asynchronously from a remote database.
    type Outboard: bao_tree::io::fsm::Outboard;
    /// The reader type.
    type DataReader: AsyncSliceReader;
    /// The entry type. An entry is a cheaply cloneable handle that can be used
    /// to open readers for both the data and the outboard
    type Entry: BaoMapEntry<Self>;
    /// Get an entry for a hash.
    ///
    /// This can also be used for a membership test by just checking if there
    /// is an entry. Creating an entry should be cheap, any expensive ops should
    /// be deferred to the creation of the actual readers.
    ///
    /// It is not guaranteed that the entry is complete. A BaoMapMut would return
    /// here both complete and partial entries, so that you can share partial entries.
    fn get(&self, hash: &Hash) -> Option<Self::Entry>;
}

/// A partial entry
pub trait BaoPartialEntry<D: BaoMapMut>: BaoMapEntry<D> {
    /// A future that resolves to an writeable outboard
    fn outboard_mut(&self) -> BoxFuture<'_, io::Result<D::OutboardMut>>;
    /// A future that resolves to a writer that can be used to write the data
    fn data_writer(&self) -> BoxFuture<'_, io::Result<D::DataWriter>>;
}

/// A mutable bao map
pub trait BaoMapMut: BaoMap {
    /// The outboard type to write data to the partial entry.
    type OutboardMut: bao_tree::io::fsm::OutboardMut;
    /// The writer type to write data to the partial entry.
    type DataWriter: AsyncSliceWriter;
    /// A partial entry. This is an entry that is writeable and possibly incomplete.
    ///
    /// It must also be readable.
    type PartialEntry: BaoPartialEntry<Self>;

    /// Get an existing partial entry, or create a new one
    ///
    /// We need to know the size of the partial entry. This might produce an
    /// error e.g. if there is not enough space on disk.
    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Self::PartialEntry>;

    /// Get an existing partial entry
    fn get_partial(&self, hash: &Hash) -> Option<Self::PartialEntry>;

    /// Upgrade a partial entry to a complete entry
    fn insert_complete_entry(&self, entry: Self::PartialEntry) -> BoxFuture<'_, io::Result<()>>;
}

/// Extension of BaoMap to add misc methods used by the rpc calls
pub trait BaoReadonlyDb: BaoMap {
    /// list all blobs in the database. This should include collections, since
    /// collections are blobs and can be requested as blobs.
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;
    /// list all roots (collections or other explicitly added things) in the database
    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;
    /// Validate the database
    fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>>;
}

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
    /// We got progress ingesting item `id`
    Progress {
        /// the unique id of the entry
        id: u64,
        /// the offset of the progress, in bytes
        offset: u64,
    },
    /// We are done with `id`
    Done {
        /// the unique id of the entry
        id: u64,
        /// an error if we failed to validate the entry
        error: Option<String>,
    },
    /// We are done with the whole operation
    AllDone,
    /// We got an error and need to abort
    Abort(RpcError),
}

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ProvideProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found {
        /// a new unique id for this entry
        id: u64,
        /// the name of the entry
        name: String,
        /// the size of the entry in bytes
        size: u64,
    },
    /// We got progress ingesting item `id`
    Progress {
        /// the unique id of the entry
        id: u64,
        /// the offset of the progress, in bytes
        offset: u64,
    },
    /// We are done with `id`, and the hash is `hash`
    Done {
        /// the unique id of the entry
        id: u64,
        /// the hash of the entry
        hash: Hash,
    },
    /// We are done with the whole operation
    AllDone {
        /// the hash of the created collection
        hash: Hash,
    },
    /// We got an error and need to abort.
    ///
    /// This will be the last message in the stream.
    Abort(RpcError),
}

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ShareProgress {
    /// An item was found with hash `hash`, from now on referred to via `id`
    Found {
        /// a new unique id for this entry
        id: u64,
        /// the name of the entry
        hash: Hash,
        /// the size of the entry in bytes
        size: u64,
    },
    /// We got progress ingesting item `id`
    Progress {
        /// the unique id of the entry
        id: u64,
        /// the offset of the progress, in bytes
        offset: u64,
    },
    /// We are done with `id`, and the hash is `hash`
    Done {
        /// the unique id of the entry
        id: u64,
    },
    /// We are done with the whole operation
    AllDone,
    ///
    Export {
        ///
        id: u64,
        ///
        hash: Hash,
        ///
        size: u64,
        ///
        target: String,
    },
    ///
    ExportProgress {
        ///
        id: u64,
        ///
        offset: u64,
    },
    /// We got an error and need to abort
    Abort(RpcError),
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
    // Database from which to fetch blobs.
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
            debug!("blob not found {}", name);
            Ok((SentStatus::NotFound, 0))
        }
    }
}

/// The mutable part of a BaoDb
pub trait BaoDb: BaoReadonlyDb + BaoMapMut {
    /// list partial blobs in the database
    fn partial_blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }

    /// extract a file to a local path
    ///
    /// `hash` is the hash of the file
    /// `target` is the path to the target file
    /// `stable` is true if the file can be assumed to be retained unchanged in the file system
    /// `progress` is a callback that is called with the total number of bytes that have been written
    fn export(
        &self,
        hash: Hash,
        target: PathBuf,
        stable: bool,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> BoxFuture<'_, io::Result<()>> {
        let _ = (hash, target, stable, progress);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    /// import a file from a local path
    ///
    /// `data` is the path to the file
    /// `stable` is true if the file can be assumed to be retained unchanged in the file system. If
    /// `stable` is false, the file will be copied.
    /// `progress` is a callback that is called with the total number of bytes that have been written
    /// to the database. This returns an error to allow the caller to abort the import.
    ///
    /// Returns the hash of the imported file. The reason to have this method is that some database
    /// implementations might be able to import a file without copying it.
    fn import(
        &self,
        data: PathBuf,
        stable: bool,
        progress: impl ProgressSender<Msg = ImportProgress> + IdGenerator,
    ) -> BoxFuture<'_, io::Result<(Hash, u64)>> {
        let _ = (data, stable, progress);
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }

    /// import a byte slice
    fn import_bytes(&self, bytes: Bytes) -> BoxFuture<'_, io::Result<Hash>> {
        let _ = bytes;
        async move { Err(io::Error::new(io::ErrorKind::Other, "not implemented")) }.boxed()
    }
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
    Found {
        id: u64,
        path: PathBuf,
        stable: bool,
    },
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
