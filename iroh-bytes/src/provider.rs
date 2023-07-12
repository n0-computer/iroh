//! Provider API

use std::borrow::Cow;
use std::fmt::Debug;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use bao_tree::io::fsm::{encode_ranges_validated, Outboard};
use bytes::{Bytes, BytesMut};
use futures::future::LocalBoxFuture;
use futures::FutureExt;
use futures::{
    future::{self, BoxFuture, Either},
    Future,
};
use iroh_io::{AsyncSliceReader, AsyncSliceReaderExt, File};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWrite;
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;
use walkdir::WalkDir;

use crate::blobs::Collection;
use crate::protocol::{
    read_lp, write_lp, CustomGetRequest, GetRequest, RangeSpec, Request, RequestToken,
};
use crate::provider::database::BaoMapEntry;
use crate::util::{io::canonicalize_path, Hash, RpcError};

pub mod collection;
pub mod database;
mod ticket;

pub use ticket::Ticket;

use self::database::BaoMap;

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
        /// the path of the entry on the local file system
        path: Option<PathBuf>,
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

/// A custom collection parser that allows the user to define what a collection is.
///
/// A collection can be anything that contains an ordered sequence of blake3 hashes.
/// Some collections store links with a fixed size and therefore allow efficient
/// skipping. Others store links with a variable size and therefore only allow
/// sequential access.
///
/// This API tries to accomodate both use cases. For collections that do not allow
/// efficient random access, the [`LinkStream::skip`] method can be implemented by just repeatedly
/// calling `next`.
///
/// For collections that do allow efficient random access, the [`LinkStream::skip`] method can be
/// used to move some internal offset.
pub trait CollectionParser: Send + Debug + Clone + 'static {
    /// Parse a collection with this parser
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        format: u64,
        reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>>;
}

/// A stream (async iterator) over the hashes of a collection.
///
/// Allows to get the next hash or skip a number of hashes.  Does not
/// implement `Stream` because of the extra `skip` method.
pub trait LinkStream: Debug {
    /// Get the next hash in the collection.
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>>;
    /// Skip a number of hashes in the collection.
    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>>;
}

/// Information about a collection.
#[derive(Debug, Clone, Copy, Default)]
pub struct CollectionStats {
    /// The number of blobs in the collection. `None` for unknown.
    pub num_blobs: Option<u64>,
    /// The total size of all blobs in the collection. `None` for unknown.
    pub total_blob_size: Option<u64>,
}

/// A collection parser that just disables collections entirely.
#[derive(Debug, Clone)]
struct NoCollectionParser;

/// A CustomCollection for NoCollectionParser.
///
/// This is useful for when you don't want to support collections at all.
impl CollectionParser for NoCollectionParser {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        _reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        future::err(anyhow::anyhow!("collections not supported")).boxed_local()
    }
}

/// Parser for the current iroh default collections
/// 
/// This is a custom collection parser that supports the current iroh default collections.
/// It loads the entire collection into memory and then extracts an array of hashes.
/// So this will not work for extremely large collections.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrohCollectionParser;

/// Iterator for the current iroh default collections
#[derive(Debug, Clone)]
pub struct ArrayLinkStream {
    hashes: Box<[Hash]>,
    offset: usize,
}

impl ArrayLinkStream {
    /// Create a new iterator over the given hashes.
    pub fn new(hashes: Box<[Hash]>) -> Self {
        Self { hashes, offset: 0 }
    }
}

impl LinkStream for ArrayLinkStream {
    fn next(&mut self) -> LocalBoxFuture<'_, anyhow::Result<Option<Hash>>> {
        let res = if self.offset < self.hashes.len() {
            let hash = self.hashes[self.offset];
            self.offset += 1;
            Some(hash)
        } else {
            None
        };
        future::ok(res).boxed_local()
    }

    fn skip(&mut self, n: u64) -> LocalBoxFuture<'_, anyhow::Result<()>> {
        let res = if let Some(offset) = self
            .offset
            .checked_add(usize::try_from(n).unwrap_or(usize::MAX))
        {
            self.offset = offset;
            Ok(())
        } else {
            Err(anyhow::anyhow!("overflow"))
        };
        future::ready(res).boxed_local()
    }
}

impl CollectionParser for IrohCollectionParser {
    fn parse<'a, R: AsyncSliceReader + 'a>(
        &'a self,
        _format: u64,
        mut reader: R,
    ) -> LocalBoxFuture<'a, anyhow::Result<(Box<dyn LinkStream>, CollectionStats)>> {
        async move {
            // read to end
            let data = reader.read_to_end().await?;
            // parse the collection and just take the hashes
            let collection = Collection::from_bytes(&data)?;
            let stats = CollectionStats {
                num_blobs: Some(collection.blobs.len() as u64),
                total_blob_size: Some(collection.total_blobs_size),
            };
            let hashes = collection
                .into_inner()
                .into_iter()
                .map(|x| x.hash)
                .collect::<Vec<_>>()
                .into_boxed_slice();
            let res: Box<dyn LinkStream> = Box::new(ArrayLinkStream { hashes, offset: 0 });
            Ok((res, stats))
        }
        .boxed_local()
    }
}

/// A [`Database`] entry.
///
/// This is either stored externally in the file system, or internally in the database.
///
/// Internally stored entries are stored in the iroh home directory when the database is
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbEntry {
    /// A blob.
    External {
        /// The bao outboard data.
        outboard: Bytes,
        /// Path to the original data, which must not change while in use.
        ///
        /// Note that when adding multiple files with the same content, only one of them
        /// will get added to the store. So the path is not that useful for information.  It
        /// is just a place to look for the data correspoding to the hash and outboard.
        // TODO: Change this to a list of paths.
        path: PathBuf,
        /// Size of the original data.
        size: u64,
    },
    /// A collection.
    Internal {
        /// The bao outboard data.
        outboard: Bytes,
        /// The inline data.
        data: Bytes,
    },
}

impl DbEntry {
    /// True if this is an entry that is stored externally.
    pub fn is_external(&self) -> bool {
        matches!(self, DbEntry::External { .. })
    }

    /// Path to the external data, or `None` if this is an internal entry.
    pub fn blob_path(&self) -> Option<&Path> {
        match self {
            DbEntry::External { path, .. } => Some(path),
            DbEntry::Internal { .. } => None,
        }
    }

    /// Get the outboard data for this entry, as a `Bytes`.
    pub fn outboard_reader(&self) -> impl Future<Output = io::Result<Bytes>> + 'static {
        futures::future::ok(match self {
            DbEntry::External { outboard, .. } => outboard.clone(),
            DbEntry::Internal { outboard, .. } => outboard.clone(),
        })
    }

    /// A reader for the data.
    pub fn data_reader(&self) -> impl Future<Output = io::Result<Either<Bytes, File>>> + 'static {
        let this = self.clone();
        async move {
            Ok(match this {
                DbEntry::External { path, .. } => Either::Right(File::open(path).await?),
                DbEntry::Internal { data, .. } => Either::Left(data),
            })
        }
    }

    /// Returns the size of the blob or collection.
    ///
    /// For collections this is the size of the serialized collection.
    /// For blobs it is the blob size.
    pub async fn size(&self) -> u64 {
        match self {
            DbEntry::External { size, .. } => *size,
            DbEntry::Internal { data, .. } => data.len() as u64,
        }
    }
}

/// Create data sources from a path.
pub fn create_data_sources(root: PathBuf) -> anyhow::Result<Vec<DataSource>> {
    Ok(if root.is_dir() {
        let files = WalkDir::new(&root).into_iter();
        let data_sources = files
            .map(|entry| {
                let entry = entry?;
                let root = root.clone();
                if !entry.file_type().is_file() {
                    // Skip symlinks. Directories are handled by WalkDir.
                    return Ok(None);
                }
                let path = entry.into_path();
                let name = canonicalize_path(path.strip_prefix(&root)?)?;
                anyhow::Ok(Some(DataSource { name, path }))
            })
            .filter_map(Result::transpose);
        let data_sources: Vec<anyhow::Result<DataSource>> = data_sources.collect::<Vec<_>>();
        data_sources
            .into_iter()
            .collect::<anyhow::Result<Vec<_>>>()?
    } else {
        // A single file, use the file name as the name of the blob.
        vec![DataSource {
            name: canonicalize_path(root.file_name().context("path must be a file")?)?,
            path: root,
        }]
    })
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
        let _ = writer.events.send(Event::TransferCollectionStarted {
            connection_id: writer.connection_id(),
            request_id: writer.request_id(),
            num_blobs: stats.num_blobs,
            total_blobs_size: stats.total_blob_size,
        });
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

                let _ = writer.events.send(Event::TransferBlobCompleted {
                    connection_id: writer.connection_id(),
                    request_id: writer.request_id(),
                    hash,
                    index: offset - 1,
                    size,
                });
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
pub trait EventSender: Clone + Send + 'static {
    /// Send an event.
    ///
    /// Returns `None` if the event was sent successfully, or `Some(event)` if the event could not be sent.
    fn send(&self, event: Event) -> Option<Event>;
}

/// Handle a single connection.
pub async fn handle_connection<D: BaoMap, E: EventSender, C: CollectionParser>(
    connecting: quinn::Connecting,
    db: D,
    events: E,
    collection_parser: C,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    authorization_handler: Arc<dyn RequestAuthorizationHandler>,
    rt: crate::runtime::Handle,
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
            events.send(Event::ClientConnected { connection_id });
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
            writer.notify_transfer_aborted();
            return Err(e);
        }
    };

    // 2. Authorize the request (may be a no-op)
    debug!("authorizing request");
    if let Err(e) = authorization_handler
        .authorize(request.token().cloned(), &request)
        .await
    {
        writer.notify_transfer_aborted();
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
    let _ = writer.events.send(Event::CustomGetRequestReceived {
        len: request.data.len(),
        connection_id: writer.connection_id(),
        request_id: writer.request_id(),
        token: request.token.clone(),
    });
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
    let _ = writer.events.send(Event::GetRequestReceived {
        hash,
        connection_id: writer.connection_id(),
        request_id: writer.request_id(),
        token: request.token().cloned(),
    });

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
                    writer.notify_transfer_completed();
                }
                Ok(SentStatus::NotFound) => {
                    writer.notify_transfer_aborted();
                }
                Err(e) => {
                    writer.notify_transfer_aborted();
                    return Err(e);
                }
            }

            debug!("finished response");
        }
        None => {
            debug!("not found {}", hash);
            writer.notify_transfer_aborted();
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

    fn notify_transfer_completed(&self) {
        let _ = self.events.send(Event::TransferCollectionCompleted {
            connection_id: self.connection_id(),
            request_id: self.request_id(),
        });
    }

    fn notify_transfer_aborted(&self) {
        let _ = self.events.send(Event::TransferAborted {
            connection_id: self.connection_id(),
            request_id: self.request_id(),
        });
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

/// Data for a blob
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobData {
    /// Outboard data from bao.
    outboard: Bytes,
    /// Path to the original data, which must not change while in use.
    ///
    /// Note that when adding multiple files with the same content, only one of them
    /// will get added to the store. So the path is not that useful for information.
    /// It is just a place to look for the data correspoding to the hash and outboard.
    path: PathBuf,
    /// Size of the original data.
    size: u64,
}

/// A data source
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DataSource {
    /// Custom name
    name: String,
    /// Path to the file
    path: PathBuf,
}

impl DataSource {
    /// Creates a new [`DataSource`] from a [`PathBuf`].
    pub fn new(path: PathBuf) -> Self {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        DataSource { path, name }
    }
    /// Creates a new [`DataSource`] from a [`PathBuf`] and a custom name.
    pub fn with_name(path: PathBuf, name: String) -> Self {
        DataSource { path, name }
    }

    /// Returns blob name for this data source.
    ///
    /// If no name was provided when created it is derived from the path name.
    pub(crate) fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.name)
    }

    /// Returns the path of this data source.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl From<PathBuf> for DataSource {
    fn from(value: PathBuf) -> Self {
        DataSource::new(value)
    }
}

impl From<&std::path::Path> for DataSource {
    fn from(value: &std::path::Path) -> Self {
        DataSource::new(value.to_path_buf())
    }
}
