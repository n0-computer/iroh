//! Provider API

use std::borrow::Cow;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context, Result};
use bao_tree::io::fsm::{encode_ranges_validated, Outboard};
use bytes::{Bytes, BytesMut};
use futures::future::{BoxFuture, Either};
use futures::{Future, FutureExt};
use iroh_io::{AsyncSliceReaderExt, FileAdapter};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;
use walkdir::WalkDir;

use crate::blobs::Collection;
use crate::protocol::{
    read_lp, write_lp, CustomGetRequest, GetRequest, Handshake, RangeSpec, Request, RequestToken,
    VERSION,
};
use crate::provider::database::BaoMapEntry;
use crate::util::{canonicalize_path, Hash, Progress, RpcError};

pub mod collection;
pub mod database;
mod ticket;

pub use database::Database;
pub use database::FNAME_PATHS;
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
        num_blobs: u64,
        /// The total blob size of the data.
        total_blobs_size: u64,
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
    Starting { total: u64 },
    /// We started validating an entry
    Entry {
        id: u64,
        hash: Hash,
        path: Option<PathBuf>,
        size: u64,
    },
    /// We got progress ingesting item `id`
    Progress { id: u64, offset: u64 },
    /// We are done with `id`
    Done { id: u64, error: Option<String> },
    /// We are done with the whole operation
    AllDone,
    /// We got an error and need to abort
    Abort(RpcError),
}

/// Progress updates for the provide operation
#[derive(Debug, Serialize, Deserialize)]
pub enum ProvideProgress {
    /// An item was found with name `name`, from now on referred to via `id`
    Found { name: String, id: u64, size: u64 },
    /// We got progress ingesting item `id`
    Progress { id: u64, offset: u64 },
    /// We are done with `id`, and the hash is `hash`
    Done { id: u64, hash: Hash },
    /// We are done with the whole operation
    AllDone { hash: Hash },
    /// We got an error and need to abort
    Abort(RpcError),
}

/// hook into the request handling to process authorization by examining
/// the request and any given token. Any error returned will abort the request,
/// and the error will be sent to the requester.
pub trait RequestAuthorizationHandler<D>: Send + Sync + Clone + 'static {
    /// Handle the authorization request, given an opaque data blob from the requester.
    fn authorize(
        &self,
        db: D,
        token: Option<RequestToken>,
        request: &Request,
    ) -> BoxFuture<'static, anyhow::Result<()>>;
}

/// Define RequestAuthorizationHandler for () so we can use it as a no-op default.
impl<D> RequestAuthorizationHandler<D> for () {
    fn authorize(
        &self,
        _db: D,
        token: Option<RequestToken>,
        _request: &Request,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        async move {
            if let Some(token) = token {
                anyhow::bail!(
                    "no authorization handler defined, but token was provided: {:?}",
                    token
                );
            }
            Ok(())
        }
        .boxed()
    }
}

/// A custom get request handler that allows the user to make up a get request
/// on the fly.
pub trait CustomGetHandler<D>: Send + Sync + Clone + 'static {
    /// Handle the custom request, given an opaque data blob from the requester.
    fn handle(
        &self,
        token: Option<RequestToken>,
        request: Bytes,
        db: D,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>>;
}

/// Handle the custom request, given an opaque data blob from the requester.
/// Define CustomGetHandler for () so we can use it as a no-op default.
impl<D> CustomGetHandler<D> for () {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _request: Bytes,
        _db: D,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        async move { Err(anyhow::anyhow!("no custom get handler defined")) }.boxed()
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
    pub fn is_external(&self) -> bool {
        matches!(self, DbEntry::External { .. })
    }

    pub fn blob_path(&self) -> Option<&Path> {
        match self {
            DbEntry::External { path, .. } => Some(path),
            DbEntry::Internal { .. } => None,
        }
    }

    pub fn outboard_reader(&self) -> impl Future<Output = io::Result<Bytes>> + 'static {
        futures::future::ok(match self {
            DbEntry::External { outboard, .. } => outboard.clone(),
            DbEntry::Internal { outboard, .. } => outboard.clone(),
        })
    }

    /// A reader for the data.
    pub fn data_reader(
        &self,
    ) -> impl Future<Output = io::Result<Either<Bytes, FileAdapter>>> + 'static {
        let this = self.clone();
        async move {
            Ok(match this {
                DbEntry::External { path, .. } => Either::Right(FileAdapter::open(path).await?),
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

/// Read and decode the handshake.
///
/// Will fail if there is an error while reading, there is a token mismatch, or no valid
/// handshake was received.
///
/// When successful, the reader is still useable after this function and the buffer will be
/// drained of any handshake data.
pub async fn read_handshake<R: AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
) -> Result<()> {
    let payload = read_lp(&mut reader, buffer)
        .await?
        .context("no valid handshake received")?;
    let handshake: Handshake = postcard::from_bytes(&payload)?;
    ensure!(
        handshake.version == VERSION,
        "expected version {} but got {}",
        VERSION,
        handshake.version
    );
    Ok(())
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
pub async fn transfer_collection<D: BaoMap, E: EventSender>(
    request: GetRequest,
    // Database from which to fetch blobs.
    db: &D,
    // Response writer, containing the quinn stream.
    writer: &mut ResponseWriter<E>,
    // the collection to transfer
    outboard: D::Outboard,
    mut data: D::DataReader,
) -> Result<SentStatus> {
    let hash = request.hash;

    // if the request is just for the root, we don't need to deserialize the collection
    let just_root = matches!(request.ranges.single(), Some((0, _)));
    let c = if !just_root {
        let bytes = data.read_to_end().await?;
        let c: Collection = postcard::from_bytes(&bytes)?;
        let _ = writer.events.send(Event::TransferCollectionStarted {
            connection_id: writer.connection_id(),
            request_id: writer.request_id(),
            num_blobs: c.blobs().len() as u64,
            total_blobs_size: c.total_blobs_size(),
        });
        Some(c)
    } else {
        None
    };

    for (offset, ranges) in request.ranges.iter_non_empty() {
        if offset == 0 {
            debug!("writing ranges '{:?}' of collection {}", ranges, hash);
            // send the root
            encode_ranges_validated(
                &mut data,
                &outboard,
                &ranges.to_chunk_ranges(),
                &mut writer.inner,
            )
            .await?;
            debug!(
                "finished writing ranges '{:?}' of collection {}",
                ranges, hash
            );
        } else {
            debug!("wrtiting ranges '{:?}' of child {}", ranges, offset);
            let c = c.as_ref().unwrap();
            if offset < c.total_entries() + 1 {
                tokio::task::yield_now().await;
                let hash = c.blobs()[(offset - 1) as usize].hash;
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
        }
    }

    debug!("done writing");
    writer.inner.finish().await?;
    Ok(SentStatus::Sent)
}

pub trait EventSender: Clone + Send + 'static {
    fn send(&self, event: Event) -> Option<Event>;
}

pub async fn handle_connection<
    D: BaoMap,
    C: CustomGetHandler<D>,
    E: EventSender,
    A: RequestAuthorizationHandler<D>,
>(
    connecting: quinn::Connecting,
    db: D,
    events: E,
    custom_get_handler: C,
    authorization_handler: A,
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
            rt.local_pool().spawn_pinned(|| {
                async move {
                    if let Err(err) = handle_stream(
                        db,
                        reader,
                        writer,
                        custom_get_handler,
                        authorization_handler,
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

async fn handle_stream<D: BaoMap, E: EventSender>(
    db: D,
    mut reader: quinn::RecvStream,
    writer: ResponseWriter<E>,
    custom_get_handler: impl CustomGetHandler<D>,
    authorization_handler: impl RequestAuthorizationHandler<D>,
) -> Result<()> {
    let mut in_buffer = BytesMut::with_capacity(1024);

    // 1. Read Handshake
    debug!("reading handshake");
    if let Err(e) = read_handshake(&mut reader, &mut in_buffer).await {
        writer.notify_transfer_aborted();
        return Err(e);
    }

    // 2. Decode the request.
    debug!("reading request");
    let request = match read_request(reader, &mut in_buffer).await {
        Ok(r) => r,
        Err(e) => {
            writer.notify_transfer_aborted();
            return Err(e);
        }
    };

    // 3. Authorize the request (may be a no-op)
    debug!("authorizing request");
    if let Err(e) = authorization_handler
        .authorize(db.clone(), request.token().cloned(), &request)
        .await
    {
        writer.notify_transfer_aborted();
        return Err(e);
    }

    match request {
        Request::Get(request) => handle_get(db, request, writer).await,
        Request::CustomGet(request) => {
            handle_custom_get(db, request, writer, custom_get_handler).await
        }
    }
}
async fn handle_custom_get<E: EventSender, D: BaoMap>(
    db: D,
    request: CustomGetRequest,
    mut writer: ResponseWriter<E>,
    custom_get_handler: impl CustomGetHandler<D>,
) -> Result<()> {
    let _ = writer.events.send(Event::CustomGetRequestReceived {
        len: request.data.len(),
        connection_id: writer.connection_id(),
        request_id: writer.request_id(),
        token: request.token.clone(),
    });
    // try to make a GetRequest from the custom bytes
    let request = custom_get_handler
        .handle(request.token, request.data, db.clone())
        .await?;
    // write it to the requester as the first thing
    let data = postcard::to_stdvec(&request)?;
    write_lp(&mut writer.inner, &data).await?;
    // from now on just handle it like a normal get request
    handle_get(db, request, writer).await
}

pub async fn handle_get<D: BaoMap, E: EventSender>(
    db: D,
    request: GetRequest,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentStatus {
    Sent,
    NotFound,
}

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

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_collection(data_sources: Vec<DataSource>) -> Result<(Database, Hash)> {
    let (db, hash) = collection::create_collection(data_sources, Progress::none()).await?;
    Ok((Database::from(db), hash))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::str::FromStr;
    use testdir::testdir;

    use crate::blobs::Blob;
    use crate::provider::database::Snapshot;

    use super::*;

    fn blob(size: usize) -> impl Strategy<Value = Bytes> {
        proptest::collection::vec(any::<u8>(), 0..size).prop_map(Bytes::from)
    }

    fn blobs(count: usize, size: usize) -> impl Strategy<Value = Vec<Bytes>> {
        proptest::collection::vec(blob(size), 0..count)
    }

    fn db(blob_count: usize, blob_size: usize) -> impl Strategy<Value = Database> {
        let blobs = blobs(blob_count, blob_size);
        blobs.prop_map(|blobs| {
            let mut map = HashMap::new();
            let mut cblobs = Vec::new();
            let mut total_blobs_size = 0u64;
            for blob in blobs {
                let size = blob.len() as u64;
                total_blobs_size += size;
                let (outboard, hash) = bao_tree::outboard(&blob, crate::IROH_BLOCK_SIZE);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                let path = PathBuf::from_str(&hash.to_string()).unwrap();
                cblobs.push(Blob {
                    name: hash.to_string(),
                    hash,
                });
                map.insert(
                    hash,
                    DbEntry::External {
                        outboard,
                        size,
                        path,
                    },
                );
            }
            let collection = Collection::new(cblobs, total_blobs_size).unwrap();
            // encode collection and add it
            {
                let data = Bytes::from(postcard::to_stdvec(&collection).unwrap());
                let (outboard, hash) = bao_tree::outboard(&data, crate::IROH_BLOCK_SIZE);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                map.insert(hash, DbEntry::Internal { outboard, data });
            }
            let db = Database::default();
            db.union_with(map);
            db
        })
    }

    proptest! {
        #[test]
        fn database_snapshot_roundtrip(db in db(10, 1024 * 64)) {
            let snapshot = db.snapshot();
            let db2 = Database::from_snapshot(snapshot).unwrap();
            prop_assert_eq!(db.to_inner(), db2.to_inner());
        }

        #[test]
        fn database_persistence_roundtrip(db in db(10, 1024 * 64)) {
            let dir = tempfile::tempdir().unwrap();
            let snapshot = db.snapshot();
            snapshot.persist(&dir).unwrap();
            let snapshot2 = Snapshot::load(&dir).unwrap();
            let db2 = Database::from_snapshot(snapshot2).unwrap();
            let db = db.to_inner();
            let db2 = db2.to_inner();
            prop_assert_eq!(db, db2);
        }
    }

    #[tokio::test]
    async fn test_create_collection() -> Result<()> {
        let dir: PathBuf = testdir!();
        let mut expect_blobs = vec![];
        let hash = blake3::hash(&[]);
        let hash = Hash::from(hash);

        // DataSource::File
        let foo = dir.join("foo");
        tokio::fs::write(&foo, vec![]).await?;
        let foo = DataSource::new(foo);
        expect_blobs.push(Blob {
            name: "foo".to_string(),
            hash,
        });

        // DataSource::NamedFile
        let bar = dir.join("bar");
        tokio::fs::write(&bar, vec![]).await?;
        let bar = DataSource::with_name(bar, "bat".to_string());
        expect_blobs.push(Blob {
            name: "bat".to_string(),
            hash,
        });

        // DataSource::NamedFile, empty string name
        let baz = dir.join("baz");
        tokio::fs::write(&baz, vec![]).await?;
        let baz = DataSource::with_name(baz, "".to_string());
        expect_blobs.push(Blob {
            name: "".to_string(),
            hash,
        });

        let expect_collection = Collection::new(expect_blobs, 0).unwrap();

        let (db, hash) = create_collection(vec![foo, bar, baz]).await?;

        let collection = {
            let c = db.get(&hash).unwrap();
            if let DbEntry::Internal { data, .. } = c {
                Collection::from_bytes(&data)?
            } else {
                panic!("expected hash to correspond with a `Collection`, found `Blob` instead");
            }
        };

        assert_eq!(expect_collection, collection);

        Ok(())
    }
}
