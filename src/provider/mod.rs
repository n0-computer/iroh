//! Provider API
//!
//! A provider is a server that serves content-addressed data (blobs or collections).
//! To create a provider, create a database using [`create_collection`], then build a
//! provider using [`Builder`] and spawn it using [`Builder::spawn`].
//!
//! You can monitor what is happening in the provider using [`Provider::subscribe`].
//!
//! To shut down the provider, call [`Provider::shutdown`].
use std::future::Future;
use std::io::{BufReader, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};

use abao::encode::SliceExtractor;
use anyhow::{ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use futures::future::{BoxFuture, Shared};
use futures::{stream, FutureExt, Stream, StreamExt, TryFutureExt, TryStreamExt};
use postcard::experimental::max_size::MaxSize;
use quic_rpc::server::RpcChannel;
use quic_rpc::transport::flume::FlumeConnection;
use quic_rpc::transport::misc::DummyServerEndpoint;
use quic_rpc::{RpcClient, RpcServer, ServiceConnection, ServiceEndpoint};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinError;
use tokio_util::io::SyncIoBridge;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, warn};
use tracing_futures::Instrument;
use walkdir::WalkDir;

use crate::blobs::{Blob, Collection};
use crate::net::find_local_addresses;
use crate::protocol::{
    read_lp, write_lp, AuthToken, Closed, Handshake, Request, Res, Response, VERSION,
};
use crate::rpc_protocol::{
    AddrsRequest, AddrsResponse, IdRequest, IdResponse, ListRequest, ListResponse, ProvideProgress,
    ProvideRequest, ProviderRequest, ProviderResponse, ProviderService, ShutdownRequest,
    ValidateProgress, ValidateRequest, VersionRequest, VersionResponse, WatchRequest,
    WatchResponse,
};
use crate::tls::{self, Keypair, PeerId};
use crate::util::{canonicalize_path, Hash, Progress, ProgressReader, ProgressReaderUpdate};

mod database;
mod ticket;

pub use database::Database;
#[cfg(cli)]
pub use database::Snapshot;
pub use ticket::Ticket;

const MAX_CONNECTIONS: u32 = 1024;
const MAX_STREAMS: u64 = 10;
const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
/// Default bind address for the provider.
pub const DEFAULT_BIND_ADDR: ([u8; 4], u16) = ([127, 0, 0, 1], 4433);

/// Builder for the [`Provider`].
///
/// You must supply a database which can be created using [`create_collection`], everything else is
/// optional.  Finally you can create and run the provider by calling [`Builder::spawn`].
///
/// The returned [`Provider`] is awaitable to know when it finishes.  It can be terminated
/// using [`Provider::shutdown`].
#[derive(Debug)]
pub struct Builder<E: ServiceEndpoint<ProviderService> = DummyServerEndpoint> {
    bind_addr: SocketAddr,
    keypair: Keypair,
    auth_token: AuthToken,
    rpc_endpoint: E,
    db: Database,
    keylog: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlobOrCollection {
    Blob(Data),
    Collection { outboard: Bytes, data: Bytes },
}

impl BlobOrCollection {
    pub fn is_blob(&self) -> bool {
        matches!(self, BlobOrCollection::Blob(_))
    }

    pub fn data(&self) -> Option<&Data> {
        match self {
            BlobOrCollection::Blob(data) => Some(data),
            BlobOrCollection::Collection { .. } => None,
        }
    }

    /// Returns the size of the blob or collection.
    ///
    /// For collections this is the size of the serialized collection.
    /// For blobs it is the blob size.
    pub fn size(&self) -> u64 {
        match self {
            BlobOrCollection::Blob(data) => data.size,
            BlobOrCollection::Collection { data, .. } => data.len() as u64,
        }
    }
}

impl Builder {
    /// Creates a new builder for [`Provider`] using the given [`Database`].
    pub fn with_db(db: Database) -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.into(),
            keypair: Keypair::generate(),
            auth_token: AuthToken::generate(),
            rpc_endpoint: Default::default(),
            db,
            keylog: false,
        }
    }
}

impl<E: ServiceEndpoint<ProviderService>> Builder<E> {
    /// Set the rpc endpoint.
    pub fn rpc_endpoint<E2: ServiceEndpoint<ProviderService>>(self, value: E2) -> Builder<E2> {
        Builder {
            bind_addr: self.bind_addr,
            keypair: self.keypair,
            auth_token: self.auth_token,
            db: self.db,
            keylog: self.keylog,
            rpc_endpoint: value,
        }
    }

    /// Binds the provider service to a different socket.
    ///
    /// By default it binds to `127.0.0.1:4433`.
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Uses the given [`Keypair`] for the [`PeerId`] instead of a newly generated one.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }

    /// Uses the given [`AuthToken`] instead of a newly generated one.
    pub fn auth_token(mut self, auth_token: AuthToken) -> Self {
        self.auth_token = auth_token;
        self
    }

    /// Whether to log the SSL pre-master key.
    ///
    /// If `true` and the `SSLKEYLOGFILE` environment variable is the path to a file this
    /// file will be used to log the SSL pre-master key.  This is useful to inspect captured
    /// traffic.
    pub fn keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Spawns the [`Provider`] in a tokio task.
    ///
    /// This will create the underlying network server and spawn a tokio task accepting
    /// connections.  The returned [`Provider`] can be used to control the task as well as
    /// get information about it.
    pub fn spawn(self) -> Result<Provider> {
        let tls_server_config = tls::make_server_config(
            &self.keypair,
            vec![crate::tls::P2P_ALPN.to_vec()],
            self.keylog,
        )?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(MAX_STREAMS.try_into()?)
            .max_concurrent_uni_streams(0u32.into());

        server_config
            .transport_config(Arc::new(transport_config))
            .concurrent_connections(MAX_CONNECTIONS);

        let endpoint = quinn::Endpoint::server(server_config, self.bind_addr)?;
        let listen_addr = endpoint.local_addr().unwrap();
        let (events_sender, _events_receiver) = broadcast::channel(8);
        let events = events_sender.clone();
        let cancel_token = CancellationToken::new();
        tracing::debug!("rpc listening on: {:?}", self.rpc_endpoint.local_addr());
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection(1);
        let inner = Arc::new(ProviderInner {
            db: self.db,
            listen_addr,
            keypair: self.keypair,
            auth_token: self.auth_token,
            events,
            controller,
            cancel_token,
        });
        let task = {
            let handler = RpcHandler {
                inner: inner.clone(),
            };
            tokio::spawn(async move {
                Self::run(
                    endpoint,
                    events_sender,
                    handler,
                    self.rpc_endpoint,
                    internal_rpc,
                )
                .await
            })
        };
        let provider = Provider {
            inner,
            task: task.map_err(Arc::new).boxed().shared(),
        };

        Ok(provider)
    }

    async fn run(
        server: quinn::Endpoint,
        events: broadcast::Sender<Event>,
        handler: RpcHandler,
        rpc: E,
        internal_rpc: impl ServiceEndpoint<ProviderService>,
    ) {
        let rpc = RpcServer::new(rpc);
        let internal_rpc = RpcServer::new(internal_rpc);
        if let Ok(addr) = server.local_addr() {
            debug!("listening at: {addr}");
        }
        let cancel_token = handler.inner.cancel_token.clone();
        loop {
            tokio::select! {
                biased;
                _ = cancel_token.cancelled() => break,
                // handle rpc requests. This will do nothing if rpc is not configured, since
                // accept is just a pending future.
                request = rpc.accept() => {
                    match request {
                        Ok((msg, chan)) => {
                            handle_rpc_request(msg, chan, &handler);
                        }
                        Err(e) => {
                            tracing::info!("rpc request error: {:?}", e);
                        }
                    }
                },
                // handle internal rpc requests.
                request = internal_rpc.accept() => {
                    match request {
                        Ok((msg, chan)) => {
                            handle_rpc_request(msg, chan, &handler);
                        }
                        Err(_) => {
                            tracing::info!("last controller dropped, shutting down");
                            break;
                        }
                    }
                },
                // handle incoming p2p connections
                Some(connecting) = server.accept() => {
                    let db = handler.inner.db.clone();
                    let events = events.clone();
                    let auth_token = handler.inner.auth_token;
                    tokio::spawn(handle_connection(connecting, db, auth_token, events));
                }
                else => break,
            }
        }

        // Closing the Endpoint is the equivalent of calling Connection::close on all
        // connections: Operations will immediately fail with
        // ConnectionError::LocallyClosed.  All streams are interrupted, this is not
        // graceful.
        let error_code = Closed::ProviderTerminating;
        server.close(error_code.into(), error_code.reason());
    }
}

/// A server which implements the iroh provider.
///
/// Clients can connect to this server and requests hashes from it.
///
/// The only way to create this is by using the [`Builder::spawn`].  [`Provider::builder`]
/// is a shorthand to create a suitable [`Builder`].
///
/// This runs a tokio task which can be aborted and joined if desired.  To join the task
/// await the [`Provider`] struct directly, it will complete when the task completes.  If
/// this is dropped the provider task is not stopped but keeps running.
#[derive(Debug, Clone)]
pub struct Provider {
    inner: Arc<ProviderInner>,
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
}

#[derive(Debug)]
struct ProviderInner {
    db: Database,
    listen_addr: SocketAddr,
    keypair: Keypair,
    auth_token: AuthToken,
    events: broadcast::Sender<Event>,
    cancel_token: CancellationToken,
    controller: FlumeConnection<ProviderResponse, ProviderRequest>,
}

/// Events emitted by the [`Provider`] informing about the current status.
#[derive(Debug, Clone)]
pub enum Event {
    /// A new client connected to the provider.
    ClientConnected {
        /// An unique connection id.
        connection_id: u64,
    },
    /// A request was received from a client.
    RequestReceived {
        /// An unique connection id.
        connection_id: u64,
        /// An identifier uniquely identifying this transfer request.
        request_id: u64,
        /// The hash for which the client wants to receive data.
        hash: Hash,
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

impl Provider {
    /// Returns a new builder for the [`Provider`].
    ///
    /// Once the done with the builder call [`Builder::spawn`] to create the provider.
    pub fn builder(db: Database) -> Builder {
        Builder::with_db(db)
    }

    /// The address on which the provider socket is bound.
    ///
    /// Note that this could be an unspecified address, if you need an address on which you
    /// can contact the provider consider using [`Provider::listen_addresses`].  However the
    /// port will always be the concrete port.
    pub fn local_address(&self) -> SocketAddr {
        self.inner.listen_addr
    }

    /// Returns all addresses on which the provider is reachable.
    ///
    /// This will never be empty.
    pub fn listen_addresses(&self) -> Result<Vec<SocketAddr>> {
        find_local_addresses(self.inner.listen_addr)
    }

    /// Returns the [`PeerId`] of the provider.
    pub fn peer_id(&self) -> PeerId {
        self.inner.keypair.public().into()
    }

    /// Returns the [`AuthToken`] needed to connect to the provider.
    pub fn auth_token(&self) -> AuthToken {
        self.inner.auth_token
    }

    /// Subscribe to [`Event`]s emitted from the provider, informing about connections and
    /// progress.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    /// Returns a handle that can be used to do RPC calls to the provider internally.
    pub fn controller(
        &self,
    ) -> RpcClient<ProviderService, impl ServiceConnection<ProviderService>> {
        RpcClient::new(self.inner.controller.clone())
    }

    /// Return a single token containing everything needed to get a hash.
    ///
    /// See [`Ticket`] for more details of how it can be used.
    pub fn ticket(&self, hash: Hash) -> Result<Ticket> {
        // TODO: Verify that the hash exists in the db?
        let addrs = self.listen_addresses()?;
        Ticket::new(hash, self.peer_id(), addrs, self.inner.auth_token)
    }

    /// Aborts the provider.
    ///
    /// This does not gracefully terminate currently: all connections are closed and
    /// anything in-transit is lost.  The task will stop running and awaiting this
    /// [`Provider`] will complete.
    ///
    /// The shutdown behaviour will become more graceful in the future.
    pub fn shutdown(&self) {
        self.inner.cancel_token.cancel();
    }

    /// Returns a token that can be used to cancel the provider.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }
}

/// The future completes when the spawned tokio task finishes.
impl Future for Provider {
    type Output = Result<(), Arc<JoinError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

#[derive(Debug, Clone)]
struct RpcHandler {
    inner: Arc<ProviderInner>,
}

impl RpcHandler {
    fn list(self, _msg: ListRequest) -> impl Stream<Item = ListResponse> + Send + 'static {
        let items = self
            .inner
            .db
            .blobs()
            .map(|(hash, path, size)| ListResponse { hash, path, size });
        futures::stream::iter(items)
    }

    /// Invoke validate on the database and stream out the result
    fn validate(
        self,
        _msg: ValidateRequest,
    ) -> impl Stream<Item = ValidateProgress> + Send + 'static {
        let (tx, rx) = mpsc::channel(1);
        let tx2 = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = self.inner.db.validate(tx).await {
                tx2.send(ValidateProgress::Abort(e.into())).await.unwrap();
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    fn provide(self, msg: ProvideRequest) -> impl Stream<Item = ProvideProgress> {
        let (tx, rx) = mpsc::channel(1);
        let tx2 = tx.clone();
        tokio::task::spawn(async move {
            if let Err(e) = self.provide0(msg, tx).await {
                tx2.send(ProvideProgress::Abort(e.into())).await.unwrap();
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    async fn provide0(
        self,
        msg: ProvideRequest,
        progress: tokio::sync::mpsc::Sender<ProvideProgress>,
    ) -> anyhow::Result<()> {
        let root = msg.path;
        anyhow::ensure!(
            root.is_dir() || root.is_file(),
            "path must be either a Directory or a File"
        );
        let data_sources = if root.is_dir() {
            let files = futures::stream::iter(WalkDir::new(&root));
            let data_sources = files.map_err(anyhow::Error::from).try_filter_map(|entry| {
                let root = root.clone();
                async move {
                    if !entry.file_type().is_file() {
                        // Skip symlinks. Directories are handled by WalkDir.
                        return Ok(None);
                    }
                    let path = entry.into_path();
                    let name = canonicalize_path(path.strip_prefix(&root)?)?;
                    anyhow::Ok(Some(DataSource::NamedFile { name, path }))
                }
            });
            let data_sources: Vec<anyhow::Result<DataSource>> =
                data_sources.collect::<Vec<_>>().await;
            data_sources
                .into_iter()
                .collect::<anyhow::Result<Vec<_>>>()?
        } else {
            // A single file, use the file name as the name of the blob.
            vec![DataSource::NamedFile {
                name: canonicalize_path(root.file_name().context("path must be a file")?)?,
                path: root,
            }]
        };
        // create the collection
        // todo: provide feedback for progress
        let (db, _) = create_collection_inner(data_sources, Progress::new(progress)).await?;
        self.inner.db.union_with(db);

        Ok(())
    }
    async fn version(self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
    async fn id(self, _: IdRequest) -> IdResponse {
        IdResponse {
            peer_id: Box::new(self.inner.keypair.public().into()),
            auth_token: Box::new(self.inner.auth_token),
            listen_addr: Box::new(self.inner.listen_addr),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
    async fn addrs(self, _: AddrsRequest) -> AddrsResponse {
        AddrsResponse {
            addrs: find_local_addresses(self.inner.listen_addr).unwrap_or_default(),
        }
    }
    async fn shutdown(self, request: ShutdownRequest) {
        if request.force {
            tracing::info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            tracing::info!("graceful shutdown requested");
            self.inner.cancel_token.cancel();
        }
    }
    fn watch(self, _: WatchRequest) -> impl Stream<Item = WatchResponse> {
        futures::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                WatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }
}

fn handle_rpc_request<C: ServiceEndpoint<ProviderService>>(
    msg: ProviderRequest,
    chan: RpcChannel<ProviderService, C>,
    handler: &RpcHandler,
) {
    let handler = handler.clone();
    tokio::spawn(async move {
        use ProviderRequest::*;
        match msg {
            List(msg) => chan.server_streaming(msg, handler, RpcHandler::list).await,
            Provide(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::provide)
                    .await
            }
            Watch(msg) => chan.server_streaming(msg, handler, RpcHandler::watch).await,
            Version(msg) => chan.rpc(msg, handler, RpcHandler::version).await,
            Id(msg) => chan.rpc(msg, handler, RpcHandler::id).await,
            Addrs(msg) => chan.rpc(msg, handler, RpcHandler::addrs).await,
            Shutdown(msg) => chan.rpc(msg, handler, RpcHandler::shutdown).await,
            Validate(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::validate)
                    .await
            }
        }
    });
}

async fn handle_connection(
    connecting: quinn::Connecting,
    db: Database,
    auth_token: AuthToken,
    events: broadcast::Sender<Event>,
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
        while let Ok(stream) = connection.accept_bi().await {
            let span = debug_span!("stream", stream_id = %stream.0.id());
            events.send(Event::ClientConnected { connection_id }).ok();
            let db = db.clone();
            let events = events.clone();
            tokio::spawn(
                async move {
                    if let Err(err) =
                        handle_stream(db, auth_token, connection_id, stream, events).await
                    {
                        warn!("error: {err:#?}",);
                    }
                }
                .instrument(span),
            );
        }
    }
    .instrument(span)
    .await
}

/// Read and decode the handshake.
///
/// Will fail if there is an error while reading, there is a token mismatch, or no valid
/// handshake was received.
///
/// When successful, the reader is still useable after this function and the buffer will be
/// drained of any handshake data.
async fn read_handshake<R: AsyncRead + Unpin>(
    mut reader: R,
    buffer: &mut BytesMut,
    token: AuthToken,
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
    ensure!(handshake.token == token, "AuthToken mismatch");
    Ok(())
}

/// Read the request from the getter.
///
/// Will fail if there is an error while reading, if the reader
/// contains more data than the Request, or if no valid request is sent.
///
/// When successful, the buffer is empty after this function call.
async fn read_request(mut reader: quinn::RecvStream, buffer: &mut BytesMut) -> Result<Request> {
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
#[allow(clippy::too_many_arguments)]
async fn transfer_collection(
    // Database from which to fetch blobs.
    db: &Database,
    // Quinn stream.
    mut writer: quinn::SendStream,
    // Buffer used when writing to writer.
    buffer: &mut BytesMut,
    // The bao outboard encoded data.
    outboard: &Bytes,
    // The actual blob data.
    data: &Bytes,
    events: broadcast::Sender<Event>,
    connection_id: u64,
    request_id: u64,
) -> Result<SentStatus> {
    // We only respond to requests for collections, not individual blobs
    let mut extractor = SliceExtractor::new_outboard(
        std::io::Cursor::new(&data[..]),
        std::io::Cursor::new(&outboard[..]),
        0,
        data.len() as u64,
    );
    let encoded_size: usize = abao::encode::encoded_size(data.len() as u64)
        .try_into()
        .unwrap();
    let mut encoded = Vec::with_capacity(encoded_size);
    extractor.read_to_end(&mut encoded)?;

    let c: Collection = postcard::from_bytes(data)?;

    let _ = events.send(Event::TransferCollectionStarted {
        connection_id,
        request_id,
        num_blobs: c.blobs().len() as u64,
        total_blobs_size: c.total_blobs_size(),
    });

    // TODO: we should check if the blobs referenced in this container
    // actually exist in this provider before returning `FoundCollection`
    write_response(
        &mut writer,
        buffer,
        Res::FoundCollection {
            total_blobs_size: c.total_blobs_size(),
        },
    )
    .await?;

    writer.write_all(&encoded).await?;
    for (i, blob) in c.blobs().iter().enumerate() {
        debug!("writing blob {}/{}", i, c.blobs().len());
        tokio::task::yield_now().await;
        let (status, writer1, size) = send_blob(db.clone(), blob.hash, writer, buffer).await?;
        writer = writer1;
        if SentStatus::NotFound == status {
            writer.finish().await?;
            return Ok(status);
        }

        let _ = events.send(Event::TransferBlobCompleted {
            connection_id,
            request_id,
            hash: blob.hash,
            index: i as u64,
            size,
        });
    }

    writer.finish().await?;
    Ok(SentStatus::Sent)
}

fn notify_transfer_aborted(events: broadcast::Sender<Event>, connection_id: u64, request_id: u64) {
    let _ = events.send(Event::TransferAborted {
        connection_id,
        request_id,
    });
}

async fn handle_stream(
    db: Database,
    token: AuthToken,
    connection_id: u64,
    (mut writer, mut reader): (quinn::SendStream, quinn::RecvStream),
    events: broadcast::Sender<Event>,
) -> Result<()> {
    let mut out_buffer = BytesMut::with_capacity(1024);
    let mut in_buffer = BytesMut::with_capacity(1024);

    // The stream ID index is used to identify this request.  Requests only arrive in
    // bi-directional RecvStreams initiated by the client, so this uniquely identifies them.
    let request_id = reader.id().index();

    // 1. Read Handshake
    debug!("reading handshake");
    if let Err(e) = read_handshake(&mut reader, &mut in_buffer, token).await {
        notify_transfer_aborted(events, connection_id, request_id);
        return Err(e);
    }

    // 2. Decode the request.
    debug!("reading request");
    let request = match read_request(reader, &mut in_buffer).await {
        Ok(r) => r,
        Err(e) => {
            notify_transfer_aborted(events, connection_id, request_id);
            return Err(e);
        }
    };

    let hash = request.name;
    debug!("got request for ({hash})");
    let _ = events.send(Event::RequestReceived {
        connection_id,
        hash,
        request_id,
    });

    // 4. Attempt to find hash
    let (outboard, data) = match db.get(&hash) {
        // We only respond to requests for collections, not individual blobs
        Some(BlobOrCollection::Collection { outboard, data }) => (outboard, data),
        _ => {
            debug!("not found {}", hash);
            notify_transfer_aborted(events, connection_id, request_id);
            write_response(&mut writer, &mut out_buffer, Res::NotFound).await?;
            writer.finish().await?;

            return Ok(());
        }
    };

    // 5. Transfer data!
    match transfer_collection(
        &db,
        writer,
        &mut out_buffer,
        &outboard,
        &data,
        events.clone(),
        connection_id,
        request_id,
    )
    .await
    {
        Ok(SentStatus::Sent) => {
            let _ = events.send(Event::TransferCollectionCompleted {
                connection_id,
                request_id,
            });
        }
        Ok(SentStatus::NotFound) => {
            notify_transfer_aborted(events, connection_id, request_id);
        }
        Err(e) => {
            notify_transfer_aborted(events, connection_id, request_id);
            return Err(e);
        }
    }

    debug!("finished response");
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SentStatus {
    Sent,
    NotFound,
}

async fn send_blob<W: AsyncWrite + Unpin + Send + 'static>(
    db: Database,
    name: Hash,
    mut writer: W,
    buffer: &mut BytesMut,
) -> Result<(SentStatus, W, u64)> {
    match db.get(&name) {
        Some(BlobOrCollection::Blob(Data {
            outboard,
            path,
            size,
        })) => {
            write_response(&mut writer, buffer, Res::Found).await?;
            // need to thread the writer though the spawn_blocking, since
            // taking a reference does not work. spawn_blocking requires
            // 'static lifetime.
            writer = tokio::task::spawn_blocking(move || {
                let file_reader = std::fs::File::open(&path)?;
                let outboard_reader = std::io::Cursor::new(outboard);
                let mut wrapper = SyncIoBridge::new(&mut writer);
                let mut slice_extractor = abao::encode::SliceExtractor::new_outboard(
                    file_reader,
                    outboard_reader,
                    0,
                    size,
                );
                let _copied = std::io::copy(&mut slice_extractor, &mut wrapper)?;
                std::io::Result::Ok(writer)
            })
            .await??;

            Ok((SentStatus::Sent, writer, size))
        }
        _ => {
            write_response(&mut writer, buffer, Res::NotFound).await?;
            Ok((SentStatus::NotFound, writer, 0))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Data {
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
pub enum DataSource {
    /// A blob of data originating from the filesystem. The name of the blob is derived from
    /// the filename.
    File(PathBuf),
    /// NamedFile is treated the same as [`DataSource::File`], except you can pass in a custom
    /// name. Passing in the empty string will explicitly _not_ persist the filename.
    NamedFile {
        /// Custom name
        name: String,
        /// Path to the file
        path: PathBuf,
    },
}

impl DataSource {
    /// Creates a new [`DataSource`] from a [`PathBuf`].
    pub fn new(path: PathBuf) -> Self {
        DataSource::File(path)
    }
    /// Creates a new [`DataSource`] from a [`PathBuf`] and a custom name.
    pub fn with_name(path: PathBuf, name: String) -> Self {
        DataSource::NamedFile { path, name }
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

/// Synchronously compute the outboard of a file, and return hash and outboard.
///
/// It is assumed that the file is not modified while this is running.
///
/// If it is modified while or after this is running, the outboard will be
/// invalid, so any attempt to compute a slice from it will fail.
///
/// If the size of the file is changed while this is running, an error will be
/// returned.
fn compute_outboard(
    path: PathBuf,
    size: u64,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> anyhow::Result<(Hash, Vec<u8>)> {
    ensure!(
        path.is_file(),
        "can only transfer blob data: {}",
        path.display()
    );
    tracing::debug!("computing outboard for {}", path.display());
    let file = std::fs::File::open(&path)?;
    // compute outboard size so we can pre-allocate the buffer.
    //
    // outboard is ~1/16 of data size, so this will fail for really large files
    // on really small devices. E.g. you want to transfer a 1TB file from a pi4 with 1gb ram.
    //
    // The way to solve this would be to have larger blocks than the blake3 chunk size of 1024.
    // I think we really want to keep the outboard in memory for simplicity.
    let outboard_size = usize::try_from(abao::encode::outboard_size(size))
        .context("outboard too large to fit in memory")?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // copy the file into the encoder. Data will be skipped by the encoder in outboard mode.
    let outboard_cursor = std::io::Cursor::new(&mut outboard);
    let mut encoder = abao::encode::Encoder::new_outboard(outboard_cursor);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader::new(file, |p| {
        if let ProgressReaderUpdate::Progress(offset) = p {
            progress(offset);
        }
    });

    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);
    // the length we have actually written, should be the same as the length of the file.
    let size2 = std::io::copy(&mut reader, &mut encoder)?;
    // this can fail if the file was appended to during encoding.
    ensure!(size == size2, "file changed during encoding");
    // this flips the outboard encoding from post-order to pre-order
    let hash = encoder.finalize()?;
    tracing::debug!("done. hash for {} is {hash}", path.display());

    Ok((hash.into(), outboard))
}

/// Creates a database of blobs (stored in outboard storage) and Collections, stored in memory.
/// Returns a the hash of the collection created by the given list of DataSources
pub async fn create_collection(data_sources: Vec<DataSource>) -> Result<(Database, Hash)> {
    let (db, hash) = create_collection_inner(data_sources, Progress::none()).await?;
    Ok((Database::from(db), hash))
}

/// The actual implementation of create_collection, except for the wrapping into arc and mutex to make
/// a public Database.
async fn create_collection_inner(
    mut data_sources: Vec<DataSource>,
    progress: Progress<ProvideProgress>,
) -> Result<(HashMap<Hash, BlobOrCollection>, Hash)> {
    // +1 is for the collection itself
    let mut db = HashMap::with_capacity(data_sources.len() + 1);
    let mut blobs = Vec::with_capacity(data_sources.len());
    let mut total_blobs_size: u64 = 0;

    data_sources.sort();

    let outboard_progress = progress.clone();
    // compute outboards in parallel, using tokio's blocking thread pool
    let outboards = stream::iter(data_sources)
        .enumerate()
        .map(|(id, data)| {
            let id = id as u64;
            let (path, name) = match data {
                DataSource::File(path) => (path, None),
                DataSource::NamedFile { path, name } => (path, Some(name)),
            };
            let size = path.metadata().unwrap().len();
            let find_progress = outboard_progress.clone();
            let outboard_progress = outboard_progress.clone();
            let done_progress = outboard_progress.clone();
            async move {
                // found events must be sent
                let pname = name.clone().unwrap_or_else(|| path.display().to_string());
                find_progress
                    .send(ProvideProgress::Found {
                        name: pname,
                        id,
                        size,
                    })
                    .await?;
                let rpath = path.clone();
                let (hash, outboard) = tokio::task::spawn_blocking(move || {
                    compute_outboard(path, size, move |offset| {
                        outboard_progress.try_send(ProvideProgress::Progress { id, offset })
                    })
                })
                .await??;
                // done events must be sent
                done_progress
                    .send(ProvideProgress::Done { id, hash })
                    .await?;
                anyhow::Ok((rpath, name, hash, outboard))
            }
        })
        // allow at most num_cpus tasks at a time, otherwise we might get too many open files
        // todo: this assumes that this is 100% cpu bound, which is likely not true.
        // we might get better performance by using a larger number here.
        .buffer_unordered(num_cpus::get());
    // wait for completion and collect results
    // weird massaging of the output to get rid of the results
    let mut outboards = outboards
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    outboards.sort();

    // insert outboards into the database and build collection
    for (path, name, hash, outboard) in outboards {
        debug_assert!(outboard.len() >= 8, "outboard must at least contain size");
        let size = u64::from_le_bytes(outboard[..8].try_into().unwrap());
        db.insert(
            hash,
            BlobOrCollection::Blob(Data {
                outboard: Bytes::from(outboard),
                path: path.clone(),
                size,
            }),
        );
        total_blobs_size += size;
        // if the given name is `None`, use the filename from the given path as the name
        let name = name.unwrap_or_else(|| {
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string()
        });
        blobs.push(Blob { name, hash });
    }

    let c = Collection::new(blobs, total_blobs_size)?;

    let data = postcard::to_stdvec(&c).context("blob encoding")?;
    let (outboard, hash) = abao::encode::outboard(&data);
    let hash = Hash::from(hash);
    db.insert(
        hash,
        BlobOrCollection::Collection {
            outboard: Bytes::from(outboard),
            data: Bytes::from(data.to_vec()),
        },
    );
    progress.send(ProvideProgress::AllDone { hash }).await?;

    Ok((db, hash))
}

async fn write_response<W: AsyncWrite + Unpin>(
    mut writer: W,
    buffer: &mut BytesMut,
    res: Res,
) -> Result<()> {
    let response = Response { data: res };

    // TODO: do not transfer blob data as part of the responses
    if buffer.len() < Response::POSTCARD_MAX_SIZE {
        buffer.resize(Response::POSTCARD_MAX_SIZE, 0u8);
    }
    let used = postcard::to_slice(&response, buffer)?;

    write_lp(&mut writer, used).await?;

    debug!("written response of length {}", used.len());
    Ok(())
}

/// Create a [`quinn::ServerConfig`] with the given keypair and limits.
pub fn make_server_config(
    keypair: &Keypair,
    max_streams: u64,
    max_connections: u32,
    alpn_protocols: Vec<Vec<u8>>,
) -> anyhow::Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(keypair, alpn_protocols, false)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_concurrent_bidi_streams(max_streams.try_into()?)
        .max_concurrent_uni_streams(0u32.into());

    server_config
        .transport_config(Arc::new(transport_config))
        .concurrent_connections(max_connections);
    Ok(server_config)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::net::Ipv4Addr;
    use std::path::Path;
    use std::str::FromStr;
    use testdir::testdir;

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
                let (outboard, hash) = abao::encode::outboard(&blob);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                let path = PathBuf::from_str(&hash.to_string()).unwrap();
                cblobs.push(Blob {
                    name: hash.to_string(),
                    hash,
                });
                map.insert(
                    hash,
                    BlobOrCollection::Blob(Data {
                        outboard,
                        size,
                        path,
                    }),
                );
            }
            let collection = Collection::new(cblobs, total_blobs_size).unwrap();
            // encode collection and add it
            {
                let data = Bytes::from(postcard::to_stdvec(&collection).unwrap());
                let (outboard, hash) = abao::encode::outboard(&data);
                let outboard = Bytes::from(outboard);
                let hash = Hash::from(hash);
                map.insert(hash, BlobOrCollection::Collection { outboard, data });
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
        let (_, hash) = abao::encode::outboard(vec![]);
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
            if let BlobOrCollection::Collection { data, .. } = c {
                Collection::from_bytes(&data)?
            } else {
                panic!("expected hash to correspond with a `Collection`, found `Blob` instead");
            }
        };

        assert_eq!(expect_collection, collection);

        Ok(())
    }

    #[tokio::test]
    async fn test_ticket_multiple_addrs() {
        let readme = Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md");
        let (db, hash) = create_collection(vec![readme.into()]).await.unwrap();
        let provider = Provider::builder(db)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .spawn()
            .unwrap();
        let _drop_guard = provider.cancel_token().drop_guard();
        let ticket = provider.ticket(hash).unwrap();
        println!("addrs: {:?}", ticket.addrs());
        assert!(!ticket.addrs().is_empty());
    }
}
