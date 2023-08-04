//! Node API
//!
//! A node is a server that serves various protocols.
//!
//! You can monitor what is happening in the node using [`Node::subscribe`].
//!
//! To shut down the node, call [`Node::shutdown`].
use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use crate::dial::Ticket;
use crate::rpc_protocol::{
    AddrsRequest, AddrsResponse, IdRequest, IdResponse, ListBlobsRequest, ListBlobsResponse,
    ListCollectionsRequest, ListCollectionsResponse, ListIncompleteBlobsRequest,
    ListIncompleteBlobsResponse, ProvideRequest, ProviderRequest, ProviderResponse,
    ProviderService, ShareRequest, ShutdownRequest, ValidateRequest, VersionRequest,
    VersionResponse, WatchRequest, WatchResponse,
};
use crate::util::progress::ProgressSliceWriter2;
use anyhow::{Context, Result};
use bao_tree::io::fsm::OutboardMut;
use bao_tree::{ByteNum, ChunkNum};
use bytes::Bytes;
use futures::future::{BoxFuture, Shared};
use futures::{FutureExt, Stream, StreamExt, TryFutureExt};
use iroh_bytes::collection::{CollectionParser, NoCollectionParser};
use iroh_bytes::get::fsm::{AtBlobHeader, AtEndBlob, ConnectedNext, EndBlobNext};
use iroh_bytes::get::{self, Stats};
use iroh_bytes::protocol::{GetRequest, RangeSpecSeq};
use iroh_bytes::provider::{BaoDb, BaoPartialMapEntry, ShareProgress};
use iroh_bytes::util::progress::{IdGenerator, ProgressSender, TokioProgressSender};
use iroh_bytes::{
    protocol::{Closed, Request, RequestToken},
    provider::{
        BaoMap, BaoMapEntry, BaoReadonlyDb, CustomGetHandler, ProvideProgress,
        RequestAuthorizationHandler, ValidateProgress,
    },
    util::runtime,
    util::Hash,
};
use iroh_io::AsyncSliceReader;
use iroh_net::{
    config::Endpoint,
    derp::DerpMap,
    tls::{self, Keypair, PeerId},
    MagicEndpoint,
};
use quic_rpc::server::RpcChannel;
use quic_rpc::transport::flume::FlumeConnection;
use quic_rpc::transport::misc::DummyServerEndpoint;
use quic_rpc::{RpcClient, RpcServer, ServiceConnection, ServiceEndpoint};
use range_collections::range_set::RangeSetRange;
use range_collections::RangeSet2;
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinError;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace};

const MAX_CONNECTIONS: u32 = 1024;
const MAX_STREAMS: u64 = 10;
const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 11204);

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Builder for the [`Node`].
///
/// You must supply a database. Various database implementations are available
/// in [`crate::database`]. Everything else is optional.
///
/// Finally you can create and run the node by calling [`Builder::spawn`].
///
/// The returned [`Node`] is awaitable to know when it finishes.  It can be terminated
/// using [`Node::shutdown`].
#[derive(Debug)]
pub struct Builder<D, E = DummyServerEndpoint, C = NoCollectionParser>
where
    D: BaoMap,
    E: ServiceEndpoint<ProviderService>,
    C: CollectionParser,
{
    bind_addr: SocketAddr,
    keypair: Keypair,
    rpc_endpoint: E,
    db: D,
    keylog: bool,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    auth_handler: Arc<dyn RequestAuthorizationHandler>,
    derp_map: Option<DerpMap>,
    collection_parser: C,
    rt: Option<runtime::Handle>,
}

const PROTOCOLS: [&[u8]; 1] = [&iroh_bytes::protocol::ALPN];

/// A noop authorization handler that does not do any authorization.
///
/// This is the default. It does not have to be pub, since it is going to be
/// boxed.
#[derive(Debug)]
struct NoopRequestAuthorizationHandler;

impl RequestAuthorizationHandler for NoopRequestAuthorizationHandler {
    fn authorize(
        &self,
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

#[derive(Debug)]
struct NoopCustomGetHandler;

impl CustomGetHandler for NoopCustomGetHandler {
    fn handle(
        &self,
        _token: Option<RequestToken>,
        _request: Bytes,
    ) -> BoxFuture<'static, anyhow::Result<GetRequest>> {
        async move { Err(anyhow::anyhow!("no custom get handler defined")) }.boxed()
    }
}

impl<D: BaoMap> Builder<D> {
    /// Creates a new builder for [`Node`] using the given database.
    fn with_db(db: D) -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.into(),
            keypair: Keypair::generate(),
            db,
            keylog: false,
            derp_map: None,
            rpc_endpoint: Default::default(),
            custom_get_handler: Arc::new(NoopCustomGetHandler),
            auth_handler: Arc::new(NoopRequestAuthorizationHandler),
            collection_parser: NoCollectionParser,
            rt: None,
        }
    }
}

impl<D, E, C> Builder<D, E, C>
where
    D: BaoDb,
    E: ServiceEndpoint<ProviderService>,
    C: CollectionParser,
{
    /// Configure rpc endpoint, changing the type of the builder to the new endpoint type.
    pub fn rpc_endpoint<E2: ServiceEndpoint<ProviderService>>(
        self,
        value: E2,
    ) -> Builder<D, E2, C> {
        // we can't use ..self here because the return type is different
        Builder {
            bind_addr: self.bind_addr,
            keypair: self.keypair,
            db: self.db,
            keylog: self.keylog,
            custom_get_handler: self.custom_get_handler,
            auth_handler: self.auth_handler,
            rpc_endpoint: value,
            derp_map: self.derp_map,
            collection_parser: self.collection_parser,
            rt: self.rt,
        }
    }

    /// Configure the collection parser, changing the type of the builder to the new collection parser type.
    pub fn collection_parser<C2: CollectionParser>(
        self,
        collection_parser: C2,
    ) -> Builder<D, E, C2> {
        // we can't use ..self here because the return type is different
        Builder {
            collection_parser,
            bind_addr: self.bind_addr,
            keypair: self.keypair,
            db: self.db,
            keylog: self.keylog,
            custom_get_handler: self.custom_get_handler,
            auth_handler: self.auth_handler,
            rpc_endpoint: self.rpc_endpoint,
            derp_map: self.derp_map,
            rt: self.rt,
        }
    }

    /// Sets the `[DerpMap]`
    pub fn derp_map(mut self, dm: DerpMap) -> Self {
        self.derp_map = Some(dm);
        self
    }

    /// Configure the custom get handler.
    pub fn custom_get_handler(self, custom_get_handler: Arc<dyn CustomGetHandler>) -> Self {
        Self {
            custom_get_handler,
            ..self
        }
    }

    /// Configures a custom authorization handler.
    pub fn custom_auth_handler(self, auth_handler: Arc<dyn RequestAuthorizationHandler>) -> Self {
        Self {
            auth_handler,
            ..self
        }
    }

    /// Binds the node service to a different socket.
    ///
    /// By default it binds to `127.0.0.1:11204`.
    pub fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Uses the given [`Keypair`] for the [`PeerId`] instead of a newly generated one.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
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

    /// Sets the tokio runtime to use.
    ///
    /// If not set, the current runtime will be picked up.
    pub fn runtime(mut self, rt: &runtime::Handle) -> Self {
        self.rt = Some(rt.clone());
        self
    }

    /// Spawns the [`Node`] in a tokio task.
    ///
    /// This will create the underlying network server and spawn a tokio task accepting
    /// connections.  The returned [`Node`] can be used to control the task as well as
    /// get information about it.
    pub async fn spawn(self) -> Result<Node<D>> {
        trace!("spawning node");
        let rt = self.rt.context("runtime not set")?;

        let (endpoints_update_s, endpoints_update_r) = flume::bounded(1);
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(MAX_STREAMS.try_into()?)
            .max_concurrent_uni_streams(0u32.into());

        let endpoint = MagicEndpoint::builder()
            .keypair(self.keypair.clone())
            .alpns(PROTOCOLS.iter().map(|p| p.to_vec()).collect())
            .keylog(self.keylog)
            .derp_map(self.derp_map)
            .transport_config(transport_config)
            .concurrent_connections(MAX_CONNECTIONS)
            .on_endpoints(Box::new(move |eps| {
                if !endpoints_update_s.is_disconnected() && !eps.is_empty() {
                    endpoints_update_s.send(()).ok();
                }
            }))
            .bind(self.bind_addr.port())
            .await?;
        trace!("created quinn endpoint");

        let (cb_sender, cb_receiver) = mpsc::channel(8);
        let cancel_token = CancellationToken::new();

        debug!("rpc listening on: {:?}", self.rpc_endpoint.local_addr());
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection(1);
        let rt2 = rt.clone();
        let rt3 = rt.clone();
        let callbacks = Callbacks::default();
        let inner = Arc::new(NodeInner {
            db: self.db,
            endpoint: endpoint.clone(),
            keypair: self.keypair,
            controller,
            cancel_token,
            callbacks: callbacks.clone(),
            cb_sender,
            rt,
        });
        let task = {
            let handler = RpcHandler {
                inner: inner.clone(),
                collection_parser: self.collection_parser.clone(),
            };
            rt2.main().spawn(async move {
                Self::run(
                    endpoint,
                    callbacks,
                    cb_receiver,
                    handler,
                    self.rpc_endpoint,
                    internal_rpc,
                    self.custom_get_handler,
                    self.auth_handler,
                    self.collection_parser,
                    rt3,
                )
                .await
            })
        };
        let node = Node {
            inner,
            task: task.map_err(Arc::new).boxed().shared(),
        };

        // Wait for a single endpoint update, to make sure
        // we found some endpoints
        tokio::time::timeout(ENDPOINT_WAIT, async move {
            endpoints_update_r.recv_async().await
        })
        .await
        .context("waiting for endpoint")??;

        Ok(node)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        server: MagicEndpoint,
        callbacks: Callbacks,
        mut cb_receiver: mpsc::Receiver<EventCallback>,
        handler: RpcHandler<D, C>,
        rpc: E,
        internal_rpc: impl ServiceEndpoint<ProviderService>,
        custom_get_handler: Arc<dyn CustomGetHandler>,
        auth_handler: Arc<dyn RequestAuthorizationHandler>,
        collection_parser: C,
        rt: runtime::Handle,
    ) {
        let rpc = RpcServer::new(rpc);
        let internal_rpc = RpcServer::new(internal_rpc);
        if let Ok((ipv4, ipv6)) = server.local_addr() {
            debug!(
                "listening at: {}{}",
                ipv4,
                ipv6.map(|addr| format!(" and {addr}")).unwrap_or_default()
            );
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
                            handle_rpc_request(msg, chan, &handler, &rt);
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
                            handle_rpc_request(msg, chan, &handler, &rt);
                        }
                        Err(_) => {
                            tracing::info!("last controller dropped, shutting down");
                            break;
                        }
                    }
                },
                // handle incoming p2p connections
                Some(mut connecting) = server.accept() => {

                    let alpn = match get_alpn(&mut connecting).await {
                        Ok(alpn) => alpn,
                        Err(err) => {
                            tracing::error!("invalid handshake: {:?}", err);
                            continue;
                        }
                    };
                    if alpn.as_bytes() == iroh_bytes::protocol::ALPN.as_ref() {
                        let db = handler.inner.db.clone();
                        let custom_get_handler = custom_get_handler.clone();
                        let auth_handler = auth_handler.clone();
                        let collection_parser = collection_parser.clone();
                        let rt2 = rt.clone();
                        let callbacks = callbacks.clone();
                        rt.main().spawn(iroh_bytes::provider::handle_connection(connecting, db, callbacks, collection_parser, custom_get_handler, auth_handler, rt2));
                    } else {
                        tracing::error!("unknown protocol: {}", alpn);
                        continue;
                    }
                }
                // Handle new callbacks
                Some(cb) = cb_receiver.recv() => {
                    callbacks.push(cb).await;
                }
                else => break,
            }
        }

        // Closing the Endpoint is the equivalent of calling Connection::close on all
        // connections: Operations will immediately fail with
        // ConnectionError::LocallyClosed.  All streams are interrupted, this is not
        // graceful.
        let error_code = Closed::ProviderTerminating;
        server
            .close(error_code.into(), error_code.reason())
            .await
            .ok();
    }
}

async fn get_alpn(connecting: &mut quinn::Connecting) -> Result<String> {
    let data = connecting.handshake_data().await?;
    match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
        Ok(data) => match data.protocol {
            Some(protocol) => std::string::String::from_utf8(protocol).map_err(Into::into),
            None => anyhow::bail!("no ALPN protocol available"),
        },
        Err(_) => anyhow::bail!("unknown handshake type"),
    }
}

type EventCallback = Box<dyn Fn(Event) -> BoxFuture<'static, ()> + 'static + Sync + Send>;

#[derive(Default, derive_more::Debug, Clone)]
struct Callbacks(#[debug("..")] Arc<RwLock<Vec<EventCallback>>>);

impl Callbacks {
    async fn push(&self, cb: EventCallback) {
        self.0.write().await.push(cb);
    }

    #[allow(dead_code)]
    async fn send(&self, event: Event) {
        let cbs = self.0.read().await;
        for cb in &*cbs {
            cb(event.clone()).await;
        }
    }
}

impl iroh_bytes::provider::EventSender for Callbacks {
    fn send(&self, event: iroh_bytes::provider::Event) -> BoxFuture<()> {
        async move {
            let cbs = self.0.read().await;
            for cb in &*cbs {
                cb(Event::ByteProvide(event.clone())).await;
            }
        }
        .boxed()
    }
}

/// A server which implements the iroh node.
///
/// Clients can connect to this server and requests hashes from it.
///
/// The only way to create this is by using the [`Builder::spawn`].  [`Node::builder`]
/// is a shorthand to create a suitable [`Builder`].
///
/// This runs a tokio task which can be aborted and joined if desired.  To join the task
/// await the [`Node`] struct directly, it will complete when the task completes.  If
/// this is dropped the node task is not stopped but keeps running.
#[derive(Debug, Clone)]
pub struct Node<D: BaoMap> {
    inner: Arc<NodeInner<D>>,
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
}

#[derive(derive_more::Debug)]
struct NodeInner<D> {
    db: D,
    endpoint: MagicEndpoint,
    keypair: Keypair,
    cancel_token: CancellationToken,
    controller: FlumeConnection<ProviderResponse, ProviderRequest>,
    #[debug("callbacks: Sender<Box<dyn Fn(Event)>>")]
    cb_sender: mpsc::Sender<Box<dyn Fn(Event) -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    #[allow(dead_code)]
    callbacks: Callbacks,
    rt: runtime::Handle,
}

/// Events emitted by the [`Node`] informing about the current status.
#[derive(Debug, Clone)]
pub enum Event {
    /// Events from the iroh-bytes transfer protocol.
    ByteProvide(iroh_bytes::provider::Event),
}

impl<D: BaoReadonlyDb> Node<D> {
    /// Returns a new builder for the [`Node`].
    ///
    /// Once the done with the builder call [`Builder::spawn`] to create the node.
    pub fn builder(db: D) -> Builder<D> {
        Builder::with_db(db)
    }

    /// The address on which the node socket is bound.
    ///
    /// Note that this could be an unspecified address, if you need an address on which you
    /// can contact the node consider using [`Node::local_endpoint_addresses`].  However the
    /// port will always be the concrete port.
    pub fn local_address(&self) -> Result<Vec<SocketAddr>> {
        self.inner.local_address()
    }

    /// Lists the local endpoint of this node.
    pub async fn local_endpoints(&self) -> Result<Vec<Endpoint>> {
        self.inner.local_endpoints().await
    }

    /// Convenience method to get just the addr part of [`Node::local_endpoints`].
    pub async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        self.inner.local_endpoint_addresses().await
    }

    /// Returns the [`PeerId`] of the node.
    pub fn peer_id(&self) -> PeerId {
        self.inner.keypair.public().into()
    }

    /// Subscribe to [`Event`]s emitted from the node, informing about connections and
    /// progress.
    ///
    /// Warning: The callback must complete quickly, as otherwise it will block ongoing work.
    pub async fn subscribe<F: Fn(Event) -> BoxFuture<'static, ()> + Send + Sync + 'static>(
        &self,
        cb: F,
    ) -> Result<()> {
        self.inner.cb_sender.send(Box::new(cb)).await?;
        Ok(())
    }

    /// Returns a handle that can be used to do RPC calls to the node internally.
    pub fn controller(
        &self,
    ) -> RpcClient<ProviderService, impl ServiceConnection<ProviderService>> {
        RpcClient::new(self.inner.controller.clone())
    }

    /// Return a single token containing everything needed to get a hash.
    ///
    /// See [`Ticket`] for more details of how it can be used.
    pub async fn ticket(&self, hash: Hash) -> Result<Ticket> {
        // TODO: Verify that the hash exists in the db?
        let addrs = self.local_endpoint_addresses().await?;
        let region = self.inner.endpoint.my_derp().await;
        Ticket::new(hash, self.peer_id(), addrs, None, true, region)
    }

    /// Return the DERP region that this provider is connected to
    pub async fn my_derp(&self) -> Option<u16> {
        self.inner.endpoint.my_derp().await
    }

    /// Aborts the node.
    ///
    /// This does not gracefully terminate currently: all connections are closed and
    /// anything in-transit is lost.  The task will stop running and awaiting this
    /// [`Node`] will complete.
    ///
    /// The shutdown behaviour will become more graceful in the future.
    pub fn shutdown(&self) {
        self.inner.cancel_token.cancel();
    }

    /// Returns a token that can be used to cancel the node.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }
}

impl<D: BaoMap> NodeInner<D> {
    async fn local_endpoints(&self) -> Result<Vec<Endpoint>> {
        self.endpoint.local_endpoints().await
    }

    async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        let endpoints = self.local_endpoints().await?;
        Ok(endpoints.into_iter().map(|x| x.addr).collect())
    }

    fn local_address(&self) -> Result<Vec<SocketAddr>> {
        let (v4, v6) = self.endpoint.local_addr()?;
        let mut addrs = vec![v4];
        if let Some(v6) = v6 {
            addrs.push(v6);
        }
        Ok(addrs)
    }
}

/// The future completes when the spawned tokio task finishes.
impl<D: BaoMap> Future for Node<D> {
    type Output = Result<(), Arc<JoinError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

#[derive(Debug, Clone)]
struct RpcHandler<D, C> {
    inner: Arc<NodeInner<D>>,
    collection_parser: C,
}

impl<D: BaoDb, C: CollectionParser> RpcHandler<D, C> {
    fn rt(&self) -> runtime::Handle {
        self.inner.rt.clone()
    }

    fn list_blobs(
        self,
        _msg: ListBlobsRequest,
    ) -> impl Stream<Item = ListBlobsResponse> + Send + 'static {
        use bao_tree::io::fsm::Outboard;

        let db = self.inner.db.clone();
        futures::stream::iter(db.blobs()).filter_map(move |hash| {
            let db = db.clone();
            async move {
                let entry = db.get(&hash)?;
                let hash = entry.hash().into();
                let size = entry.outboard().await.ok()?.tree().size().0;
                let path = "".to_owned();
                Some(ListBlobsResponse { hash, size, path })
            }
        })
    }

    fn list_incomplete_blobs(
        self,
        _msg: ListIncompleteBlobsRequest,
    ) -> impl Stream<Item = ListIncompleteBlobsResponse> + Send + 'static {
        let db = self.inner.db.clone();
        let local = self.inner.rt.local_pool().clone();
        futures::stream::iter(db.partial_blobs()).filter_map(move |hash| {
            let db = db.clone();
            let t = local.spawn_pinned(move || async move {
                let Some(entry) = db.get_partial(&hash) else {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no partial entry found",
                    ));
                };
                io::Result::Ok(ListIncompleteBlobsResponse {
                    hash,
                    size: 0,
                    expected_size: entry.size(),
                    path: "".to_owned(),
                })
            });
            async move { t.await.ok()?.ok() }
        })
    }

    fn list_collections(
        self,
        _msg: ListCollectionsRequest,
    ) -> impl Stream<Item = ListCollectionsResponse> + Send + 'static {
        let db = self.inner.db.clone();
        let local = self.inner.rt.local_pool().clone();
        let roots = db.roots();
        futures::stream::iter(roots).filter_map(move |hash| {
            let db = db.clone();
            let local = local.clone();
            let cp = self.collection_parser.clone();
            async move {
                let entry = db.get(&hash)?;
                let stats = local
                    .spawn_pinned(|| async move {
                        let reader = entry.data_reader().await.ok()?;
                        let (_collection, stats) = cp.parse(0, reader).await.ok()?;
                        Some(stats)
                    })
                    .await
                    .ok()??;
                Some(ListCollectionsResponse {
                    hash,
                    total_blobs_count: stats.num_blobs,
                    total_blobs_size: stats.total_blob_size,
                })
            }
        })
    }

    /// Invoke validate on the database and stream out the result
    fn validate(
        self,
        _msg: ValidateRequest,
    ) -> impl Stream<Item = ValidateProgress> + Send + 'static {
        let (tx, rx) = mpsc::channel(1);
        let tx2 = tx.clone();
        let db = self.inner.db.clone();
        self.rt().main().spawn(async move {
            if let Err(e) = db.validate(tx).await {
                tx2.send(ValidateProgress::Abort(e.into())).await.unwrap();
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    fn provide(self, msg: ProvideRequest) -> impl Stream<Item = ProvideProgress> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = mpsc::channel(32);
        let tx2 = tx.clone();
        self.rt().local_pool().spawn_pinned(|| async move {
            if let Err(e) = self.provide0(msg, tx).await {
                tx2.send(ProvideProgress::Abort(e.into())).await.unwrap();
            }
        });
        tokio_stream::wrappers::ReceiverStream::new(rx)
    }

    async fn get(
        self,
        conn: quinn::Connection,
        hash: Hash,
        recursive: bool,
        sender: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<Stats> {
        let res = if recursive {
            self.get_collection(conn, &hash, sender).await
        } else {
            self.get_blob(conn, &hash, sender).await
        };
        if let Err(e) = res.as_ref() {
            tracing::error!("get failed: {}", e);
        }
        res
    }

    async fn export(
        self,
        out: String,
        hash: Hash,
        recursive: bool,
        stable: bool,
        progress: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<()> {
        let db = &self.inner.db;
        let path = PathBuf::from(&out);
        if recursive {
            #[cfg(feature = "iroh-collection")]
            {
                use crate::collection::{Blob, Collection};
                use crate::util::io::pathbuf_from_name;
                use iroh_io::AsyncSliceReaderExt;
                tracing::trace!("exporting collection {} to {}", hash, path.display());
                tokio::fs::create_dir_all(&path).await?;
                let collection = db.get(&hash).context("collection not there")?;
                let mut reader = collection.data_reader().await?;
                let bytes: Bytes = reader.read_to_end().await?;
                let collection = Collection::from_bytes(&bytes).context("invalid collection")?;
                for Blob { hash, name } in collection.blobs() {
                    let path = path.join(pathbuf_from_name(name));
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    tracing::trace!("exporting blob {} to {}", hash, path.display());
                    let id = progress.new_id();
                    let progress1 = progress.clone();
                    db.export(*hash, path, stable, move |offset| {
                        Ok(progress1.try_send(ShareProgress::ExportProgress { id, offset })?)
                    })
                    .await?;
                }
            }
            #[cfg(not(feature = "iroh-collection"))]
            anyhow::bail!("recursive export not supported without iroh-collection feature");
        } else if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
            let id = progress.new_id();
            let entry = db.get(&hash).context("entry not there")?;
            progress
                .send(ShareProgress::Export {
                    id,
                    hash,
                    target: out,
                    size: entry.size(),
                })
                .await?;
            let progress1 = progress.clone();
            db.export(hash, path, stable, move |offset| {
                Ok(progress1.try_send(ShareProgress::ExportProgress { id, offset })?)
            })
            .await?;
        }
        anyhow::Ok(())
    }

    /// Get a blob that was requested completely.
    ///
    /// We need to create our own files and handle the case where an outboard
    /// is not needed.
    async fn get_blob_inner(
        db: &D,
        header: AtBlobHeader,
        sender: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<AtEndBlob> {
        use iroh_io::AsyncSliceWriter;

        let hash = header.hash();
        // read the size
        let (content, size) = header.next().await?;
        // create the temp file pair
        let entry = db.get_or_create_partial(hash, size)?;
        // open the data file in any case
        let df = entry.data_writer().await?;
        // allocate a new id for progress reports for this transfer
        let id = sender.new_id();
        sender.send(ShareProgress::Found { id, hash, size }).await?;
        let sender2 = sender.clone();
        let on_write = move |offset: u64, _length: usize| {
            // if try send fails it means that the receiver has been dropped.
            // in that case we want to abort the write_all_with_outboard.
            sender2
                .try_send(ShareProgress::Progress { id, offset })
                .map_err(|e| {
                    tracing::info!("aborting download of {}", hash);
                    e
                })?;
            Ok(())
        };
        let mut pw = ProgressSliceWriter2::new(df, on_write);
        // use the convenience method to write all to the two vfs objects
        let (end, ofo) = content
            .write_all_with_outboard(|_, _| entry.outboard_mut(), &mut pw)
            .await?;
        // sync the data file
        pw.sync().await?;
        // sync the outboard file, if we wrote one
        if let Some(mut of) = ofo {
            of.sync().await?;
        }
        db.insert_complete(entry).await?;
        // notify that we are done
        sender.send(ShareProgress::Done { id }).await?;
        Ok(end)
    }

    /// Get a blob that was requested partially.
    ///
    /// We get passed the data and outboard ids. Partial downloads are only done
    /// for large blobs where the outboard is present.
    async fn get_blob_inner_partial(
        db: &D,
        header: AtBlobHeader,
        entry: D::PartialEntry,
        sender: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<AtEndBlob> {
        // TODO: the data we get is validated at this point, but we need to check
        // that it actually contains the requested ranges. Or DO WE?
        use iroh_io::AsyncSliceWriter;

        let hash = header.hash();
        // read the size
        let (content, size) = header.next().await?;
        // open the data file in any case
        let df = entry.data_writer().await?;
        // allocate a new id for progress reports for this transfer
        let id = sender.new_id();
        sender.send(ShareProgress::Found { id, hash, size }).await?;
        let sender2 = sender.clone();
        let on_write = move |offset: u64, _length: usize| {
            // if try send fails it means that the receiver has been dropped.
            // in that case we want to abort the write_all_with_outboard.
            sender2
                .try_send(ShareProgress::Progress { id, offset })
                .map_err(|e| {
                    tracing::info!("aborting download of {}", hash);
                    e
                })?;
            Ok(())
        };
        let mut pw = ProgressSliceWriter2::new(df, on_write);
        // use the convenience method to write all to the two vfs objects
        let (end, ofo) = content
            .write_all_with_outboard(|_, _| entry.outboard_mut(), &mut pw)
            .await?;
        // sync the data file
        pw.sync().await?;
        // sync the outboard file
        if let Some(mut of) = ofo {
            of.sync().await?;
        }
        // actually store the data. it is up to the db to decide if it wants to
        // rename the files or not.
        db.insert_complete(entry).await?;
        // notify that we are done
        sender.send(ShareProgress::Done { id }).await?;
        Ok(end)
    }

    async fn get_missing_ranges_blob(
        entry: &D::PartialEntry,
    ) -> anyhow::Result<RangeSet2<ChunkNum>> {
        use tracing::trace as log;
        // compute the valid range from just looking at the data file
        let mut data_reader = entry.data_reader().await?;
        let data_size = data_reader.len().await?;
        let valid_from_data = RangeSet2::from(..ByteNum(data_size).full_chunks());
        // compute the valid range from just looking at the outboard file
        let mut outboard = entry.outboard().await?;
        let valid_from_outboard = bao_tree::io::fsm::valid_ranges(&mut outboard).await?;
        let valid: RangeSet2<ChunkNum> = valid_from_data.intersection(&valid_from_outboard);
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
        let invalid = RangeSet2::all().difference(&valid);
        Ok(invalid)
    }

    async fn get_blob(
        &self,
        conn: quinn::Connection,
        hash: &Hash,
        progress: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<Stats> {
        let db = &self.inner.db;
        let end = if let Some(entry) = db.get_partial(hash) {
            trace!("got partial data for {}", hash,);

            let required_ranges = Self::get_missing_ranges_blob(&entry)
                .await
                .ok()
                .unwrap_or_else(RangeSet2::all);
            let request = GetRequest::new(*hash, RangeSpecSeq::new([required_ranges]));
            // full request
            let request = get::fsm::start(conn, iroh_bytes::protocol::Request::Get(request));
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database

            Self::get_blob_inner_partial(db, header, entry, progress).await?
        } else {
            // full request
            let request = get::fsm::start(
                conn,
                iroh_bytes::protocol::Request::Get(GetRequest::single(*hash)),
            );
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // do the ceremony of getting the blob and adding it to the database
            Self::get_blob_inner(db, header, progress).await?
        };

        // we have requested a single hash, so we must be at closing
        let EndBlobNext::Closing(end) = end.next() else {
            anyhow::bail!("expected Closing");
        };
        // this closes the bidi stream. Do something with the stats?
        let stats = end.next().await?;
        anyhow::Ok(stats)
    }

    /// Given a collection of hashes, figure out what is missing
    async fn get_missing_ranges_collection(
        &self,
        collection: &Vec<Hash>,
    ) -> io::Result<Vec<BlobInfo<D>>> {
        let db = &self.inner.db;
        let items = collection.iter().map(|hash| async move {
            io::Result::Ok(if let Some(entry) = db.get_partial(hash) {
                // first look for partial
                trace!("got partial data for {}", hash,);
                let missing_chunks = Self::get_missing_ranges_blob(&entry)
                    .await
                    .ok()
                    .unwrap_or_else(RangeSet2::all);
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
        let mut res = Vec::with_capacity(collection.len());
        // todo: parallelize maybe?
        for item in items {
            res.push(item.await?);
        }
        Ok(res)
    }

    async fn get_collection(
        &self,
        conn: quinn::Connection,
        root_hash: &Hash,
        sender: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<Stats> {
        use tracing::info as log;
        let db = &self.inner.db;
        let finishing = if let Some(entry) = db.get(root_hash) {
            log!("already got collection - doing partial download");
            // got the collection
            let reader = entry.data_reader().await?;
            let (mut collection, stats) = self.collection_parser.parse(0, reader).await?;
            sender
                .send(ShareProgress::FoundCollection {
                    hash: *root_hash,
                    num_blobs: stats.num_blobs,
                    total_blobs_size: stats.total_blob_size,
                })
                .await?;
            let mut children: Vec<Hash> = vec![];
            while let Some(hash) = collection.next().await? {
                children.push(hash);
            }
            let missing_info = self.get_missing_ranges_collection(&children).await?;
            if missing_info.iter().all(|x| matches!(x, BlobInfo::Complete)) {
                log!("nothing to do");
                return Ok(Stats::default());
            }
            let missing_iter = std::iter::once(RangeSet2::empty())
                .chain(missing_info.iter().map(|x| x.missing_chunks()))
                .collect::<Vec<_>>();
            log!("requesting chunks {:?}", missing_iter);
            let request = GetRequest::new(*root_hash, RangeSpecSeq::new(missing_iter));
            let request = get::fsm::start(conn, request.into());
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
                    BlobInfo::Missing => Self::get_blob_inner(db, header, sender.clone()).await?,
                    BlobInfo::Partial { entry, .. } => {
                        Self::get_blob_inner_partial(db, header, entry.clone(), sender.clone())
                            .await?
                    }
                    BlobInfo::Complete => anyhow::bail!("got data we have not requested"),
                };
                next = end_blob.next();
            }
        } else {
            tracing::info!("don't have collection - doing full download");
            // don't have the collection, so probably got nothing
            let request = get::fsm::start(
                conn,
                iroh_bytes::protocol::Request::Get(GetRequest::all(*root_hash)),
            );
            // create a new bidi stream
            let connected = request.next().await?;
            // next step. we have requested a single hash, so this must be StartRoot
            let ConnectedNext::StartRoot(start) = connected.next().await? else {
                anyhow::bail!("expected StartRoot");
            };
            // move to the header
            let header = start.next();
            // read the blob and add it to the database
            let end_root = Self::get_blob_inner(db, header, sender.clone()).await?;
            // read the collection fully for now
            let entry = db.get(root_hash).context("just downloaded")?;
            let reader = entry.data_reader().await?;
            let (mut collection, stats) = self.collection_parser.parse(0, reader).await?;
            sender
                .send(ShareProgress::FoundCollection {
                    hash: *root_hash,
                    num_blobs: stats.num_blobs,
                    total_blobs_size: stats.total_blob_size,
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
                let end_blob = Self::get_blob_inner(db, header, sender.clone()).await?;
                next = end_blob.next();
            }
        };
        // this closes the bidi stream. Do something with the stats?
        let stats = finishing.next().await?;
        anyhow::Ok(stats)
    }

    async fn share0(
        self,
        msg: ShareRequest,
        progress: impl ProgressSender<Msg = ShareProgress> + IdGenerator,
    ) -> anyhow::Result<()> {
        let local = self.inner.rt.local_pool().clone();
        let hash = msg.hash;
        tracing::info!("share: {:?}", msg);
        let conn = self
            .inner
            .endpoint
            .connect(
                msg.peer,
                &iroh_bytes::protocol::ALPN,
                msg.derp_region,
                &msg.addrs,
            )
            .await?;
        progress.send(ShareProgress::Connected).await?;
        let progress2 = progress.clone();
        let progress3 = progress.clone();
        let this = self.clone();
        let download =
            local.spawn_pinned(move || self.get(conn, msg.hash, msg.recursive, progress2));
        let _export = local.spawn_pinned(move || async move {
            let stats = download.await.unwrap()?;
            progress
                .send(ShareProgress::NetworkDone {
                    bytes_written: stats.bytes_written,
                    bytes_read: stats.bytes_read,
                    elapsed: stats.elapsed,
                })
                .await?;
            if let Some(out) = msg.out {
                if let Err(cause) = this
                    .export(out, hash, msg.recursive, msg.in_place, progress3)
                    .await
                {
                    progress.send(ShareProgress::Abort(cause.into())).await?;
                }
            }
            progress.send(ShareProgress::AllDone).await?;
            anyhow::Ok(())
        });
        Ok(())
    }

    fn share(self, msg: ShareRequest) -> impl Stream<Item = ShareProgress> {
        async move {
            let (sender, receiver) = mpsc::channel(1024);
            let sender = TokioProgressSender::new(sender);
            if let Err(cause) = self.share0(msg, sender.clone()).await {
                sender
                    .send(ShareProgress::Abort(cause.into()))
                    .await
                    .unwrap();
            };
            ReceiverStream::new(receiver)
        }
        .flatten_stream()
    }

    #[cfg(feature = "iroh-collection")]
    async fn provide0(
        self,
        msg: ProvideRequest,
        progress: tokio::sync::mpsc::Sender<ProvideProgress>,
    ) -> anyhow::Result<()> {
        use crate::collection::{Blob, Collection};
        use futures::TryStreamExt;
        use iroh_bytes::provider::ImportProgress;
        use std::{collections::BTreeMap, sync::Mutex};

        let progress = TokioProgressSender::new(progress);
        let names = Arc::new(Mutex::new(BTreeMap::new()));
        // convert import progress to provide progress
        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::Found { id, path, .. } => {
                names.lock().unwrap().insert(id, path);
                None
            }
            ImportProgress::Size { id, size } => {
                let path = names.lock().unwrap().remove(&id)?;
                Some(ProvideProgress::Found {
                    id,
                    name: path.display().to_string(),
                    size,
                })
            }
            ImportProgress::OutboardProgress { id, offset } => {
                Some(ProvideProgress::Progress { id, offset })
            }
            ImportProgress::OutboardDone { hash, id } => Some(ProvideProgress::Done { hash, id }),
            _ => None,
        });
        let root = msg.path;
        anyhow::ensure!(root.is_absolute(), "path must be absolute");
        anyhow::ensure!(
            root.is_dir() || root.is_file(),
            "path must be either a Directory or a File"
        );
        let data_sources = crate::util::fs::scan_path(root)?;
        const IO_PARALLELISM: usize = 4;
        let result: Vec<(Blob, u64)> = futures::stream::iter(data_sources)
            .map(|source| {
                let import_progress = import_progress.clone();
                let db = self.inner.db.clone();
                async move {
                    let name = source.name().to_string();
                    let (hash, size) = db
                        .import(source.path().to_owned(), msg.in_place, import_progress)
                        .await?;
                    io::Result::Ok((Blob { hash, name }, size))
                }
            })
            .buffered(IO_PARALLELISM)
            .try_collect::<Vec<_>>()
            .await?;
        let total_blobs_size = result.iter().map(|(_, size)| *size).sum();
        let blobs = result.into_iter().map(|(blob, _)| blob).collect::<Vec<_>>();
        let collection = Collection::new(blobs, total_blobs_size)?;
        let data = collection.to_bytes()?;
        let hash = self.inner.db.import_bytes(data.into()).await?;
        progress.send(ProvideProgress::AllDone { hash }).await?;

        self.inner
            .callbacks
            .send(Event::ByteProvide(
                iroh_bytes::provider::Event::CollectionAdded { hash },
            ))
            .await;

        Ok(())
    }

    #[cfg(not(feature = "iroh-collection"))]
    async fn provide0(
        self,
        _msg: ProvideRequest,
        _progress: tokio::sync::mpsc::Sender<ProvideProgress>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("collections not supported");
    }

    async fn version(self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
    async fn id(self, _: IdRequest) -> IdResponse {
        IdResponse {
            peer_id: Box::new(self.inner.keypair.public().into()),
            listen_addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
    async fn addrs(self, _: AddrsRequest) -> AddrsResponse {
        AddrsResponse {
            addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
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

fn handle_rpc_request<D: BaoDb, E: ServiceEndpoint<ProviderService>, C: CollectionParser>(
    msg: ProviderRequest,
    chan: RpcChannel<ProviderService, E>,
    handler: &RpcHandler<D, C>,
    rt: &runtime::Handle,
) {
    let handler = handler.clone();
    rt.main().spawn(async move {
        use ProviderRequest::*;
        tracing::info!(
            "handling rpc request: {:?} {}",
            msg,
            std::any::type_name::<E>()
        );
        match msg {
            ListBlobs(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::list_blobs)
                    .await
            }
            ListIncompleteBlobs(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::list_incomplete_blobs)
                    .await
            }
            ListCollections(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::list_collections)
                    .await
            }
            Provide(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::provide)
                    .await
            }
            Share(msg) => chan.server_streaming(msg, handler, RpcHandler::share).await,
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

#[derive(Debug, Clone)]
enum BlobInfo<D: BaoDb> {
    // we have the blob completely
    Complete,
    // we have the blob partially
    Partial {
        entry: D::PartialEntry,
        missing_chunks: RangeSet2<ChunkNum>,
    },
    // we don't have the blob at all
    Missing,
}

impl<D: BaoDb> BlobInfo<D> {
    fn missing_chunks(&self) -> RangeSet2<ChunkNum> {
        match self {
            BlobInfo::Complete => RangeSet2::empty(),
            BlobInfo::Partial { missing_chunks, .. } => missing_chunks.clone(),
            BlobInfo::Missing => RangeSet2::all(),
        }
    }
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

/// Use a single token of opaque bytes to authorize all requests
#[derive(Debug, Clone)]
pub struct StaticTokenAuthHandler {
    token: Option<RequestToken>,
}

impl StaticTokenAuthHandler {
    /// Creates a new handler with provided token.
    ///
    /// The single static token provided can be used to authorise all the requests.  If it
    /// is `None` no authorisation is performed and all requests are allowed.
    pub fn new(token: Option<RequestToken>) -> Self {
        Self { token }
    }
}

impl RequestAuthorizationHandler for StaticTokenAuthHandler {
    fn authorize(
        &self,
        token: Option<RequestToken>,
        _request: &Request,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        match &self.token {
            None => async move {
                if let Some(token) = token {
                    anyhow::bail!(
                        "no authorization handler defined, but token was provided: {:?}",
                        token
                    );
                }
                Ok(())
            }
            .boxed(),
            Some(expect) => {
                let expect = expect.clone();
                async move {
                    match token {
                        Some(token) => {
                            if token == expect {
                                Ok(())
                            } else {
                                anyhow::bail!("invalid token")
                            }
                        }
                        None => anyhow::bail!("no token provided"),
                    }
                }
                .boxed()
            }
        }
    }
}

#[cfg(all(test, feature = "flat-db"))]
mod tests {
    use anyhow::bail;
    use futures::StreamExt;
    use std::net::Ipv4Addr;
    use std::path::Path;

    use super::*;

    /// Pick up the tokio runtime from the thread local and add a
    /// thread per core runtime.
    fn test_runtime() -> runtime::Handle {
        runtime::Handle::from_currrent(1).unwrap()
    }

    #[tokio::test]
    async fn test_ticket_multiple_addrs() {
        let rt = test_runtime();
        let (db, hashes) = crate::database::test::Database::new([("test", b"hello")]);
        let hash = hashes["test"].into();
        let node = Node::builder(db)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .runtime(&rt)
            .spawn()
            .await
            .unwrap();
        let _drop_guard = node.cancel_token().drop_guard();
        let ticket = node.ticket(hash).await.unwrap();
        println!("addrs: {:?}", ticket.addrs());
        assert!(!ticket.addrs().is_empty());
    }

    #[cfg(feature = "mem-db")]
    #[tokio::test]
    async fn test_node_add_collection_event() -> Result<()> {
        let db = crate::database::mem::Database::default();
        let node = Node::builder(db)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .runtime(&test_runtime())
            .spawn()
            .await?;

        let _drop_guard = node.cancel_token().drop_guard();

        let (r, mut s) = mpsc::channel(1);
        node.subscribe(move |event| {
            let r = r.clone();
            async move {
                if let Event::ByteProvide(iroh_bytes::provider::Event::CollectionAdded { hash }) =
                    event
                {
                    r.send(hash).await.ok();
                }
            }
            .boxed()
        })
        .await?;

        let got_hash = tokio::time::timeout(Duration::from_secs(1), async move {
            let mut stream = node
                .controller()
                .server_streaming(ProvideRequest {
                    path: Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
                    in_place: false,
                })
                .await?;

            while let Some(item) = stream.next().await {
                match item? {
                    ProvideProgress::AllDone { hash } => {
                        return Ok(hash);
                    }
                    ProvideProgress::Abort(e) => {
                        bail!("Error while adding data: {e}");
                    }
                    _ => {}
                }
            }
            bail!("stream ended without providing data");
        })
        .await
        .context("timeout")?
        .context("get failed")?;

        let event_hash = s.recv().await.expect("missing collection event");
        assert_eq!(got_hash, event_hash);

        Ok(())
    }
}
