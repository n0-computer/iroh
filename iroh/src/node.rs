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

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use futures::future::{BoxFuture, Shared};
use futures::{FutureExt, Stream, StreamExt, TryFutureExt};
use iroh_bytes::baomap::{
    ExportMode, GcMarkEvent, GcSweepEvent, Map, MapEntry, ReadableStore, Store as BaoStore,
    ValidateProgress,
};
use iroh_bytes::collection::{CollectionParser, LinkSeqCollectionParser};
use iroh_bytes::protocol::GetRequest;
use iroh_bytes::provider::GetProgress;
use iroh_bytes::util::progress::{FlumeProgressSender, IdGenerator, ProgressSender};
use iroh_bytes::util::{BlobFormat, HashAndFormat, RpcResult, SetTagOption};
use iroh_bytes::{
    protocol::{Closed, Request, RequestToken},
    provider::{AddProgress, CustomGetHandler, RequestAuthorizationHandler},
    util::runtime,
    util::Hash,
};
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_io::AsyncSliceReader;
use iroh_net::defaults::default_derp_map;
use iroh_net::magic_endpoint::get_alpn;
use iroh_net::util::AbortingJoinHandle;
use iroh_net::{
    config::Endpoint,
    derp::DerpMap,
    key::{PublicKey, SecretKey},
    tls, MagicEndpoint, PeerAddr,
};
use iroh_sync::store::Store as DocStore;
use quic_rpc::server::RpcChannel;
use quic_rpc::transport::flume::FlumeConnection;
use quic_rpc::transport::misc::DummyServerEndpoint;
use quic_rpc::{RpcClient, RpcServer, ServiceEndpoint};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use crate::dial::Ticket;
use crate::downloader::Downloader;
use crate::rpc_protocol::{
    BlobAddPathRequest, BlobDeleteBlobRequest, BlobDownloadRequest, BlobListCollectionsRequest,
    BlobListCollectionsResponse, BlobListIncompleteRequest, BlobListIncompleteResponse,
    BlobListRequest, BlobListResponse, BlobReadResponse, BlobValidateRequest, BytesGetRequest,
    DeleteTagRequest, DownloadLocation, ListTagsRequest, ListTagsResponse,
    NodeConnectionInfoRequest, NodeConnectionInfoResponse, NodeConnectionsRequest,
    NodeConnectionsResponse, NodeShutdownRequest, NodeStatsRequest, NodeStatsResponse,
    NodeStatusRequest, NodeStatusResponse, NodeWatchRequest, NodeWatchResponse, ProviderRequest,
    ProviderResponse, ProviderService,
};
use crate::sync_engine::{SyncEngine, SYNC_ALPN};

const MAX_CONNECTIONS: u32 = 1024;
const MAX_STREAMS: u64 = 10;
const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_ADDR: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 11204);

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Chunk size for getting blobs over RPC
const RPC_BLOB_GET_CHUNK_SIZE: usize = 1024 * 64;
/// Channel cap for getting blobs over RPC
const RPC_BLOB_GET_CHANNEL_CAP: usize = 2;

/// Policy for garbage collection.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcPolicy {
    /// Garbage collection is disabled.
    #[default]
    Disabled,
    /// Garbage collection is run at the given interval.
    Interval(Duration),
}

/// Builder for the [`Node`].
///
/// You must supply a blob store. Various store implementations are available
/// in [`crate::baomap`]. Everything else is optional.
///
/// Finally you can create and run the node by calling [`Builder::spawn`].
///
/// The returned [`Node`] is awaitable to know when it finishes.  It can be terminated
/// using [`Node::shutdown`].
#[derive(Debug)]
pub struct Builder<
    D,
    S = iroh_sync::store::memory::Store,
    E = DummyServerEndpoint,
    C = LinkSeqCollectionParser,
> where
    D: Map,
    S: DocStore,
    E: ServiceEndpoint<ProviderService>,
    C: CollectionParser,
{
    bind_addr: SocketAddr,
    secret_key: SecretKey,
    rpc_endpoint: E,
    db: D,
    keylog: bool,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    auth_handler: Arc<dyn RequestAuthorizationHandler>,
    derp_map: Option<DerpMap>,
    collection_parser: C,
    gc_policy: GcPolicy,
    rt: Option<runtime::Handle>,
    docs: S,
    /// Path to store peer data. If `None`, peer data will not be persisted.
    peers_data_path: Option<PathBuf>,
}

const PROTOCOLS: [&[u8]; 3] = [&iroh_bytes::protocol::ALPN, GOSSIP_ALPN, SYNC_ALPN];

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

impl<D: Map, S: DocStore> Builder<D, S> {
    /// Creates a new builder for [`Node`] using the given database.
    fn with_db_and_store(db: D, docs: S) -> Self {
        Self {
            bind_addr: DEFAULT_BIND_ADDR.into(),
            secret_key: SecretKey::generate(),
            db,
            keylog: false,
            derp_map: Some(default_derp_map()),
            rpc_endpoint: Default::default(),
            custom_get_handler: Arc::new(NoopCustomGetHandler),
            auth_handler: Arc::new(NoopRequestAuthorizationHandler),
            collection_parser: LinkSeqCollectionParser,
            gc_policy: GcPolicy::Disabled,
            rt: None,
            docs,
            peers_data_path: None,
        }
    }
}

impl<D, S, E, C> Builder<D, S, E, C>
where
    D: BaoStore,
    S: DocStore,
    E: ServiceEndpoint<ProviderService>,
    C: CollectionParser,
{
    /// Configure rpc endpoint, changing the type of the builder to the new endpoint type.
    pub fn rpc_endpoint<E2: ServiceEndpoint<ProviderService>>(
        self,
        value: E2,
    ) -> Builder<D, S, E2, C> {
        // we can't use ..self here because the return type is different
        Builder {
            bind_addr: self.bind_addr,
            secret_key: self.secret_key,
            db: self.db,
            keylog: self.keylog,
            custom_get_handler: self.custom_get_handler,
            auth_handler: self.auth_handler,
            rpc_endpoint: value,
            derp_map: self.derp_map,
            collection_parser: self.collection_parser,
            gc_policy: self.gc_policy,
            rt: self.rt,
            docs: self.docs,
            peers_data_path: self.peers_data_path,
        }
    }

    /// Configure the collection parser, changing the type of the builder to the new collection parser type.
    pub fn collection_parser<C2: CollectionParser>(
        self,
        collection_parser: C2,
    ) -> Builder<D, S, E, C2> {
        // we can't use ..self here because the return type is different
        Builder {
            collection_parser,
            bind_addr: self.bind_addr,
            secret_key: self.secret_key,
            db: self.db,
            keylog: self.keylog,
            custom_get_handler: self.custom_get_handler,
            auth_handler: self.auth_handler,
            rpc_endpoint: self.rpc_endpoint,
            derp_map: self.derp_map,
            gc_policy: self.gc_policy,
            rt: self.rt,
            docs: self.docs,
            peers_data_path: self.peers_data_path,
        }
    }

    /// Sets the garbage collection policy.
    ///
    /// By default garbage collection is disabled.
    pub fn gc_policy(mut self, gc_policy: GcPolicy) -> Self {
        self.gc_policy = gc_policy;
        self
    }

    /// Enables using DERP servers to assist in establishing connectivity.
    ///
    /// DERP servers are used to discover other nodes by [`PublicKey`] and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// The provided `derp_map` must contain at least one region with a configured derp
    /// node.
    ///
    /// When calling neither this, nor [`disable_derp`] the builder uses the
    /// [`default_derp_map`] containing number0's global derp servers.
    ///
    /// [`disable_derp`]: Builder::disable_derp
    pub fn enable_derp(mut self, dm: DerpMap) -> Self {
        self.derp_map = Some(dm);
        self
    }

    /// Disables using DERP servers.
    ///
    /// See [`enable_derp`] for details.
    ///
    /// [`enable_derp`]: Builder::enable_derp
    pub fn disable_derp(mut self) -> Self {
        self.derp_map = None;
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

    /// Uses the given [`SecretKey`] for the [`PublicKey`] instead of a newly generated one.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = secret_key;
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

    /// Set the path where known peer data is loaded on start-up and later persisted.
    pub fn peers_data_path(mut self, path: PathBuf) -> Self {
        self.peers_data_path = Some(path);
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
    pub async fn spawn(self) -> Result<Node<D, S>> {
        trace!("spawning node");
        let rt = self.rt.context("runtime not set")?;
        ensure!(
            self.derp_map
                .as_ref()
                .map(|m| !m.is_empty())
                .unwrap_or(true),
            "Derp server enabled but DerpMap is empty",
        );

        // Initialize the metrics collection.
        //
        // The metrics are global per process. Subsequent calls do not change the metrics
        // collection and will return an error. We ignore this error. This means that if you'd
        // spawn multiple Iroh nodes in the same process, the metrics would be shared between the
        // nodes.
        #[cfg(feature = "metrics")]
        crate::metrics::try_init_metrics_collection().ok();

        let (endpoints_update_s, endpoints_update_r) = flume::bounded(1);
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(MAX_STREAMS.try_into()?)
            .max_concurrent_uni_streams(0u32.into());

        let endpoint = MagicEndpoint::builder()
            .secret_key(self.secret_key.clone())
            .alpns(PROTOCOLS.iter().map(|p| p.to_vec()).collect())
            .keylog(self.keylog)
            .transport_config(transport_config)
            .concurrent_connections(MAX_CONNECTIONS)
            .on_endpoints(Box::new(move |eps| {
                if !eps.is_empty() {
                    endpoints_update_s.send(eps.to_vec()).ok();
                }
            }));
        let endpoint = match self.peers_data_path {
            Some(path) => endpoint.peers_data_path(path),
            None => endpoint,
        };
        let endpoint = match self.derp_map {
            Some(derp_map) => endpoint.enable_derp(derp_map),
            None => endpoint,
        };
        let endpoint = endpoint.bind(self.bind_addr.port()).await?;
        trace!("created quinn endpoint");

        let (cb_sender, cb_receiver) = mpsc::channel(8);
        let cancel_token = CancellationToken::new();

        debug!("rpc listening on: {:?}", self.rpc_endpoint.local_addr());

        // initialize the gossip protocol
        let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default());

        // spawn the sync engine
        let downloader = Downloader::new(
            self.db.clone(),
            self.collection_parser.clone(),
            endpoint.clone(),
            rt.clone(),
        )
        .await;
        let ds = self.docs.clone();
        let sync = SyncEngine::spawn(
            rt.clone(),
            endpoint.clone(),
            gossip.clone(),
            self.docs,
            self.db.clone(),
            downloader,
        );

        let gc_task = if let GcPolicy::Interval(gc_period) = self.gc_policy {
            tracing::info!("Starting GC task with interval {}s", gc_period.as_secs());
            let db = self.db.clone();
            let cp = self.collection_parser.clone();
            let task = rt
                .local_pool()
                .spawn_pinned(move || Self::gc_loop(db, ds, cp, gc_period));
            Some(AbortingJoinHandle(task))
        } else {
            None
        };
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection(1);
        let rt2 = rt.clone();
        let rt3 = rt.clone();
        let callbacks = Callbacks::default();
        let inner = Arc::new(NodeInner {
            db: self.db,
            endpoint: endpoint.clone(),
            secret_key: self.secret_key,
            controller,
            cancel_token,
            callbacks: callbacks.clone(),
            cb_sender,
            gc_task,
            rt: rt.clone(),
            sync,
        });
        let task = {
            let gossip = gossip.clone();
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
                    gossip,
                )
                .await
            })
        };
        let node = Node {
            inner,
            task: task.map_err(Arc::new).boxed().shared(),
        };

        // spawn a task that updates the gossip endpoints.
        let (first_endpoint_update_tx, first_endpoint_update_rx) = oneshot::channel();
        let mut first_endpoint_update_tx = Some(first_endpoint_update_tx);
        rt.main().spawn(async move {
            while let Ok(eps) = endpoints_update_r.recv_async().await {
                if let Err(err) = gossip.update_endpoints(&eps) {
                    warn!("Failed to update gossip endpoints: {err:?}");
                }
                if let Some(tx) = first_endpoint_update_tx.take() {
                    tx.send(()).ok();
                }
            }
        });

        // Wait for a single endpoint update, to make sure
        // we found some endpoints
        tokio::time::timeout(ENDPOINT_WAIT, first_endpoint_update_rx)
            .await
            .context("waiting for endpoint")??;

        Ok(node)
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        server: MagicEndpoint,
        callbacks: Callbacks,
        mut cb_receiver: mpsc::Receiver<EventCallback>,
        handler: RpcHandler<D, S, C>,
        rpc: E,
        internal_rpc: impl ServiceEndpoint<ProviderService>,
        custom_get_handler: Arc<dyn CustomGetHandler>,
        auth_handler: Arc<dyn RequestAuthorizationHandler>,
        collection_parser: C,
        rt: runtime::Handle,
        gossip: Gossip,
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

        // forward our initial endpoints to the gossip protocol
        // it may happen the the first endpoint update callback is missed because the gossip cell
        // is only initialized once the endpoint is fully bound
        if let Ok(local_endpoints) = server.local_endpoints().await {
            if !local_endpoints.is_empty() {
                debug!(me = ?server.peer_id(), "gossip initial update: {local_endpoints:?}");
                gossip.update_endpoints(&local_endpoints).ok();
            }
        }

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
                            info!("rpc request error: {:?}", e);
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
                            info!("last controller dropped, shutting down");
                            break;
                        }
                    }
                },
                // handle incoming p2p connections
                Some(mut connecting) = server.accept() => {
                    let alpn = match get_alpn(&mut connecting).await {
                        Ok(alpn) => alpn,
                        Err(err) => {
                            error!("invalid handshake: {:?}", err);
                            continue;
                        }
                    };
                    let gossip = gossip.clone();
                    let inner = handler.inner.clone();
                    let collection_parser = collection_parser.clone();
                    let custom_get_handler = custom_get_handler.clone();
                    let auth_handler = auth_handler.clone();
                    let sync = handler.inner.sync.clone();
                    rt.main().spawn(async move {
                        if let Err(err) = handle_connection(connecting, alpn, inner, gossip, sync, collection_parser, custom_get_handler, auth_handler).await {
                            warn!("Handling incoming connection ended with error: {err}");
                        }
                    });
                },
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

    async fn gc_loop(db: D, ds: S, cp: C, gc_period: Duration) {
        'outer: loop {
            // do delay before the two phases of GC
            tokio::time::sleep(gc_period).await;
            db.clear_live();
            let doc_hashes = match ds.content_hashes() {
                Ok(hashes) => hashes,
                Err(err) => {
                    tracing::error!("Error getting doc hashes: {}", err);
                    continue 'outer;
                }
            };
            let mut doc_db_error = false;
            let doc_hashes = doc_hashes.filter_map(|e| {
                let hash = match e {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::error!("Error getting doc hash: {}", err);
                        doc_db_error = true;
                        return None;
                    }
                };
                Some(hash)
            });
            db.add_live(doc_hashes);
            if doc_db_error {
                tracing::error!("Error getting doc hashes, skipping GC to be safe");
                continue 'outer;
            }

            tracing::info!("Starting GC mark phase");
            let mut stream = db.gc_mark(cp.clone(), None);
            while let Some(item) = stream.next().await {
                match item {
                    GcMarkEvent::CustomInfo(text) => {
                        tracing::info!("{}", text);
                    }
                    GcMarkEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcMarkEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
            tracing::info!("Starting GC sweep phase");
            let mut stream = db.gc_sweep();
            while let Some(item) = stream.next().await {
                match item {
                    GcSweepEvent::CustomInfo(text) => {
                        tracing::info!("{}", text);
                    }
                    GcSweepEvent::CustomWarning(text, _) => {
                        tracing::warn!("{}", text);
                    }
                    GcSweepEvent::Error(err) => {
                        tracing::error!("Fatal error during GC mark {}", err);
                        continue 'outer;
                    }
                }
            }
        }
    }
}

// TODO: Restructure this code to not take all these arguments.
#[allow(clippy::too_many_arguments)]
async fn handle_connection<D: BaoStore, S: DocStore, C: CollectionParser>(
    connecting: quinn::Connecting,
    alpn: String,
    node: Arc<NodeInner<D, S>>,
    gossip: Gossip,
    sync: SyncEngine<S>,
    collection_parser: C,
    custom_get_handler: Arc<dyn CustomGetHandler>,
    auth_handler: Arc<dyn RequestAuthorizationHandler>,
) -> Result<()> {
    match alpn.as_bytes() {
        GOSSIP_ALPN => gossip.handle_connection(connecting.await?).await?,
        SYNC_ALPN => sync.handle_connection(connecting).await?,
        alpn if alpn == iroh_bytes::protocol::ALPN => {
            iroh_bytes::provider::handle_connection(
                connecting,
                node.db.clone(),
                node.callbacks.clone(),
                collection_parser,
                custom_get_handler,
                auth_handler,
                node.rt.clone(),
            )
            .await
        }
        _ => bail!("ignoring connection: unsupported ALPN protocol"),
    }
    Ok(())
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
pub struct Node<D: Map, S: DocStore> {
    inner: Arc<NodeInner<D, S>>,
    task: Shared<BoxFuture<'static, Result<(), Arc<JoinError>>>>,
}

#[derive(derive_more::Debug)]
struct NodeInner<D, S: DocStore> {
    db: D,
    endpoint: MagicEndpoint,
    secret_key: SecretKey,
    cancel_token: CancellationToken,
    controller: FlumeConnection<ProviderResponse, ProviderRequest>,
    #[debug("callbacks: Sender<Box<dyn Fn(Event)>>")]
    cb_sender: mpsc::Sender<Box<dyn Fn(Event) -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    #[allow(dead_code)]
    callbacks: Callbacks,
    #[allow(dead_code)]
    gc_task: Option<AbortingJoinHandle<()>>,
    rt: runtime::Handle,
    pub(crate) sync: SyncEngine<S>,
}

/// Events emitted by the [`Node`] informing about the current status.
#[derive(Debug, Clone)]
pub enum Event {
    /// Events from the iroh-bytes transfer protocol.
    ByteProvide(iroh_bytes::provider::Event),
}

impl<D: ReadableStore, S: DocStore> Node<D, S> {
    /// Returns a new builder for the [`Node`].
    ///
    /// Once the done with the builder call [`Builder::spawn`] to create the node.
    pub fn builder(bao_store: D, doc_store: S) -> Builder<D, S> {
        Builder::with_db_and_store(bao_store, doc_store)
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

    /// Returns the [`PublicKey`] of the node.
    pub fn peer_id(&self) -> PublicKey {
        self.inner.secret_key.public()
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
    pub fn controller(&self) -> crate::client::mem::RpcClient {
        RpcClient::new(self.inner.controller.clone())
    }

    /// Return a client to control this node over an in-memory channel.
    pub fn client(&self) -> crate::client::mem::Iroh {
        crate::client::Iroh::new(self.controller())
    }

    /// Return a single token containing everything needed to get a hash.
    ///
    /// See [`Ticket`] for more details of how it can be used.
    // TODO: We should not assume `recursive: true` as we do currently. Take as argument instead.
    pub async fn ticket(&self, hash: Hash, format: BlobFormat) -> Result<Ticket> {
        // TODO: Verify that the hash exists in the db?
        let me = self.my_addr().await?;
        Ticket::new(me, hash, format, None)
    }

    /// Return the [`PeerAddr`] for this node.
    pub async fn my_addr(&self) -> Result<PeerAddr> {
        self.inner.endpoint.my_addr().await
    }

    /// Get the DERP region we are connected to.
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

impl<D: Map, S: DocStore> NodeInner<D, S> {
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
impl<D: Map, S: DocStore> Future for Node<D, S> {
    type Output = Result<(), Arc<JoinError>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(cx)
    }
}

#[derive(Debug, Clone)]
struct RpcHandler<D, S: DocStore, C> {
    inner: Arc<NodeInner<D, S>>,
    collection_parser: C,
}

impl<D: BaoStore, S: DocStore, C: CollectionParser> RpcHandler<D, S, C> {
    fn rt(&self) -> runtime::Handle {
        self.inner.rt.clone()
    }

    fn blob_list(
        self,
        _msg: BlobListRequest,
    ) -> impl Stream<Item = BlobListResponse> + Send + 'static {
        use bao_tree::io::fsm::Outboard;

        let db = self.inner.db.clone();
        futures::stream::iter(db.blobs()).filter_map(move |hash| {
            let db = db.clone();
            async move {
                let entry = db.get(&hash)?;
                let hash = entry.hash().into();
                let size = entry.outboard().await.ok()?.tree().size().0;
                let path = "".to_owned();
                Some(BlobListResponse { hash, size, path })
            }
        })
    }

    fn blob_list_incomplete(
        self,
        _msg: BlobListIncompleteRequest,
    ) -> impl Stream<Item = BlobListIncompleteResponse> + Send + 'static {
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
                io::Result::Ok(BlobListIncompleteResponse {
                    hash,
                    size: 0,
                    expected_size: entry.size(),
                })
            });
            async move { t.await.ok()?.ok() }
        })
    }

    fn blob_list_collections(
        self,
        _msg: BlobListCollectionsRequest,
    ) -> impl Stream<Item = BlobListCollectionsResponse> + Send + 'static {
        let db = self.inner.db.clone();
        let local = self.inner.rt.local_pool().clone();
        let tags = db.tags();
        futures::stream::iter(tags).filter_map(move |(name, HashAndFormat(hash, format))| {
            let db = db.clone();
            let local = local.clone();
            let cp = self.collection_parser.clone();
            async move {
                if !format.is_collection() {
                    return None;
                }
                let entry = db.get(&hash)?;
                let stats = local
                    .spawn_pinned(|| async move {
                        let reader = entry.data_reader().await.ok()?;
                        let (_collection, stats) = cp.parse(reader).await.ok()?;
                        Some(stats)
                    })
                    .await
                    .ok()??;
                Some(BlobListCollectionsResponse {
                    tag: name,
                    hash,
                    total_blobs_count: stats.num_blobs,
                    total_blobs_size: stats.total_blob_size,
                })
            }
        })
    }

    async fn blob_delete_tag(self, msg: DeleteTagRequest) -> RpcResult<()> {
        self.inner.db.set_tag(msg.name, None).await?;
        Ok(())
    }

    async fn blob_delete_blob(self, msg: BlobDeleteBlobRequest) -> RpcResult<()> {
        self.inner.db.delete(&msg.hash).await?;
        Ok(())
    }

    fn blob_list_tags(
        self,
        _msg: ListTagsRequest,
    ) -> impl Stream<Item = ListTagsResponse> + Send + 'static {
        tracing::info!("blob_list_tags");
        futures::stream::iter(
            self.inner
                .db
                .tags()
                .map(|(name, HashAndFormat(hash, format))| {
                    tracing::info!("{:?} {} {:?}", name, hash, format);
                    ListTagsResponse { name, hash, format }
                }),
        )
    }

    /// Invoke validate on the database and stream out the result
    fn blob_validate(
        self,
        _msg: BlobValidateRequest,
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

    fn blob_add_from_path(self, msg: BlobAddPathRequest) -> impl Stream<Item = AddProgress> {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        let tx2 = tx.clone();
        self.rt().local_pool().spawn_pinned(|| async move {
            if let Err(e) = self.blob_add_from_path0(msg, tx).await {
                tx2.send_async(AddProgress::Abort(e.into())).await.ok();
            }
        });
        rx.into_stream()
    }

    async fn blob_export(
        self,
        out: String,
        hash: Hash,
        recursive: bool,
        stable: bool,
        progress: impl ProgressSender<Msg = GetProgress> + IdGenerator,
    ) -> anyhow::Result<()> {
        let db = &self.inner.db;
        let path = PathBuf::from(&out);
        let mode = if stable {
            ExportMode::TryReference
        } else {
            ExportMode::Copy
        };
        if recursive {
            #[cfg(feature = "iroh-collection")]
            {
                use crate::collection::{Blob, Collection};
                use crate::util::io::pathbuf_from_name;
                tokio::fs::create_dir_all(&path).await?;
                let collection = Collection::load(db, &hash).await?;
                for Blob { hash, name } in collection.blobs() {
                    #[allow(clippy::needless_borrow)]
                    let path = path.join(pathbuf_from_name(&name));
                    if let Some(parent) = path.parent() {
                        tokio::fs::create_dir_all(parent).await?;
                    }
                    trace!("exporting blob {} to {}", hash, path.display());
                    let id = progress.new_id();
                    let progress1 = progress.clone();
                    db.export(*hash, path, mode, move |offset| {
                        Ok(progress1.try_send(GetProgress::ExportProgress { id, offset })?)
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
                .send(GetProgress::Export {
                    id,
                    hash,
                    target: out,
                    size: entry.size(),
                })
                .await?;
            let progress1 = progress.clone();
            db.export(hash, path, mode, move |offset| {
                Ok(progress1.try_send(GetProgress::ExportProgress { id, offset })?)
            })
            .await?;
        }
        anyhow::Ok(())
    }

    async fn blob_download0(
        self,
        msg: BlobDownloadRequest,
        progress: impl ProgressSender<Msg = GetProgress> + IdGenerator,
    ) -> anyhow::Result<()> {
        let local = self.inner.rt.local_pool().clone();
        let hash = msg.hash;
        debug!("share: {:?}", msg);
        let format = msg.format;
        let db = self.inner.db.clone();
        let haf = HashAndFormat(hash, format);
        let temp_pin = db.temp_tag(haf);
        let conn = self
            .inner
            .endpoint
            .connect(msg.peer, &iroh_bytes::protocol::ALPN)
            .await?;
        progress.send(GetProgress::Connected).await?;
        let progress2 = progress.clone();
        let progress3 = progress.clone();
        let db = self.inner.db.clone();
        let db2 = db.clone();
        let collection_parser = self.collection_parser.clone();
        let download = local.spawn_pinned(move || async move {
            crate::get::get(
                &db2,
                &collection_parser,
                conn,
                hash,
                msg.format.is_collection(),
                progress2,
            )
            .await
        });

        let this = self.clone();
        let _export = local.spawn_pinned(move || async move {
            let stats = download.await.unwrap()?;
            progress
                .send(GetProgress::NetworkDone {
                    bytes_written: stats.bytes_written,
                    bytes_read: stats.bytes_read,
                    elapsed: stats.elapsed,
                })
                .await?;
            if let DownloadLocation::External { path, in_place } = msg.out {
                if let Err(cause) = this
                    .blob_export(path, hash, msg.format.is_collection(), in_place, progress3)
                    .await
                {
                    progress.send(GetProgress::Abort(cause.into())).await?;
                }
            }
            match msg.tag {
                SetTagOption::Named(tag) => {
                    db.set_tag(tag, Some(haf)).await?;
                }
                SetTagOption::Auto => {
                    db.create_tag(haf).await?;
                }
            }
            drop(temp_pin);
            progress.send(GetProgress::AllDone).await?;
            anyhow::Ok(())
        });
        Ok(())
    }

    fn blob_download(self, msg: BlobDownloadRequest) -> impl Stream<Item = GetProgress> {
        async move {
            let (sender, receiver) = flume::bounded(1024);
            let sender = FlumeProgressSender::new(sender);
            if let Err(cause) = self.blob_download0(msg, sender.clone()).await {
                sender.send(GetProgress::Abort(cause.into())).await.unwrap();
            };
            receiver.into_stream()
        }
        .flatten_stream()
    }

    #[cfg(feature = "iroh-collection")]
    async fn blob_add_from_path0(
        self,
        msg: BlobAddPathRequest,
        progress: flume::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        use crate::{
            collection::{Blob, Collection},
            rpc_protocol::WrapOption,
        };
        use futures::TryStreamExt;
        use iroh_bytes::baomap::{ImportMode, ImportProgress, TempTag};
        use std::{collections::BTreeMap, sync::Mutex};

        let progress = FlumeProgressSender::new(progress);
        let names = Arc::new(Mutex::new(BTreeMap::new()));
        // convert import progress to provide progress
        let import_progress = progress.clone().with_filter_map(move |x| match x {
            ImportProgress::Found { id, path, .. } => {
                names.lock().unwrap().insert(id, path);
                None
            }
            ImportProgress::Size { id, size } => {
                let path = names.lock().unwrap().remove(&id)?;
                Some(AddProgress::Found {
                    id,
                    name: path.display().to_string(),
                    size,
                })
            }
            ImportProgress::OutboardProgress { id, offset } => {
                Some(AddProgress::Progress { id, offset })
            }
            ImportProgress::OutboardDone { hash, id } => Some(AddProgress::Done { hash, id }),
            _ => None,
        });
        let BlobAddPathRequest {
            wrap,
            path: root,
            in_place,
            tag,
        } = msg;
        // Check that the path is absolute and exists.
        anyhow::ensure!(root.is_absolute(), "path must be absolute");
        anyhow::ensure!(root.exists(), "path must exist");

        let import_mode = match in_place {
            true => ImportMode::TryReference,
            false => ImportMode::Copy,
        };

        let create_collection = match wrap {
            WrapOption::Wrap { .. } => true,
            WrapOption::NoWrap => root.is_dir(),
        };

        let temp_tag = if create_collection {
            // import all files below root recursively
            let data_sources = crate::util::fs::scan_path(root, wrap)?;
            const IO_PARALLELISM: usize = 4;
            let result: Vec<(Blob, u64, TempTag)> = futures::stream::iter(data_sources)
                .map(|source| {
                    let import_progress = import_progress.clone();
                    let db = self.inner.db.clone();
                    async move {
                        let name = source.name().to_string();
                        let (tag, size) = db
                            .import(
                                source.path().to_owned(),
                                import_mode,
                                BlobFormat::RAW,
                                import_progress,
                            )
                            .await?;
                        let hash = *tag.hash();
                        let blob = Blob { hash, name };
                        io::Result::Ok((blob, size, tag))
                    }
                })
                .buffered(IO_PARALLELISM)
                .try_collect::<Vec<_>>()
                .await?;
            let total_blobs_size = result.iter().map(|(_, size, _)| *size).sum();

            // create a collection
            let (blobs, _child_tags): (Vec<_>, Vec<_>) =
                result.into_iter().map(|(blob, _, tag)| (blob, tag)).unzip();
            let collection = Collection::new(blobs, total_blobs_size)?;

            collection.store(&self.inner.db).await?
        } else {
            // import a single file
            let (tag, _size) = self
                .inner
                .db
                .import(root, import_mode, BlobFormat::RAW, import_progress)
                .await?;
            tag
        };

        let hash_and_format = temp_tag.inner();
        let HashAndFormat(hash, format) = *hash_and_format;
        let tag = match tag {
            SetTagOption::Named(tag) => {
                self.inner
                    .db
                    .set_tag(tag.clone(), Some(*hash_and_format))
                    .await?;
                tag
            }
            SetTagOption::Auto => self.inner.db.create_tag(*hash_and_format).await?,
        };
        progress
            .send(AddProgress::AllDone {
                hash,
                format,
                tag: tag.clone(),
            })
            .await?;
        self.inner
            .callbacks
            .send(Event::ByteProvide(
                iroh_bytes::provider::Event::TaggedBlobAdded { hash, format, tag },
            ))
            .await;

        Ok(())
    }

    #[cfg(not(feature = "iroh-collection"))]
    async fn blob_add_from_path0(
        self,
        _msg: BlobAddPathRequest,
        _progress: flume::Sender<AddProgress>,
    ) -> anyhow::Result<()> {
        anyhow::bail!("collections not supported");
    }

    async fn node_stats(self, _req: NodeStatsRequest) -> RpcResult<NodeStatsResponse> {
        #[cfg(feature = "metrics")]
        let res = Ok(NodeStatsResponse {
            stats: crate::metrics::get_metrics()?,
        });

        #[cfg(not(feature = "metrics"))]
        let res = Err(anyhow::anyhow!("metrics are disabled").into());

        res
    }

    async fn node_status(self, _: NodeStatusRequest) -> RpcResult<NodeStatusResponse> {
        Ok(NodeStatusResponse {
            addr: self.inner.endpoint.my_addr().await?,
            listen_addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }
    async fn node_shutdown(self, request: NodeShutdownRequest) {
        if request.force {
            info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            info!("graceful shutdown requested");
            self.inner.cancel_token.cancel();
        }
    }

    fn node_watch(self, _: NodeWatchRequest) -> impl Stream<Item = NodeWatchResponse> {
        futures::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                NodeWatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }

    fn blob_read(
        self,
        req: BytesGetRequest,
    ) -> impl Stream<Item = RpcResult<BlobReadResponse>> + Send + 'static {
        let (tx, rx) = flume::bounded(RPC_BLOB_GET_CHANNEL_CAP);
        let entry = self.inner.db.get(&req.hash);
        self.inner.rt.local_pool().spawn_pinned(move || async move {
            if let Err(err) = read_loop(entry, tx.clone(), RPC_BLOB_GET_CHUNK_SIZE).await {
                tx.send_async(RpcResult::Err(err.into())).await.ok();
            }
        });

        async fn read_loop<M: Map>(
            entry: Option<impl MapEntry<M>>,
            tx: flume::Sender<RpcResult<BlobReadResponse>>,
            chunk_size: usize,
        ) -> anyhow::Result<()> {
            let entry = entry.ok_or_else(|| anyhow!("Blob not found"))?;
            let size = entry.size();
            tx.send_async(Ok(BlobReadResponse::Entry {
                size,
                is_complete: entry.is_complete(),
            }))
            .await?;
            let mut reader = entry.data_reader().await?;
            let mut offset = 0u64;
            loop {
                let chunk = reader.read_at(offset, chunk_size).await?;
                let len = chunk.len();
                if !chunk.is_empty() {
                    tx.send_async(Ok(BlobReadResponse::Data { chunk })).await?;
                }
                if len < chunk_size {
                    break;
                } else {
                    offset += len as u64;
                }
            }
            Ok(())
        }

        rx.into_stream()
    }

    fn node_connections(
        self,
        _: NodeConnectionsRequest,
    ) -> impl Stream<Item = RpcResult<NodeConnectionsResponse>> + Send + 'static {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = flume::bounded(32);
        self.rt().local_pool().spawn_pinned(|| async move {
            match self.inner.endpoint.connection_infos().await {
                Ok(mut conn_infos) => {
                    conn_infos.sort_by_key(|n| n.public_key.to_string());
                    for conn_info in conn_infos {
                        tx.send_async(Ok(NodeConnectionsResponse { conn_info }))
                            .await
                            .ok();
                    }
                }
                Err(e) => {
                    tx.send_async(Err(e.into())).await.ok();
                }
            }
        });
        rx.into_stream()
    }

    async fn node_connection_info(
        self,
        req: NodeConnectionInfoRequest,
    ) -> RpcResult<NodeConnectionInfoResponse> {
        let NodeConnectionInfoRequest { node_id } = req;
        let conn_info = self.inner.endpoint.connection_info(node_id).await?;
        Ok(NodeConnectionInfoResponse { conn_info })
    }
}

fn handle_rpc_request<
    D: BaoStore,
    S: DocStore,
    E: ServiceEndpoint<ProviderService>,
    C: CollectionParser,
>(
    msg: ProviderRequest,
    chan: RpcChannel<ProviderService, E>,
    handler: &RpcHandler<D, S, C>,
    rt: &runtime::Handle,
) {
    let handler = handler.clone();
    rt.main().spawn(async move {
        use ProviderRequest::*;
        debug!("handling rpc request: {msg}");
        match msg {
            NodeWatch(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::node_watch)
                    .await
            }
            NodeStatus(msg) => chan.rpc(msg, handler, RpcHandler::node_status).await,
            NodeShutdown(msg) => chan.rpc(msg, handler, RpcHandler::node_shutdown).await,
            NodeStats(msg) => chan.rpc(msg, handler, RpcHandler::node_stats).await,
            NodeConnections(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::node_connections)
                    .await
            }
            NodeConnectionInfo(msg) => {
                chan.rpc(msg, handler, RpcHandler::node_connection_info)
                    .await
            }
            BlobList(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_list)
                    .await
            }
            BlobListIncomplete(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_list_incomplete)
                    .await
            }
            BlobListCollections(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_list_collections)
                    .await
            }
            ListTags(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_list_tags)
                    .await
            }
            DeleteTag(msg) => chan.rpc(msg, handler, RpcHandler::blob_delete_tag).await,
            BlobDeleteBlob(msg) => chan.rpc(msg, handler, RpcHandler::blob_delete_blob).await,
            BlobAddPath(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_add_from_path)
                    .await
            }
            BlobDownload(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_download)
                    .await
            }
            BlobValidate(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_validate)
                    .await
            }
            BlobRead(msg) => {
                chan.server_streaming(msg, handler, RpcHandler::blob_read)
                    .await
            }
            AuthorList(msg) => {
                chan.server_streaming(msg, handler, |handler, req| {
                    handler.inner.sync.author_list(req)
                })
                .await
            }
            AuthorCreate(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.author_create(req)
                })
                .await
            }
            AuthorImport(_msg) => {
                todo!()
            }
            DocInfo(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_info(req).await
                })
                .await
            }
            DocList(msg) => {
                chan.server_streaming(msg, handler, |handler, req| {
                    handler.inner.sync.doc_list(req)
                })
                .await
            }
            DocCreate(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_create(req)
                })
                .await
            }
            DocImport(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_import(req).await
                })
                .await
            }
            DocSet(msg) => {
                let bao_store = handler.inner.db.clone();
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_set(&bao_store, req).await
                })
                .await
            }
            DocDeletePrefix(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_delete_prefix(req).await
                })
                .await
            }
            DocGet(msg) => {
                chan.server_streaming(msg, handler, |handler, req| {
                    handler.inner.sync.doc_get_many(req)
                })
                .await
            }
            DocGetOne(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_get_one(req).await
                })
                .await
            }
            DocStartSync(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_start_sync(req).await
                })
                .await
            }
            DocStopSync(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_stop_sync(req).await
                })
                .await
            }
            DocShare(msg) => {
                chan.rpc(msg, handler, |handler, req| async move {
                    handler.inner.sync.doc_share(req).await
                })
                .await
            }
            DocSubscribe(msg) => {
                chan.server_streaming(msg, handler, |handler, req| {
                    async move { handler.inner.sync.doc_subscribe(req).await }.flatten_stream()
                })
                .await
            }
        }
    });
}

/// Create a [`quinn::ServerConfig`] with the given secret key and limits.
pub fn make_server_config(
    secret_key: &SecretKey,
    max_streams: u64,
    max_connections: u32,
    alpn_protocols: Vec<Vec<u8>>,
) -> anyhow::Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(secret_key, alpn_protocols, false)?;
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

    use crate::rpc_protocol::WrapOption;

    use super::*;

    /// Pick up the tokio runtime from the thread local and add a
    /// thread per core runtime.
    fn test_runtime() -> runtime::Handle {
        runtime::Handle::from_current(1).unwrap()
    }

    #[tokio::test]
    async fn test_ticket_multiple_addrs() {
        let rt = test_runtime();
        let (db, hashes) = crate::baomap::readonly_mem::Store::new([("test", b"hello")]);
        let doc_store = iroh_sync::store::memory::Store::default();
        let hash = hashes["test"].into();
        let node = Node::builder(db, doc_store)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .runtime(&rt)
            .spawn()
            .await
            .unwrap();
        let _drop_guard = node.cancel_token().drop_guard();
        let ticket = node.ticket(hash, BlobFormat::RAW).await.unwrap();
        println!("addrs: {:?}", ticket.node_addr().info);
        assert!(!ticket.node_addr().info.direct_addresses.is_empty());
    }

    #[cfg(feature = "mem-db")]
    #[tokio::test]
    async fn test_node_add_tagged_blob_event() -> Result<()> {
        use iroh_bytes::util::SetTagOption;

        let rt = runtime::Handle::from_current(1)?;
        let db = crate::baomap::mem::Store::new(rt);
        let doc_store = iroh_sync::store::memory::Store::default();
        let node = Node::builder(db, doc_store)
            .bind_addr((Ipv4Addr::UNSPECIFIED, 0).into())
            .runtime(&test_runtime())
            .spawn()
            .await?;

        let _drop_guard = node.cancel_token().drop_guard();

        let (r, mut s) = mpsc::channel(1);
        node.subscribe(move |event| {
            let r = r.clone();
            async move {
                if let Event::ByteProvide(iroh_bytes::provider::Event::TaggedBlobAdded {
                    hash,
                    ..
                }) = event
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
                .server_streaming(BlobAddPathRequest {
                    path: Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
                    in_place: false,
                    tag: SetTagOption::Auto,
                    wrap: WrapOption::NoWrap,
                })
                .await?;

            while let Some(item) = stream.next().await {
                match item? {
                    AddProgress::AllDone { hash, .. } => {
                        return Ok(hash);
                    }
                    AddProgress::Abort(e) => {
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

        let event_hash = s.recv().await.expect("missing add tagged blob event");
        assert_eq!(got_hash, event_hash);

        Ok(())
    }
}
