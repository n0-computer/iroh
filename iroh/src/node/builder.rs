use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use iroh_base::key::SecretKey;
use iroh_blobs::{
    downloader::Downloader,
    provider::EventSender,
    store::{Map, Store as BaoStore},
    util::local_pool::{self, LocalPool, LocalPoolHandle, PanicMode},
};
use iroh_docs::engine::DefaultAuthorStorage;
use iroh_docs::net::DOCS_ALPN;
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
#[cfg(not(test))]
use iroh_net::discovery::local_swarm_discovery::LocalSwarmDiscovery;
use iroh_net::{
    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher, ConcurrentDiscovery, Discovery},
    dns::DnsResolver,
    relay::RelayMode,
    Endpoint,
};

use quic_rpc::transport::{boxed::BoxableServerEndpoint, quinn::QuinnServerEndpoint};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error_span, trace, Instrument};

use crate::{
    client::RPC_ALPN,
    node::{
        nodes_storage::load_node_addrs,
        protocol::{BlobsProtocol, ProtocolMap},
        ProtocolHandler,
    },
    rpc_protocol::RpcService,
    util::{fs::load_secret_key, path::IrohPaths},
};

use super::{docs::DocsEngine, rpc_status::RpcStatus, IrohServerEndpoint, Node, NodeInner};

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_PORT: u16 = 11204;

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Default interval between GC runs.
const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60 * 5);

/// Storage backend for documents.
#[derive(Debug, Clone)]
pub enum DocsStorage {
    /// Disable docs completely.
    Disabled,
    /// In-memory storage.
    Memory,
    /// File-based persistent storage.
    Persistent(PathBuf),
}

/// Storage backend for spaces.
#[derive(Debug, Clone)]
pub enum SpacesStorage {
    /// Disable docs completely.
    Disabled,
    /// In-memory storage.
    Memory,
    /// File-based persistent storage.
    #[allow(unused)]
    Persistent(PathBuf),
}

/// Builder for the [`Node`].
///
/// You must supply a blob store and a document store.
///
/// Blob store implementations are available in [`iroh_blobs::store`].
/// Document store implementations are available in [`iroh_docs::store`].
///
/// Everything else is optional, with some sensible defaults.
///
/// The default **relay servers** are hosted by [number 0] on the `iroh.network` domain.  To
/// customise this use the [`Builder::relay_mode`] function.
///
/// For **node discovery** the default is to use the [number 0] hosted DNS server hosted on
/// `iroh.link`.  To customise this use the [`Builder::node_discovery`] function.
///
/// Note that some defaults change when running using `cfg(test)`, see the individual
/// methods for details.
///
/// Finally you can create and run the node by calling [`Builder::spawn`].
///
/// The returned [`Node`] is awaitable to know when it finishes.  It can be terminated
/// using [`Node::shutdown`].
///
/// [number 0]: https://n0.computer
#[derive(derive_more::Debug)]
pub struct Builder<D>
where
    D: Map,
{
    storage: StorageConfig,
    bind_port: Option<u16>,
    secret_key: SecretKey,
    rpc_endpoint: IrohServerEndpoint,
    rpc_addr: Option<SocketAddr>,
    blobs_store: D,
    keylog: bool,
    relay_mode: RelayMode,
    gc_policy: GcPolicy,
    dns_resolver: Option<DnsResolver>,
    node_discovery: DiscoveryConfig,
    docs_storage: DocsStorage,
    spaces_storage: SpacesStorage,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    /// Callback to register when a gc loop is done
    #[debug("callback")]
    gc_done_callback: Option<Box<dyn Fn() + Send>>,
    blob_events: EventSender,
}

/// Configuration for storage.
#[derive(Debug)]
pub enum StorageConfig {
    /// In memory
    Mem,
    /// On disk persistet, at this location.
    Persistent(PathBuf),
}

impl StorageConfig {
    fn default_author_storage(&self) -> DefaultAuthorStorage {
        match self {
            StorageConfig::Persistent(ref root) => {
                let path = IrohPaths::DefaultAuthor.with_root(root);
                DefaultAuthorStorage::Persistent(path)
            }
            StorageConfig::Mem => DefaultAuthorStorage::Mem,
        }
    }
}

/// Configuration for node discovery.
///
/// Node discovery enables connecting to other peers by only the [`NodeId`].  This usually
/// works by the nodes publishing their [`RelayUrl`] and/or their direct addresses to some
/// publicly available service.
///
/// [`NodeId`]: crate::base::key::NodeId
/// [`RelayUrl`]: crate::base::node_addr::RelayUrl
#[derive(Debug, Default)]
pub enum DiscoveryConfig {
    /// Use no node discovery mechanism.
    None,
    /// Use the default discovery mechanism.
    ///
    /// This uses two discovery services concurrently:
    ///
    /// - It publishes to a pkarr service operated by [number 0] which makes the information
    ///   available via DNS in the `iroh.link` domain.
    ///
    /// - It uses an mDNS-like system to announce itself on the local network.
    ///
    /// # Usage during tests
    ///
    /// Note that the default changes when compiling with `cfg(test)` or the `test-utils`
    /// cargo feature from [iroh-net] is enabled.  In this case only the Pkarr/DNS service
    /// is used, but on the `iroh.test` domain.  This domain is not integrated with the
    /// global DNS network and thus node discovery is effectively disabled.  To use node
    /// discovery in a test use the [`iroh_net::test_utils::DnsPkarrServer`] in the test and
    /// configure it here as a custom discovery mechanism ([`DiscoveryConfig::Custom`]).
    ///
    /// [number 0]: https://n0.computer
    /// [iroh-net]: crate::net
    #[default]
    Default,
    /// Use a custom discovery mechanism.
    Custom(Box<dyn Discovery>),
}

impl From<Box<ConcurrentDiscovery>> for DiscoveryConfig {
    fn from(value: Box<ConcurrentDiscovery>) -> Self {
        Self::Custom(value)
    }
}

/// A server endpoint that does nothing. Accept will never resolve.
///
/// This is used unless an external rpc endpoint is configured.
#[derive(Debug, Default)]
struct DummyServerEndpoint;

impl BoxableServerEndpoint<crate::rpc_protocol::Request, crate::rpc_protocol::Response>
    for DummyServerEndpoint
{
    fn clone_box(
        &self,
    ) -> Box<dyn BoxableServerEndpoint<crate::rpc_protocol::Request, crate::rpc_protocol::Response>>
    {
        Box::new(DummyServerEndpoint)
    }

    fn accept_bi_boxed(
        &self,
    ) -> quic_rpc::transport::boxed::AcceptFuture<
        crate::rpc_protocol::Request,
        crate::rpc_protocol::Response,
    > {
        quic_rpc::transport::boxed::AcceptFuture::boxed(futures_lite::future::pending())
    }

    fn local_addr(&self) -> &[quic_rpc::transport::LocalAddr] {
        &[]
    }
}

fn mk_external_rpc() -> IrohServerEndpoint {
    quic_rpc::transport::boxed::ServerEndpoint::new(DummyServerEndpoint)
}

impl Default for Builder<iroh_blobs::store::mem::Store> {
    fn default() -> Self {
        // Use staging in testing
        #[cfg(not(any(test, feature = "test-utils")))]
        let relay_mode = RelayMode::Default;
        #[cfg(any(test, feature = "test-utils"))]
        let relay_mode = RelayMode::Staging;

        Self {
            storage: StorageConfig::Mem,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store: Default::default(),
            keylog: false,
            relay_mode,
            dns_resolver: None,
            rpc_endpoint: mk_external_rpc(),
            rpc_addr: None,
            gc_policy: GcPolicy::Disabled,
            docs_storage: DocsStorage::Memory,
            spaces_storage: SpacesStorage::Memory,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: None,
            blob_events: Default::default(),
        }
    }
}

impl<D: Map> Builder<D> {
    /// Creates a new builder for [`Node`] using the given databases.
    pub fn with_db_and_store(
        blobs_store: D,
        docs_storage: DocsStorage,
        storage: StorageConfig,
    ) -> Self {
        // Use staging in testing
        #[cfg(not(any(test, feature = "test-utils")))]
        let relay_mode = RelayMode::Default;
        #[cfg(any(test, feature = "test-utils"))]
        let relay_mode = RelayMode::Staging;

        Self {
            storage,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store,
            keylog: false,
            relay_mode,
            dns_resolver: None,
            rpc_endpoint: mk_external_rpc(),
            rpc_addr: None,
            gc_policy: GcPolicy::Disabled,
            docs_storage,
            // TODO: Expose in function
            spaces_storage: SpacesStorage::Disabled,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: None,
            blob_events: Default::default(),
        }
    }
}

impl<D> Builder<D>
where
    D: BaoStore,
{
    /// Configure a blob events sender. This will replace the previous blob
    /// event sender. By default, no events are sent.
    ///
    /// To define an event sender, implement the [`iroh_blobs::provider::CustomEventSender`] trait.
    pub fn blobs_events(mut self, blob_events: impl Into<EventSender>) -> Self {
        self.blob_events = blob_events.into();
        self
    }

    /// Persist all node data in the provided directory.
    pub async fn persist(
        self,
        root: impl AsRef<Path>,
    ) -> Result<Builder<iroh_blobs::store::fs::Store>> {
        let root = root.as_ref();
        let blob_dir = IrohPaths::BaoStoreDir.with_root(root);

        tokio::fs::create_dir_all(&blob_dir).await?;
        let blobs_store = iroh_blobs::store::fs::Store::load(&blob_dir)
            .await
            .with_context(|| {
                format!("Failed to load blobs database from {}", blob_dir.display())
            })?;
        let docs_storage = DocsStorage::Persistent(IrohPaths::DocsDatabase.with_root(root));

        let secret_key_path = IrohPaths::SecretKey.with_root(root);
        let secret_key = load_secret_key(secret_key_path).await?;

        Ok(Builder {
            storage: StorageConfig::Persistent(root.into()),
            bind_port: self.bind_port,
            secret_key,
            blobs_store,
            keylog: self.keylog,
            rpc_endpoint: self.rpc_endpoint,
            rpc_addr: self.rpc_addr,
            relay_mode: self.relay_mode,
            dns_resolver: self.dns_resolver,
            gc_policy: self.gc_policy,
            docs_storage,
            // TODO: Switch to SpacesStorage::Persistent once we have a store.
            spaces_storage: SpacesStorage::Disabled,
            node_discovery: self.node_discovery,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: self.gc_done_callback,
            blob_events: self.blob_events,
        })
    }

    /// Configure rpc endpoint.
    pub fn rpc_endpoint(self, value: IrohServerEndpoint, rpc_addr: Option<SocketAddr>) -> Self {
        Self {
            rpc_endpoint: value,
            rpc_addr,
            ..self
        }
    }

    /// Configure the default iroh rpc endpoint, on the default address.
    pub async fn enable_rpc(self) -> Result<Builder<D>> {
        self.enable_rpc_with_addr(DEFAULT_RPC_ADDR).await
    }

    /// Configure the default iroh rpc endpoint.
    pub async fn enable_rpc_with_addr(self, mut rpc_addr: SocketAddr) -> Result<Builder<D>> {
        let (ep, actual_rpc_port) = make_rpc_endpoint(&self.secret_key, rpc_addr)?;
        rpc_addr.set_port(actual_rpc_port);

        let ep = quic_rpc::transport::boxed::ServerEndpoint::new(ep);
        if let StorageConfig::Persistent(ref root) = self.storage {
            // store rpc endpoint
            RpcStatus::store(root, actual_rpc_port).await?;
        }

        Ok(Self {
            rpc_endpoint: ep,
            rpc_addr: Some(rpc_addr),
            ..self
        })
    }

    /// Sets the garbage collection policy.
    ///
    /// By default garbage collection is disabled.
    pub fn gc_policy(mut self, gc_policy: GcPolicy) -> Self {
        self.gc_policy = gc_policy;
        self
    }

    /// Disables documents support on this node completely.
    pub fn disable_docs(mut self) -> Self {
        self.docs_storage = DocsStorage::Disabled;
        self
    }

    /// Disables spaces support on this node completely.
    pub fn disable_spaces(mut self) -> Self {
        self.spaces_storage = SpacesStorage::Disabled;
        self
    }

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to discover other nodes by `PublicKey` and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [`RelayMode::Custom`], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`iroh_net::relay::RelayMode`] is provided
    /// [`Self::spawn`] will result in an error.
    ///
    /// # Usage during tests
    ///
    /// Note that while the default is [`RelayMode::Default`], when using `cfg(test)` or
    /// when the `test-utils` cargo feature [`RelayMode::Staging`] is the default.
    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        self.relay_mode = relay_mode;
        self
    }

    /// Sets the node discovery mechanism.
    ///
    /// Node discovery enables connecting to other peers by only the [`NodeId`].  This
    /// usually works by the nodes publishing their [`RelayUrl`] and/or their direct
    /// addresses to some publicly available service.
    ///
    /// See [`DiscoveryConfig::default`] for the defaults, note that the defaults change
    /// when using `cfg(test)`.
    ///
    /// [`NodeId`]: crate::base::key::NodeId
    /// [`RelayUrl`]: crate::base::node_addr::RelayUrl
    pub fn node_discovery(mut self, config: DiscoveryConfig) -> Self {
        self.node_discovery = config;
        self
    }

    /// Optionally set a custom DNS resolver to use for the magic endpoint.
    ///
    /// The DNS resolver is used to resolve relay hostnames, and node addresses if
    /// [`DnsDiscovery`] is configured (which is the default).
    ///
    /// By default, all magic endpoints share a DNS resolver, which is configured to use the
    /// host system's DNS configuration. You can pass a custom instance of [`DnsResolver`]
    /// here to use a differently configured DNS resolver for this endpoint.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Binds the node service to a different socket.
    ///
    /// By default it binds to `127.0.0.1:11204`.
    pub fn bind_port(mut self, port: u16) -> Self {
        self.bind_port.replace(port);
        self
    }

    /// Uses the given [`SecretKey`] for the `PublicKey` instead of a newly generated one.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = secret_key;
        self
    }

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn insecure_skip_relay_cert_verify(mut self, skip_verify: bool) -> Self {
        self.insecure_skip_relay_cert_verify = skip_verify;
        self
    }

    /// Register a callback for when GC is done.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn register_gc_done_cb(mut self, cb: Box<dyn Fn() + Send>) -> Self {
        self.gc_done_callback.replace(cb);
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

    /// Spawns the [`Node`] in a tokio task.
    ///
    /// This will create the underlying network server and spawn a tokio task accepting
    /// connections.  The returned [`Node`] can be used to control the task as well as
    /// get information about it.
    pub async fn spawn(self) -> Result<Node<D>> {
        let unspawned_node = self.build().await?;
        unspawned_node.spawn().await
    }

    /// Builds a node without spawning it.
    ///
    /// Returns a [`ProtocolBuilder`], on which custom protocols can be registered with
    /// [`ProtocolBuilder::accept`]. To spawn the node, call [`ProtocolBuilder::spawn`].
    pub async fn build(self) -> Result<ProtocolBuilder<D>> {
        // Clone the blob store to shutdown in case of error.
        let blobs_store = self.blobs_store.clone();
        match self.build_inner().await {
            Ok(node) => Ok(node),
            Err(err) => {
                blobs_store.shutdown().await;
                Err(err)
            }
        }
    }

    async fn build_inner(self) -> Result<ProtocolBuilder<D>> {
        trace!("building node");
        let lp = LocalPool::new(local_pool::Config {
            panic_mode: PanicMode::LogAndContinue,
            ..Default::default()
        });
        let (endpoint, nodes_data_path) = {
            let discovery: Option<Box<dyn Discovery>> = match self.node_discovery {
                DiscoveryConfig::None => None,
                DiscoveryConfig::Custom(discovery) => Some(discovery),
                DiscoveryConfig::Default => {
                    #[cfg(not(test))]
                    let discovery = {
                        let mut discovery_services: Vec<Box<dyn Discovery>> = vec![
                            // Enable DNS discovery by default
                            Box::new(DnsDiscovery::n0_dns()),
                            // Enable pkarr publishing by default
                            Box::new(PkarrPublisher::n0_dns(self.secret_key.clone())),
                        ];
                        // Enable local swarm discovery by default, but fail silently if it errors
                        match LocalSwarmDiscovery::new(self.secret_key.public()) {
                            Err(e) => {
                                tracing::error!("unable to start LocalSwarmDiscoveryService: {e:?}")
                            }
                            Ok(service) => {
                                discovery_services.push(Box::new(service));
                            }
                        }
                        ConcurrentDiscovery::from_services(discovery_services)
                    };
                    #[cfg(test)]
                    let discovery = ConcurrentDiscovery::from_services(vec![
                        // Enable DNS discovery by default
                        Box::new(DnsDiscovery::n0_dns()),
                        // Enable pkarr publishing by default
                        Box::new(PkarrPublisher::n0_dns(self.secret_key.clone())),
                    ]);
                    Some(Box::new(discovery))
                }
            };

            let endpoint = Endpoint::builder()
                .secret_key(self.secret_key.clone())
                .proxy_from_env()
                .keylog(self.keylog)
                .relay_mode(self.relay_mode);
            let endpoint = match discovery {
                Some(discovery) => endpoint.discovery(discovery),
                None => endpoint,
            };
            let mut endpoint = match self.dns_resolver {
                Some(resolver) => endpoint.dns_resolver(resolver),
                None => endpoint,
            };

            #[cfg(any(test, feature = "test-utils"))]
            {
                endpoint =
                    endpoint.insecure_skip_relay_cert_verify(self.insecure_skip_relay_cert_verify);
            }

            let nodes_data_path = match self.storage {
                StorageConfig::Persistent(ref root) => {
                    let nodes_data_path = IrohPaths::PeerData.with_root(root);
                    let node_addrs = load_node_addrs(&nodes_data_path)
                        .await
                        .context("loading known node addresses")?;
                    endpoint = endpoint.known_nodes(node_addrs);
                    Some(nodes_data_path)
                }
                StorageConfig::Mem => None,
            };
            let bind_port = self.bind_port.unwrap_or(DEFAULT_BIND_PORT);
            (endpoint.bind(bind_port).await?, nodes_data_path)
        };
        trace!("created endpoint");

        let addr = endpoint.node_addr().await?;
        trace!("endpoint address: {addr:?}");

        // Initialize the gossip protocol.
        let gossip = Gossip::from_endpoint(endpoint.clone(), Default::default(), &addr.info);
        // Initialize the downloader.
        let downloader = Downloader::new(self.blobs_store.clone(), endpoint.clone(), lp.clone());

        // Spawn the docs engine, if enabled.
        // This returns None for DocsStorage::Disabled, otherwise Some(DocsEngine).
        let docs = DocsEngine::spawn(
            self.docs_storage,
            self.blobs_store.clone(),
            self.storage.default_author_storage(),
            endpoint.clone(),
            gossip.clone(),
            downloader.clone(),
        )
        .await?;

        let willow = match self.spaces_storage {
            SpacesStorage::Disabled => None,
            SpacesStorage::Memory => {
                let blobs_store = self.blobs_store.clone();
                let create_store = move || iroh_willow::store::memory::Store::new(blobs_store);
                let engine = iroh_willow::Engine::spawn(
                    endpoint.clone(),
                    create_store,
                    iroh_willow::engine::AcceptOpts::default(),
                );
                Some(engine)
            }
            SpacesStorage::Persistent(_) => {
                unimplemented!("persistent storage for willow is not yet implemented")
            }
        };
        // Spawn the willow engine.
        // TODO: Allow to disable.

        // Initialize the internal RPC connection.
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection::<RpcService>(32);
        let internal_rpc = quic_rpc::transport::boxed::ServerEndpoint::new(internal_rpc);
        // box the controller. Boxing has a special case for the flume channel that avoids allocations,
        // so this has zero overhead.
        let controller = quic_rpc::transport::boxed::Connection::new(controller);
        let client = crate::client::Iroh::new(quic_rpc::RpcClient::new(controller.clone()));

        let inner = Arc::new(NodeInner {
            rpc_addr: self.rpc_addr,
            db: self.blobs_store,
            docs,
            endpoint,
            secret_key: self.secret_key,
            client,
            cancel_token: CancellationToken::new(),
            downloader,
            gossip,
            local_pool_handle: lp.handle().clone(),
            blob_batches: Default::default(),
            willow,
        });

        let protocol_builder = ProtocolBuilder {
            inner,
            protocols: Default::default(),
            internal_rpc,
            external_rpc: self.rpc_endpoint,
            gc_policy: self.gc_policy,
            gc_done_callback: self.gc_done_callback,
            nodes_data_path,
            local_pool: lp,
        };

        let protocol_builder = protocol_builder.register_iroh_protocols(self.blob_events);

        Ok(protocol_builder)
    }
}

/// A node that is initialized but not yet spawned.
///
/// This is returned from [`Builder::build`] and may be used to register custom protocols with
/// [`Self::accept`]. It provides access to the services which are already started, the node's
/// endpoint and a client to the node.
///
/// Note that RPC calls performed with client returned from [`Self::client`] will not complete
/// until the node is spawned.
#[derive(derive_more::Debug)]
pub struct ProtocolBuilder<D> {
    inner: Arc<NodeInner<D>>,
    internal_rpc: IrohServerEndpoint,
    external_rpc: IrohServerEndpoint,
    protocols: ProtocolMap,
    #[debug("callback")]
    gc_done_callback: Option<Box<dyn Fn() + Send>>,
    gc_policy: GcPolicy,
    nodes_data_path: Option<PathBuf>,
    local_pool: LocalPool,
}

impl<D: iroh_blobs::store::Store> ProtocolBuilder<D> {
    /// Registers a protocol handler for incoming connections.
    ///
    /// Use this to register custom protocols onto the iroh node. Whenever a new connection for
    /// `alpn` comes in, it is passed to this protocol handler.
    ///
    /// See the [`ProtocolHandler`] trait for details.
    ///
    /// Example usage:
    ///
    /// ```rust
    /// # use std::sync::Arc;
    /// # use anyhow::Result;
    /// # use futures_lite::future::Boxed as BoxedFuture;
    /// # use iroh::{node::{Node, ProtocolHandler}, net::endpoint::Connecting, client::Iroh};
    /// #
    /// # #[tokio::main]
    /// # async fn main() -> Result<()> {
    ///
    /// const MY_ALPN: &[u8] = b"my-protocol/1";
    ///
    /// #[derive(Debug)]
    /// struct MyProtocol {
    ///     client: Iroh
    /// }
    ///
    /// impl ProtocolHandler for MyProtocol {
    ///     fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
    ///         todo!();
    ///     }
    /// }
    ///
    /// let unspawned_node = Node::memory()
    ///     .build()
    ///     .await?;
    ///
    /// let client = unspawned_node.client().clone();
    /// let handler = MyProtocol { client };
    ///
    /// let node = unspawned_node
    ///     .accept(MY_ALPN, Arc::new(handler))
    ///     .spawn()
    ///     .await?;
    /// # node.shutdown().await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    ///
    pub fn accept(mut self, alpn: &'static [u8], handler: Arc<dyn ProtocolHandler>) -> Self {
        self.protocols.insert(alpn, handler);
        self
    }

    /// Returns a client to control this node over an in-memory channel.
    ///
    /// Note that RPC calls performed with the client will not complete until the node is
    /// spawned.
    pub fn client(&self) -> &crate::client::Iroh {
        &self.inner.client
    }

    /// Returns the [`Endpoint`] of the node.
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// Returns the [`crate::blobs::store::Store`] used by the node.
    pub fn blobs_db(&self) -> &D {
        &self.inner.db
    }

    /// Returns a reference to the used [`LocalPoolHandle`].
    pub fn local_pool_handle(&self) -> &LocalPoolHandle {
        self.local_pool.handle()
    }

    /// Returns a reference to the [`Downloader`] used by the node.
    pub fn downloader(&self) -> &Downloader {
        &self.inner.downloader
    }

    /// Returns a reference to the [`Gossip`] handle used by the node.
    pub fn gossip(&self) -> &Gossip {
        &self.inner.gossip
    }

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.protocols.get_typed(alpn)
    }

    /// Registers the core iroh protocols (blobs, gossip, docs).
    fn register_iroh_protocols(mut self, blob_events: EventSender) -> Self {
        // Register blobs.
        let blobs_proto = BlobsProtocol::new_with_events(
            self.blobs_db().clone(),
            self.local_pool_handle().clone(),
            blob_events,
        );
        self = self.accept(iroh_blobs::protocol::ALPN, Arc::new(blobs_proto));

        // Register gossip.
        let gossip = self.gossip().clone();
        self = self.accept(GOSSIP_ALPN, Arc::new(gossip));

        // Register docs, if enabled.
        if let Some(docs) = self.inner.docs.clone() {
            self = self.accept(DOCS_ALPN, Arc::new(docs));
        }

        if let Some(engine) = self.inner.willow.clone() {
            self = self.accept(iroh_willow::ALPN, Arc::new(engine));
        }

        self
    }

    /// Spawns the node and starts accepting connections.
    pub async fn spawn(self) -> Result<Node<D>> {
        let Self {
            inner,
            internal_rpc,
            external_rpc,
            protocols,
            gc_done_callback,
            gc_policy,
            nodes_data_path,
            local_pool: rt,
        } = self;
        let protocols = Arc::new(protocols);
        let node_id = inner.endpoint.node_id();

        // Update the endpoint with our alpns.
        let alpns = protocols
            .alpns()
            .map(|alpn| alpn.to_vec())
            .collect::<Vec<_>>();
        if let Err(err) = inner.endpoint.set_alpns(alpns) {
            inner.shutdown(protocols).await;
            return Err(err);
        }

        // Spawn the main task and store it in the node for structured termination in shutdown.
        let fut = inner
            .clone()
            .run(
                external_rpc,
                internal_rpc,
                protocols.clone(),
                gc_policy,
                gc_done_callback,
                nodes_data_path,
                rt,
            )
            .instrument(error_span!("node", me=%node_id.fmt_short()));
        let task = tokio::task::spawn(fut);

        let node = Node {
            inner,
            protocols,
            task: task.into(),
        };

        // Wait for a single direct address update, to make sure
        // we found at least one direct address.
        let wait_for_endpoints = {
            let node = node.clone();
            async move {
                tokio::time::timeout(ENDPOINT_WAIT, node.endpoint().direct_addresses().next())
                    .await
                    .context("waiting for endpoint")?
                    .context("no endpoints")?;
                Ok(())
            }
        };

        if let Err(err) = wait_for_endpoints.await {
            node.shutdown().await.ok();
            return Err(err);
        }

        Ok(node)
    }
}

/// Policy for garbage collection.
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcPolicy {
    /// Garbage collection is disabled.
    Disabled,
    /// Garbage collection is run at the given interval.
    Interval(Duration),
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self::Interval(DEFAULT_GC_INTERVAL)
    }
}

const DEFAULT_RPC_PORT: u16 = 0x1337;
const MAX_RPC_STREAMS: u32 = 1024;

/// The default bind addr of the RPC .
pub const DEFAULT_RPC_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_RPC_PORT));

/// Makes a an RPC endpoint that uses a QUIC transport.
///
/// Note that this uses the Quinn version used by quic-rpc.
fn make_rpc_endpoint(
    secret_key: &SecretKey,
    mut rpc_addr: SocketAddr,
) -> Result<(QuinnServerEndpoint<RpcService>, u16)> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_concurrent_bidi_streams(MAX_RPC_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into());
    let server_config = iroh_net::endpoint::make_server_config(
        secret_key,
        vec![RPC_ALPN.to_vec()],
        Arc::new(transport_config),
        false,
    )?;

    let rpc_quinn_endpoint = quinn::Endpoint::server(server_config.clone(), rpc_addr);
    let rpc_quinn_endpoint = match rpc_quinn_endpoint {
        Ok(ep) => ep,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AddrInUse {
                tracing::warn!(
                    "RPC port: {} already in use, switching to random port",
                    rpc_addr,
                );
                // Use a random port
                rpc_addr.set_port(0);
                quinn::Endpoint::server(server_config, rpc_addr)?
            } else {
                return Err(err.into());
            }
        }
    };

    let actual_rpc_port = rpc_quinn_endpoint.local_addr()?.port();
    let rpc_endpoint = QuinnServerEndpoint::<RpcService>::new(rpc_quinn_endpoint)?;

    Ok((rpc_endpoint, actual_rpc_port))
}
