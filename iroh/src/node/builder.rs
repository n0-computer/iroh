use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use iroh_base::key::SecretKey;
use iroh_blobs::{
    downloader::Downloader,
    store::{Map, Store as BaoStore},
};
use iroh_docs::engine::DefaultAuthorStorage;
use iroh_docs::net::DOCS_ALPN;
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_net::{
    discovery::{dns::DnsDiscovery, pkarr_publish::PkarrPublisher, ConcurrentDiscovery, Discovery},
    dns::DnsResolver,
    relay::RelayMode,
    Endpoint,
};
use quic_rpc::{
    transport::{
        flume::FlumeServerEndpoint, misc::DummyServerEndpoint, quinn::QuinnServerEndpoint,
    },
    ServiceEndpoint,
};
use serde::{Deserialize, Serialize};
use tokio_util::{sync::CancellationToken, task::LocalPoolHandle};
use tracing::{debug, error_span, trace, Instrument};

use crate::{
    client::RPC_ALPN,
    node::{
        protocol::{BlobsProtocol, ProtocolMap},
        ProtocolHandler,
    },
    rpc_protocol::RpcService,
    util::{fs::load_secret_key, path::IrohPaths},
};

use super::{docs::DocsEngine, rpc_status::RpcStatus, Node, NodeInner};

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_PORT: u16 = 11204;

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Default interval between GC runs.
const DEFAULT_GC_INTERVAL: Duration = Duration::from_secs(60 * 5);

const MAX_CONNECTIONS: u32 = 1024;
const MAX_STREAMS: u64 = 10;

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

/// Builder for the [`Node`].
///
/// You must supply a blob store and a document store.
///
/// Blob store implementations are available in [`iroh_blobs::store`].
/// Document store implementations are available in [`iroh_docs::store`].
///
/// Everything else is optional.
///
/// Finally you can create and run the node by calling [`Builder::spawn`].
///
/// The returned [`Node`] is awaitable to know when it finishes.  It can be terminated
/// using [`Node::shutdown`].
#[derive(derive_more::Debug)]
pub struct Builder<D, E = DummyServerEndpoint>
where
    D: Map,
    E: ServiceEndpoint<RpcService>,
{
    storage: StorageConfig,
    bind_port: Option<u16>,
    secret_key: SecretKey,
    rpc_endpoint: E,
    blobs_store: D,
    keylog: bool,
    relay_mode: RelayMode,
    gc_policy: GcPolicy,
    dns_resolver: Option<DnsResolver>,
    node_discovery: DiscoveryConfig,
    docs_storage: DocsStorage,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    /// Callback to register when a gc loop is done
    #[debug("callback")]
    gc_done_callback: Option<Box<dyn Fn() + Send>>,
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
#[derive(Debug, Default)]
pub enum DiscoveryConfig {
    /// Use no node discovery mechanism.
    None,
    /// Use the default discovery mechanism.
    ///
    /// This enables the [`DnsDiscovery`] service.
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

impl Default for Builder<iroh_blobs::store::mem::Store> {
    fn default() -> Self {
        Self {
            storage: StorageConfig::Mem,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store: Default::default(),
            keylog: false,
            relay_mode: RelayMode::Default,
            dns_resolver: None,
            rpc_endpoint: Default::default(),
            gc_policy: GcPolicy::Disabled,
            docs_storage: DocsStorage::Memory,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: None,
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
        Self {
            storage,
            bind_port: None,
            secret_key: SecretKey::generate(),
            blobs_store,
            keylog: false,
            relay_mode: RelayMode::Default,
            dns_resolver: None,
            rpc_endpoint: Default::default(),
            gc_policy: GcPolicy::Disabled,
            docs_storage,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: None,
        }
    }
}

impl<D, E> Builder<D, E>
where
    D: BaoStore,
    E: ServiceEndpoint<RpcService>,
{
    /// Persist all node data in the provided directory.
    pub async fn persist(
        self,
        root: impl AsRef<Path>,
    ) -> Result<Builder<iroh_blobs::store::fs::Store, E>> {
        let root = root.as_ref();
        let blob_dir = IrohPaths::BaoStoreDir.with_root(root);

        tokio::fs::create_dir_all(&blob_dir).await?;
        let blobs_store = iroh_blobs::store::fs::Store::load(&blob_dir)
            .await
            .with_context(|| {
                format!("Failed to load blobs database from {}", blob_dir.display())
            })?;
        let docs_storage = DocsStorage::Persistent(IrohPaths::DocsDatabase.with_root(root));

        let v0 = blobs_store
            .import_flat_store(iroh_blobs::store::fs::FlatStorePaths {
                complete: root.join("blobs.v0"),
                partial: root.join("blobs-partial.v0"),
                meta: root.join("blobs-meta.v0"),
            })
            .await?;
        let v1 = blobs_store
            .import_flat_store(iroh_blobs::store::fs::FlatStorePaths {
                complete: root.join("blobs.v1").join("complete"),
                partial: root.join("blobs.v1").join("partial"),
                meta: root.join("blobs.v1").join("meta"),
            })
            .await?;
        if v0 || v1 {
            tracing::info!("flat data was imported - reapply inline options");
            blobs_store
                .update_inline_options(iroh_blobs::store::fs::InlineOptions::default(), true)
                .await?;
        }

        let secret_key_path = IrohPaths::SecretKey.with_root(root);
        let secret_key = load_secret_key(secret_key_path).await?;

        Ok(Builder {
            storage: StorageConfig::Persistent(root.into()),
            bind_port: self.bind_port,
            secret_key,
            blobs_store,
            keylog: self.keylog,
            rpc_endpoint: self.rpc_endpoint,
            relay_mode: self.relay_mode,
            dns_resolver: self.dns_resolver,
            gc_policy: self.gc_policy,
            docs_storage,
            node_discovery: self.node_discovery,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            gc_done_callback: self.gc_done_callback,
        })
    }

    /// Configure rpc endpoint, changing the type of the builder to the new endpoint type.
    pub fn rpc_endpoint<E2: ServiceEndpoint<RpcService>>(self, value: E2) -> Builder<D, E2> {
        // we can't use ..self here because the return type is different
        Builder {
            storage: self.storage,
            bind_port: self.bind_port,
            secret_key: self.secret_key,
            blobs_store: self.blobs_store,
            keylog: self.keylog,
            rpc_endpoint: value,
            relay_mode: self.relay_mode,
            dns_resolver: self.dns_resolver,
            gc_policy: self.gc_policy,
            docs_storage: self.docs_storage,
            node_discovery: self.node_discovery,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: self.insecure_skip_relay_cert_verify,
            gc_done_callback: self.gc_done_callback,
        }
    }

    /// Configure the default iroh rpc endpoint.
    pub async fn enable_rpc(self) -> Result<Builder<D, QuinnServerEndpoint<RpcService>>> {
        let (ep, actual_rpc_port) = make_rpc_endpoint(&self.secret_key, DEFAULT_RPC_PORT)?;
        if let StorageConfig::Persistent(ref root) = self.storage {
            // store rpc endpoint
            RpcStatus::store(root, actual_rpc_port).await?;
        }

        Ok(Builder {
            storage: self.storage,
            bind_port: self.bind_port,
            secret_key: self.secret_key,
            blobs_store: self.blobs_store,
            keylog: self.keylog,
            rpc_endpoint: ep,
            relay_mode: self.relay_mode,
            dns_resolver: self.dns_resolver,
            gc_policy: self.gc_policy,
            docs_storage: self.docs_storage,
            node_discovery: self.node_discovery,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: self.insecure_skip_relay_cert_verify,
            gc_done_callback: self.gc_done_callback,
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

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to discover other nodes by `PublicKey` and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`iroh_net::relay::RelayMode`]
    /// is provided [`Self::spawn`] will result in an error.
    pub fn relay_mode(mut self, dm: RelayMode) -> Self {
        self.relay_mode = dm;
        self
    }

    /// Sets the node discovery mechanism.
    ///
    /// The default is [`DiscoveryConfig::Default`]. Use [`DiscoveryConfig::Custom`] to pass a
    /// custom [`Discovery`].
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
    /// Returns an [`ProtocolBuilder`], on which custom protocols can be registered with
    /// [`ProtocolBuilder::accept`]. To spawn the node, call [`ProtocolBuilder::spawn`].
    pub async fn build(self) -> Result<ProtocolBuilder<D, E>> {
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

    async fn build_inner(self) -> Result<ProtocolBuilder<D, E>> {
        trace!("building node");
        let lp = LocalPoolHandle::new(num_cpus::get());
        let endpoint = {
            let mut transport_config = quinn::TransportConfig::default();
            transport_config
                .max_concurrent_bidi_streams(MAX_STREAMS.try_into()?)
                .max_concurrent_uni_streams(0u32.into());

            let discovery: Option<Box<dyn Discovery>> = match self.node_discovery {
                DiscoveryConfig::None => None,
                DiscoveryConfig::Custom(discovery) => Some(discovery),
                DiscoveryConfig::Default => {
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
                .transport_config(transport_config)
                .concurrent_connections(MAX_CONNECTIONS)
                .relay_mode(self.relay_mode);
            let endpoint = match discovery {
                Some(discovery) => endpoint.discovery(discovery),
                None => endpoint,
            };
            let endpoint = match self.dns_resolver {
                Some(resolver) => endpoint.dns_resolver(resolver),
                None => endpoint,
            };

            #[cfg(any(test, feature = "test-utils"))]
            let endpoint =
                endpoint.insecure_skip_relay_cert_verify(self.insecure_skip_relay_cert_verify);

            let endpoint = match self.storage {
                StorageConfig::Persistent(ref root) => {
                    let peers_data_path = IrohPaths::PeerData.with_root(root);
                    endpoint.peers_data_path(peers_data_path)
                }
                StorageConfig::Mem => endpoint,
            };
            let bind_port = self.bind_port.unwrap_or(DEFAULT_BIND_PORT);
            endpoint.bind(bind_port).await?
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

        // Initialize the internal RPC connection.
        let (internal_rpc, controller) = quic_rpc::transport::flume::connection(1);
        // box the controller. Boxing has a special case for the flume channel that avoids allocations,
        // so this has zero overhead.
        let controller = quic_rpc::transport::boxed::Connection::new(controller);
        let client = crate::client::Iroh::new(quic_rpc::RpcClient::new(controller.clone()));

        let inner = Arc::new(NodeInner {
            db: self.blobs_store,
            docs,
            endpoint,
            secret_key: self.secret_key,
            client,
            cancel_token: CancellationToken::new(),
            rt: lp,
            downloader,
            gossip,
        });

        let protocol_builder = ProtocolBuilder {
            inner,
            protocols: Default::default(),
            internal_rpc,
            external_rpc: self.rpc_endpoint,
            gc_policy: self.gc_policy,
            gc_done_callback: self.gc_done_callback,
        };

        let protocol_builder = protocol_builder.register_iroh_protocols();

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
pub struct ProtocolBuilder<D, E> {
    inner: Arc<NodeInner<D>>,
    internal_rpc: FlumeServerEndpoint<RpcService>,
    external_rpc: E,
    protocols: ProtocolMap,
    #[debug("callback")]
    gc_done_callback: Option<Box<dyn Fn() + Send>>,
    gc_policy: GcPolicy,
}

impl<D: iroh_blobs::store::Store, E: ServiceEndpoint<RpcService>> ProtocolBuilder<D, E> {
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
        &self.inner.rt
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
    fn register_iroh_protocols(mut self) -> Self {
        // Register blobs.
        let blobs_proto =
            BlobsProtocol::new(self.blobs_db().clone(), self.local_pool_handle().clone());
        self = self.accept(iroh_blobs::protocol::ALPN, Arc::new(blobs_proto));

        // Register gossip.
        let gossip = self.gossip().clone();
        self = self.accept(GOSSIP_ALPN, Arc::new(gossip));

        // Register docs, if enabled.
        if let Some(docs) = self.inner.docs.clone() {
            self = self.accept(DOCS_ALPN, Arc::new(docs));
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
const MAX_RPC_CONNECTIONS: u32 = 16;
const MAX_RPC_STREAMS: u32 = 1024;

/// Makes a an RPC endpoint that uses a QUIC transport
fn make_rpc_endpoint(
    secret_key: &SecretKey,
    rpc_port: u16,
) -> Result<(QuinnServerEndpoint<RpcService>, u16)> {
    let rpc_addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, rpc_port);
    let mut transport_config = quinn::TransportConfig::default();
    transport_config
        .max_concurrent_bidi_streams(MAX_RPC_STREAMS.into())
        .max_concurrent_uni_streams(0u32.into());
    let mut server_config = iroh_net::endpoint::make_server_config(
        secret_key,
        vec![RPC_ALPN.to_vec()],
        Arc::new(transport_config),
        false,
    )?;
    server_config.concurrent_connections(MAX_RPC_CONNECTIONS);

    let rpc_quinn_endpoint = quinn::Endpoint::server(server_config.clone(), rpc_addr.into());
    let rpc_quinn_endpoint = match rpc_quinn_endpoint {
        Ok(ep) => ep,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AddrInUse {
                tracing::warn!(
                    "RPC port {} already in use, switching to random port",
                    rpc_port
                );
                // Use a random port
                quinn::Endpoint::server(
                    server_config,
                    SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
                )?
            } else {
                return Err(err.into());
            }
        }
    };

    let actual_rpc_port = rpc_quinn_endpoint.local_addr()?.port();
    let rpc_endpoint = QuinnServerEndpoint::<RpcService>::new(rpc_quinn_endpoint)?;

    Ok((rpc_endpoint, actual_rpc_port))
}
