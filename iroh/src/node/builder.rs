use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use futures_lite::StreamExt;
use futures_util::{FutureExt as _, TryFutureExt as _};
use iroh_base::key::SecretKey;
#[cfg(not(test))]
use iroh_net::discovery::local_swarm_discovery::LocalSwarmDiscovery;
use iroh_net::{
    discovery::{dns::DnsDiscovery, pkarr::PkarrPublisher, ConcurrentDiscovery, Discovery},
    dns::DnsResolver,
    endpoint::{force_staging_infra, TransportConfig},
    Endpoint, RelayMode,
};
use iroh_router::{ProtocolHandler, RouterBuilder};
use quic_rpc::transport::{boxed::BoxableListener, quinn::QuinnListener};
use tokio::task::JoinError;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{error_span, trace, Instrument};

use super::{rpc_status::RpcStatus, IrohServerEndpoint, JoinErrToStr, Node, NodeInner};
use crate::{
    client::RPC_ALPN,
    node::nodes_storage::load_node_addrs,
    util::{fs::load_secret_key, path::IrohPaths},
};

/// Default bind address for the node.
/// 11204 is "iroh" in leetspeak <https://simple.wikipedia.org/wiki/Leet>
pub const DEFAULT_BIND_PORT: u16 = 11204;

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// The default bind address for the iroh IPv4 socket.
pub const DEFAULT_BIND_ADDR_V4: SocketAddrV4 =
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_BIND_PORT);

/// The default bind address for the iroh IPv6 socket.
pub const DEFAULT_BIND_ADDR_V6: SocketAddrV6 =
    SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_BIND_PORT + 1, 0, 0);

/// Builder for the [`Node`].
///
/// You must supply a blob store and a document store.
///
/// Blob store implementations are available in [`iroh_blobs::store`].
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
pub struct Builder {
    storage: StorageConfig,
    addr_v4: SocketAddrV4,
    addr_v6: SocketAddrV6,
    secret_key: SecretKey,
    rpc_endpoint: IrohServerEndpoint,
    rpc_addr: Option<SocketAddr>,
    keylog: bool,
    relay_mode: RelayMode,
    dns_resolver: Option<DnsResolver>,
    node_discovery: DiscoveryConfig,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    transport_config: Option<TransportConfig>,
}

/// Configuration for storage.
#[derive(Debug)]
pub enum StorageConfig {
    /// In memory
    Mem,
    /// On disk persistet, at this location.
    Persistent(PathBuf),
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

impl BoxableListener<crate::rpc_protocol::Request, crate::rpc_protocol::Response>
    for DummyServerEndpoint
{
    fn clone_box(
        &self,
    ) -> Box<dyn BoxableListener<crate::rpc_protocol::Request, crate::rpc_protocol::Response>> {
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
    quic_rpc::transport::boxed::BoxedListener::new(DummyServerEndpoint)
}

impl Builder {
    /// Creates a default node builder with in memory configuration.
    pub fn memory() -> Self {
        // Use staging in testing
        let relay_mode = match force_staging_infra() {
            true => RelayMode::Staging,
            false => RelayMode::Default,
        };

        Self {
            storage: StorageConfig::Mem,
            addr_v4: DEFAULT_BIND_ADDR_V4,
            addr_v6: DEFAULT_BIND_ADDR_V6,
            secret_key: SecretKey::generate(),
            keylog: false,
            relay_mode,
            dns_resolver: None,
            rpc_endpoint: mk_external_rpc(),
            rpc_addr: None,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            transport_config: None,
        }
    }

    /// Creates a new builder for [`Node`] using the given databases.
    pub fn with_db_and_store(storage: StorageConfig) -> Self {
        // Use staging in testing
        let relay_mode = match force_staging_infra() {
            true => RelayMode::Staging,
            false => RelayMode::Default,
        };

        Self {
            storage,
            addr_v4: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DEFAULT_BIND_PORT),
            addr_v6: SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DEFAULT_BIND_PORT + 1, 0, 0),
            secret_key: SecretKey::generate(),
            keylog: false,
            relay_mode,
            dns_resolver: None,
            rpc_endpoint: mk_external_rpc(),
            rpc_addr: None,
            node_discovery: Default::default(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            transport_config: None,
        }
    }
}

impl Builder {
    /// Persist all node data in the provided directory.
    pub async fn persist(self, root: impl AsRef<Path>) -> Result<Builder> {
        let root = root.as_ref();
        let secret_key_path = IrohPaths::SecretKey.with_root(root);
        let secret_key = load_secret_key(secret_key_path).await?;

        Ok(Builder {
            storage: StorageConfig::Persistent(root.into()),
            addr_v4: self.addr_v4,
            addr_v6: self.addr_v6,
            secret_key,
            keylog: self.keylog,
            rpc_endpoint: self.rpc_endpoint,
            rpc_addr: self.rpc_addr,
            relay_mode: self.relay_mode,
            dns_resolver: self.dns_resolver,
            node_discovery: self.node_discovery,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            transport_config: self.transport_config,
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
    pub async fn enable_rpc(self) -> Result<Builder> {
        self.enable_rpc_with_addr(DEFAULT_RPC_ADDR).await
    }

    /// Configure the default iroh rpc endpoint.
    pub async fn enable_rpc_with_addr(self, mut rpc_addr: SocketAddr) -> Result<Builder> {
        let (ep, actual_rpc_port) = make_rpc_endpoint(&self.secret_key, rpc_addr)?;
        rpc_addr.set_port(actual_rpc_port);

        let ep = quic_rpc::transport::boxed::BoxedListener::new(ep);
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

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to discover other nodes by `PublicKey` and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [`RelayMode::Custom`], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`iroh_net::RelayMode`] is provided
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

    /// Binds the node service to a specific socket IPv4 address.
    ///
    /// By default this will be set to `0.0.0.0:11204`
    ///
    /// Setting the port to `0` will assign a random port.
    /// If the port used is not free, a random different port will be used.
    pub fn bind_addr_v4(mut self, addr: SocketAddrV4) -> Self {
        self.addr_v4 = addr;
        self
    }

    /// Binds the node service to a specific socket IPv6 address.
    ///
    /// By default this will be set to `[::]:11205`
    ///
    /// Setting the port to `0` will assign a random port.
    /// If the port used is not free, a random different port will be used.
    pub fn bind_addr_v6(mut self, addr: SocketAddrV6) -> Self {
        self.addr_v6 = addr;
        self
    }

    /// Use a random port for both IPv4 and IPv6.
    ///
    /// This is a convenience function useful when you do not need a specific port
    /// and want to avoid conflicts when running multiple instances, e.g. in tests.
    ///
    /// This overrides the ports of the socket addresses provided by [`Builder::bind_addr_v4`]
    /// and [`Builder::bind_addr_v6`].  By default both of those bind to the
    /// unspecified address, which would result in `0.0.0.0:11204` and `[::]:11205` as bind
    /// addresses unless they are changed.
    pub fn bind_random_port(mut self) -> Self {
        self.addr_v4.set_port(0);
        self.addr_v6.set_port(0);
        self
    }

    /// Uses the given [`SecretKey`] for the `PublicKey` instead of a newly generated one.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = secret_key;
        self
    }

    /// Sets a custom [`TransportConfig`] to be used by the [`Endpoint`].
    ///
    /// If not set, the [`Endpoint`] will use its default [`TransportConfig`]. See
    /// [`crate::net::endpoint::Builder::transport_config`] for details.
    pub fn transport_config(mut self, config: TransportConfig) -> Self {
        self.transport_config = Some(config);
        self
    }

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    #[cfg_attr(iroh_docsrs, doc(cfg(any(test, feature = "test-utils"))))]
    pub fn insecure_skip_relay_cert_verify(mut self, skip_verify: bool) -> Self {
        self.insecure_skip_relay_cert_verify = skip_verify;
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
    pub async fn spawn(self) -> Result<Node> {
        let unspawned_node = self.build().await?;
        unspawned_node.spawn().await
    }

    /// Builds a node without spawning it.
    ///
    /// Returns a [`ProtocolBuilder`], on which custom protocols can be registered with
    /// [`ProtocolBuilder::accept`]. To spawn the node, call [`ProtocolBuilder::spawn`].
    pub async fn build(self) -> Result<ProtocolBuilder> {
        trace!("building node");
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

            let endpoint = match self.transport_config {
                Some(config) => endpoint.transport_config(config),
                None => endpoint,
            };
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

            (
                endpoint
                    .bind_addr_v4(self.addr_v4)
                    .bind_addr_v6(self.addr_v6)
                    .bind()
                    .await?,
                nodes_data_path,
            )
        };
        trace!("created endpoint");

        let addr = endpoint.node_addr().await?;
        trace!("endpoint address: {addr:?}");

        // Initialize the internal RPC connection.
        let (internal_rpc, controller) = quic_rpc::transport::flume::channel(32);
        let internal_rpc = quic_rpc::transport::boxed::BoxedListener::new(internal_rpc);
        // box the controller. Boxing has a special case for the flume channel that avoids allocations,
        // so this has zero overhead.
        let controller = quic_rpc::transport::boxed::BoxedConnector::new(controller);
        let client = crate::client::Iroh::new(quic_rpc::RpcClient::new(controller.clone()));

        let inner = Arc::new(NodeInner {
            rpc_addr: self.rpc_addr,
            endpoint: endpoint.clone(),
            client,
            cancel_token: CancellationToken::new(),
        });

        let protocol_builder = ProtocolBuilder {
            inner,
            router: RouterBuilder::new(endpoint),
            internal_rpc,
            external_rpc: self.rpc_endpoint,
            nodes_data_path,
        };

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
pub struct ProtocolBuilder {
    inner: Arc<NodeInner>,
    internal_rpc: IrohServerEndpoint,
    external_rpc: IrohServerEndpoint,
    router: RouterBuilder,
    nodes_data_path: Option<PathBuf>,
}

impl ProtocolBuilder {
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
    /// # use iroh::{node::{Node}, net::endpoint::Connecting, client::Iroh, router::ProtocolHandler};
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
    ///     .accept(MY_ALPN.to_vec(), Arc::new(handler))
    ///     .spawn()
    ///     .await?;
    /// # node.shutdown().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept(mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) -> Self {
        self.router = self.router.accept(alpn, handler);
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

    /// Returns a protocol handler for an ALPN.
    ///
    /// This downcasts to the concrete type and returns `None` if the handler registered for `alpn`
    /// does not match the passed type.
    pub fn get_protocol<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        self.router.get_protocol::<P>(alpn)
    }

    /// Spawns the node and starts accepting connections.
    pub async fn spawn(self) -> Result<Node> {
        let Self {
            inner,
            internal_rpc,
            external_rpc,
            router,
            nodes_data_path,
        } = self;
        let node_id = inner.endpoint.node_id();

        let router = router.spawn().await?;

        // Spawn the main task and store it in the node for structured termination in shutdown.
        let fut = inner
            .clone()
            .run(external_rpc, internal_rpc, router.clone(), nodes_data_path)
            .instrument(error_span!("node", me=%node_id.fmt_short()));
        let task = tokio::task::spawn(fut);

        let node = Node {
            inner,
            router,
            task: AbortOnDropHandle::new(task)
                .map_err(Box::new(|e: JoinError| e.to_string()) as JoinErrToStr)
                .shared(),
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
) -> Result<(
    QuinnListener<crate::rpc_protocol::Request, crate::rpc_protocol::Response>,
    u16,
)> {
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
    let rpc_endpoint = QuinnListener::new(rpc_quinn_endpoint)?;

    Ok((rpc_endpoint, actual_rpc_port))
}
