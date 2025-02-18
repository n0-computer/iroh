//! The [`Endpoint`] allows establishing connections to other iroh nodes.
//!
//! The [`Endpoint`] is the main API interface to manage a local iroh node.  It allows
//! connecting to and accepting connections from other nodes.  See the [module docs] for
//! more details on how iroh connections work.
//!
//! The main items in this module are:
//!
//! - [`Endpoint`] to establish iroh connections with other nodes.
//! - [`Builder`] to create an [`Endpoint`].
//!
//! [module docs]: crate

use std::{
    any::Any,
    collections::BTreeSet,
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use anyhow::{bail, Context, Result};
use data_encoding::BASE32_DNSSEC;
use iroh_base::{NodeAddr, NodeId, RelayUrl, SecretKey};
use iroh_relay::RelayMap;
use n0_future::time::Duration;
use pin_project::pin_project;
use tracing::{debug, instrument, trace, warn};
use url::Url;

use crate::{
    discovery::{
        dns::DnsDiscovery, pkarr::PkarrPublisher, ConcurrentDiscovery, Discovery, DiscoveryTask,
        UserData,
    },
    dns::DnsResolver,
    magicsock::{self, Handle, NodeIdMappedAddr},
    tls,
    watchable::Watcher,
};

mod rtt_actor;

// Missing still: SendDatagram and ConnectionClose::frame_type's Type.
pub use quinn::{
    AcceptBi, AcceptUni, AckFrequencyConfig, ApplicationClose, Chunk, ClosedStream,
    ConnectionClose, ConnectionError, ConnectionStats, MtuDiscoveryConfig, OpenBi, OpenUni,
    ReadDatagram, ReadError, ReadExactError, ReadToEndError, RecvStream, ResetError, RetryError,
    SendDatagramError, SendStream, ServerConfig, StoppedError, StreamId, TransportConfig, VarInt,
    WeakConnectionHandle, WriteError,
};
pub use quinn_proto::{
    congestion::{Controller, ControllerFactory},
    crypto::{
        AeadKey, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey,
        ServerConfig as CryptoServerConfig, UnsupportedVersion,
    },
    FrameStats, PathStats, TransportError, TransportErrorCode, UdpStats, Written,
};

use self::rtt_actor::RttMessage;
pub use super::magicsock::{
    ConnectionType, ControlMsg, DirectAddr, DirectAddrInfo, DirectAddrType, RemoteInfo, Source,
};

/// The delay to fall back to discovery when direct addresses fail.
///
/// When a connection is attempted with a [`NodeAddr`] containing direct addresses the
/// [`Endpoint`] assumes one of those addresses probably works.  If after this delay there
/// is still no connection the configured [`Discovery`] will be used however.
const DISCOVERY_WAIT_PERIOD: Duration = Duration::from_millis(500);

/// Maximum amount of TLS tickets we will cache (by default) for 0-RTT connection
/// establishment.
///
/// 8 tickets per remote endpoint, 32 different endpoints would max out the required storage:
/// ~200 bytes per session + certificates (which are ~387 bytes)
/// So 8 * 32 * (200 + 387) = 150.272 bytes, assuming pointers to certificates
/// are never aliased pointers (they're Arc'ed).
/// I think 150KB is an acceptable default upper limit for such a cache.
const MAX_TLS_TICKETS: usize = 8 * 32;

type DiscoveryBuilder = Box<dyn FnOnce(&SecretKey) -> Option<Box<dyn Discovery>> + Send + Sync>;

/// Defines the mode of path selection for all traffic flowing through
/// the endpoint.
#[cfg(any(test, feature = "test-utils"))]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub enum PathSelection {
    /// Uses all available paths
    #[default]
    All,
    /// Forces all traffic to go exclusively through relays
    RelayOnly,
}

/// Builder for [`Endpoint`].
///
/// By default the endpoint will generate a new random [`SecretKey`], which will result in a
/// new [`NodeId`].
///
/// To create the [`Endpoint`] call [`Builder::bind`].
#[derive(derive_more::Debug)]
pub struct Builder {
    secret_key: Option<SecretKey>,
    relay_mode: RelayMode,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: quinn::TransportConfig,
    keylog: bool,
    #[debug(skip)]
    discovery: Vec<DiscoveryBuilder>,
    discovery_user_data: Option<UserData>,
    proxy_url: Option<Url>,
    /// List of known nodes. See [`Builder::known_nodes`].
    node_map: Option<Vec<NodeAddr>>,
    dns_resolver: Option<DnsResolver>,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    addr_v4: Option<SocketAddrV4>,
    addr_v6: Option<SocketAddrV6>,
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
}

impl Default for Builder {
    fn default() -> Self {
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
        Self {
            secret_key: Default::default(),
            relay_mode: default_relay_mode(),
            alpn_protocols: Default::default(),
            transport_config,
            keylog: Default::default(),
            discovery: Default::default(),
            discovery_user_data: Default::default(),
            proxy_url: None,
            node_map: None,
            dns_resolver: None,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            addr_v4: None,
            addr_v6: None,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: PathSelection::default(),
        }
    }
}

impl Builder {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users.

    // # The final constructor that everyone needs.

    /// Binds the magic endpoint.
    pub async fn bind(self) -> Result<Endpoint> {
        let relay_map = self.relay_mode.relay_map();
        let secret_key = self
            .secret_key
            .unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng));
        let static_config = StaticConfig {
            transport_config: Arc::new(self.transport_config),
            keylog: self.keylog,
            secret_key: secret_key.clone(),
        };
        let dns_resolver = self.dns_resolver.unwrap_or_default();
        let discovery = self
            .discovery
            .into_iter()
            .filter_map(|f| f(&secret_key))
            .collect::<Vec<_>>();
        let discovery: Option<Box<dyn Discovery>> = match discovery.len() {
            0 => None,
            1 => Some(discovery.into_iter().next().expect("checked length")),
            _ => Some(Box::new(ConcurrentDiscovery::from_services(discovery))),
        };
        let server_config = static_config.create_server_config(self.alpn_protocols)?;

        let msock_opts = magicsock::Options {
            addr_v4: self.addr_v4,
            addr_v6: self.addr_v6,
            secret_key,
            relay_map,
            node_map: self.node_map,
            discovery,
            discovery_user_data: self.discovery_user_data,
            proxy_url: self.proxy_url,
            dns_resolver,
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: self.insecure_skip_relay_cert_verify,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: self.path_selection,
        };
        Endpoint::bind(static_config, msock_opts).await
    }

    // # The very common methods everyone basically needs.

    /// Sets the IPv4 bind address.
    ///
    /// Setting the port to `0` will use a random port.
    /// If the port specified is already in use, it will fallback to choosing a random port.
    ///
    /// By default will use `0.0.0.0:0` to bind to.
    pub fn bind_addr_v4(mut self, addr: SocketAddrV4) -> Self {
        self.addr_v4.replace(addr);
        self
    }

    /// Sets the IPv6 bind address.
    ///
    /// Setting the port to `0` will use a random port.
    /// If the port specified is already in use, it will fallback to choosing a random port.
    ///
    /// By default will use `[::]:0` to bind to.
    pub fn bind_addr_v6(mut self, addr: SocketAddrV6) -> Self {
        self.addr_v6.replace(addr);
        self
    }

    /// Sets a secret key to authenticate with other peers.
    ///
    /// This secret key's public key will be the [`PublicKey`] of this endpoint and thus
    /// also its [`NodeId`]
    ///
    /// If not set, a new secret key will be generated.
    ///
    /// [`PublicKey`]: iroh_base::PublicKey
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Sets the [ALPN] protocols that this endpoint will accept on incoming connections.
    ///
    /// Not setting this will still allow creating connections, but to accept incoming
    /// connections the [ALPN] must be set.
    ///
    /// [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
    pub fn alpns(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    // # Methods for common customisation items.

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// Relay servers are used to establish initial connection with another iroh node.
    /// They also perform various functions related to hole punching, see the [crate docs]
    /// for more details.
    ///
    /// By default the [number 0] relay servers are used, see [`RelayMode::Default`].
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid RelayMap is provided [`bind`]
    /// will result in an error.
    ///
    /// [`bind`]: Builder::bind
    /// [crate docs]: crate
    /// [number 0]: https://n0.computer
    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        self.relay_mode = relay_mode;
        self
    }

    /// Removes all discovery services from the builder.
    pub fn clear_discovery(mut self) -> Self {
        self.discovery.clear();
        self
    }

    /// Optionally sets a discovery mechanism for this endpoint.
    ///
    /// If you want to combine multiple discovery services, you can use
    /// [`Builder::add_discovery`] instead. This will internally create a
    /// [`crate::discovery::ConcurrentDiscovery`].
    ///
    /// If no discovery service is set, connecting to a node without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// See the documentation of the [`Discovery`] trait for details.
    pub fn discovery(mut self, discovery: Box<dyn Discovery>) -> Self {
        self.discovery.clear();
        self.discovery.push(Box::new(move |_| Some(discovery)));
        self
    }

    /// Adds a discovery mechanism for this endpoint.
    ///
    /// The function `discovery`
    /// will be called on endpoint creation with the configured secret key of
    /// the endpoint. Discovery services that need to publish information need
    /// to use this secret key to sign the information.
    ///
    /// If you add multiple discovery services, they will be combined using a
    /// [`crate::discovery::ConcurrentDiscovery`].
    ///
    /// If no discovery service is set, connecting to a node without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// To clear all discovery services, use [`Builder::clear_discovery`].
    ///
    /// See the documentation of the [`Discovery`] trait for details.
    pub fn add_discovery<F, D>(mut self, discovery: F) -> Self
    where
        F: FnOnce(&SecretKey) -> Option<D> + Send + Sync + 'static,
        D: Discovery + 'static,
    {
        let discovery: DiscoveryBuilder =
            Box::new(move |secret_key| discovery(secret_key).map(|x| Box::new(x) as _));
        self.discovery.push(discovery);
        self
    }

    /// Configures the endpoint to use the default n0 DNS discovery service.
    ///
    /// The default discovery service publishes to and resolves from the
    /// n0.computer dns server `iroh.link`.
    ///
    /// This is equivalent to adding both a [`crate::discovery::pkarr::PkarrPublisher`]
    /// and a [`crate::discovery::dns::DnsDiscovery`], both configured to use the
    /// n0.computer dns server.
    ///
    /// This will by default use [`N0_DNS_PKARR_RELAY_PROD`].
    /// When in tests, or when the `test-utils` feature is enabled, this will use the
    /// [`N0_DNS_PKARR_RELAY_STAGING`].
    ///
    /// [`N0_DNS_PKARR_RELAY_PROD`]: crate::discovery::pkarr::N0_DNS_PKARR_RELAY_PROD
    /// [`N0_DNS_PKARR_RELAY_STAGING`]: crate::discovery::pkarr::N0_DNS_PKARR_RELAY_STAGING
    pub fn discovery_n0(mut self) -> Self {
        self.discovery.push(Box::new(|secret_key| {
            Some(Box::new(PkarrPublisher::n0_dns(secret_key.clone())))
        }));
        self.discovery
            .push(Box::new(|_| Some(Box::new(DnsDiscovery::n0_dns()))));
        self
    }

    #[cfg(feature = "discovery-pkarr-dht")]
    /// Configures the endpoint to also use the mainline DHT with default settings.
    ///
    /// This is equivalent to adding a [`crate::discovery::pkarr::dht::DhtDiscovery`]
    /// with default settings. Note that DhtDiscovery has various more advanced
    /// configuration options. If you need any of those, you should manually
    /// create a DhtDiscovery and add it with [`Builder::add_discovery`].
    pub fn discovery_dht(mut self) -> Self {
        use crate::discovery::pkarr::dht::DhtDiscovery;
        self.discovery.push(Box::new(|secret_key| {
            match DhtDiscovery::builder()
                .secret_key(secret_key.clone())
                .build()
            {
                Ok(discovery) => Some(Box::new(discovery)),
                Err(err) => {
                    tracing::error!("failed to build discovery: {:?}", err);
                    None
                }
            }
        }));
        self
    }

    #[cfg(feature = "discovery-local-network")]
    /// Configures the endpoint to also use local network discovery.
    ///
    /// This is equivalent to adding a [`crate::discovery::local_swarm_discovery::LocalSwarmDiscovery`]
    /// with default settings. Note that LocalSwarmDiscovery has various more advanced
    /// configuration options. If you need any of those, you should manually
    /// create a LocalSwarmDiscovery and add it with [`Builder::add_discovery`].
    pub fn discovery_local_network(mut self) -> Self {
        use crate::discovery::local_swarm_discovery::LocalSwarmDiscovery;
        self.discovery.push(Box::new(|secret_key| {
            LocalSwarmDiscovery::new(secret_key.public())
                .map(|x| Box::new(x) as _)
                .ok()
        }));
        self
    }

    /// Sets the user-defined data to be published in discovery services with this node's addresses.
    ///
    /// When using discovery services, this string of [`UserData`] will be published together
    /// with the node's addresses and relay URL. When other nodes discover this node,
    /// they retrieve the [`UserData`] in addition to the addressing info.
    ///
    /// Iroh itself does not interpret the user-defined data in any way, it is purely left
    /// for applications to parse and use.
    pub fn user_data_for_discovery(mut self, user_data: UserData) -> Self {
        self.discovery_user_data = Some(user_data);
        self
    }

    /// Optionally set a list of known nodes.
    pub fn known_nodes(mut self, nodes: Vec<NodeAddr>) -> Self {
        self.node_map = Some(nodes);
        self
    }

    // # Methods for more specialist customisation.

    /// Sets a custom [`quinn::TransportConfig`] for this endpoint.
    ///
    /// The transport config contains parameters governing the QUIC state machine.
    ///
    /// If unset, the default config is used. Default values should be suitable for most
    /// internet applications. Applications protocols which forbid remotely-initiated
    /// streams should set `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` to
    /// zero.
    ///
    /// Please be aware that changing some settings may have adverse effects on establishing
    /// and maintaining direct connections.
    pub fn transport_config(mut self, transport_config: quinn::TransportConfig) -> Self {
        self.transport_config = transport_config;
        self
    }

    /// Optionally sets a custom DNS resolver to use for this endpoint.
    ///
    /// The DNS resolver is used to resolve relay hostnames, and node addresses if
    /// [`crate::discovery::dns::DnsDiscovery`] is configured.
    ///
    /// By default, a new DNS resolver is created which is configured to use the
    /// host system's DNS configuration. You can pass a custom instance of [`DnsResolver`]
    /// here to use a differently configured DNS resolver for this endpoint, or to share
    /// a [`DnsResolver`] between multiple endpoints.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Sets an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Sets the proxy url from the environment, in this order:
    ///
    /// - `HTTP_PROXY`
    /// - `http_proxy`
    /// - `HTTPS_PROXY`
    /// - `https_proxy`
    pub fn proxy_from_env(mut self) -> Self {
        self.proxy_url = proxy_url_from_env();
        self
    }

    /// Enables saving the TLS pre-master key for connections.
    ///
    /// This key should normally remain secret but can be useful to debug networking issues
    /// by decrypting captured traffic.
    ///
    /// If *keylog* is `true` then setting the `SSLKEYLOGFILE` environment variable to a
    /// filename will result in this file being used to log the TLS pre-master keys.
    pub fn keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
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

    /// This implies we only use the relay to communicate
    /// and do not attempt to do any hole punching.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn path_selection(mut self, path_selection: PathSelection) -> Self {
        self.path_selection = path_selection;
        self
    }
}

/// Configuration for a [`quinn::Endpoint`] that cannot be changed at runtime.
#[derive(Debug)]
struct StaticConfig {
    secret_key: SecretKey,
    transport_config: Arc<quinn::TransportConfig>,
    keylog: bool,
}

impl StaticConfig {
    /// Create a [`quinn::ServerConfig`] with the specified ALPN protocols.
    fn create_server_config(&self, alpn_protocols: Vec<Vec<u8>>) -> Result<ServerConfig> {
        let server_config = make_server_config(
            &self.secret_key,
            alpn_protocols,
            self.transport_config.clone(),
            self.keylog,
        )?;
        Ok(server_config)
    }
}

/// Creates a [`ServerConfig`] with the given secret key and limits.
// This return type can not longer be used anywhere in our public API.  It is however still
// used by iroh::node::Node (or rather iroh::node::Builder) to create a plain Quinn
// endpoint.
pub fn make_server_config(
    secret_key: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Arc<TransportConfig>,
    keylog: bool,
) -> Result<ServerConfig> {
    let quic_server_config = tls::make_server_config(secret_key, alpn_protocols, keylog)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(transport_config);

    Ok(server_config)
}

/// Controls an iroh node, establishing connections with other nodes.
///
/// This is the main API interface to create connections to, and accept connections from
/// other iroh nodes.  The connections are peer-to-peer and encrypted, a Relay server is
/// used to make the connections reliable.  See the [crate docs] for a more detailed
/// overview of iroh.
///
/// It is recommended to only create a single instance per application.  This ensures all
/// the connections made share the same peer-to-peer connections to other iroh nodes,
/// while still remaining independent connections.  This will result in more optimal network
/// behaviour.
///
/// The endpoint is created using the [`Builder`], which can be created using
/// [`Endpoint::builder`].
///
/// Once an endpoint exists, new connections are typically created using the
/// [`Endpoint::connect`] and [`Endpoint::accept`] methods.  Once established, the
/// [`Connection`] gives access to most [QUIC] features.  Individual streams to send data to
/// the peer are created using the [`Connection::open_bi`], [`Connection::accept_bi`],
/// [`Connection::open_uni`] and [`Connection::open_bi`] functions.
///
/// Note that due to the light-weight properties of streams a stream will only be accepted
/// once the initiating peer has sent some data on it.
///
/// [QUIC]: https://quicwg.org
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// Handle to the magicsocket/actor
    msock: Handle,
    /// Handle to the actor that resets the quinn RTT estimator
    rtt_actor: Arc<rtt_actor::RttHandle>,
    /// Configuration structs for quinn, holds the transport config, certificate setup, secret key etc.
    static_config: Arc<StaticConfig>,
    /// Cache for TLS session keys we receive.
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
}

impl Endpoint {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users, but grouped in similar
    // items.

    // # Methods relating to construction.

    /// Returns the builder for an [`Endpoint`], with a production configuration.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Creates a quinn endpoint backed by a magicsock.
    ///
    /// This is for internal use, the public interface is the [`Builder`] obtained from
    /// [Self::builder]. See the methods on the builder for documentation of the parameters.
    #[instrument("ep", skip_all, fields(me = %static_config.secret_key.public().fmt_short()))]
    async fn bind(static_config: StaticConfig, msock_opts: magicsock::Options) -> Result<Self> {
        let msock = magicsock::MagicSock::spawn(msock_opts).await?;
        trace!("created magicsock");
        debug!(version = env!("CARGO_PKG_VERSION"), "iroh Endpoint created");

        let ep = Self {
            msock: msock.clone(),
            rtt_actor: Arc::new(rtt_actor::RttHandle::new()),
            static_config: Arc::new(static_config),
            session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(
                MAX_TLS_TICKETS,
            )),
        };
        Ok(ep)
    }

    /// Sets the list of accepted ALPN protocols.
    ///
    /// This will only affect new incoming connections.
    /// Note that this *overrides* the current list of ALPNs.
    pub fn set_alpns(&self, alpns: Vec<Vec<u8>>) -> Result<()> {
        let server_config = self.static_config.create_server_config(alpns)?;
        self.msock.endpoint().set_server_config(Some(server_config));
        Ok(())
    }

    // # Methods for establishing connectivity.

    /// Connects to a remote [`Endpoint`].
    ///
    /// A value that can be converted into a [`NodeAddr`] is required. This can be either a
    /// [`NodeAddr`], a [`NodeId`] or a [`iroh_base::ticket::NodeTicket`].
    ///
    /// The [`NodeAddr`] must contain the [`NodeId`] to dial and may also contain a [`RelayUrl`]
    /// and direct addresses. If direct addresses are provided, they will be used to try and
    /// establish a direct connection without involving a relay server.
    ///
    /// If neither a [`RelayUrl`] or direct addresses are configured in the [`NodeAddr`] it
    /// may still be possible a connection can be established.  This depends on other calls
    /// to [`Endpoint::add_node_addr`] which may provide contact information, or via the
    /// [`Discovery`] service configured using [`Builder::discovery`].  The discovery
    /// service will also be used if the remote node is not reachable on the provided direct
    /// addresses and there is no [`RelayUrl`].
    ///
    /// If addresses or relay servers are neither provided nor can be discovered, the
    /// connection attempt will fail with an error.
    ///
    /// The `alpn`, or application-level protocol identifier, is also required. The remote
    /// endpoint must support this `alpn`, otherwise the connection attempt will fail with
    /// an error.
    pub async fn connect(&self, node_addr: impl Into<NodeAddr>, alpn: &[u8]) -> Result<Connection> {
        let node_addr = node_addr.into();
        let remote = node_addr.node_id;
        let connecting = self
            .connect_with_opts(node_addr, alpn, Default::default())
            .await?;
        let conn = connecting
            .await
            .context("failed connecting to remote endpoint")?;
        debug!(
            me = %self.node_id().fmt_short(),
            remote = %remote.fmt_short(),
            alpn = %String::from_utf8_lossy(alpn),
            "Connection established."
        );
        Ok(conn)
    }

    /// Starts a connection attempt with a remote [`Endpoint`].
    ///
    /// Like [`Endpoint::connect`] (see also its docs for general details), but allows for a more
    /// advanced connection setup with more customization in two aspects:
    /// 1. The returned future resolves to a [`Connecting`], which can be further processed into
    ///    a [`Connection`] by awaiting, or alternatively allows connecting with 0RTT via
    ///    [`Connecting::into_0rtt`].
    ///    **Note:** Please read the documentation for `into_0rtt` carefully to assess
    ///    security concerns.
    /// 2. The [`TransportConfig`] for the connection can be modified via the provided
    ///    [`ConnectOptions`].
    ///    **Note:** Please be aware that changing transport config settings may have adverse effects on
    ///    establishing and maintaining direct connections.  Carefully test settings you use and
    ///    consider this currently as still rather experimental.
    #[instrument(name = "connect", skip_all, fields(
        me = self.node_id().fmt_short(),
        remote = tracing::field::Empty,
        alpn = String::from_utf8_lossy(alpn).to_string(),
    ))]
    pub async fn connect_with_opts(
        &self,
        node_addr: impl Into<NodeAddr>,
        alpn: &[u8],
        options: ConnectOptions,
    ) -> Result<Connecting> {
        let node_addr: NodeAddr = node_addr.into();
        tracing::Span::current().record("remote", node_addr.node_id.fmt_short());

        // Connecting to ourselves is not supported.
        if node_addr.node_id == self.node_id() {
            bail!(
                "Connecting to ourself is not supported ({} is the node id of this node)",
                node_addr.node_id.fmt_short()
            );
        }

        if !node_addr.is_empty() {
            self.add_node_addr(node_addr.clone())?;
        }
        let node_id = node_addr.node_id;
        let direct_addresses = node_addr.direct_addresses.clone();
        let relay_url = node_addr.relay_url.clone();

        // Get the mapped IPv6 address from the magic socket. Quinn will connect to this
        // address.  Start discovery for this node if it's enabled and we have no valid or
        // verified address information for this node.  Dropping the discovery cancels any
        // still running task.
        let (mapped_addr, _discovery_drop_guard) = self
            .get_mapping_addr_and_maybe_start_discovery(node_addr)
            .await
            .with_context(|| {
                format!(
                    "No addressing information for NodeId({}), unable to connect",
                    node_id.fmt_short()
                )
            })?;

        let transport_config = options
            .transport_config
            .unwrap_or(self.static_config.transport_config.clone());

        // Start connecting via quinn. This will time out after 10 seconds if no reachable
        // address is available.

        debug!(
            ?mapped_addr,
            ?direct_addresses,
            ?relay_url,
            "Attempting connection..."
        );
        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let quic_client_config = tls::make_client_config(
                &self.static_config.secret_key,
                Some(node_id),
                alpn_protocols,
                Some(self.session_store.clone()),
                self.static_config.keylog,
            )?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
            client_config.transport_config(transport_config);
            client_config
        };

        // We used to use a constant "localhost" for this - however, that would put all of
        // the TLS session tickets we receive into the same bucket in the TLS session ticket cache.
        // So we choose something that'd dependent on the NodeId.
        // We cannot use hex to encode the NodeId, as that'd encode to 64 characters, but we only
        // have 63 maximum per DNS subdomain. Base32 is the next best alternative.
        // We use the `.invalid` TLD, as that's specified (in RFC 2606) to never actually resolve
        // "for real", unlike `.localhost` which is allowed to resolve to `127.0.0.1`.
        // We also add "iroh" as a subdomain, although those 5 bytes might not be necessary.
        // We *could* decide to remove that indicator in the future likely without breakage.
        let server_name = &format!("{}.iroh.invalid", BASE32_DNSSEC.encode(node_id.as_bytes()));
        let connect = self.msock.endpoint().connect_with(
            client_config,
            mapped_addr.socket_addr(),
            server_name,
        )?;

        Ok(Connecting {
            inner: connect,
            ep: self.clone(),
            remote_node_id: Some(node_id),
            _discovery_drop_guard,
        })
    }

    /// Accepts an incoming connection on the endpoint.
    ///
    /// Only connections with the ALPNs configured in [`Builder::alpns`] will be accepted.
    /// If multiple ALPNs have been configured the ALPN can be inspected before accepting
    /// the connection using [`Connecting::alpn`].
    ///
    /// The returned future will yield `None` if the endpoint is closed by calling
    /// [`Endpoint::close`].
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            inner: self.msock.endpoint().accept(),
            ep: self.clone(),
        }
    }

    // # Methods for manipulating the internal state about other nodes.

    /// Informs this [`Endpoint`] about addresses of the iroh node.
    ///
    /// This updates the local state for the remote node.  If the provided [`NodeAddr`]
    /// contains a [`RelayUrl`] this will be used as the new relay server for this node.  If
    /// it contains any new IP endpoints they will also be stored and tried when next
    /// connecting to this node. Any address that matches this node's direct addresses will be
    /// silently ignored.
    ///
    /// See also [`Endpoint::add_node_addr_with_source`].
    ///
    /// # Using node discovery instead
    ///
    /// It is strongly advised to use node discovery using the [`StaticProvider`] instead.
    /// This provides more flexibility and future proofing.
    ///
    /// # Errors
    ///
    /// Will return an error if we attempt to add our own [`NodeId`] to the node map or
    /// if the direct addresses are a subset of ours.
    ///
    /// [`StaticProvider`]: crate::discovery::static_provider::StaticProvider
    pub fn add_node_addr(&self, node_addr: NodeAddr) -> Result<()> {
        self.add_node_addr_inner(node_addr, magicsock::Source::App)
    }

    /// Informs this [`Endpoint`] about addresses of the iroh node, noting the source.
    ///
    /// This updates the local state for the remote node.  If the provided [`NodeAddr`] contains a
    /// [`RelayUrl`] this will be used as the new relay server for this node.  If it contains any
    /// new IP endpoints they will also be stored and tried when next connecting to this node. Any
    /// address that matches this node's direct addresses will be silently ignored. The *source* is
    /// used for logging exclusively and will not be stored.
    ///
    /// # Using node discovery instead
    ///
    /// It is strongly advised to use node discovery using the [`StaticProvider`] instead.
    /// This provides more flexibility and future proofing.
    ///
    /// # Errors
    ///
    /// Will return an error if we attempt to add our own [`NodeId`] to the node map or
    /// if the direct addresses are a subset of ours.
    ///
    /// [`StaticProvider`]: crate::discovery::static_provider::StaticProvider
    pub fn add_node_addr_with_source(
        &self,
        node_addr: NodeAddr,
        source: &'static str,
    ) -> Result<()> {
        self.add_node_addr_inner(
            node_addr,
            magicsock::Source::NamedApp {
                name: source.into(),
            },
        )
    }

    fn add_node_addr_inner(&self, node_addr: NodeAddr, source: magicsock::Source) -> Result<()> {
        // Connecting to ourselves is not supported.
        if node_addr.node_id == self.node_id() {
            bail!(
                "Adding our own address is not supported ({} is the node id of this node)",
                node_addr.node_id.fmt_short()
            );
        }
        self.msock.add_node_addr(node_addr, source)
    }

    // # Getter methods for properties of this Endpoint itself.

    /// Returns the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.static_config.secret_key
    }

    /// Returns the node id of this endpoint.
    ///
    /// This ID is the unique addressing information of this node and other peers must know
    /// it to be able to connect to this node.
    pub fn node_id(&self) -> NodeId {
        self.static_config.secret_key.public()
    }

    /// Returns the current [`NodeAddr`] for this endpoint.
    ///
    /// The returned [`NodeAddr`] will have the current [`RelayUrl`] and direct addresses
    /// as they would be returned by [`Endpoint::home_relay`] and
    /// [`Endpoint::direct_addresses`].
    pub async fn node_addr(&self) -> Result<NodeAddr> {
        let addrs = self.direct_addresses().initialized().await?;
        let relay = self.home_relay().get()?;
        Ok(NodeAddr::from_parts(
            self.node_id(),
            relay,
            addrs.into_iter().map(|x| x.addr),
        ))
    }

    /// Returns a [`Watcher`] for the [`RelayUrl`] of the Relay server used as home relay.
    ///
    /// Every endpoint has a home Relay server which it chooses as the server with the
    /// lowest latency out of the configured servers provided by [`Builder::relay_mode`].
    /// This is the server other iroh nodes can use to reliably establish a connection
    /// to this node.
    ///
    /// The watcher stores `None` if we are not connected to any Relay server.
    ///
    /// Note that this will store `None` right after the [`Endpoint`] is created since it takes
    /// some time to connect to find and connect to the home relay server.
    ///
    /// # Examples
    ///
    /// To wait for a home relay connection to be established, use [`Watcher::initialized`]:
    /// ```no_run
    /// use futures_lite::StreamExt;
    /// use iroh::Endpoint;
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let mep = Endpoint::builder().bind().await.unwrap();
    /// let _relay_url = mep.home_relay().initialized().await.unwrap();
    /// # });
    /// ```
    pub fn home_relay(&self) -> Watcher<Option<RelayUrl>> {
        self.msock.home_relay()
    }

    /// Returns a [`Watcher`] for the direct addresses of this [`Endpoint`].
    ///
    /// The direct addresses of the [`Endpoint`] are those that could be used by other
    /// iroh nodes to establish direct connectivity, depending on the network
    /// situation. The yielded lists of direct addresses contain both the locally-bound
    /// addresses and the [`Endpoint`]'s publicly reachable addresses discovered through
    /// mechanisms such as [STUN] and port mapping.  Hence usually only a subset of these
    /// will be applicable to a certain remote iroh node.
    ///
    /// The [`Endpoint`] continuously monitors the direct addresses for changes as its own
    /// location in the network might change.  Whenever changes are detected this stream
    /// will yield a new list of direct addresses.
    ///
    /// When issuing the first call to this method the first direct address discovery might
    /// still be underway, in this case the [`Watcher`] might not be initialized with [`Some`]
    /// value yet.  Once the first set of local direct addresses are discovered the [`Watcher`]
    /// will always return [`Some`] set of direct addresses immediately, which are the most
    /// recently discovered direct addresses.
    ///
    /// # Examples
    ///
    /// To get the first set of direct addresses use [`Watcher::initialized`]:
    /// ```no_run
    /// use futures_lite::StreamExt;
    /// use iroh::Endpoint;
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let mep = Endpoint::builder().bind().await.unwrap();
    /// let _addrs = mep.direct_addresses().initialized().await.unwrap();
    /// # });
    /// ```
    ///
    /// [STUN]: https://en.wikipedia.org/wiki/STUN
    pub fn direct_addresses(&self) -> Watcher<Option<BTreeSet<DirectAddr>>> {
        self.msock.direct_addresses()
    }

    /// Returns the local socket addresses on which the underlying sockets are bound.
    ///
    /// The [`Endpoint`] always binds on an IPv4 address and also tries to bind on an IPv6
    /// address if available.
    pub fn bound_sockets(&self) -> (SocketAddr, Option<SocketAddr>) {
        self.msock.local_addr()
    }

    // # Getter methods for information about other nodes.

    /// Returns information about the remote node identified by a [`NodeId`].
    ///
    /// The [`Endpoint`] keeps some information about remote iroh nodes, which it uses to find
    /// the best path to a node. Having information on a remote node, however, does not mean we have
    /// ever connected to it to or even whether a connection is even possible. The information about a
    /// remote node will change over time, as the [`Endpoint`] learns more about the node. Future
    /// calls may return different information. Furthermore, node information may even be
    /// completely evicted as it becomes stale.
    ///
    /// See also [`Endpoint::remote_info_iter`] which returns information on all nodes known
    /// by this [`Endpoint`].
    pub fn remote_info(&self, node_id: NodeId) -> Option<RemoteInfo> {
        self.msock.remote_info(node_id)
    }

    /// Returns information about all the remote nodes this [`Endpoint`] knows about.
    ///
    /// This returns the same information as [`Endpoint::remote_info`] for each node known to this
    /// [`Endpoint`].
    ///
    /// The [`Endpoint`] keeps some information about remote iroh nodes, which it uses to find
    /// the best path to a node. This returns all the nodes it knows about, regardless of whether a
    /// connection was ever made or is even possible.
    ///
    /// See also [`Endpoint::remote_info`] to only retrieve information about a single node.
    pub fn remote_info_iter(&self) -> impl Iterator<Item = RemoteInfo> {
        self.msock.list_remote_infos().into_iter()
    }

    // # Methods for less common getters.
    //
    // Partially they return things passed into the builder.

    /// Returns a [`Watcher`] that reports the current connection type and any changes for
    /// given remote node.
    ///
    /// This watcher allows observing a stream of [`ConnectionType`] items by calling
    /// [`Watcher::stream()`]. If the underlying connection to a remote node changes, it will
    /// yield a new item.  These connection changes are when the connection switches between
    /// using the Relay server and a direct connection.
    ///
    /// Note that this does not guarantee each connection change is yielded in the stream.
    /// If the connection type changes several times before this stream is polled, only the
    /// last recorded state is returned.  This can be observed e.g. right at the start of a
    /// connection when the switch from a relayed to a direct connection can be so fast that
    /// the relayed state is never exposed.
    ///
    /// If there is currently a connection with the remote node, then using [`Watcher::get`]
    /// will immediately return either [`ConnectionType::Relay`], [`ConnectionType::Direct`]
    /// or [`ConnectionType::Mixed`].
    ///
    /// It is possible for the connection type to be [`ConnectionType::None`] if you've
    /// recently connected to this node id but previous methods of reaching the node have
    /// become inaccessible.
    ///
    /// # Errors
    ///
    /// Will error if we do not have any address information for the given `node_id`.
    pub fn conn_type(&self, node_id: NodeId) -> Result<Watcher<ConnectionType>> {
        self.msock.conn_type(node_id)
    }

    /// Returns the DNS resolver used in this [`Endpoint`].
    ///
    /// See [`Builder::dns_resolver`].
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.msock.dns_resolver()
    }

    /// Returns the discovery mechanism, if configured.
    ///
    /// See [`Builder::discovery`].
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.msock.discovery()
    }

    // # Methods for less common state updates.

    /// Notifies the system of potential network changes.
    ///
    /// On many systems iroh is able to detect network changes by itself, however
    /// some systems like android do not expose this functionality to native code.
    /// Android does however provide this functionality to Java code.  This
    /// function allows for notifying iroh of any potential network changes like
    /// this.
    ///
    /// Even when the network did not change, or iroh was already able to detect
    /// the network change itself, there is no harm in calling this function.
    pub async fn network_change(&self) {
        self.msock.network_change().await;
    }

    // # Methods to update internal state.

    /// Sets the user-defined data to be published in discovery services with this node's addresses.
    ///
    /// See [`Builder::user_data_for_discovery`] for details.
    pub fn set_user_data_for_discovery(&self, user_data: Option<UserData>) {
        self.msock.set_user_data_for_discovery(user_data);
    }

    // # Methods for terminating the endpoint.

    /// Closes the QUIC endpoint and the magic socket.
    ///
    /// This will close any remaining open [`Connection`]s with an error code
    /// of `0` and an empty reason.  Though it is best practice to close those
    /// explicitly before with a custom error code and reason.
    ///
    /// It will then make a best effort to wait for all close notifications to be
    /// acknowledged by the peers, re-transmitting them if needed. This ensures the
    /// peers are aware of the closed connections instead of having to wait for a timeout
    /// on the connection. Once all connections are closed or timed out, the future
    /// finishes.
    ///
    /// The maximum time-out that this future will wait for depends on QUIC transport
    /// configurations of non-drained connections at the time of calling, and their current
    /// estimates of round trip time. With default parameters and a conservative estimate
    /// of round trip time, this call's future should take 3 seconds to resolve in cases of
    /// bad connectivity or failed connections. In the usual case, this call's future should
    /// return much more quickly.
    ///
    /// It is highly recommended you *do* wait for this close call to finish, if possible.
    /// Not doing so will make connections that were still open while closing the endpoint
    /// time out on the remote end. Thus remote ends will assume connections to have failed
    /// even if all application data was transmitted successfully.
    ///
    /// Note: Someone used to closing TCP sockets might wonder why it is necessary to wait
    /// for timeouts when closing QUIC endpoints, while they don't have to do this for TCP
    /// sockets. This is due to QUIC and its acknowledgments being implemented in user-land,
    /// while TCP sockets usually get closed and drained by the operating system in the
    /// kernel during the "Time-Wait" period of the TCP socket.
    ///
    /// Be aware however that the underlying UDP sockets are only closed once all clones of
    /// the the respective [`Endpoint`] are dropped.
    pub async fn close(&self) {
        if self.is_closed() {
            return;
        }

        tracing::debug!("Connections closed");
        self.msock.close().await;
    }

    /// Check if this endpoint is still alive, or already closed.
    pub fn is_closed(&self) -> bool {
        self.msock.is_closed()
    }

    // # Remaining private methods

    /// Return the quic mapped address for this `node_id` and possibly start discovery
    /// services if discovery is enabled on this magic endpoint.
    ///
    /// This will launch discovery in all cases except if:
    /// 1) we do not have discovery enabled
    /// 2) we have discovery enabled, but already have at least one verified, unexpired
    ///    addresses for this `node_id`
    ///
    /// # Errors
    ///
    /// This method may fail if we have no way of dialing the node. This can occur if
    /// we were given no dialing information in the [`NodeAddr`] and no discovery
    /// services were configured or if discovery failed to fetch any dialing information.
    async fn get_mapping_addr_and_maybe_start_discovery(
        &self,
        node_addr: NodeAddr,
    ) -> Result<(NodeIdMappedAddr, Option<DiscoveryTask>)> {
        let node_id = node_addr.node_id;

        // Only return a mapped addr if we have some way of dialing this node, in other
        // words, we have either a relay URL or at least one direct address.
        let addr = if self.msock.has_send_address(node_id) {
            self.msock.get_mapping_addr(node_id)
        } else {
            None
        };
        match addr {
            Some(addr) => {
                // We have some way of dialing this node, but that doesn't actually mean
                // we can actually connect to any of these addresses.
                // Therefore, we will invoke the discovery service if we haven't received from the
                // endpoint on any of the existing paths recently.
                // If the user provided addresses in this connect call, we will add a delay
                // followed by a recheck before starting the discovery, to give the magicsocket a
                // chance to test the newly provided addresses.
                let delay = (!node_addr.is_empty()).then_some(DISCOVERY_WAIT_PERIOD);
                let discovery = DiscoveryTask::maybe_start_after_delay(self, node_id, delay)
                    .ok()
                    .flatten();
                Ok((addr, discovery))
            }

            None => {
                // We have no known addresses or relay URLs for this node.
                // So, we start a discovery task and wait for the first result to arrive, and
                // only then continue, because otherwise we wouldn't have any
                // path to the remote endpoint.
                let mut discovery = DiscoveryTask::start(self.clone(), node_id)
                    .context("Discovery service required due to missing addressing information")?;
                discovery
                    .first_arrived()
                    .await
                    .context("Discovery service failed")?;
                if let Some(addr) = self.msock.get_mapping_addr(node_id) {
                    Ok((addr, Some(discovery)))
                } else {
                    bail!("Discovery did not find addressing information");
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn magic_sock(&self) -> Handle {
        self.msock.clone()
    }
    #[cfg(test)]
    pub(crate) fn endpoint(&self) -> &quinn::Endpoint {
        self.msock.endpoint()
    }
}

/// Options for the [`Endpoint::connect_with_opts`] function.
#[derive(Default, Debug, Clone)]
pub struct ConnectOptions {
    transport_config: Option<Arc<TransportConfig>>,
}

impl ConnectOptions {
    /// Initializes new connection options.
    ///
    /// By default, the connection will use the same options
    /// as [`Endpoint::connect`], e.g. a default [`TransportConfig`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the QUIC transport config options for this connection.
    pub fn with_transport_config(mut self, transport_config: Arc<TransportConfig>) -> Self {
        self.transport_config = Some(transport_config);
        self
    }
}

/// Future produced by [`Endpoint::accept`].
#[derive(derive_more::Debug)]
#[pin_project]
pub struct Accept<'a> {
    #[pin]
    #[debug("quinn::Accept")]
    inner: quinn::Accept<'a>,
    ep: Endpoint,
}

impl Future for Accept<'_> {
    type Output = Option<Incoming>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(inner)) => Poll::Ready(Some(Incoming {
                inner,
                ep: this.ep.clone(),
            })),
        }
    }
}

/// An incoming connection for which the server has not yet begun its parts of the
/// handshake.
#[derive(Debug)]
pub struct Incoming {
    inner: quinn::Incoming,
    ep: Endpoint,
}

impl Incoming {
    /// Attempts to accept this incoming connection (an error may still occur).
    ///
    /// Errors occurring here are likely not caused by the application or remote.  The QUIC
    /// connection listens on a normal UDP socket and any reachable network endpoint can
    /// send datagrams to it, solicited or not.  Even if the first few bytes look like a
    /// QUIC packet, it might not even be a QUIC packet that is being received.
    ///
    /// Thus it is common to simply log the errors here and accept them as something which
    /// can happen.
    pub fn accept(self) -> Result<Connecting, ConnectionError> {
        self.inner.accept().map(|conn| Connecting {
            inner: conn,
            ep: self.ep,
            remote_node_id: None,
            _discovery_drop_guard: None,
        })
    }

    /// Accepts this incoming connection using a custom configuration.
    ///
    /// See [`accept()`] for more details.
    ///
    /// [`accept()`]: Incoming::accept
    pub fn accept_with(
        self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        self.inner
            .accept_with(server_config)
            .map(|conn| Connecting {
                inner: conn,
                ep: self.ep,
                remote_node_id: None,
                _discovery_drop_guard: None,
            })
    }

    /// Rejects this incoming connection attempt.
    pub fn refuse(self) {
        self.inner.refuse()
    }

    /// Responds with a retry packet.
    ///
    /// This requires the client to retry with address validation.
    ///
    /// Errors if `remote_address_validated()` is true.
    pub fn retry(self) -> Result<(), RetryError> {
        self.inner.retry()
    }

    /// Ignores this incoming connection attempt, not sending any packet in response.
    pub fn ignore(self) {
        self.inner.ignore()
    }

    /// Returns the local IP address which was used when the peer established the
    /// connection.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.inner.local_ip()
    }

    /// Returns the peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated.
    ///
    /// This means that the sender of the initial packet has proved that they can receive
    /// traffic sent to `self.remote_address()`.
    pub fn remote_address_validated(&self) -> bool {
        self.inner.remote_address_validated()
    }
}

impl IntoFuture for Incoming {
    type Output = Result<Connection, ConnectionError>;
    type IntoFuture = IncomingFuture;

    fn into_future(self) -> Self::IntoFuture {
        IncomingFuture {
            inner: self.inner.into_future(),
            ep: self.ep,
        }
    }
}

/// Adaptor to let [`Incoming`] be `await`ed like a [`Connecting`].
#[derive(Debug)]
#[pin_project]
pub struct IncomingFuture {
    #[pin]
    inner: quinn::IncomingFuture,
    ep: Endpoint,
}

impl Future for IncomingFuture {
    type Output = Result<Connection, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(inner)) => {
                let conn = Connection { inner };
                try_send_rtt_msg(&conn, this.ep, None);
                Poll::Ready(Ok(conn))
            }
        }
    }
}

/// In-progress connection attempt future
#[derive(derive_more::Debug)]
#[pin_project]
pub struct Connecting {
    #[pin]
    inner: quinn::Connecting,
    ep: Endpoint,
    remote_node_id: Option<NodeId>,
    /// We run discovery as long as we haven't established a connection yet.
    #[debug("Option<DiscoveryTask>")]
    _discovery_drop_guard: Option<DiscoveryTask>,
}

impl Connecting {
    /// Converts this [`Connecting`] into a 0-RTT or 0.5-RTT connection at the cost of weakened
    /// security.
    ///
    /// Returns `Ok` immediately if the local endpoint is able to attempt sending 0/0.5-RTT data.
    /// If so, the returned [`Connection`] can be used to send application data without waiting for
    /// the rest of the handshake to complete, at the cost of weakened cryptographic security
    /// guarantees. The returned [`ZeroRttAccepted`] future resolves when the handshake does
    /// complete, at which point subsequently opened streams and written data will have full
    /// cryptographic protection.
    ///
    /// Once the [`ZeroRttAccepted`] future completed, a full handshake has been carried through
    /// and any data sent and any streams opened on the [`Connection`] will operate with the same
    /// security as on normal 1-RTT connections.
    ///
    /// ## Outgoing
    ///
    /// For outgoing connections, the initial attempt to convert to a [`Connection`] which sends
    /// 0-RTT data will attempt to resume a previous TLS session. However, **the remote endpoint
    /// may not actually _accept_ the 0-RTT data**--yet still accept the connection attempt in
    /// general. This possibility is conveyed through the [`ZeroRttAccepted`] future--when the
    /// handshake completes, it resolves to true if the 0-RTT data was accepted and false if it was
    /// rejected. If it was rejected, the existence of streams opened and other application data
    /// sent prior to the handshake completing will not be conveyed to the remote application, and
    /// local operations on them will return `ZeroRttRejected` errors.
    ///
    /// A server may reject 0-RTT data at its discretion, but accepting 0-RTT data requires the
    /// relevant resumption state to be stored in the server, which servers may limit or lose for
    /// various reasons including not persisting resumption state across server restarts.
    ///
    /// ## Incoming
    ///
    /// For incoming connections, conversion to 0.5-RTT will always fully succeed. `into_0rtt` will
    /// always return `Ok` and the [`ZeroRttAccepted`] will always resolve to true.
    ///
    /// ## Security
    ///
    /// On outgoing connections, this enables transmission of 0-RTT data, which is vulnerable to
    /// replay attacks, and should therefore never invoke non-idempotent operations.
    ///
    /// On incoming connections, this enables transmission of 0.5-RTT data, which may be sent
    /// before TLS client authentication has occurred, and should therefore not be used to send
    /// data for which client authentication is being used.
    ///
    /// You can use [`RecvStream::is_0rtt`] to check whether a stream has been opened in 0-RTT
    /// and thus whether parts of the stream are operating under this reduced security level.
    pub fn into_0rtt(self) -> Result<(Connection, ZeroRttAccepted), Self> {
        match self.inner.into_0rtt() {
            Ok((inner, zrtt_accepted)) => {
                let conn = Connection { inner };
                let zrtt_accepted = ZeroRttAccepted {
                    inner: zrtt_accepted,
                    _discovery_drop_guard: self._discovery_drop_guard,
                };
                // This call is why `self.remote_node_id` was introduced.
                // When we `Connecting::into_0rtt`, then we don't yet have `handshake_data`
                // in our `Connection`, thus `try_send_rtt_msg` won't be able to pick up
                // `Connection::remote_node_id`.
                // Instead, we provide `self.remote_node_id` here - we know it in advance,
                // after all.
                try_send_rtt_msg(&conn, &self.ep, self.remote_node_id);
                Ok((conn, zrtt_accepted))
            }
            Err(inner) => Err(Self {
                inner,
                ep: self.ep,
                remote_node_id: self.remote_node_id,
                _discovery_drop_guard: self._discovery_drop_guard,
            }),
        }
    }

    /// Parameters negotiated during the handshake
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, ConnectionError> {
        self.inner.handshake_data().await
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    // Note, we could totally provide this method to be on a Connection as well.  But we'd
    // need to wrap Connection too.
    pub async fn alpn(&mut self) -> Result<Vec<u8>> {
        let data = self.handshake_data().await?;
        match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            Ok(data) => match data.protocol {
                Some(protocol) => Ok(protocol),
                None => bail!("no ALPN protocol available"),
            },
            Err(_) => bail!("unknown handshake type"),
        }
    }
}

impl Future for Connecting {
    type Output = Result<Connection, ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(inner)) => {
                let conn = Connection { inner };
                try_send_rtt_msg(&conn, this.ep, *this.remote_node_id);
                Poll::Ready(Ok(conn))
            }
        }
    }
}

/// Future that completes when a connection is fully established.
///
/// For clients, the resulting value indicates if 0-RTT was accepted. For servers, the resulting
/// value is meaningless.
#[derive(derive_more::Debug)]
#[debug("ZeroRttAccepted")]
pub struct ZeroRttAccepted {
    inner: quinn::ZeroRttAccepted,
    /// When we call `Connecting::into_0rtt`, we don't want to stop discovery, so we transfer the task
    /// to this future.
    /// When `quinn::ZeroRttAccepted` resolves, we've successfully received data from the remote.
    /// Thus, that's the right time to drop discovery to preserve the behaviour similar to
    /// `Connecting` -> `Connection` without 0-RTT.
    /// Should we eventually decide to keep the discovery task alive for the duration of the whole
    /// `Connection`, then this task should be transferred to the `Connection` instead of here.
    _discovery_drop_guard: Option<DiscoveryTask>,
}

impl Future for ZeroRttAccepted {
    type Output = bool;
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

/// A QUIC connection.
///
/// If all references to a connection (including every clone of the Connection handle,
/// streams of incoming streams, and the various stream types) have been dropped, then the
/// connection will be automatically closed with an error_code of 0 and an empty reason. You
/// can also close the connection explicitly by calling [`Connection::close`].
///
/// Closing the connection immediately abandons efforts to deliver data to the peer. Upon
/// receiving CONNECTION_CLOSE the peer may drop any stream data not yet delivered to the
/// application. [`Connection::close`] describes in more detail how to gracefully close a
/// connection without losing application data.
///
/// May be cloned to obtain another handle to the same connection.
// This has repr(transparent) as it opens the door to potentially allow casting it to a
// quinn::Connection in the future.  Right now however that'd be iroh_quinn::Connection.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Connection {
    inner: quinn::Connection,
}

impl Connection {
    /// Initiates a new outgoing unidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won’t be notified that a stream has been opened until the
    /// stream is actually used.
    #[inline]
    pub fn open_uni(&self) -> OpenUni<'_> {
        self.inner.open_uni()
    }

    /// Initiates a new outgoing bidirectional stream.
    ///
    /// Streams are cheap and instantaneous to open unless blocked by flow control. As a
    /// consequence, the peer won't be notified that a stream has been opened until the
    /// stream is actually used. Calling [`open_bi`] then waiting on the [`RecvStream`]
    /// without writing anything to [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    #[inline]
    pub fn open_bi(&self) -> OpenBi<'_> {
        self.inner.open_bi()
    }

    /// Accepts the next incoming uni-directional stream.
    #[inline]
    pub fn accept_uni(&self) -> AcceptUni<'_> {
        self.inner.accept_uni()
    }

    /// Accept the next incoming bidirectional stream.
    ///
    /// **Important Note**: The peer that calls [`open_bi`] must write to its [`SendStream`]
    /// before the peer `Connection` is able to accept the stream using
    /// `accept_bi()`. Calling [`open_bi`] then waiting on the [`RecvStream`] without
    /// writing anything to the connected [`SendStream`] will never succeed.
    ///
    /// [`open_bi`]: Connection::open_bi
    #[inline]
    pub fn accept_bi(&self) -> AcceptBi<'_> {
        self.inner.accept_bi()
    }

    /// Receives an application datagram.
    #[inline]
    pub fn read_datagram(&self) -> ReadDatagram<'_> {
        self.inner.read_datagram()
    }

    /// Wait for the connection to be closed for any reason.
    ///
    /// Despite the return type's name, closed connections are often not an error condition
    /// at the application layer. Cases that might be routine include
    /// [`ConnectionError::LocallyClosed`] and [`ConnectionError::ApplicationClosed`].
    #[inline]
    pub async fn closed(&self) -> ConnectionError {
        self.inner.closed().await
    }

    /// If the connection is closed, the reason why.
    ///
    /// Returns `None` if the connection is still open.
    #[inline]
    pub fn close_reason(&self) -> Option<ConnectionError> {
        self.inner.close_reason()
    }

    /// Closes the connection immediately.
    ///
    /// Pending operations will fail immediately with [`ConnectionError::LocallyClosed`]. No
    /// more data is sent to the peer and the peer may drop buffered data upon receiving the
    /// CONNECTION_CLOSE frame.
    ///
    /// `error_code` and `reason` are not interpreted, and are provided directly to the
    /// peer.
    ///
    /// `reason` will be truncated to fit in a single packet with overhead; to improve odds
    /// that it is preserved in full, it should be kept under 1KiB.
    ///
    /// # Gracefully closing a connection
    ///
    /// Only the peer last receiving application data can be certain that all data is
    /// delivered. The only reliable action it can then take is to close the connection,
    /// potentially with a custom error code. The delivery of the final CONNECTION_CLOSE
    /// frame is very likely if both endpoints stay online long enough, calling
    /// [`Endpoint::close`] will wait to provide sufficient time. Otherwise, the remote peer
    /// will time out the connection, provided that the idle timeout is not disabled.
    ///
    /// The sending side can not guarantee all stream data is delivered to the remote
    /// application. It only knows the data is delivered to the QUIC stack of the remote
    /// endpoint. Once the local side sends a CONNECTION_CLOSE frame in response to calling
    /// [`close`] the remote endpoint may drop any data it received but is as yet
    /// undelivered to the application, including data that was acknowledged as received to
    /// the local endpoint.
    ///
    /// [`close`]: Connection::close
    #[inline]
    pub fn close(&self, error_code: VarInt, reason: &[u8]) {
        self.inner.close(error_code, reason)
    }

    /// Transmits `data` as an unreliable, unordered application datagram.
    ///
    /// Application datagrams are a low-level primitive. They may be lost or delivered out
    /// of order, and `data` must both fit inside a single QUIC packet and be smaller than
    /// the maximum dictated by the peer.
    #[inline]
    pub fn send_datagram(&self, data: bytes::Bytes) -> Result<(), SendDatagramError> {
        self.inner.send_datagram(data)
    }

    // TODO: It seems `SendDatagram` is not yet exposed by quinn.  This has been fixed
    //       upstream and will be in the next release.
    // /// Transmits `data` as an unreliable, unordered application datagram
    // ///
    // /// Unlike [`send_datagram()`], this method will wait for buffer space during congestion
    // /// conditions, which effectively prioritizes old datagrams over new datagrams.
    // ///
    // /// See [`send_datagram()`] for details.
    // ///
    // /// [`send_datagram()`]: Connection::send_datagram
    // #[inline]
    // pub fn send_datagram_wait(&self, data: bytes::Bytes) -> SendDatagram<'_> {
    //     self.inner.send_datagram_wait(data)
    // }

    /// Computes the maximum size of datagrams that may be passed to [`send_datagram`].
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path
    /// MTU estimate. The peer can also enforce an arbitrarily small fixed limit, but if the
    /// peer's limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.inner.max_datagram_size()
    }

    /// Bytes available in the outgoing datagram buffer.
    ///
    /// When greater than zero, calling [`send_datagram`] with a
    /// datagram of at most this size is guaranteed not to cause older datagrams to be
    /// dropped.
    ///
    /// [`send_datagram`]: Self::send_datagram
    #[inline]
    pub fn datagram_send_buffer_space(&self) -> usize {
        self.inner.datagram_send_buffer_space()
    }

    /// Current best estimate of this connection's latency (round-trip-time).
    #[inline]
    pub fn rtt(&self) -> Duration {
        self.inner.rtt()
    }

    /// Returns connection statistics.
    #[inline]
    pub fn stats(&self) -> ConnectionStats {
        self.inner.stats()
    }

    /// Current state of the congestion control algorithm, for debugging purposes.
    #[inline]
    pub fn congestion_state(&self) -> Box<dyn quinn_proto::congestion::Controller> {
        self.inner.congestion_state()
    }

    /// Parameters negotiated during the handshake.
    ///
    /// Guaranteed to return `Some` on fully established connections or after
    /// [`Connecting::handshake_data()`] succeeds. See that method's documentations for
    /// details on the returned value.
    ///
    /// [`Connection::handshake_data()`]: crate::Connecting::handshake_data
    #[inline]
    pub fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.inner.handshake_data()
    }

    /// Extracts the ALPN protocol from the peer's handshake data.
    pub fn alpn(&self) -> Option<Vec<u8>> {
        let data = self.handshake_data()?;
        match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            Ok(data) => data.protocol,
            Err(_) => None,
        }
    }

    /// Cryptographic identity of the peer.
    ///
    /// The dynamic type returned is determined by the configured [`Session`]. For the
    /// default `rustls` session, the return value can be [`downcast`] to a
    /// <code>Vec<[rustls::pki_types::CertificateDer]></code>
    ///
    /// [`Session`]: quinn_proto::crypto::Session
    /// [`downcast`]: Box::downcast
    #[inline]
    pub fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    /// Returns the [`NodeId`] from the peer's TLS certificate.
    ///
    /// The [`PublicKey`] of a node is also known as a [`NodeId`].  This [`PublicKey`] is
    /// included in the TLS certificate presented during the handshake when connecting.
    /// This function allows you to get the [`NodeId`] of the remote node of this
    /// connection.
    ///
    /// [`PublicKey`]: iroh_base::PublicKey
    // TODO: Would be nice if this could be infallible.
    pub fn remote_node_id(&self) -> Result<NodeId> {
        let data = self.peer_identity();
        match data {
            None => bail!("no peer certificate found"),
            Some(data) => match data.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
                Ok(certs) => {
                    if certs.len() != 1 {
                        bail!(
                            "expected a single peer certificate, but {} found",
                            certs.len()
                        );
                    }
                    let cert = tls::certificate::parse(&certs[0])?;
                    Ok(cert.peer_id())
                }
                Err(_) => bail!("invalid peer certificate"),
            },
        }
    }

    /// A stable identifier for this connection.
    ///
    /// Peer addresses and connection IDs can change, but this value will remain fixed for
    /// the lifetime of the connection.
    #[inline]
    pub fn stable_id(&self) -> usize {
        self.inner.stable_id()
    }

    /// Derives keying material from this connection's TLS session secrets.
    ///
    /// When both peers call this method with the same `label` and `context`
    /// arguments and `output` buffers of equal length, they will get the
    /// same sequence of bytes in `output`. These bytes are cryptographically
    /// strong and pseudorandom, and are suitable for use as keying material.
    ///
    /// See [RFC5705](https://tools.ietf.org/html/rfc5705) for more information.
    #[inline]
    pub fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), quinn_proto::crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }

    /// Modifies the number of unidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_uni_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_uni_streams(count)
    }

    /// See [`quinn_proto::TransportConfig::receive_window`].
    #[inline]
    pub fn set_receive_window(&self, receive_window: VarInt) {
        self.inner.set_receive_window(receive_window)
    }

    /// Modifies the number of bidirectional streams that may be concurrently opened.
    ///
    /// No streams may be opened by the peer unless fewer than `count` are already
    /// open. Large `count`s increase both minimum and worst-case memory consumption.
    #[inline]
    pub fn set_max_concurrent_bi_streams(&self, count: VarInt) {
        self.inner.set_max_concurrent_bi_streams(count)
    }
}

/// Try send a message to the rtt-actor.
///
/// If we can't notify the actor that will impact performance a little, but we can still
/// function.
fn try_send_rtt_msg(conn: &Connection, magic_ep: &Endpoint, remote_node_id: Option<NodeId>) {
    // If we can't notify the rtt-actor that's not great but not critical.
    let Some(node_id) = remote_node_id.or_else(|| conn.remote_node_id().ok()) else {
        warn!(?conn, "failed to get remote node id");
        return;
    };
    let Ok(conn_type_changes) = magic_ep.conn_type(node_id) else {
        warn!(?conn, "failed to create conn_type stream");
        return;
    };
    let rtt_msg = RttMessage::NewConnection {
        connection: conn.inner.weak_handle(),
        conn_type_changes: conn_type_changes.stream(),
        node_id,
    };
    if let Err(err) = magic_ep.rtt_actor.msg_tx.try_send(rtt_msg) {
        warn!(?conn, "rtt-actor not reachable: {err:#}");
    }
}

/// Read a proxy url from the environment, in this order
///
/// - `HTTP_PROXY`
/// - `http_proxy`
/// - `HTTPS_PROXY`
/// - `https_proxy`
fn proxy_url_from_env() -> Option<Url> {
    if let Some(url) = std::env::var("HTTP_PROXY")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        if is_cgi() {
            warn!("HTTP_PROXY environment variable ignored in CGI");
        } else {
            return Some(url);
        }
    }
    if let Some(url) = std::env::var("http_proxy")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }
    if let Some(url) = std::env::var("HTTPS_PROXY")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }
    if let Some(url) = std::env::var("https_proxy")
        .ok()
        .and_then(|s| s.parse::<Url>().ok())
    {
        return Some(url);
    }

    None
}

/// Configuration of the relay servers for an [`Endpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// Disable relay servers completely.
    Disabled,
    /// Use the default relay map, with production relay servers from n0.
    ///
    /// See [`crate::defaults::prod`] for the severs used.
    Default,
    /// Use the staging relay servers from n0.
    Staging,
    /// Use a custom relay map.
    Custom(RelayMap),
}

impl RelayMode {
    /// Returns the relay map for this mode.
    pub fn relay_map(&self) -> RelayMap {
        match self {
            RelayMode::Disabled => RelayMap::empty(),
            RelayMode::Default => crate::defaults::prod::default_relay_map(),
            RelayMode::Staging => crate::defaults::staging::default_relay_map(),
            RelayMode::Custom(relay_map) => relay_map.clone(),
        }
    }
}

/// Environment variable to force the use of staging relays.
pub const ENV_FORCE_STAGING_RELAYS: &str = "IROH_FORCE_STAGING_RELAYS";

/// Returns `true` if the use of staging relays is forced.
pub fn force_staging_infra() -> bool {
    matches!(std::env::var(ENV_FORCE_STAGING_RELAYS), Ok(value) if !value.is_empty())
}

/// Returns the default relay mode.
///
/// If the `IROH_FORCE_STAGING_RELAYS` environment variable is non empty, it will return `RelayMode::Staging`.
/// Otherwise, it will return `RelayMode::Default`.
pub fn default_relay_mode() -> RelayMode {
    // Use staging in testing
    match force_staging_infra() {
        true => RelayMode::Staging,
        false => RelayMode::Default,
    }
}

/// Check if we are being executed in a CGI context.
///
/// If so, a malicious client can send the `Proxy:` header, and it will
/// be in the `HTTP_PROXY` env var. So we don't use it :)
fn is_cgi() -> bool {
    std::env::var_os("REQUEST_METHOD").is_some()
}

// TODO: These tests could still be flaky, lets fix that:
// https://github.com/n0-computer/iroh/issues/1183
#[cfg(test)]
mod tests {

    use std::time::Instant;

    use n0_future::StreamExt;
    use rand::SeedableRng;
    use testresult::TestResult;
    use tracing::{error_span, info, info_span, Instrument};
    use tracing_test::traced_test;

    use super::*;
    use crate::test_utils::{run_relay_server, run_relay_server_with};

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[tokio::test]
    #[traced_test]
    async fn test_connect_self() {
        let ep = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let my_addr = ep.node_addr().await.unwrap();
        let res = ep.connect(my_addr.clone(), TEST_ALPN).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().starts_with("Connecting to ourself"));

        let res = ep.add_node_addr(my_addr);
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().starts_with("Adding our own address"));
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_connect_close() {
        let (relay_map, relay_url, _guard) = run_relay_server().await.unwrap();
        let server_secret_key = SecretKey::generate(rand::thread_rng());
        let server_peer_id = server_secret_key.public();

        let server = {
            let relay_map = relay_map.clone();
            tokio::spawn(
                async move {
                    let ep = Endpoint::builder()
                        .secret_key(server_secret_key)
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .relay_mode(RelayMode::Custom(relay_map))
                        .insecure_skip_relay_cert_verify(true)
                        .bind()
                        .await
                        .unwrap();
                    info!("accepting connection");
                    let incoming = ep.accept().await.unwrap();
                    let conn = incoming.await.unwrap();
                    let mut stream = conn.accept_uni().await.unwrap();
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await.unwrap();
                    info!("Accepted 1 stream, received {buf:?}.  Closing now.");
                    // close the connection
                    conn.close(7u8.into(), b"bye");

                    let res = conn.accept_uni().await;
                    assert_eq!(res.unwrap_err(), quinn::ConnectionError::LocallyClosed);

                    let res = stream.read_to_end(10).await;
                    assert_eq!(
                        res.unwrap_err(),
                        quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(
                            quinn::ConnectionError::LocallyClosed
                        ))
                    );
                    info!("server test completed");
                }
                .instrument(info_span!("test-server")),
            )
        };

        let client = tokio::spawn(
            async move {
                let ep = Endpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .relay_mode(RelayMode::Custom(relay_map))
                    .insecure_skip_relay_cert_verify(true)
                    .bind()
                    .await
                    .unwrap();
                info!("client connecting");
                let node_addr = NodeAddr::new(server_peer_id).with_relay_url(relay_url);
                let conn = ep.connect(node_addr, TEST_ALPN).await.unwrap();
                let mut stream = conn.open_uni().await.unwrap();

                // First write is accepted by server.  We need this bit of synchronisation
                // because if the server closes after simply accepting the connection we can
                // not be sure our .open_uni() call would succeed as it may already receive
                // the error.
                stream.write_all(b"hello").await.unwrap();

                info!("waiting for closed");
                // Remote now closes the connection, we should see an error sometime soon.
                let err = conn.closed().await;
                let expected_err =
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code: 7u8.into(),
                        reason: b"bye".to_vec().into(),
                    });
                assert_eq!(err, expected_err);

                info!("opening new - expect it to fail");
                let res = conn.open_uni().await;
                assert_eq!(res.unwrap_err(), expected_err);
                info!("client test completed");
            }
            .instrument(info_span!("test-client")),
        );

        let (server, client) = tokio::time::timeout(
            Duration::from_secs(30),
            n0_future::future::zip(server, client),
        )
        .await
        .expect("timeout");
        server.unwrap();
        client.unwrap();
    }

    /// Test that peers are properly restored
    #[tokio::test]
    #[traced_test]
    async fn restore_peers() {
        let secret_key = SecretKey::generate(rand::thread_rng());

        /// Create an endpoint for the test.
        async fn new_endpoint(secret_key: SecretKey, nodes: Option<Vec<NodeAddr>>) -> Endpoint {
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let mut builder = Endpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config);
            if let Some(nodes) = nodes {
                builder = builder.known_nodes(nodes);
            }
            builder
                .alpns(vec![TEST_ALPN.to_vec()])
                .bind()
                .await
                .unwrap()
        }

        // create the peer that will be added to the peer map
        let peer_id = SecretKey::generate(rand::thread_rng()).public();
        let direct_addr: SocketAddr =
            (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8758u16).into();
        let node_addr = NodeAddr::new(peer_id).with_direct_addresses([direct_addr]);

        info!("setting up first endpoint");
        // first time, create a magic endpoint without peers but a peers file and add addressing
        // information for a peer
        let endpoint = new_endpoint(secret_key.clone(), None).await;
        assert_eq!(endpoint.remote_info_iter().count(), 0);
        endpoint.add_node_addr(node_addr.clone()).unwrap();

        // Grab the current addrs
        let node_addrs: Vec<NodeAddr> = endpoint.remote_info_iter().map(Into::into).collect();
        assert_eq!(node_addrs.len(), 1);
        assert_eq!(node_addrs[0], node_addr);

        info!("closing endpoint");
        // close the endpoint and restart it
        endpoint.close().await;

        info!("restarting endpoint");
        // now restart it and check the addressing info of the peer
        let endpoint = new_endpoint(secret_key, Some(node_addrs)).await;
        let RemoteInfo { mut addrs, .. } = endpoint.remote_info(peer_id).unwrap();
        let conn_addr = addrs.pop().unwrap().addr;
        assert_eq!(conn_addr, direct_addr);
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_relay_connect_loop() {
        let start = Instant::now();
        let n_clients = 5;
        let n_chunks_per_client = 2;
        let chunk_size = 10;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let (relay_map, relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let server_secret_key = SecretKey::generate(&mut rng);
        let server_node_id = server_secret_key.public();

        // The server accepts the connections of the clients sequentially.
        let server = {
            let relay_map = relay_map.clone();
            tokio::spawn(
                async move {
                    let ep = Endpoint::builder()
                        .insecure_skip_relay_cert_verify(true)
                        .secret_key(server_secret_key)
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .relay_mode(RelayMode::Custom(relay_map))
                        .bind()
                        .await
                        .unwrap();
                    let eps = ep.bound_sockets();
                    info!(me = %ep.node_id().fmt_short(), ipv4=%eps.0, ipv6=?eps.1, "server listening on");
                    for i in 0..n_clients {
                        let round_start = Instant::now();
                        info!("[server] round {i}");
                        let incoming = ep.accept().await.unwrap();
                        let conn = incoming.await.unwrap();
                        let node_id = conn.remote_node_id().unwrap();
                        info!(%i, peer = %node_id.fmt_short(), "accepted connection");
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; chunk_size];
                        for _i in 0..n_chunks_per_client {
                            recv.read_exact(&mut buf).await.unwrap();
                            send.write_all(&buf).await.unwrap();
                        }
                        send.finish().unwrap();
                        send.stopped().await.unwrap();
                        recv.read_to_end(0).await.unwrap();
                        info!(%i, peer = %node_id.fmt_short(), "finished");
                        info!("[server] round {i} done in {:?}", round_start.elapsed());
                    }
                }
                .instrument(error_span!("server")),
            )
        };

        for i in 0..n_clients {
            let round_start = Instant::now();
            info!("[client] round {}", i);
            let relay_map = relay_map.clone();
            let client_secret_key = SecretKey::generate(&mut rng);
            let relay_url = relay_url.clone();
            async {
                info!("client binding");
                let ep = Endpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .insecure_skip_relay_cert_verify(true)
                    .relay_mode(RelayMode::Custom(relay_map))
                    .secret_key(client_secret_key)
                    .bind()
                    .await
                    .unwrap();
                let eps = ep.bound_sockets();
                info!(me = %ep.node_id().fmt_short(), ipv4=%eps.0, ipv6=?eps.1, "client bound");
                let node_addr = NodeAddr::new(server_node_id).with_relay_url(relay_url);
                info!(to = ?node_addr, "client connecting");
                let conn = ep.connect(node_addr, TEST_ALPN).await.unwrap();
                info!("client connected");
                let (mut send, mut recv) = conn.open_bi().await.unwrap();

                for i in 0..n_chunks_per_client {
                    let mut buf = vec![i; chunk_size];
                    send.write_all(&buf).await.unwrap();
                    recv.read_exact(&mut buf).await.unwrap();
                    assert_eq!(buf, vec![i; chunk_size]);
                }
                send.finish().unwrap();
                send.stopped().await.unwrap();
                recv.read_to_end(0).await.unwrap();
                info!("client finished");
                ep.close().await;
                info!("client closed");
            }
            .instrument(error_span!("client", %i))
            .await;
            info!("[client] round {i} done in {:?}", round_start.elapsed());
        }

        server.await.unwrap();

        // We appear to have seen this being very slow at times.  So ensure we fail if this
        // test is too slow.  We're only making two connections transferring very little
        // data, this really shouldn't take long.
        if start.elapsed() > Duration::from_secs(15) {
            panic!("Test too slow, something went wrong");
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_bidi_send_recv() {
        let ep1 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let ep2 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let ep1_nodeaddr = ep1.node_addr().await.unwrap();
        let ep2_nodeaddr = ep2.node_addr().await.unwrap();
        ep1.add_node_addr(ep2_nodeaddr.clone()).unwrap();
        ep2.add_node_addr(ep1_nodeaddr.clone()).unwrap();
        let ep1_nodeid = ep1.node_id();
        let ep2_nodeid = ep2.node_id();
        eprintln!("node id 1 {ep1_nodeid}");
        eprintln!("node id 2 {ep2_nodeid}");

        async fn connect_hello(ep: Endpoint, dst: NodeAddr) {
            let conn = ep.connect(dst, TEST_ALPN).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            info!("sending hello");
            send.write_all(b"hello").await.unwrap();
            send.finish().unwrap();
            info!("receiving world");
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"world");
            conn.close(1u8.into(), b"done");
        }

        async fn accept_world(ep: Endpoint, src: NodeId) {
            let incoming = ep.accept().await.unwrap();
            let mut iconn = incoming.accept().unwrap();
            let alpn = iconn.alpn().await.unwrap();
            let conn = iconn.await.unwrap();
            let node_id = conn.remote_node_id().unwrap();
            assert_eq!(node_id, src);
            assert_eq!(alpn, TEST_ALPN);
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            info!("receiving hello");
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"hello");
            info!("sending hello");
            send.write_all(b"world").await.unwrap();
            send.finish().unwrap();
            match conn.closed().await {
                ConnectionError::ApplicationClosed(closed) => {
                    assert_eq!(closed.error_code, 1u8.into());
                }
                _ => panic!("wrong close error"),
            }
        }

        let p1_accept = tokio::spawn(accept_world(ep1.clone(), ep2_nodeid).instrument(info_span!(
            "p1_accept",
            ep1 = %ep1.node_id().fmt_short(),
            dst = %ep2_nodeid.fmt_short(),
        )));
        let p2_accept = tokio::spawn(accept_world(ep2.clone(), ep1_nodeid).instrument(info_span!(
            "p2_accept",
            ep2 = %ep2.node_id().fmt_short(),
            dst = %ep1_nodeid.fmt_short(),
        )));
        let p1_connect = tokio::spawn(connect_hello(ep1.clone(), ep2_nodeaddr).instrument(
            info_span!(
                "p1_connect",
                ep1 = %ep1.node_id().fmt_short(),
                dst = %ep2_nodeid.fmt_short(),
            ),
        ));
        let p2_connect = tokio::spawn(connect_hello(ep2.clone(), ep1_nodeaddr).instrument(
            info_span!(
                "p2_connect",
                ep2 = %ep2.node_id().fmt_short(),
                dst = %ep1_nodeid.fmt_short(),
            ),
        ));

        p1_accept.await.unwrap();
        p2_accept.await.unwrap();
        p1_connect.await.unwrap();
        p2_connect.await.unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_conn_type_stream() {
        const TIMEOUT: Duration = std::time::Duration::from_secs(15);
        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let ep1_secret_key = SecretKey::generate(&mut rng);
        let ep2_secret_key = SecretKey::generate(&mut rng);
        let ep1 = Endpoint::builder()
            .secret_key(ep1_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .bind()
            .await
            .unwrap();
        let ep2 = Endpoint::builder()
            .secret_key(ep2_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .bind()
            .await
            .unwrap();

        async fn handle_direct_conn(ep: &Endpoint, node_id: NodeId) -> Result<()> {
            let mut stream = ep.conn_type(node_id)?.stream();
            let src = ep.node_id().fmt_short();
            let dst = node_id.fmt_short();
            while let Some(conn_type) = stream.next().await {
                tracing::info!(me = %src, dst = %dst, conn_type = ?conn_type);
                if matches!(conn_type, ConnectionType::Direct(_)) {
                    return Ok(());
                }
            }
            anyhow::bail!("conn_type stream ended before `ConnectionType::Direct`");
        }

        async fn accept(ep: &Endpoint) -> NodeId {
            let incoming = ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let node_id = conn.remote_node_id().unwrap();
            tracing::info!(node_id=%node_id.fmt_short(), "accepted connection");
            node_id
        }

        let ep1_nodeid = ep1.node_id();
        let ep2_nodeid = ep2.node_id();

        let ep1_nodeaddr = ep1.node_addr().await.unwrap();
        tracing::info!(
            "node id 1 {ep1_nodeid}, relay URL {:?}",
            ep1_nodeaddr.relay_url()
        );
        tracing::info!("node id 2 {ep2_nodeid}");

        let ep1_side = async move {
            accept(&ep1).await;
            handle_direct_conn(&ep1, ep2_nodeid).await
        };

        let ep2_side = async move {
            ep2.connect(ep1_nodeaddr, TEST_ALPN).await.unwrap();
            handle_direct_conn(&ep2, ep1_nodeid).await
        };

        let res_ep1 = tokio::spawn(tokio::time::timeout(TIMEOUT, ep1_side));
        let res_ep2 = tokio::spawn(tokio::time::timeout(TIMEOUT, ep2_side));

        let (r1, r2) = tokio::try_join!(res_ep1, res_ep2).unwrap();
        r1.expect("ep1 timeout").unwrap();
        r2.expect("ep2 timeout").unwrap();
    }

    #[tokio::test]
    #[traced_test]
    async fn test_direct_addresses_no_stun_relay() {
        let (relay_map, _, _guard) = run_relay_server_with(None, false).await.unwrap();

        let ep = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(10), ep.direct_addresses().initialized())
            .await
            .unwrap()
            .unwrap();
    }

    async fn spawn_0rtt_server(secret_key: SecretKey, log_span: tracing::Span) -> Result<Endpoint> {
        let server = Endpoint::builder()
            .secret_key(secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;

        // Gets aborted via the endpoint closing causing an `Err`
        // a simple echo server
        tokio::spawn({
            let server = server.clone();
            async move {
                while let Some(incoming) = server.accept().await {
                    let connecting = incoming.accept()?;
                    let conn = match connecting.into_0rtt() {
                        Ok((conn, _)) => {
                            info!("0rtt accepted");
                            conn
                        }
                        Err(connecting) => {
                            info!("0rtt denied");
                            connecting.await?
                        }
                    };
                    let (mut send, mut recv) = conn.accept_bi().await?;
                    let data = recv.read_to_end(10_000_000).await?;
                    send.write_all(&data).await?;
                    send.finish()?;

                    // Stay alive until the other side closes the connection.
                    conn.closed().await;
                }
                anyhow::Ok(())
            }
            .instrument(log_span)
        });

        Ok(server)
    }

    async fn connect_client_0rtt_expect_err(
        client: &Endpoint,
        server_addr: NodeAddr,
    ) -> Result<()> {
        let conn = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await?
            .into_0rtt()
            .expect_err("expected 0rtt to fail")
            .await?;

        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"hello").await?;
        send.finish()?;
        let received = recv.read_to_end(1_000).await?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    async fn connect_client_0rtt_expect_ok(
        client: &Endpoint,
        server_addr: NodeAddr,
        expect_server_accepts: bool,
    ) -> Result<()> {
        let (conn, accepted_0rtt) = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await?
            .into_0rtt()
            .map_err(|_| "0rtt failed")
            .unwrap();

        // This is how we send data in 0-RTT:
        let (mut send, recv) = conn.open_bi().await?;
        send.write_all(b"hello").await?;
        send.finish()?;
        // When this resolves, we've gotten a response from the server about whether the 0-RTT data above was accepted:
        let accepted = accepted_0rtt.await;
        assert_eq!(accepted, expect_server_accepts);
        let mut recv = if accepted {
            recv
        } else {
            // in this case we need to re-send data by re-creating the connection.
            let (mut send, recv) = conn.open_bi().await?;
            send.write_all(b"hello").await?;
            send.finish()?;
            recv
        };
        let received = recv.read_to_end(1_000).await?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_0rtt() -> TestResult {
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server = spawn_0rtt_server(
            SecretKey::generate(rand::thread_rng()),
            info_span!("server"),
        )
        .await?;

        connect_client_0rtt_expect_err(&client, server.node_addr().await?).await?;
        // The second 0rtt attempt should work
        connect_client_0rtt_expect_ok(&client, server.node_addr().await?, true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // We have this test, as this would've failed at some point.
    // This effectively tests that we correctly categorize the TLS session tickets we
    // receive into the respective "bucket" for the recipient.
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_non_consecutive() -> TestResult {
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server = spawn_0rtt_server(
            SecretKey::generate(rand::thread_rng()),
            info_span!("server"),
        )
        .await?;

        connect_client_0rtt_expect_err(&client, server.node_addr().await?).await?;

        // connecting with another endpoint should not interfere with our
        // TLS session ticket cache for the first endpoint:
        let another = spawn_0rtt_server(
            SecretKey::generate(rand::thread_rng()),
            info_span!("another"),
        )
        .await?;
        connect_client_0rtt_expect_err(&client, another.node_addr().await?).await?;
        another.close().await;

        connect_client_0rtt_expect_ok(&client, server.node_addr().await?, true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // Test whether 0-RTT is possible after a restart:
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_after_server_restart() -> TestResult {
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server_key = SecretKey::generate(rand::thread_rng());
        let server = spawn_0rtt_server(server_key.clone(), info_span!("server-initial")).await?;

        connect_client_0rtt_expect_err(&client, server.node_addr().await?).await?;
        connect_client_0rtt_expect_ok(&client, server.node_addr().await?, true).await?;

        server.close().await;

        let server = spawn_0rtt_server(server_key, info_span!("server-restart")).await?;

        // we expect the client to *believe* it can 0-RTT connect to the server (hence expect_ok),
        // but the server will reject the early data because it discarded necessary state
        // to decrypt it when restarting.
        connect_client_0rtt_expect_ok(&client, server.node_addr().await?, false).await?;

        client.close().await;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn graceful_close() -> testresult::TestResult {
        let client = Endpoint::builder().bind().await?;
        let server = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let server_addr = server.node_addr().await?;
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let msg = recv.read_to_end(1_000).await?;
            send.write_all(&msg).await?;
            send.finish()?;
            let close_reason = conn.closed().await;
            testresult::TestResult::Ok(close_reason)
        });

        let conn = client.connect(server_addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(b"Hello, world!").await?;
        send.finish()?;
        recv.read_to_end(1_000).await?;
        conn.close(42u32.into(), b"thanks, bye!");
        client.close().await;

        let close_err = server_task.await??;
        let ConnectionError::ApplicationClosed(app_close) = close_err else {
            panic!("Unexpected close reason: {close_err:?}");
        };

        assert_eq!(app_close.error_code, 42u32.into());
        assert_eq!(app_close.reason.as_ref(), b"thanks, bye!");

        Ok(())
    }
}
