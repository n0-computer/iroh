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
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

use ed25519_dalek::{VerifyingKey, pkcs8::DecodePublicKey};
use iroh_base::{NodeAddr, NodeId, SecretKey};
use iroh_relay::RelayMap;
use n0_future::time::Duration;
use n0_watcher::Watcher;
use nested_enum_utils::common_fields;
use pin_project::pin_project;
use quinn_proto::PathId;
use snafu::{ResultExt, Snafu, ensure};
use tracing::{debug, instrument, trace, warn};
use url::Url;

#[cfg(wasm_browser)]
use crate::discovery::pkarr::PkarrResolver;
#[cfg(not(wasm_browser))]
use crate::{discovery::dns::DnsDiscovery, dns::DnsResolver};
use crate::{
    discovery::{
        ConcurrentDiscovery, DiscoveryError, DiscoveryTask, DynIntoDiscovery, IntoDiscovery,
        UserData, pkarr::PkarrPublisher,
    },
    magicsock::{
        self, HEARTBEAT_INTERVAL, Handle, MAX_MULTIPATH_PATHS, OwnAddressSnafu,
        PATH_MAX_IDLE_TIMEOUT, PathInfo,
        mapped_addrs::{MappedAddr, MultipathMappedAddr, NodeIdMappedAddr},
        node_map::TransportType,
    },
    metrics::EndpointMetrics,
    net_report::Report,
    tls::{self, DEFAULT_MAX_TLS_TICKETS},
};

// Missing still: SendDatagram and ConnectionClose::frame_type's Type.
pub use quinn::{
    AcceptBi, AcceptUni, AckFrequencyConfig, ApplicationClose, Chunk, ClosedStream,
    ConnectionClose, ConnectionError, ConnectionStats, MtuDiscoveryConfig, OpenBi, OpenUni,
    ReadDatagram, ReadError, ReadExactError, ReadToEndError, RecvStream, ResetError, RetryError,
    SendDatagramError, SendStream, ServerConfig, StoppedError, StreamId, TransportConfig, VarInt,
    WeakConnectionHandle, WriteError,
};
pub use quinn_proto::{
    FrameStats, PathStats, TransportError, TransportErrorCode, UdpStats, Written,
    congestion::{Controller, ControllerFactory},
    crypto::{
        AeadKey, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey,
        ServerConfig as CryptoServerConfig, UnsupportedVersion,
    },
};

pub use super::magicsock::{AddNodeAddrError, ConnectionType, DirectAddr, DirectAddrType};

/// The delay to fall back to discovery when direct addresses fail.
///
/// When a connection is attempted and we have some addressing info for the remote, we
/// assume that one of these probably works.  If after this delay there is still no
/// connection, discovery will be started.
const DISCOVERY_WAIT_PERIOD: Duration = Duration::from_millis(150);

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
#[derive(Debug)]
pub struct Builder {
    secret_key: Option<SecretKey>,
    relay_mode: RelayMode,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: quinn::TransportConfig,
    keylog: bool,
    discovery: Vec<Box<dyn DynIntoDiscovery>>,
    discovery_user_data: Option<UserData>,
    proxy_url: Option<Url>,
    #[cfg(not(wasm_browser))]
    dns_resolver: Option<DnsResolver>,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
    addr_v4: Option<SocketAddrV4>,
    addr_v6: Option<SocketAddrV6>,
    #[cfg(any(test, feature = "test-utils"))]
    path_selection: PathSelection,
    max_tls_tickets: usize,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            secret_key: Default::default(),
            relay_mode: default_relay_mode(),
            alpn_protocols: Default::default(),
            transport_config: quinn::TransportConfig::default(),
            keylog: Default::default(),
            discovery: Default::default(),
            discovery_user_data: Default::default(),
            proxy_url: None,
            #[cfg(not(wasm_browser))]
            dns_resolver: None,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            addr_v4: None,
            addr_v6: None,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: PathSelection::default(),
            max_tls_tickets: DEFAULT_MAX_TLS_TICKETS,
        }
    }
}

impl Builder {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users.

    // # The final constructor that everyone needs.

    /// Binds the magic endpoint.
    pub async fn bind(mut self) -> Result<Endpoint, BindError> {
        let mut rng = rand::rng();
        let relay_map = self.relay_mode.relay_map();
        let secret_key = self
            .secret_key
            .unwrap_or_else(move || SecretKey::generate(&mut rng));

        // Override some transport config settings.
        self.transport_config
            .keep_alive_interval(Some(HEARTBEAT_INTERVAL));
        self.transport_config
            .default_path_keep_alive_interval(Some(HEARTBEAT_INTERVAL));
        self.transport_config
            .default_path_max_idle_timeout(Some(PATH_MAX_IDLE_TIMEOUT));
        self.transport_config
            .max_concurrent_multipath_paths(MAX_MULTIPATH_PATHS);

        let static_config = StaticConfig {
            transport_config: Arc::new(self.transport_config),
            tls_config: tls::TlsConfig::new(secret_key.clone(), self.max_tls_tickets),
            keylog: self.keylog,
        };
        let server_config = static_config.create_server_config(self.alpn_protocols);

        #[cfg(not(wasm_browser))]
        let dns_resolver = self.dns_resolver.unwrap_or_default();

        let metrics = EndpointMetrics::default();

        let msock_opts = magicsock::Options {
            addr_v4: self.addr_v4,
            addr_v6: self.addr_v6,
            secret_key,
            relay_map,
            discovery: self.discovery,
            discovery_user_data: self.discovery_user_data,
            proxy_url: self.proxy_url,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: self.insecure_skip_relay_cert_verify,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: self.path_selection,
            metrics,
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
    /// connections at least one [ALPN] must be set.
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
    /// See the documentation of the [`crate::discovery::Discovery`] trait for details.
    pub fn discovery(mut self, discovery: impl IntoDiscovery) -> Self {
        self.discovery.clear();
        self.discovery.push(Box::new(discovery));
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
    /// See the documentation of the [`crate::discovery::Discovery`] trait for details.
    pub fn add_discovery(mut self, discovery: impl IntoDiscovery) -> Self {
        self.discovery.push(Box::new(discovery));
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
        self = self.add_discovery(PkarrPublisher::n0_dns());
        // Resolve using HTTPS requests to our DNS server's /pkarr path in browsers
        #[cfg(wasm_browser)]
        {
            self = self.add_discovery(PkarrResolver::n0_dns());
        }
        // Resolve using DNS queries outside browsers.
        #[cfg(not(wasm_browser))]
        {
            self = self.add_discovery(DnsDiscovery::n0_dns());
        }
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
        self = self.add_discovery(crate::discovery::pkarr::dht::DhtDiscovery::builder());
        self
    }

    #[cfg(feature = "discovery-local-network")]
    /// Configures the endpoint to also use local network discovery.
    ///
    /// This is equivalent to adding a [`crate::discovery::mdns::MdnsDiscovery`]
    /// with default settings. Note that MdnsDiscovery has various more advanced
    /// configuration options. If you need any of those, you should manually
    /// create a MdnsDiscovery and add it with [`Builder::add_discovery`].
    pub fn discovery_local_network(mut self) -> Self {
        self = self.add_discovery(crate::discovery::mdns::MdnsDiscovery::builder());
        self
    }

    /// Sets the initial user-defined data to be published in discovery services for this node.
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
    #[cfg(not(wasm_browser))]
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

    /// Set the maximum number of TLS tickets to cache.
    ///
    /// Set this to a larger value if you want to do 0rtt connections to a large
    /// number of clients.
    ///
    /// The default is 256, taking about 150 KiB in memory.
    pub fn max_tls_tickets(mut self, n: usize) -> Self {
        self.max_tls_tickets = n;
        self
    }
}

/// Configuration for a [`quinn::Endpoint`] that cannot be changed at runtime.
#[derive(Debug)]
struct StaticConfig {
    tls_config: tls::TlsConfig,
    transport_config: Arc<quinn::TransportConfig>,
    keylog: bool,
}

impl StaticConfig {
    /// Create a [`quinn::ServerConfig`] with the specified ALPN protocols.
    fn create_server_config(&self, alpn_protocols: Vec<Vec<u8>>) -> ServerConfig {
        let quic_server_config = self
            .tls_config
            .make_server_config(alpn_protocols, self.keylog);
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(self.transport_config.clone());

        server_config
    }
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
    /// Configuration structs for quinn, holds the transport config, certificate setup, secret key etc.
    static_config: Arc<StaticConfig>,
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConnectWithOptsError {
    #[snafu(transparent)]
    AddNodeAddr { source: AddNodeAddrError },
    #[snafu(display("Connecting to ourself is not supported"))]
    SelfConnect {},
    #[snafu(display("No addressing information available"))]
    NoAddress { source: GetMappingAddressError },
    #[snafu(display("Unable to connect to remote"))]
    Quinn { source: quinn::ConnectError },
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConnectError {
    #[snafu(transparent)]
    Connect {
        #[snafu(source(from(ConnectWithOptsError, Box::new)))]
        source: Box<ConnectWithOptsError>,
    },
    #[snafu(transparent)]
    Connection {
        #[snafu(source(from(ConnectionError, Box::new)))]
        source: Box<ConnectionError>,
    },
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum BindError {
    #[snafu(transparent)]
    MagicSpawn {
        source: magicsock::CreateHandleError,
    },
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum GetMappingAddressError {
    #[snafu(display("Discovery service required due to missing addressing information"))]
    DiscoveryStart { source: DiscoveryError },
    #[snafu(display("Discovery service failed"))]
    Discover { source: DiscoveryError },
    #[snafu(display("No addressing information found"))]
    NoAddress {},
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
    #[instrument("ep", skip_all, fields(me = %static_config.tls_config.secret_key.public().fmt_short()))]
    async fn bind(
        static_config: StaticConfig,
        msock_opts: magicsock::Options,
    ) -> Result<Self, BindError> {
        let msock = magicsock::MagicSock::spawn(msock_opts).await?;
        trace!("created magicsock");
        debug!(version = env!("CARGO_PKG_VERSION"), "iroh Endpoint created");

        let ep = Self {
            msock,
            static_config: Arc::new(static_config),
        };
        Ok(ep)
    }

    /// Sets the list of accepted ALPN protocols.
    ///
    /// This will only affect new incoming connections.
    /// Note that this *overrides* the current list of ALPNs.
    pub fn set_alpns(&self, alpns: Vec<Vec<u8>>) {
        let server_config = self.static_config.create_server_config(alpns);
        self.msock.endpoint().set_server_config(Some(server_config));
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
    /// may still be possible a connection can be established.  This depends on which, if any,
    /// [`crate::discovery::Discovery`] services were configured using [`Builder::discovery`].  The discovery
    /// service will also be used if the remote node is not reachable on the provided direct
    /// addresses and there is no [`RelayUrl`].
    ///
    /// If addresses or relay servers are neither provided nor can be discovered, the
    /// connection attempt will fail with an error.
    ///
    /// The `alpn`, or application-level protocol identifier, is also required. The remote
    /// endpoint must support this `alpn`, otherwise the connection attempt will fail with
    /// an error.
    ///
    /// [`RelayUrl`]: crate::RelayUrl
    pub async fn connect(
        &self,
        node_addr: impl Into<NodeAddr>,
        alpn: &[u8],
    ) -> Result<Connection, ConnectError> {
        let node_addr = node_addr.into();
        let remote = node_addr.node_id;
        let connecting = self
            .connect_with_opts(node_addr, alpn, Default::default())
            .await?;
        let conn = connecting.await?;

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
        me = %self.node_id().fmt_short(),
        remote = tracing::field::Empty,
        alpn = String::from_utf8_lossy(alpn).to_string(),
    ))]
    pub async fn connect_with_opts(
        &self,
        node_addr: impl Into<NodeAddr>,
        alpn: &[u8],
        options: ConnectOptions,
    ) -> Result<Connecting, ConnectWithOptsError> {
        let node_addr: NodeAddr = node_addr.into();
        tracing::Span::current().record(
            "remote",
            tracing::field::display(node_addr.node_id.fmt_short()),
        );

        // Connecting to ourselves is not supported.
        ensure!(node_addr.node_id != self.node_id(), SelfConnectSnafu);

        if !node_addr.is_empty() {
            self.add_node_addr(node_addr.clone()).await?;
        }
        let node_id = node_addr.node_id;
        trace!(dst_node_id = %node_id.fmt_short(), "connecting");

        // When we start a connection we want to send the QUIC Initial packets on all the
        // known paths for the remote node.  For this we use an AllPathsMappedAddr as
        // destination for Quinn.  Start discovery for this node if it's enabled and we have
        // no valid or verified address information for this node.  Dropping the discovery
        // cancels any still running task.
        let (mapped_addr, _discovery_drop_guard) = self
            .get_mapping_addr_and_maybe_start_discovery(node_addr)
            .await
            .context(NoAddressSnafu)?;

        let transport_config = options
            .transport_config
            .unwrap_or(self.static_config.transport_config.clone());

        // Start connecting via quinn. This will time out after 10 seconds if no reachable
        // address is available.

        let client_config = {
            let mut alpn_protocols = vec![alpn.to_vec()];
            alpn_protocols.extend(options.additional_alpns);
            let quic_client_config = self
                .static_config
                .tls_config
                .make_client_config(alpn_protocols, self.static_config.keylog);
            let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
            client_config.transport_config(transport_config);
            client_config
        };

        let dest_addr = mapped_addr.private_socket_addr();
        let server_name = &tls::name::encode(node_id);
        let connect = self
            .msock
            .endpoint()
            .connect_with(client_config, dest_addr, server_name)
            .context(QuinnSnafu)?;

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
    async fn add_node_addr(&self, node_addr: NodeAddr) -> Result<(), AddNodeAddrError> {
        self.add_node_addr_inner(node_addr, magicsock::node_map::Source::App)
            .await
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
    pub(crate) async fn add_node_addr_with_source(
        &self,
        node_addr: NodeAddr,
        source: &'static str,
    ) -> Result<(), AddNodeAddrError> {
        self.add_node_addr_inner(
            node_addr,
            magicsock::node_map::Source::NamedApp {
                name: source.into(),
            },
        )
        .await
    }

    async fn add_node_addr_inner(
        &self,
        node_addr: NodeAddr,
        source: magicsock::node_map::Source,
    ) -> Result<(), AddNodeAddrError> {
        // Connecting to ourselves is not supported.
        snafu::ensure!(node_addr.node_id != self.node_id(), OwnAddressSnafu);
        self.msock.add_node_addr(node_addr, source).await
    }

    // # Getter methods for properties of this Endpoint itself.

    /// Returns the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.static_config.tls_config.secret_key
    }

    /// Returns the node id of this endpoint.
    ///
    /// This ID is the unique addressing information of this node and other peers must know
    /// it to be able to connect to this node.
    pub fn node_id(&self) -> NodeId {
        self.static_config.tls_config.secret_key.public()
    }

    /// Returns the current [`NodeAddr`].
    /// As long as the endpoint was able to binde to a network interfaces, some
    /// local addresses will be available.
    ///
    /// The state of other fields depends on the state of networking and connectivity.
    /// Use the [`Endpoint::online`] method to ensure that the endpoint is considered
    /// "online" (has contacted a relay server) before calling this method, if you want
    /// to ensure that the `NodeAddr` will contain enough information to allow this endpoint
    /// to be dialable by a remote endpoint over the internet.
    ///
    /// You can use the [`Endpoint::watch_node_addr`] method to get updates when the `NodeAddr`
    /// changes.
    pub fn node_addr(&self) -> NodeAddr {
        self.watch_node_addr().get()
    }

    /// Returns a [`Watcher`] for the current [`NodeAddr`] for this endpoint.
    ///
    /// The observed [`NodeAddr`] will have the current [`RelayUrl`] and direct addresses.
    ///
    /// ```no_run
    /// # async fn wrapper() -> n0_snafu::Result {
    /// use iroh::{Endpoint, Watcher};
    ///
    /// let endpoint = Endpoint::builder()
    ///     .alpns(vec![b"my-alpn".to_vec()])
    ///     .bind()
    ///     .await?;
    /// let node_addr = endpoint.watch_node_addr().get();
    /// # let _ = node_addr;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The [`Endpoint::online`] method can be used as a convenience method to
    /// understand if the endpoint has ever been considered "online". But after
    /// that initial call to [`Endpoint::online`], to understand if your
    /// endpoint is no longer able to be connected to by endpoints outside
    /// of the private or local network, watch for changes in it's [`NodeAddr`].
    /// If the `relay_url` is `None` or if there are no `direct_addresses` in
    /// the [`NodeAddr`], you may not be dialable by other endpoints on the internet.
    ///
    ///
    /// The `NodeAddr` will change as:
    /// - network conditions change
    /// - the endpoint connects to a relay server
    /// - the endpoint changes its preferred relay server
    /// - more addresses are discovered for this endpoint
    ///
    /// [`RelayUrl`]: crate::RelayUrl
    #[cfg(not(wasm_browser))]
    pub fn watch_node_addr(&self) -> impl n0_watcher::Watcher<Value = NodeAddr> + use<> {
        let watch_addrs = self.msock.direct_addresses();
        let watch_relay = self.msock.home_relay();
        let node_id = self.node_id();

        watch_addrs
            .or(watch_relay)
            .map(move |(addrs, mut relays)| {
                debug_assert!(!addrs.is_empty(), "direct addresses must never be empty");

                NodeAddr::from_parts(node_id, relays.pop(), addrs.into_iter().map(|x| x.addr))
            })
            .expect("watchable is alive - cannot be disconnected yet")
    }

    /// Returns a [`Watcher`] for the current [`NodeAddr`] for this endpoint.
    ///
    /// When compiled to Wasm, this function returns a watcher that initializes
    /// with a [`NodeAddr`] that only contains a relay URL, but no direct addresses,
    /// as there are no APIs for directly using sockets in browsers.
    #[cfg(wasm_browser)]
    pub fn watch_node_addr(&self) -> impl n0_watcher::Watcher<Value = NodeAddr> + use<> {
        // In browsers, there will never be any direct addresses, so we wait
        // for the home relay instead. This makes the `NodeAddr` have *some* way
        // of connecting to us.
        let watch_relay = self.msock.home_relay();
        let node_id = self.node_id();
        watch_relay
            .map(move |mut relays| NodeAddr::from_parts(node_id, relays.pop(), std::iter::empty()))
            .expect("watchable is alive - cannot be disconnected yet")
    }

    /// A convenience method that waits for the endpoint to be considered "online".
    ///
    /// This currently means at least one relay server was connected,
    /// and at least one local IP address is available.
    /// Event if no relays are configured, this will still wait for a relay connection.
    ///
    /// Once this has been resolved once, this will always immediately resolve.
    ///
    /// This has no timeout, so if that is needed, you need to wrap it in a timeout.
    ///
    /// To understand if the endpoint has gone back "offline",
    /// you must use the [`Endpoint::watch_node_addr`] method, to
    /// get information on the current relay and direct address information.
    pub async fn online(&self) {
        self.msock.home_relay().initialized().await;
    }

    /// Returns a [`Watcher`] for any net-reports run from this [`Endpoint`].
    ///
    /// A `net-report` checks the network conditions of the [`Endpoint`], such as
    /// whether it is connected to the internet via Ipv4 and/or Ipv6, its NAT
    /// status, its latency to the relay servers, and its public addresses.
    ///
    /// The [`Endpoint`] continuously runs `net-reports` to monitor if network
    /// conditions have changed. This [`Watcher`] will return the latest result
    /// of the `net-report`.
    ///
    /// When issuing the first call to this method the first report might
    /// still be underway, in this case the [`Watcher`] might not be initialized
    /// with [`Some`] value yet.  Once the net-report has been successfully
    /// run, the [`Watcher`] will always return [`Some`] report immediately, which
    /// is the most recently run `net-report`.
    ///
    /// # Examples
    ///
    /// To get the first report use [`Watcher::initialized`]:
    /// ```no_run
    /// use iroh::{Endpoint, Watcher as _};
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let ep = Endpoint::builder().bind().await.unwrap();
    /// let _report = ep.net_report().initialized().await;
    /// # });
    /// ```
    #[doc(hidden)]
    pub fn net_report(&self) -> impl Watcher<Value = Option<Report>> + use<> {
        self.msock.net_report()
    }

    /// Returns the local socket addresses on which the underlying sockets are bound.
    ///
    /// The [`Endpoint`] always binds on an IPv4 address and also tries to bind on an IPv6
    /// address if available.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.msock
            .local_addr()
            .into_iter()
            .filter_map(|addr| addr.into_socket_addr())
            .collect()
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
    /// Will return `None` if we do not have any address information for the given `node_id`.
    pub fn conn_type(&self, node_id: NodeId) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.msock.conn_type(node_id)
    }

    /// Returns the currently lowest latency for this node.
    ///
    /// Will return `None` if we do not have any address information for the given `node_id`.
    pub async fn latency(&self, node_id: NodeId) -> Option<Duration> {
        self.msock.latency(node_id).await
    }

    /// Returns the DNS resolver used in this [`Endpoint`].
    ///
    /// See [`Builder::dns_resolver`].
    #[cfg(not(wasm_browser))]
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.msock.dns_resolver()
    }

    /// Returns the discovery mechanism, if configured.
    ///
    /// See [`Builder::discovery`].
    pub fn discovery(&self) -> &ConcurrentDiscovery {
        self.msock.discovery()
    }

    /// Returns metrics collected for this endpoint.
    ///
    /// The endpoint internally collects various metrics about its operation.
    /// The returned [`EndpointMetrics`] struct contains all of these metrics.
    ///
    /// You can access individual metrics directly by using the public fields:
    /// ```rust
    /// # use std::collections::BTreeMap;
    /// # use iroh::endpoint::Endpoint;
    /// # async fn wrapper() -> n0_snafu::Result {
    /// let endpoint = Endpoint::builder().bind().await?;
    /// assert_eq!(endpoint.metrics().magicsock.recv_datagrams.get(), 0);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`EndpointMetrics`] implements [`MetricsGroupSet`], and each field
    /// implements [`MetricsGroup`]. These traits provide methods to iterate over
    /// the groups in the set, and over the individual metrics in each group, without having
    /// to access each field manually. With these methods, it is straightforward to collect
    /// all metrics into a map or push their values to a metrics collector.
    ///
    /// For example, the following snippet collects all metrics into a map:
    /// ```rust
    /// # use std::collections::BTreeMap;
    /// # use iroh_metrics::{Metric, MetricsGroup, MetricValue, MetricsGroupSet};
    /// # use iroh::endpoint::Endpoint;
    /// # async fn wrapper() -> n0_snafu::Result {
    /// let endpoint = Endpoint::builder().bind().await?;
    /// let metrics: BTreeMap<String, MetricValue> = endpoint
    ///     .metrics()
    ///     .iter()
    ///     .map(|(group, metric)| {
    ///         let name = [group, metric.name()].join(":");
    ///         (name, metric.value())
    ///     })
    ///     .collect();
    ///
    /// assert_eq!(metrics["magicsock:recv_datagrams"], MetricValue::Counter(0));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The metrics can also be encoded into the OpenMetrics text format, as used by Prometheus.
    /// To do so, use the [`iroh_metrics::Registry`], add the endpoint metrics to the
    /// registry with [`Registry::register_all`], and encode the metrics to a string with
    /// [`encode_openmetrics_to_string`]:
    /// ```rust
    /// # use iroh_metrics::{Registry, MetricsSource};
    /// # use iroh::endpoint::Endpoint;
    /// # async fn wrapper() -> n0_snafu::Result {
    /// let endpoint = Endpoint::builder().bind().await?;
    /// let mut registry = Registry::default();
    /// registry.register_all(endpoint.metrics());
    /// let s = registry.encode_openmetrics_to_string()?;
    /// assert!(s.contains(r#"TYPE magicsock_recv_datagrams counter"#));
    /// assert!(s.contains(r#"magicsock_recv_datagrams_total 0"#));
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Through a registry, you can also add labels or prefixes to metrics with
    /// [`Registry::sub_registry_with_label`] or [`Registry::sub_registry_with_prefix`].
    /// Furthermore, [`iroh_metrics::service`] provides functions to easily start services
    /// to serve the metrics with a HTTP server, dump them to a file, or push them
    /// to a Prometheus gateway.
    ///
    /// For example, the following snippet launches an HTTP server that serves the metrics in the
    /// OpenMetrics text format:
    /// ```no_run
    /// # use std::{sync::{Arc, RwLock}, time::Duration};
    /// # use iroh_metrics::{Registry, MetricsSource};
    /// # use iroh::endpoint::Endpoint;
    /// # use n0_snafu::ResultExt;
    /// # async fn wrapper() -> n0_snafu::Result {
    /// // Create a registry, wrapped in a read-write lock so that we can register and serve
    /// // the metrics independently.
    /// let registry = Arc::new(RwLock::new(Registry::default()));
    /// // Spawn a task to serve the metrics on an OpenMetrics HTTP endpoint.
    /// let metrics_task = tokio::task::spawn({
    ///     let registry = registry.clone();
    ///     async move {
    ///         let addr = "0.0.0.0:9100".parse().unwrap();
    ///         iroh_metrics::service::start_metrics_server(addr, registry).await
    ///     }
    /// });
    ///
    /// // Spawn an endpoint and add the metrics to the registry.
    /// let endpoint = Endpoint::builder().bind().await?;
    /// registry.write().unwrap().register_all(endpoint.metrics());
    ///
    /// // Wait for the metrics server to bind, then fetch the metrics via HTTP.
    /// tokio::time::sleep(Duration::from_millis(500));
    /// let res = reqwest::get("http://localhost:9100/metrics")
    ///     .await
    ///     .context("get")?
    ///     .text()
    ///     .await
    ///     .context("text")?;
    ///
    /// assert!(res.contains(r#"TYPE magicsock_recv_datagrams counter"#));
    /// assert!(res.contains(r#"magicsock_recv_datagrams_total 0"#));
    /// # metrics_task.abort();
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`Registry`]: iroh_metrics::Registry
    /// [`Registry::register_all`]: iroh_metrics::Registry::register_all
    /// [`Registry::sub_registry_with_label`]: iroh_metrics::Registry::sub_registry_with_label
    /// [`Registry::sub_registry_with_prefix`]: iroh_metrics::Registry::sub_registry_with_prefix
    /// [`encode_openmetrics_to_string`]: iroh_metrics::MetricsSource::encode_openmetrics_to_string
    /// [`MetricsGroup`]: iroh_metrics::MetricsGroup
    /// [`MetricsGroupSet`]: iroh_metrics::MetricsGroupSet
    #[cfg(feature = "metrics")]
    pub fn metrics(&self) -> &EndpointMetrics {
        &self.msock.metrics
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

    /// Sets the initial user-defined data to be published in discovery services for this node.
    ///
    /// If the user-defined data passed to this function is different to the previous one,
    /// the endpoint will republish its node info to the configured discovery services.
    ///
    /// See also [`Builder::user_data_for_discovery`] for setting an initial value when
    /// building the endpoint.
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
    ) -> Result<(NodeIdMappedAddr, Option<DiscoveryTask>), GetMappingAddressError> {
        let node_id = node_addr.node_id;

        // Only return a mapped addr if we have some way of dialing this node, in other
        // words, we have either a relay URL or at least one direct address.
        let addr = if self.msock.has_send_address(node_id).await {
            Some(self.msock.get_node_mapped_addr(node_id))
        } else {
            None
        };
        match addr {
            Some(maddr) => {
                // We have some way of dialing this node, but that doesn't mean we can
                // connect to any of these addresses.  Start discovery after a small delay.
                let discovery =
                    DiscoveryTask::start_after_delay(self, node_id, DISCOVERY_WAIT_PERIOD)
                        .ok()
                        .flatten();
                Ok((maddr, discovery))
            }

            None => {
                // We have no known addresses or relay URLs for this node.
                // So, we start a discovery task and wait for the first result to arrive, and
                // only then continue, because otherwise we wouldn't have any
                // path to the remote endpoint.
                let res = DiscoveryTask::start(self.clone(), node_id);
                let mut discovery = res.context(get_mapping_address_error::DiscoveryStartSnafu)?;
                discovery
                    .first_arrived()
                    .await
                    .context(get_mapping_address_error::DiscoverSnafu)?;
                let addr = self.msock.get_node_mapped_addr(node_id);
                Ok((addr, Some(discovery)))
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
    additional_alpns: Vec<Vec<u8>>,
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

    /// Sets [ALPN] identifiers that should be signaled as supported on connection, *in
    /// addition* to the main [ALPN] identifier used in [`Endpoint::connect_with_opts`].
    ///
    /// This allows connecting to servers that may only support older versions of your
    /// protocol. In this case, you would add the older [ALPN] identifiers with this
    /// function.
    ///
    /// You'll know the final negotiated [ALPN] identifier once your connection was
    /// established using [`Connection::alpn`], or even slightly earlier in the
    /// handshake by using [`Connecting::alpn`].
    /// The negotiated [ALPN] identifier may be any of the [ALPN] identifiers in this
    /// list or the main [ALPN] used in [`Endpoint::connect_with_opts`].
    ///
    /// The [ALPN] identifier order on the connect side doesn't matter, since it's the
    /// accept side that determines the protocol.
    ///
    /// For setting the supported [ALPN] identifiers on the accept side, see the endpoint
    /// builder's [`Builder::alpns`] function.
    ///
    /// [ALPN]: https://en.wikipedia.org/wiki/Application-Layer_Protocol_Negotiation
    pub fn with_additional_alpns(mut self, alpns: Vec<Vec<u8>>) -> Self {
        self.additional_alpns = alpns;
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
    #[allow(clippy::result_large_err)]
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
                let conn = Connection::new(inner, None, this.ep);
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

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum AlpnError {
    #[snafu(transparent)]
    ConnectionError { source: ConnectionError },
    #[snafu(display("No ALPN available"))]
    Unavailable {},
    #[snafu(display("Unknown handshake type"))]
    UnknownHandshake {},
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
    #[allow(clippy::result_large_err)]
    pub fn into_0rtt(self) -> Result<(Connection, ZeroRttAccepted), Self> {
        match self.inner.into_0rtt() {
            Ok((inner, zrtt_accepted)) => {
                // This call is why `self.remote_node_id` was introduced.
                // When we `Connecting::into_0rtt`, then we don't yet have `handshake_data`
                // in our `Connection`, thus we won't be able to pick up
                // `Connection::remote_node_id`.
                // Instead, we provide `self.remote_node_id` here - we know it in advance,
                // after all.
                let conn = Connection::new(inner, self.remote_node_id, &self.ep);
                let zrtt_accepted = ZeroRttAccepted {
                    inner: zrtt_accepted,
                    _discovery_drop_guard: self._discovery_drop_guard,
                };

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
    pub async fn alpn(&mut self) -> Result<Vec<u8>, AlpnError> {
        let data = self.handshake_data().await?;
        match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            Ok(data) => match data.protocol {
                Some(protocol) => Ok(protocol),
                None => Err(UnavailableSnafu.build()),
            },
            Err(_) => Err(UnknownHandshakeSnafu.build()),
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
                let conn = Connection::new(inner, *this.remote_node_id, this.ep);
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
#[derive(Debug, Clone)]
pub struct Connection {
    inner: quinn::Connection,
    paths_info: n0_watcher::Direct<Vec<PathInfo>>,
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(display("Protocol error: no remote id available"))]
pub struct RemoteNodeIdError {
    backtrace: Option<snafu::Backtrace>,
}

impl Connection {
    fn new(inner: quinn::Connection, remote_id: Option<NodeId>, ep: &Endpoint) -> Self {
        let mut paths_info = Vec::with_capacity(1);
        if let Some(path0) = inner.path(PathId::ZERO) {
            // This all is supposed to be infallible, but anyway.
            if let Ok(remote) = path0.remote_address() {
                let mapped = MultipathMappedAddr::from(remote);
                let transport = TransportType::from(mapped);
                paths_info.push(PathInfo { transport });
            }
        }
        let paths_info_watcher = n0_watcher::Watchable::new(paths_info);
        let conn = Connection {
            inner,
            paths_info: paths_info_watcher.watch(),
        };

        // Grab the remote identity and register this connection
        if let Some(remote) = remote_id {
            ep.msock
                .register_connection(remote, &conn.inner, paths_info_watcher);
        } else if let Ok(remote) = conn.remote_node_id() {
            ep.msock
                .register_connection(remote, &conn.inner, paths_info_watcher);
        } else {
            warn!("unable to determine node id for the remote");
        }

        conn
    }

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
    /// [`Connection::handshake_data()`]: crate::endpoint::Connecting::handshake_data
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
    pub fn remote_node_id(&self) -> Result<NodeId, RemoteNodeIdError> {
        let data = self.peer_identity();
        match data {
            None => {
                warn!("no peer certificate found");
                Err(RemoteNodeIdSnafu.build())
            }
            Some(data) => match data.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
                Ok(certs) => {
                    if certs.len() != 1 {
                        warn!(
                            "expected a single peer certificate, but {} found",
                            certs.len()
                        );
                        return Err(RemoteNodeIdSnafu.build());
                    }

                    let peer_id = VerifyingKey::from_public_key_der(&certs[0])
                        .map_err(|_| RemoteNodeIdSnafu.build())?
                        .into();
                    Ok(peer_id)
                }
                Err(err) => {
                    warn!("invalid peer certificate: {:?}", err);
                    Err(RemoteNodeIdSnafu.build())
                }
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

    /// Returns information about the network paths in use by this connection.
    ///
    /// A connection can have several network paths to the remote endpoint, commonly there
    /// will be a path via the relay server and a holepunched path.  This returns all the
    /// paths in use by this connection.
    pub fn paths_info(&self) -> impl Watcher<Value = Vec<PathInfo>> {
        self.paths_info.clone()
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
    use std::time::{Duration, Instant};

    use iroh_base::{NodeAddr, NodeId, SecretKey};
    use n0_future::{BufferedStreamExt, StreamExt, stream, task::AbortOnDropHandle};
    use n0_snafu::{Error, Result, ResultExt};
    use n0_watcher::Watcher;
    use quinn::ConnectionError;
    use rand::SeedableRng;
    use tracing::{Instrument, error_span, info, info_span, instrument};
    use tracing_test::traced_test;

    use super::Endpoint;
    use crate::{
        RelayMode,
        discovery::static_provider::StaticProvider,
        endpoint::{ConnectOptions, Connection, ConnectionType},
        magicsock::node_map::TransportType,
        protocol::{AcceptError, ProtocolHandler, Router},
        test_utils::{run_relay_server, run_relay_server_with},
    };

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[tokio::test]
    #[traced_test]
    async fn test_connect_self() -> Result {
        let ep = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let my_addr = ep.node_addr();
        let res = ep.connect(my_addr.clone(), TEST_ALPN).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().starts_with("Connecting to ourself"));

        let res = ep.add_node_addr(my_addr).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().starts_with("Adding our own address"));
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_connect_close() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let (relay_map, relay_url, _guard) = run_relay_server().await?;
        let server_secret_key = SecretKey::generate(&mut rng);
        let server_peer_id = server_secret_key.public();

        // Wait for the endpoint to be started to make sure it's up before clients try to connect
        let ep = Endpoint::builder()
            .secret_key(server_secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        // Wait for the endpoint to be reachable via relay
        ep.online().await;

        let server = tokio::spawn(
            async move {
                info!("accepting connection");
                let incoming = ep.accept().await.e()?;
                let conn = incoming.await.e()?;
                let mut stream = conn.accept_uni().await.e()?;
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.e()?;
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
                Ok::<_, Error>(())
            }
            .instrument(info_span!("test-server")),
        );

        let client = tokio::spawn(
            async move {
                let ep = Endpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .relay_mode(RelayMode::Custom(relay_map))
                    .insecure_skip_relay_cert_verify(true)
                    .bind()
                    .await?;
                info!("client connecting");
                let node_addr = NodeAddr::new(server_peer_id).with_relay_url(relay_url);
                let conn = ep.connect(node_addr, TEST_ALPN).await?;
                let mut stream = conn.open_uni().await.e()?;

                // First write is accepted by server.  We need this bit of synchronisation
                // because if the server closes after simply accepting the connection we can
                // not be sure our .open_uni() call would succeed as it may already receive
                // the error.
                stream.write_all(b"hello").await.e()?;

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
                Ok::<_, Error>(())
            }
            .instrument(info_span!("test-client")),
        );

        let (server, client) = tokio::time::timeout(
            Duration::from_secs(30),
            n0_future::future::zip(server, client),
        )
        .await
        .e()?;
        server.e()??;
        client.e()??;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_relay_connect_loop() -> Result {
        let test_start = Instant::now();
        let n_clients = 5;
        let n_chunks_per_client = 2;
        let chunk_size = 10;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let (relay_map, relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let server_secret_key = SecretKey::generate(&mut rng);
        let server_node_id = server_secret_key.public();

        // Make sure the server is bound before having clients connect to it:
        let ep = Endpoint::builder()
            .insecure_skip_relay_cert_verify(true)
            .secret_key(server_secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .bind()
            .await?;
        // Also make sure the server has a working relay connection
        ep.online().await;

        info!(time = ?test_start.elapsed(), "test setup done");

        // The server accepts the connections of the clients sequentially.
        let server = tokio::spawn(
            async move {
                let eps = ep.bound_sockets();

                info!(me = %ep.node_id().fmt_short(), eps = ?eps, "server listening on");
                for i in 0..n_clients {
                    let round_start = Instant::now();
                    info!("[server] round {i}");
                    let incoming = ep.accept().await.e()?;
                    let conn = incoming.await.e()?;
                    let node_id = conn.remote_node_id()?;
                    info!(%i, peer = %node_id.fmt_short(), "accepted connection");
                    let (mut send, mut recv) = conn.accept_bi().await.e()?;
                    let mut buf = vec![0u8; chunk_size];
                    for _i in 0..n_chunks_per_client {
                        recv.read_exact(&mut buf).await.e()?;
                        send.write_all(&buf).await.e()?;
                    }
                    send.finish().e()?;
                    conn.closed().await; // we're the last to send data, so we wait for the other side to close
                    info!(%i, peer = %node_id.fmt_short(), "finished");
                    info!("[server] round {i} done in {:?}", round_start.elapsed());
                }
                Ok::<_, Error>(())
            }
            .instrument(error_span!("server")),
        );

        let start = Instant::now();

        for i in 0..n_clients {
            let round_start = Instant::now();
            info!("[client] round {i}");
            let client_secret_key = SecretKey::generate(&mut rng);
            async {
                info!("client binding");
                let ep = Endpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .insecure_skip_relay_cert_verify(true)
                    .relay_mode(RelayMode::Custom(relay_map.clone()))
                    .secret_key(client_secret_key)
                    .bind()
                    .await?;
                let eps = ep.bound_sockets();

                info!(me = %ep.node_id().fmt_short(), eps=?eps, "client bound");
                let node_addr = NodeAddr::new(server_node_id).with_relay_url(relay_url.clone());
                info!(to = ?node_addr, "client connecting");
                let conn = ep.connect(node_addr, TEST_ALPN).await.e()?;
                info!("client connected");
                let (mut send, mut recv) = conn.open_bi().await.e()?;

                for i in 0..n_chunks_per_client {
                    let mut buf = vec![i; chunk_size];
                    send.write_all(&buf).await.e()?;
                    recv.read_exact(&mut buf).await.e()?;
                    assert_eq!(buf, vec![i; chunk_size]);
                }
                // we're the last to receive data, so we close
                conn.close(0u32.into(), b"bye!");
                info!("client finished");
                ep.close().await;
                info!("client closed");
                Ok::<_, Error>(())
            }
            .instrument(error_span!("client", %i))
            .await?;
            info!("[client] round {i} done in {:?}", round_start.elapsed());
        }

        server.await.e()??;

        // We appear to have seen this being very slow at times.  So ensure we fail if this
        // test is too slow.  We're only making two connections transferring very little
        // data, this really shouldn't take long.
        if start.elapsed() > Duration::from_secs(15) {
            panic!("Test too slow, something went wrong");
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_send_relay() -> Result {
        let (relay_map, _relay_url, _guard) = run_relay_server().await?;
        let client = Endpoint::builder()
            .insecure_skip_relay_cert_verify(true)
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .bind()
            .await?;
        let server = Endpoint::builder()
            .insecure_skip_relay_cert_verify(true)
            .relay_mode(RelayMode::Custom(relay_map))
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        let task = tokio::spawn({
            let server = server.clone();
            async move {
                let Some(conn) = server.accept().await else {
                    snafu::whatever!("Expected an incoming connection");
                };
                let conn = conn.await.e()?;
                let (mut send, mut recv) = conn.accept_bi().await.e()?;
                let data = recv.read_to_end(1000).await.e()?;
                send.write_all(&data).await.e()?;
                send.finish().e()?;
                conn.closed().await;

                Ok::<_, Error>(())
            }
        });

        let addr = server.node_addr();
        let conn = client.connect(addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.e()?;
        send.write_all(b"Hello, world!").await.e()?;
        send.finish().e()?;
        let data = recv.read_to_end(1000).await.e()?;
        conn.close(0u32.into(), b"bye!");

        task.await.e()??;

        client.close().await;
        server.close().await;

        assert_eq!(&data, b"Hello, world!");

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_two_direct_only() -> Result {
        // Connect two endpoints on the same network, without a relay server, without
        // discovery.
        let ep1 = {
            let span = info_span!("server");
            let _guard = span.enter();
            Endpoint::builder()
                .alpns(vec![TEST_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await?
        };
        let ep2 = {
            let span = info_span!("client");
            let _guard = span.enter();
            Endpoint::builder()
                .alpns(vec![TEST_ALPN.to_vec()])
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await?
        };
        let ep1_nodeaddr = ep1.node_addr();

        #[instrument(name = "client", skip_all)]
        async fn connect(ep: Endpoint, dst: NodeAddr) -> Result<quinn::ConnectionError> {
            info!(me = %ep.node_id().fmt_short(), "client starting");
            let conn = ep.connect(dst, TEST_ALPN).await?;
            let mut send = conn.open_uni().await.e()?;
            send.write_all(b"hello").await.e()?;
            send.finish().e()?;
            Ok(conn.closed().await)
        }

        #[instrument(name = "server", skip_all)]
        async fn accept(ep: Endpoint, src: NodeId) -> Result {
            info!(me = %ep.node_id().fmt_short(), "server starting");
            let conn = ep.accept().await.e()?.await.e()?;
            let node_id = conn.remote_node_id()?;
            assert_eq!(node_id, src);
            let mut recv = conn.accept_uni().await.e()?;
            let msg = recv.read_to_end(100).await.e()?;
            assert_eq!(msg, b"hello");
            // Dropping the connection closes it just fine.
            Ok(())
        }

        let ep1_accept = tokio::spawn(accept(ep1.clone(), ep2.node_id()));
        let ep2_connect = tokio::spawn(connect(ep2.clone(), ep1_nodeaddr));

        ep1_accept.await.e()??;
        let conn_closed = dbg!(ep2_connect.await.e()??);
        assert!(matches!(
            conn_closed,
            ConnectionError::ApplicationClosed(quinn::ApplicationClose { .. })
        ));

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_two_relay_only() -> Result {
        // Connect two endpoints on the same network, via a relay server, without
        // discovery.
        let (relay_map, _relay_url, _relay_server_guard) = run_relay_server().await?;
        let server = {
            let span = info_span!("server");
            let _guard = span.enter();
            Endpoint::builder()
                .alpns(vec![TEST_ALPN.to_vec()])
                .insecure_skip_relay_cert_verify(true)
                .relay_mode(RelayMode::Custom(relay_map.clone()))
                .bind()
                .await?
        };
        let client = {
            let span = info_span!("client");
            let _guard = span.enter();
            Endpoint::builder()
                .alpns(vec![TEST_ALPN.to_vec()])
                .insecure_skip_relay_cert_verify(true)
                .relay_mode(RelayMode::Custom(relay_map))
                .bind()
                .await?
        };
        server.online().await;
        let server_node_addr = NodeAddr {
            direct_addresses: Default::default(),
            ..server.node_addr()
        };

        #[instrument(name = "client", skip_all)]
        async fn connect(ep: Endpoint, dst: NodeAddr) -> Result<quinn::ConnectionError> {
            info!(me = %ep.node_id().fmt_short(), "client starting");
            let conn = ep.connect(dst, TEST_ALPN).await?;
            let mut send = conn.open_uni().await.e()?;
            send.write_all(b"hello").await.e()?;
            let mut paths = conn.paths_info().stream();
            info!("Waiting for direct connection");
            while let Some(infos) = paths.next().await {
                info!(?infos, "new PathInfos");
                if infos.iter().any(|info| info.transport == TransportType::Ip) {
                    break;
                }
            }
            info!("Have direct connection");
            send.write_all(b"close please").await.e()?;
            send.finish().e()?;
            Ok(conn.closed().await)
        }

        #[instrument(name = "server", skip_all)]
        async fn accept(ep: Endpoint, src: NodeId) -> Result {
            info!(me = %ep.node_id().fmt_short(), "server starting");
            let conn = ep.accept().await.e()?.await.e()?;
            let node_id = conn.remote_node_id()?;
            assert_eq!(node_id, src);
            let mut recv = conn.accept_uni().await.e()?;
            let mut msg = [0u8; 5];
            recv.read_exact(&mut msg).await.e()?;
            assert_eq!(&msg, b"hello");
            info!("received hello");
            let msg = recv.read_to_end(100).await.e()?;
            assert_eq!(msg, b"close please");
            info!("received 'close please'");
            // Dropping the connection closes it just fine.
            Ok(())
        }

        let server_task = tokio::spawn(accept(server.clone(), client.node_id()));
        let client_task = tokio::spawn(connect(client.clone(), server_node_addr));

        server_task.await.e()??;
        let conn_closed = dbg!(client_task.await.e()??);
        assert!(matches!(
            conn_closed,
            ConnectionError::ApplicationClosed(quinn::ApplicationClose { .. })
        ));

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_bidi_send_recv() -> Result {
        let ep1 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled);

        let ep1 = ep1.bind().await?;
        let ep2 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled);

        let ep2 = ep2.bind().await?;

        let ep1_nodeaddr = ep1.node_addr();
        let ep2_nodeaddr = ep2.node_addr();
        ep1.add_node_addr(ep2_nodeaddr.clone()).await?;
        ep2.add_node_addr(ep1_nodeaddr.clone()).await?;
        let ep1_nodeid = ep1.node_id();
        let ep2_nodeid = ep2.node_id();
        eprintln!("node id 1 {ep1_nodeid}");
        eprintln!("node id 2 {ep2_nodeid}");

        async fn connect_hello(ep: Endpoint, dst: NodeAddr) -> Result {
            let conn = ep.connect(dst, TEST_ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await.e()?;
            info!("sending hello");
            send.write_all(b"hello").await.e()?;
            send.finish().e()?;
            info!("receiving world");
            let m = recv.read_to_end(100).await.e()?;
            assert_eq!(m, b"world");
            conn.close(1u8.into(), b"done");
            Ok(())
        }

        async fn accept_world(ep: Endpoint, src: NodeId) -> Result {
            let incoming = ep.accept().await.e()?;
            let mut iconn = incoming.accept().e()?;
            let alpn = iconn.alpn().await?;
            let conn = iconn.await.e()?;
            let node_id = conn.remote_node_id()?;
            assert_eq!(node_id, src);
            assert_eq!(alpn, TEST_ALPN);
            let (mut send, mut recv) = conn.accept_bi().await.e()?;
            info!("receiving hello");
            let m = recv.read_to_end(100).await.e()?;
            assert_eq!(m, b"hello");
            info!("sending hello");
            send.write_all(b"world").await.e()?;
            send.finish().e()?;
            match conn.closed().await {
                ConnectionError::ApplicationClosed(closed) => {
                    assert_eq!(closed.error_code, 1u8.into());
                    Ok(())
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

        p1_accept.await.e()??;
        p2_accept.await.e()??;
        p1_connect.await.e()??;
        p2_connect.await.e()??;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_conn_type_becomes_direct() -> Result {
        const TIMEOUT: Duration = std::time::Duration::from_secs(15);
        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await?;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let ep1_secret_key = SecretKey::generate(&mut rng);
        let ep2_secret_key = SecretKey::generate(&mut rng);
        let ep1 = Endpoint::builder()
            .secret_key(ep1_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .bind()
            .await?;
        let ep2 = Endpoint::builder()
            .secret_key(ep2_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .bind()
            .await?;

        async fn wait_for_conn_type_direct(ep: &Endpoint, node_id: NodeId) -> Result {
            let mut stream = ep.conn_type(node_id).expect("connection exists").stream();
            let src = ep.node_id().fmt_short();
            let dst = node_id.fmt_short();
            while let Some(conn_type) = stream.next().await {
                tracing::info!(me = %src, dst = %dst, conn_type = ?conn_type);
                if matches!(conn_type, ConnectionType::Direct(_)) {
                    return Ok(());
                }
            }
            snafu::whatever!("conn_type stream ended before `ConnectionType::Direct`");
        }

        async fn accept(ep: &Endpoint) -> Result<Connection> {
            let incoming = ep.accept().await.expect("ep closed");
            let conn = incoming.await.e()?;
            let node_id = conn.remote_node_id()?;
            tracing::info!(node_id=%node_id.fmt_short(), "accepted connection");
            Ok(conn)
        }

        let ep1_nodeid = ep1.node_id();
        let ep2_nodeid = ep2.node_id();

        let ep1_nodeaddr = ep1.node_addr();
        tracing::info!(
            "node id 1 {ep1_nodeid}, relay URL {:?}",
            ep1_nodeaddr.relay_url()
        );
        tracing::info!("node id 2 {ep2_nodeid}");

        let ep1_side = tokio::time::timeout(TIMEOUT, async move {
            let conn = accept(&ep1).await?;
            let mut send = conn.open_uni().await.e()?;
            wait_for_conn_type_direct(&ep1, ep2_nodeid).await?;
            send.write_all(b"Conn is direct").await.e()?;
            send.finish().e()?;
            conn.closed().await;
            Ok::<(), Error>(())
        });

        let ep2_side = tokio::time::timeout(TIMEOUT, async move {
            let conn = ep2.connect(ep1_nodeaddr, TEST_ALPN).await?;
            let mut recv = conn.accept_uni().await.e()?;
            wait_for_conn_type_direct(&ep2, ep1_nodeid).await?;
            let read = recv.read_to_end(100).await.e()?;
            assert_eq!(read, b"Conn is direct".to_vec());
            conn.close(0u32.into(), b"done");
            conn.closed().await;
            Ok::<(), Error>(())
        });

        let res_ep1 = AbortOnDropHandle::new(tokio::spawn(ep1_side));
        let res_ep2 = AbortOnDropHandle::new(tokio::spawn(ep2_side));

        let (r1, r2) = tokio::try_join!(res_ep1, res_ep2).e()?;
        r1.e()??;
        r2.e()??;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_direct_addresses_no_qad_relay() -> Result {
        let (relay_map, _, _guard) = run_relay_server_with(false).await.unwrap();

        let ep = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;

        assert!(!ep.node_addr().direct_addresses.is_empty());

        Ok(())
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
                tracing::trace!("Server accept loop started");
                while let Some(incoming) = server.accept().await {
                    tracing::trace!("Server received incoming connection");
                    // Handle connection errors gracefully instead of exiting the task
                    let connecting = match incoming.accept() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("Failed to accept incoming connection: {e:?}");
                            continue;
                        }
                    };

                    let conn = match connecting.into_0rtt() {
                        Ok((conn, _)) => {
                            info!("0rtt accepted");
                            conn
                        }
                        Err(connecting) => {
                            info!("0rtt denied");
                            match connecting.await {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!("Connection failed: {e:?}");
                                    continue;
                                }
                            }
                        }
                    };

                    // Handle stream errors gracefully
                    let (mut send, mut recv) = match conn.accept_bi().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("Failed to accept bi stream: {e:?}");
                            continue;
                        }
                    };

                    let data = match recv.read_to_end(10_000_000).await {
                        Ok(d) => d,
                        Err(e) => {
                            tracing::warn!("Failed to read data: {e:?}");
                            continue;
                        }
                    };

                    if let Err(e) = send.write_all(&data).await {
                        tracing::warn!("Failed to write data: {e:?}");
                        continue;
                    }

                    if let Err(e) = send.finish() {
                        tracing::warn!("Failed to finish send: {e:?}");
                        continue;
                    }

                    // Stay alive until the other side closes the connection.
                    conn.closed().await;
                    tracing::trace!("Connection closed, ready for next");
                }
                tracing::trace!("Server accept loop exiting");
                Ok::<_, Error>(())
            }
            .instrument(log_span)
        });

        Ok(server)
    }

    async fn connect_client_0rtt_expect_err(client: &Endpoint, server_addr: NodeAddr) -> Result {
        let conn = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await?
            .into_0rtt()
            .expect_err("expected 0rtt to fail")
            .await
            .e()?;

        let (mut send, mut recv) = conn.open_bi().await.e()?;
        send.write_all(b"hello").await.e()?;
        send.finish().e()?;
        let received = recv.read_to_end(1_000).await.e()?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    async fn connect_client_0rtt_expect_ok(
        client: &Endpoint,
        server_addr: NodeAddr,
        expect_server_accepts: bool,
    ) -> Result {
        tracing::trace!(?server_addr, "Client connecting with 0-RTT");
        let (conn, accepted_0rtt) = client
            .connect_with_opts(server_addr, TEST_ALPN, ConnectOptions::new())
            .await?
            .into_0rtt()
            .ok()
            .e()?;

        tracing::trace!("Client established 0-RTT connection");
        // This is how we send data in 0-RTT:
        let (mut send, recv) = conn.open_bi().await.e()?;
        send.write_all(b"hello").await.e()?;
        send.finish().e()?;
        tracing::trace!("Client sent 0-RTT data, waiting for server response");
        // When this resolves, we've gotten a response from the server about whether the 0-RTT data above was accepted:
        let accepted = accepted_0rtt.await;
        tracing::trace!(?accepted, "Server responded to 0-RTT");
        assert_eq!(accepted, expect_server_accepts);
        let mut recv = if accepted {
            recv
        } else {
            // in this case we need to re-send data by re-creating the connection.
            let (mut send, recv) = conn.open_bi().await.e()?;
            send.write_all(b"hello").await.e()?;
            send.finish().e()?;
            recv
        };
        let received = recv.read_to_end(1_000).await.e()?;
        assert_eq!(&received, b"hello");
        conn.close(0u32.into(), b"thx");
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_0rtt() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server = spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("server")).await?;

        connect_client_0rtt_expect_err(&client, server.node_addr()).await?;
        // The second 0rtt attempt should work
        connect_client_0rtt_expect_ok(&client, server.node_addr(), true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // We have this test, as this would've failed at some point.
    // This effectively tests that we correctly categorize the TLS session tickets we
    // receive into the respective "bucket" for the recipient.
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_non_consecutive() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server = spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("server")).await?;

        connect_client_0rtt_expect_err(&client, server.node_addr()).await?;

        // connecting with another endpoint should not interfere with our
        // TLS session ticket cache for the first endpoint:
        let another =
            spawn_0rtt_server(SecretKey::generate(&mut rng), info_span!("another")).await?;
        connect_client_0rtt_expect_err(&client, another.node_addr()).await?;
        another.close().await;

        connect_client_0rtt_expect_ok(&client, server.node_addr(), true).await?;

        client.close().await;
        server.close().await;

        Ok(())
    }

    // Test whether 0-RTT is possible after a restart:
    #[tokio::test]
    #[traced_test]
    async fn test_0rtt_after_server_restart() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server_key = SecretKey::generate(&mut rng);
        let server = spawn_0rtt_server(server_key.clone(), info_span!("server-initial")).await?;

        connect_client_0rtt_expect_err(&client, server.node_addr()).await?;
        connect_client_0rtt_expect_ok(&client, server.node_addr(), true).await?;

        server.close().await;

        let server = spawn_0rtt_server(server_key, info_span!("server-restart")).await?;

        // we expect the client to *believe* it can 0-RTT connect to the server (hence expect_ok),
        // but the server will reject the early data because it discarded necessary state
        // to decrypt it when restarting.
        connect_client_0rtt_expect_ok(&client, server.node_addr(), false).await?;

        client.close().await;

        Ok(())
    }

    #[cfg_attr(target_os = "windows", ignore = "flaky")]
    #[tokio::test]
    #[traced_test]
    async fn graceful_close() -> Result {
        let client = Endpoint::builder().bind().await?;
        let server = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let server_addr = server.node_addr();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.e()?;
            let conn = incoming.await.e()?;
            let (mut send, mut recv) = conn.accept_bi().await.e()?;
            let msg = recv.read_to_end(1_000).await.e()?;
            send.write_all(&msg).await.e()?;
            send.finish().e()?;
            let close_reason = conn.closed().await;
            Ok::<_, Error>(close_reason)
        });

        let conn = client.connect(server_addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.e()?;
        send.write_all(b"Hello, world!").await.e()?;
        send.finish().e()?;
        recv.read_to_end(1_000).await.e()?;
        conn.close(42u32.into(), b"thanks, bye!");
        client.close().await;

        let close_err = server_task.await.e()??;
        let ConnectionError::ApplicationClosed(app_close) = close_err else {
            panic!("Unexpected close reason: {close_err:?}");
        };

        assert_eq!(app_close.error_code, 42u32.into());
        assert_eq!(app_close.reason.as_ref(), b"thanks, bye!");

        Ok(())
    }

    #[cfg(feature = "metrics")]
    #[tokio::test]
    #[traced_test]
    async fn metrics_smoke() -> Result {
        use iroh_metrics::{MetricsSource, Registry};

        let secret_key = SecretKey::from_bytes(&[0u8; 32]);
        let client = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let server = Endpoint::builder()
            .secret_key(secret_key)
            .relay_mode(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let server_addr = server.node_addr();
        let server_task = tokio::task::spawn(async move {
            let conn = server.accept().await.e()?.accept().e()?.await.e()?;
            let mut uni = conn.accept_uni().await.e()?;
            uni.read_to_end(10).await.e()?;
            drop(conn);
            Ok::<_, Error>(server)
        });
        let conn = client.connect(server_addr, TEST_ALPN).await?;
        let mut uni = conn.open_uni().await.e()?;
        uni.write_all(b"helloworld").await.e()?;
        uni.finish().e()?;
        conn.closed().await;
        drop(conn);
        let server = server_task.await.e()??;

        let m = client.metrics();
        assert_eq!(m.magicsock.num_direct_conns_added.get(), 1);
        assert_eq!(m.magicsock.connection_became_direct.get(), 1);
        assert_eq!(m.magicsock.connection_handshake_success.get(), 1);
        assert_eq!(m.magicsock.nodes_contacted_directly.get(), 1);
        assert!(m.magicsock.recv_datagrams.get() > 0);

        let m = server.metrics();
        assert_eq!(m.magicsock.num_direct_conns_added.get(), 1);
        assert_eq!(m.magicsock.connection_became_direct.get(), 1);
        assert_eq!(m.magicsock.nodes_contacted_directly.get(), 1);
        assert_eq!(m.magicsock.connection_handshake_success.get(), 1);
        assert!(m.magicsock.recv_datagrams.get() > 0);

        // test openmetrics encoding with labeled subregistries per endpoint
        fn register_endpoint(registry: &mut Registry, endpoint: &Endpoint) {
            let id = endpoint.node_id().fmt_short();
            let sub_registry = registry.sub_registry_with_label("id", id.to_string());
            sub_registry.register_all(endpoint.metrics());
        }
        let mut registry = Registry::default();
        register_endpoint(&mut registry, &client);
        register_endpoint(&mut registry, &server);
        let s = registry.encode_openmetrics_to_string()?;
        assert!(s.contains(r#"magicsock_nodes_contacted_directly_total{id="3b6a27bcce"} 1"#));
        assert!(s.contains(r#"magicsock_nodes_contacted_directly_total{id="8a88e3dd74"} 1"#));
        Ok(())
    }

    /// Configures the accept side to take `accept_alpns` ALPNs, then connects to it with `primary_connect_alpn`
    /// with `secondary_connect_alpns` set, and finally returns the negotiated ALPN.
    async fn alpn_connection_test(
        accept_alpns: Vec<Vec<u8>>,
        primary_connect_alpn: &[u8],
        secondary_connect_alpns: Vec<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        let client = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await?;
        let server = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .alpns(accept_alpns)
            .bind()
            .await?;
        let server_addr = server.node_addr();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.accept().await.e()?;
                let conn = incoming.await.e()?;
                conn.close(0u32.into(), b"bye!");
                Ok::<_, n0_snafu::Error>(conn.alpn())
            }
        });

        let conn = client
            .connect_with_opts(
                server_addr,
                primary_connect_alpn,
                ConnectOptions::new().with_additional_alpns(secondary_connect_alpns),
            )
            .await?;
        let conn = conn.await.e()?;
        let client_alpn = conn.alpn();
        conn.closed().await;
        client.close().await;
        server.close().await;

        let server_alpn = server_task.await.e()??;

        assert_eq!(client_alpn, server_alpn);

        Ok(server_alpn)
    }

    #[tokio::test]
    #[traced_test]
    async fn connect_multiple_alpn_negotiated() -> Result {
        const ALPN_ONE: &[u8] = b"alpn/1";
        const ALPN_TWO: &[u8] = b"alpn/2";

        assert_eq!(
            alpn_connection_test(
                // Prefer version 2 over version 1 on the accept side
                vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()],
                ALPN_TWO,
                vec![ALPN_ONE.to_vec()],
            )
            .await?,
            Some(ALPN_TWO.to_vec()),
            "accept side prefers version 2 over 1"
        );

        assert_eq!(
            alpn_connection_test(
                // Only support the old version
                vec![ALPN_ONE.to_vec()],
                ALPN_TWO,
                vec![ALPN_ONE.to_vec()],
            )
            .await?,
            Some(ALPN_ONE.to_vec()),
            "accept side only supports the old version"
        );

        assert_eq!(
            alpn_connection_test(
                vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()],
                ALPN_ONE,
                vec![ALPN_TWO.to_vec()],
            )
            .await?,
            Some(ALPN_TWO.to_vec()),
            "connect side ALPN order doesn't matter"
        );

        assert_eq!(
            alpn_connection_test(vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()], ALPN_ONE, vec![],)
                .await?,
            Some(ALPN_ONE.to_vec()),
            "connect side only supports the old version"
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn watch_net_report() -> Result {
        let endpoint = Endpoint::builder()
            .relay_mode(RelayMode::Staging)
            .bind()
            .await?;

        // can get a first report
        endpoint.net_report().updated().await?;

        Ok(())
    }

    /// Tests that initial connection establishment isn't extremely slow compared
    /// to subsequent connections.
    ///
    /// This is a time based test, but uses a very large ratio to reduce flakiness.
    /// It also does a number of connections to average out any anomalies.
    #[tokio::test]
    #[traced_test]
    async fn connect_multi_time() -> Result {
        let n = 32;

        const NOOP_ALPN: &[u8] = b"noop";

        #[derive(Debug, Clone)]
        struct Noop;

        impl ProtocolHandler for Noop {
            async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
                connection.closed().await;
                Ok(())
            }
        }

        async fn noop_server() -> Result<(Router, NodeAddr)> {
            let endpoint = Endpoint::builder()
                .relay_mode(RelayMode::Disabled)
                .bind()
                .await
                .e()?;
            let addr = endpoint.node_addr();
            let router = Router::builder(endpoint).accept(NOOP_ALPN, Noop).spawn();
            Ok((router, addr))
        }

        let routers = stream::iter(0..n)
            .map(|_| noop_server())
            .buffered_unordered(32)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .e()?;

        let addrs = routers
            .iter()
            .map(|(_, addr)| addr.clone())
            .collect::<Vec<_>>();
        let ids = addrs.iter().map(|addr| addr.node_id).collect::<Vec<_>>();
        let discovery = StaticProvider::from_node_info(addrs);
        let endpoint = Endpoint::builder()
            .relay_mode(RelayMode::Disabled)
            .discovery(discovery)
            .bind()
            .await
            .e()?;
        // wait for the endpoint to be initialized. This should not be needed,
        // but we don't want to measure endpoint init time but connection time
        // from a fully initialized endpoint.
        endpoint.node_addr();
        let t0 = Instant::now();
        for id in &ids {
            let conn = endpoint.connect(*id, NOOP_ALPN).await?;
            conn.close(0u32.into(), b"done");
        }
        let dt0 = t0.elapsed().as_secs_f64();
        let t1 = Instant::now();
        for id in &ids {
            let conn = endpoint.connect(*id, NOOP_ALPN).await?;
            conn.close(0u32.into(), b"done");
        }
        let dt1 = t1.elapsed().as_secs_f64();

        assert!(dt0 / dt1 < 20.0, "First round: {dt0}s, second round {dt1}s");
        Ok(())
    }
}
