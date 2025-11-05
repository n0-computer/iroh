//! The [`Endpoint`] allows establishing connections to other iroh endpoints.
//!
//! The [`Endpoint`] is the main API interface to manage a local iroh endpoint.  It allows
//! connecting to and accepting connections from other endpoints.  See the [module docs] for
//! more details on how iroh connections work.
//!
//! The main items in this module are:
//!
//! - [`Endpoint`] to establish iroh connections with other endpoints.
//! - [`Builder`] to create an [`Endpoint`].
//!
//! [module docs]: crate

use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use iroh_base::{EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::{RelayConfig, RelayMap};
use n0_error::{e, ensure, stack_error};
use n0_future::time::Duration;
use n0_watcher::Watcher;
use tracing::{debug, instrument, trace, warn};
use url::Url;

#[cfg(wasm_browser)]
use crate::discovery::pkarr::PkarrResolver;
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
use crate::{
    discovery::{
        ConcurrentDiscovery, DiscoveryError, DiscoveryTask, DynIntoDiscovery, IntoDiscovery,
        UserData,
    },
    endpoint::presets::Preset,
    magicsock::{self, EndpointIdMappedAddr, Handle},
    metrics::EndpointMetrics,
    net_report::Report,
    tls::{self, DEFAULT_MAX_TLS_TICKETS},
};

mod connection;
pub mod presets;
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
    FrameStats, PathStats, TransportError, TransportErrorCode, UdpStats, Written,
    congestion::{Controller, ControllerFactory},
    crypto::{
        AeadKey, CryptoError, ExportKeyingMaterialError, HandshakeTokenKey,
        ServerConfig as CryptoServerConfig, UnsupportedVersion,
    },
};

pub use self::connection::{
    Accept, Accepting, AlpnError, AuthenticationError, Connecting, ConnectingError, Connection,
    HandshakeCompleted, Incoming, IncomingZeroRttConnection, OutgoingZeroRttConnection,
    RemoteEndpointIdError, ZeroRttConnection, ZeroRttStatus,
};
pub use super::magicsock::{
    AddEndpointAddrError, ConnectionType, ControlMsg, DirectAddr, DirectAddrInfo, DirectAddrType,
    Source,
};

/// The delay to fall back to discovery when direct addresses fail.
///
/// When a connection is attempted with an [`EndpointAddr`] containing direct addresses the
/// [`Endpoint`] assumes one of those addresses probably works.  If after this delay there
/// is still no connection the configured [`crate::discovery::Discovery`] will be used however.
const DISCOVERY_WAIT_PERIOD: Duration = Duration::from_millis(500);

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
/// new [`EndpointId`].
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

impl Builder {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users.

    /// Creates a new [`Builder`] using the given [`Preset`].
    ///
    /// See [`presets`] for more.
    pub fn new<P: Preset>(preset: P) -> Self {
        Self::empty(RelayMode::Disabled).preset(preset)
    }

    /// Applies the given [`Preset`].
    pub fn preset<P: Preset>(mut self, preset: P) -> Self {
        self = preset.apply(self);
        self
    }

    /// Creates an empty builder with no discovery services.
    pub fn empty(relay_mode: RelayMode) -> Self {
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
        Self {
            secret_key: Default::default(),
            relay_mode,
            alpn_protocols: Default::default(),
            transport_config,
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

    // # The final constructor that everyone needs.

    /// Binds the magic endpoint.
    pub async fn bind(self) -> Result<Endpoint, BindError> {
        let mut rng = rand::rng();
        let relay_map = self.relay_mode.relay_map();
        let secret_key = self
            .secret_key
            .unwrap_or_else(move || SecretKey::generate(&mut rng));
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

        let msock = magicsock::MagicSock::spawn(msock_opts).await?;
        trace!("created magicsock");
        debug!(version = env!("CARGO_PKG_VERSION"), "iroh Endpoint created");

        let metrics = msock.metrics.magicsock.clone();
        let ep = Endpoint {
            msock,
            rtt_actor: Arc::new(rtt_actor::RttHandle::new(metrics)),
            static_config: Arc::new(static_config),
        };

        // Add discovery mechanisms
        for create_service in self.discovery {
            let service = create_service.into_discovery(&ep)?;
            ep.discovery().add_boxed(service);
        }

        Ok(ep)
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
    /// also its [`EndpointId`]
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
    /// Relay servers are used to establish initial connection with another iroh endpoint.
    /// They also perform various functions related to hole punching, see the [crate docs]
    /// for more details.
    ///
    /// By default the [number 0] relay servers are used, see [`RelayMode::Default`].
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay endpoint.  If an invalid RelayMap is provided [`bind`]
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
    ///
    /// If no discovery service is set, connecting to an endpoint without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// See the documentation of the [`crate::discovery::Discovery`] trait for details.
    pub fn clear_discovery(mut self) -> Self {
        self.discovery.clear();
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
    /// If no discovery service is set, connecting to an endpoint without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// To clear all discovery services, use [`Builder::clear_discovery`].
    ///
    /// See the documentation of the [`crate::discovery::Discovery`] trait for details.
    pub fn discovery(mut self, discovery: impl IntoDiscovery) -> Self {
        self.discovery.push(Box::new(discovery));
        self
    }

    /// Sets the initial user-defined data to be published in discovery services for this node.
    ///
    /// When using discovery services, this string of [`UserData`] will be published together
    /// with the endpoint's addresses and relay URL. When other endpoints discover this endpoint,
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
    /// The DNS resolver is used to resolve relay hostnames, and endpoint addresses if
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

/// Controls an iroh endpoint, establishing connections with other endpoints.
///
/// This is the main API interface to create connections to, and accept connections from
/// other iroh endpoints.  The connections are peer-to-peer and encrypted, a Relay server is
/// used to make the connections reliable.  See the [crate docs] for a more detailed
/// overview of iroh.
///
/// It is recommended to only create a single instance per application.  This ensures all
/// the connections made share the same peer-to-peer connections to other iroh endpoints,
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
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ConnectWithOptsError {
    #[error(transparent)]
    AddEndpointAddr { source: AddEndpointAddrError },
    #[error("Connecting to ourself is not supported")]
    SelfConnect,
    #[error("No addressing information available")]
    NoAddress { source: GetMappingAddressError },
    #[error("Unable to connect to remote")]
    Quinn {
        #[error(std_err)]
        source: quinn_proto::ConnectError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ConnectError {
    #[error(transparent)]
    Connect { source: ConnectWithOptsError },
    #[error(transparent)]
    Connecting { source: ConnectingError },
    #[error(transparent)]
    Connection {
        #[error(std_err)]
        source: ConnectionError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum BindError {
    #[error(transparent)]
    MagicSpawn {
        source: magicsock::CreateHandleError,
    },
    #[error(transparent)]
    Discovery {
        source: crate::discovery::IntoDiscoveryError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum GetMappingAddressError {
    #[error("Discovery service required due to missing addressing information")]
    DiscoveryStart { source: DiscoveryError },
    #[error("Discovery service failed")]
    Discover { source: DiscoveryError },
    #[error("No addressing information found")]
    NoAddress,
}

impl Endpoint {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users, but grouped in similar
    // items.

    // # Methods relating to construction.

    /// Returns the builder for an [`Endpoint`], with a production configuration.
    ///
    /// This uses the [`presets::N0`] as the configuration.
    pub fn builder() -> Builder {
        Builder::new(presets::N0)
    }

    /// Returns the builder for an [`Endpoint`], with an empty configuration.
    ///
    /// See [`Builder::empty`] for details.
    pub fn empty_builder(relay_mode: RelayMode) -> Builder {
        Builder::empty(relay_mode)
    }

    /// Constructs a default [`Endpoint`] and binds it immediately.
    ///
    /// Uses the [`presets::N0`] as configuration.
    pub async fn bind() -> Result<Self, BindError> {
        Self::builder().bind().await
    }

    /// Sets the list of accepted ALPN protocols.
    ///
    /// This will only affect new incoming connections.
    /// Note that this *overrides* the current list of ALPNs.
    pub fn set_alpns(&self, alpns: Vec<Vec<u8>>) {
        let server_config = self.static_config.create_server_config(alpns);
        self.msock.endpoint().set_server_config(Some(server_config));
    }

    /// Adds the provided configuration to the [`RelayMap`].
    ///
    /// Replacing and returning any existing configuration for [`RelayUrl`].
    pub async fn insert_relay(
        &self,
        relay: RelayUrl,
        config: Arc<RelayConfig>,
    ) -> Option<Arc<RelayConfig>> {
        self.msock.insert_relay(relay, config).await
    }

    /// Removes the configuration from the [`RelayMap`] for the provided [`RelayUrl`].
    ///
    /// Returns any existing configuration.
    pub async fn remove_relay(&self, relay: &RelayUrl) -> Option<Arc<RelayConfig>> {
        self.msock.remove_relay(relay).await
    }

    // # Methods for establishing connectivity.

    /// Connects to a remote [`Endpoint`].
    ///
    /// A value that can be converted into an [`EndpointAddr`] is required. This can be either an
    /// [`EndpointAddr`] or an [`EndpointId`].
    ///
    /// The [`EndpointAddr`] must contain the [`EndpointId`] to dial and may also contain a [`RelayUrl`]
    /// and direct addresses. If direct addresses are provided, they will be used to try and
    /// establish a direct connection without involving a relay server.
    ///
    /// If neither a [`RelayUrl`] or direct addresses are configured in the [`EndpointAddr`] it
    /// may still be possible a connection can be established.  This depends on which, if any,
    /// [`crate::discovery::Discovery`] services were configured using [`Builder::discovery`].  The discovery
    /// service will also be used if the remote endpoint is not reachable on the provided direct
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
        endpoint_addr: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<Connection, ConnectError> {
        let endpoint_addr = endpoint_addr.into();
        let remote = endpoint_addr.id;
        let connecting = self
            .connect_with_opts(endpoint_addr, alpn, Default::default())
            .await?;
        let conn = connecting.await?;

        debug!(
            me = %self.id().fmt_short(),
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
    ///    a [`Connection`] by awaiting, or alternatively allows connecting with 0-RTT via
    ///    [`Connecting::into_0rtt`].
    ///    **Note:** Please read the documentation for `into_0rtt` carefully to assess
    ///    security concerns.
    /// 2. The [`TransportConfig`] for the connection can be modified via the provided
    ///    [`ConnectOptions`].
    ///    **Note:** Please be aware that changing transport config settings may have adverse effects on
    ///    establishing and maintaining direct connections.  Carefully test settings you use and
    ///    consider this currently as still rather experimental.
    #[instrument(name = "connect", skip_all, fields(
        me = %self.id().fmt_short(),
        remote = tracing::field::Empty,
        alpn = String::from_utf8_lossy(alpn).to_string(),
    ))]
    pub async fn connect_with_opts(
        &self,
        endpoint_addr: impl Into<EndpointAddr>,
        alpn: &[u8],
        options: ConnectOptions,
    ) -> Result<Connecting, ConnectWithOptsError> {
        let endpoint_addr: EndpointAddr = endpoint_addr.into();
        tracing::Span::current().record(
            "remote",
            tracing::field::display(endpoint_addr.id.fmt_short()),
        );

        // Connecting to ourselves is not supported.
        ensure!(
            endpoint_addr.id != self.id(),
            ConnectWithOptsError::SelfConnect
        );

        if !endpoint_addr.is_empty() {
            self.add_endpoint_addr(endpoint_addr.clone(), Source::App)?;
        }
        let endpoint_id = endpoint_addr.id;
        let ip_addresses: Vec<_> = endpoint_addr.ip_addrs().cloned().collect();
        let relay_url = endpoint_addr.relay_urls().next().cloned();

        // Get the mapped IPv6 address from the magic socket. Quinn will connect to this
        // address.  Start discovery for this endpoint if it's enabled and we have no valid or
        // verified address information for this endpoint.  Dropping the discovery cancels any
        // still running task.
        let (mapped_addr, _discovery_drop_guard) = self
            .get_mapping_addr_and_maybe_start_discovery(endpoint_addr)
            .await?;

        let transport_config = options
            .transport_config
            .unwrap_or(self.static_config.transport_config.clone());

        // Start connecting via quinn. This will time out after 10 seconds if no reachable
        // address is available.

        debug!(
            ?mapped_addr,
            ?ip_addresses,
            ?relay_url,
            "Attempting connection..."
        );
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

        let server_name = &tls::name::encode(endpoint_id);
        let connect = self.msock.endpoint().connect_with(
            client_config,
            mapped_addr.private_socket_addr(),
            server_name,
        )?;

        Ok(Connecting::new(
            connect,
            self.clone(),
            endpoint_id,
            _discovery_drop_guard,
        ))
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

    // # Methods for manipulating the internal state about other endpoints.

    /// Informs this [`Endpoint`] about addresses of the iroh endpoint.
    ///
    /// This updates the local state for the remote endpoint.  If the provided [`EndpointAddr`]
    /// contains a [`RelayUrl`] this will be used as the new relay server for this endpoint.  If
    /// it contains any new IP endpoints they will also be stored and tried when next
    /// connecting to this endpoint. Any address that matches this endpoint's direct addresses will be
    /// silently ignored.
    ///
    /// The *source* is used for logging exclusively and will not be stored.
    ///
    /// # Using endpoint discovery instead
    ///
    /// It is strongly advised to use endpoint discovery using the [`StaticProvider`] instead.
    /// This provides more flexibility and future proofing.
    ///
    /// # Errors
    ///
    /// Will return an error if we attempt to add our own [`EndpointId`] to the endpoint map or
    /// if the direct addresses are a subset of ours.
    ///
    /// [`StaticProvider`]: crate::discovery::static_provider::StaticProvider
    /// [`RelayUrl`]: crate::RelayUrl
    pub(crate) fn add_endpoint_addr(
        &self,
        endpoint_addr: EndpointAddr,
        source: Source,
    ) -> Result<(), AddEndpointAddrError> {
        // Connecting to ourselves is not supported.
        ensure!(
            endpoint_addr.id != self.id(),
            AddEndpointAddrError::OwnAddress
        );
        self.msock.add_endpoint_addr(endpoint_addr, source)
    }

    // # Getter methods for properties of this Endpoint itself.

    /// Returns the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.static_config.tls_config.secret_key
    }

    /// Returns the endpoint id of this endpoint.
    ///
    /// This ID is the unique addressing information of this endpoint and other peers must know
    /// it to be able to connect to this endpoint.
    pub fn id(&self) -> EndpointId {
        self.static_config.tls_config.secret_key.public()
    }

    /// Returns the current [`EndpointAddr`].
    /// As long as the endpoint was able to binde to a network interfaces, some
    /// local addresses will be available.
    ///
    /// The state of other fields depends on the state of networking and connectivity.
    /// Use the [`Endpoint::online`] method to ensure that the endpoint is considered
    /// "online" (has contacted a relay server) before calling this method, if you want
    /// to ensure that the `EndpointAddr` will contain enough information to allow this endpoint
    /// to be dialable by a remote endpoint over the internet.
    ///
    /// You can use the [`Endpoint::watch_addr`] method to get updates when the `EndpointAddr`
    /// changes.
    pub fn addr(&self) -> EndpointAddr {
        self.watch_addr().get()
    }

    /// Returns a [`Watcher`] for the current [`EndpointAddr`] for this endpoint.
    ///
    /// The observed [`EndpointAddr`] will have the current [`RelayUrl`] and direct addresses.
    ///
    /// ```no_run
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// use iroh::{Endpoint, Watcher};
    ///
    /// let endpoint = Endpoint::builder()
    ///     .alpns(vec![b"my-alpn".to_vec()])
    ///     .bind()
    ///     .await?;
    /// let endpoint_addr = endpoint.watch_addr().get();
    /// # let _ = endpoint_addr;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// The [`Endpoint::online`] method can be used as a convenience method to
    /// understand if the endpoint has ever been considered "online". But after
    /// that initial call to [`Endpoint::online`], to understand if your
    /// endpoint is no longer able to be connected to by endpoints outside
    /// of the private or local network, watch for changes in it's [`EndpointAddr`].
    /// If there are no `addrs`in the [`EndpointAddr`], you may not be dialable by other endpoints
    /// on the internet.
    ///
    ///
    /// The `EndpointAddr` will change as:
    /// - network conditions change
    /// - the endpoint connects to a relay server
    /// - the endpoint changes its preferred relay server
    /// - more addresses are discovered for this endpoint
    ///
    /// [`RelayUrl`]: crate::RelayUrl
    #[cfg(not(wasm_browser))]
    pub fn watch_addr(&self) -> impl n0_watcher::Watcher<Value = EndpointAddr> + use<> {
        let watch_addrs = self.msock.ip_addrs();
        let watch_relay = self.msock.home_relay();
        let endpoint_id = self.id();

        watch_addrs.or(watch_relay).map(move |(addrs, relays)| {
            debug_assert!(!addrs.is_empty(), "direct addresses must never be empty");

            EndpointAddr::from_parts(
                endpoint_id,
                relays
                    .into_iter()
                    .map(TransportAddr::Relay)
                    .chain(addrs.into_iter().map(|x| TransportAddr::Ip(x.addr))),
            )
        })
    }

    /// Returns a [`Watcher`] for the current [`EndpointAddr`] for this endpoint.
    ///
    /// When compiled to Wasm, this function returns a watcher that initializes
    /// with an [`EndpointAddr`] that only contains a relay URL, but no direct addresses,
    /// as there are no APIs for directly using sockets in browsers.
    #[cfg(wasm_browser)]
    pub fn watch_addr(&self) -> impl n0_watcher::Watcher<Value = EndpointAddr> + use<> {
        // In browsers, there will never be any direct addresses, so we wait
        // for the home relay instead. This makes the `EndpointAddr` have *some* way
        // of connecting to us.
        let watch_relay = self.msock.home_relay();
        let endpoint_id = self.id();
        watch_relay.map(move |mut relays| {
            EndpointAddr::from_parts(endpoint_id, relays.into_iter().map(TransportAddr::Relay))
        })
    }

    /// A convenience method that waits for the endpoint to be considered "online".
    ///
    /// This currently means at least one relay server was connected,
    /// and at least one local IP address is available.
    /// Event if no relays are configured, this will still wait for a relay connection.
    ///
    /// Once this has been resolved once, this will always immediately resolve.
    ///
    /// This has no timeout, so if that is needed, you need to wrap it in a
    /// timeout. We recommend using a timeout close to
    /// [`crate::net_report::TIMEOUT`], so you can be sure that at least one
    /// [`crate::net_report::Report`] has been attempted.
    ///
    /// To understand if the endpoint has gone back "offline",
    /// you must use the [`Endpoint::watch_addr`] method, to
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
    /// let ep = Endpoint::bind().await.unwrap();
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
    /// given remote endpoint.
    ///
    /// This watcher allows observing a stream of [`ConnectionType`] items by calling
    /// [`Watcher::stream()`]. If the underlying connection to a remote endpoint changes, it will
    /// yield a new item.  These connection changes are when the connection switches between
    /// using the Relay server and a direct connection.
    ///
    /// Note that this does not guarantee each connection change is yielded in the stream.
    /// If the connection type changes several times before this stream is polled, only the
    /// last recorded state is returned.  This can be observed e.g. right at the start of a
    /// connection when the switch from a relayed to a direct connection can be so fast that
    /// the relayed state is never exposed.
    ///
    /// If there is currently a connection with the remote endpoint, then using [`Watcher::get`]
    /// will immediately return either [`ConnectionType::Relay`], [`ConnectionType::Direct`]
    /// or [`ConnectionType::Mixed`].
    ///
    /// It is possible for the connection type to be [`ConnectionType::None`] if you've
    /// recently connected to this endpoint id but previous methods of reaching the endpoint have
    /// become inaccessible.
    ///
    /// Will return `None` if we do not have any address information for the given `endpoint_id`.
    pub fn conn_type(&self, endpoint_id: EndpointId) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.msock.conn_type(endpoint_id)
    }

    /// Returns the currently lowest latency for this endpoint.
    ///
    /// Will return `None` if we do not have any address information for the given `endpoint_id`.
    pub fn latency(&self, endpoint_id: EndpointId) -> Option<Duration> {
        self.msock.latency(endpoint_id)
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
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind().await?;
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
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind().await?;
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
    /// # async fn wrapper() -> n0_error::Result<()> {
    /// let endpoint = Endpoint::bind().await?;
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
    /// # use n0_error::{StackResultExt, StdResultExt};
    /// # async fn wrapper() -> n0_error::Result<()> {
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
    /// let endpoint = Endpoint::bind().await?;
    /// registry.write().unwrap().register_all(endpoint.metrics());
    ///
    /// // Wait for the metrics server to bind, then fetch the metrics via HTTP.
    /// tokio::time::sleep(Duration::from_millis(500));
    /// let res = reqwest::get("http://localhost:9100/metrics")
    ///     .await
    ///     .std_context("get")?
    ///     .text()
    ///     .await
    ///     .std_context("text")?;
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

    /// Sets the initial user-defined data to be published in discovery services for this endpoint.
    ///
    /// If the user-defined data passed to this function is different to the previous one,
    /// the endpoint will republish its endpoint info to the configured discovery services.
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

    /// Checks if the given `EndpointId` needs discovery.
    pub(crate) fn needs_discovery(&self, endpoint_id: EndpointId, max_age: Duration) -> bool {
        match self.msock.remote_info(endpoint_id) {
            // No info means no path to endpoint -> start discovery.
            None => true,
            Some(info) => {
                match (
                    info.last_received(),
                    info.relay_url.as_ref().and_then(|r| r.last_alive),
                ) {
                    // No path to endpoint -> start discovery.
                    (None, None) => true,
                    // If we haven't received on direct addresses or the relay for MAX_AGE,
                    // start discovery.
                    (Some(elapsed), Some(elapsed_relay)) => {
                        elapsed > max_age && elapsed_relay > max_age
                    }
                    (Some(elapsed), _) | (_, Some(elapsed)) => elapsed > max_age,
                }
            }
        }
    }

    /// Return the quic mapped address for this `endpoint_id` and possibly start discovery
    /// services if discovery is enabled on this magic endpoint.
    ///
    /// This will launch discovery in all cases except if:
    /// 1) we do not have discovery enabled
    /// 2) we have discovery enabled, but already have at least one verified, unexpired
    ///    addresses for this `endpoint_id`
    ///
    /// # Errors
    ///
    /// This method may fail if we have no way of dialing the endpoint. This can occur if
    /// we were given no dialing information in the [`EndpointAddr`] and no discovery
    /// services were configured or if discovery failed to fetch any dialing information.
    async fn get_mapping_addr_and_maybe_start_discovery(
        &self,
        endpoint_addr: EndpointAddr,
    ) -> Result<(EndpointIdMappedAddr, Option<DiscoveryTask>), GetMappingAddressError> {
        let endpoint_id = endpoint_addr.id;

        // Only return a mapped addr if we have some way of dialing this endpoint, in other
        // words, we have either a relay URL or at least one direct address.
        let addr = if self.msock.has_send_address(endpoint_id) {
            self.msock.get_mapping_addr(endpoint_id)
        } else {
            None
        };
        match addr {
            Some(addr) => {
                // We have some way of dialing this endpoint, but that doesn't actually mean
                // we can actually connect to any of these addresses.
                // Therefore, we will invoke the discovery service if we haven't received from the
                // endpoint on any of the existing paths recently.
                // If the user provided addresses in this connect call, we will add a delay
                // followed by a recheck before starting the discovery, to give the magicsocket a
                // chance to test the newly provided addresses.
                let delay = (!endpoint_addr.is_empty()).then_some(DISCOVERY_WAIT_PERIOD);
                let discovery = DiscoveryTask::maybe_start_after_delay(self, endpoint_id, delay)
                    .ok()
                    .flatten();
                Ok((addr, discovery))
            }

            None => {
                // We have no known addresses or relay URLs for this endpoint.
                // So, we start a discovery task and wait for the first result to arrive, and
                // only then continue, because otherwise we wouldn't have any
                // path to the remote endpoint.
                let res = DiscoveryTask::start(self.clone(), endpoint_id);
                let mut discovery =
                    res.map_err(|err| e!(GetMappingAddressError::DiscoveryStart, err))?;
                discovery
                    .first_arrived()
                    .await
                    .map_err(|err| e!(GetMappingAddressError::Discover, err))?;
                if let Some(addr) = self.msock.get_mapping_addr(endpoint_id) {
                    Ok((addr, Some(discovery)))
                } else {
                    Err(e!(GetMappingAddressError::NoAddress))
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

    use iroh_base::{EndpointAddr, EndpointId, SecretKey, TransportAddr};
    use n0_error::{AnyError as Error, Result, StdResultExt};
    use n0_future::{BufferedStreamExt, StreamExt, stream, task::AbortOnDropHandle};
    use n0_watcher::Watcher;
    use quinn::ConnectionError;
    use rand::SeedableRng;
    use tracing::{Instrument, error_span, info, info_span};
    use tracing_test::traced_test;

    use super::Endpoint;
    use crate::{
        RelayMode,
        discovery::static_provider::StaticProvider,
        endpoint::{ConnectOptions, Connection, ConnectionType},
        protocol::{AcceptError, ProtocolHandler, Router},
        test_utils::{run_relay_server, run_relay_server_with},
    };

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[tokio::test]
    #[traced_test]
    async fn test_connect_self() -> Result {
        let ep = Endpoint::empty_builder(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let my_addr = ep.addr();
        let res = ep.connect(my_addr.clone(), TEST_ALPN).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.to_string().starts_with("Connecting to ourself"));
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
        let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .secret_key(server_secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        // Wait for the endpoint to be reachable via relay
        ep.online().await;

        let server = tokio::spawn(
            async move {
                info!("accepting connection");
                let incoming = ep.accept().await.anyerr()?;
                let conn = incoming.await.anyerr()?;
                let mut stream = conn.accept_uni().await.anyerr()?;
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.anyerr()?;
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
                let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map))
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .insecure_skip_relay_cert_verify(true)
                    .bind()
                    .await?;
                info!("client connecting");
                let endpoint_addr = EndpointAddr::new(server_peer_id).with_relay_url(relay_url);
                let conn = ep.connect(endpoint_addr, TEST_ALPN).await?;
                let mut stream = conn.open_uni().await.anyerr()?;

                // First write is accepted by server.  We need this bit of synchronisation
                // because if the server closes after simply accepting the connection we can
                // not be sure our .open_uni() call would succeed as it may already receive
                // the error.
                stream.write_all(b"hello").await.anyerr()?;

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
        .anyerr()?;
        server.anyerr()??;
        client.anyerr()??;
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
        let server_endpoint_id = server_secret_key.public();

        // Make sure the server is bound before having clients connect to it:
        let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .secret_key(server_secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        // Also make sure the server has a working relay connection
        ep.online().await;

        info!(time = ?test_start.elapsed(), "test setup done");

        // The server accepts the connections of the clients sequentially.
        let server = tokio::spawn(
            async move {
                let eps = ep.bound_sockets();

                info!(me = %ep.id().fmt_short(), eps = ?eps, "server listening on");
                for i in 0..n_clients {
                    let round_start = Instant::now();
                    info!("[server] round {i}");
                    let incoming = ep.accept().await.anyerr()?;
                    let conn = incoming.await.anyerr()?;
                    let endpoint_id = conn.remote_id();
                    info!(%i, peer = %endpoint_id.fmt_short(), "accepted connection");
                    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                    let mut buf = vec![0u8; chunk_size];
                    for _i in 0..n_chunks_per_client {
                        recv.read_exact(&mut buf).await.anyerr()?;
                        send.write_all(&buf).await.anyerr()?;
                    }
                    send.finish().anyerr()?;
                    conn.closed().await; // we're the last to send data, so we wait for the other side to close
                    info!(%i, peer = %endpoint_id.fmt_short(), "finished");
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
                let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .insecure_skip_relay_cert_verify(true)
                    .secret_key(client_secret_key)
                    .bind()
                    .await?;
                let eps = ep.bound_sockets();

                info!(me = %ep.id().fmt_short(), eps=?eps, "client bound");
                let endpoint_addr =
                    EndpointAddr::new(server_endpoint_id).with_relay_url(relay_url.clone());
                info!(to = ?endpoint_addr, "client connecting");
                let conn = ep.connect(endpoint_addr, TEST_ALPN).await.anyerr()?;
                info!("client connected");
                let (mut send, mut recv) = conn.open_bi().await.anyerr()?;

                for i in 0..n_chunks_per_client {
                    let mut buf = vec![i; chunk_size];
                    send.write_all(&buf).await.anyerr()?;
                    recv.read_exact(&mut buf).await.anyerr()?;
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

        server.await.anyerr()??;

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
        let client = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        let server = Endpoint::empty_builder(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        let task = tokio::spawn({
            let server = server.clone();
            async move {
                let Some(conn) = server.accept().await else {
                    n0_error::bail_any!("Expected an incoming connection");
                };
                let conn = conn.await.anyerr()?;
                let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                let data = recv.read_to_end(1000).await.anyerr()?;
                send.write_all(&data).await.anyerr()?;
                send.finish().anyerr()?;
                conn.closed().await;

                Ok::<_, Error>(())
            }
        });

        let addr = server.addr();
        let conn = client.connect(addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(b"Hello, world!").await.anyerr()?;
        send.finish().anyerr()?;
        let data = recv.read_to_end(1000).await.anyerr()?;
        conn.close(0u32.into(), b"bye!");

        task.await.anyerr()??;

        client.close().await;
        server.close().await;

        assert_eq!(&data, b"Hello, world!");

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_relay_map_change() -> Result {
        let (relay_map, relay_url, _guard1) = run_relay_server().await?;
        let client = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;
        let server = Endpoint::empty_builder(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        let task = tokio::spawn({
            let server = server.clone();
            async move {
                for i in 0..2 {
                    println!("accept: round {i}");
                    let Some(conn) = server.accept().await else {
                        n0_error::bail_any!("Expected an incoming connection");
                    };
                    let conn = conn.await.anyerr()?;
                    let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
                    let data = recv.read_to_end(1000).await.anyerr()?;
                    send.write_all(&data).await.anyerr()?;
                    send.finish().anyerr()?;
                    conn.closed().await;
                }
                Ok::<_, Error>(())
            }
        });

        server.online().await;

        let mut addr = server.addr();
        println!("round1: {:?}", addr);

        // remove direct addrs to force relay usage
        addr.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));

        let conn = client.connect(addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(b"Hello, world!").await.anyerr()?;
        send.finish().anyerr()?;
        let data = recv.read_to_end(1000).await.anyerr()?;
        conn.close(0u32.into(), b"bye!");

        assert_eq!(&data, b"Hello, world!");

        // setup a second relay server
        let (new_relay_map, new_relay_url, _guard2) = run_relay_server().await?;
        let new_endpoint = new_relay_map
            .get(&new_relay_url)
            .expect("missing endpoint")
            .clone();
        dbg!(&new_relay_map);

        let addr_watcher = server.watch_addr();

        // add new new relay
        assert!(
            server
                .insert_relay(new_relay_url.clone(), new_endpoint.clone())
                .await
                .is_none()
        );
        // remove the old relay
        assert!(server.remove_relay(&relay_url).await.is_some());

        println!("------- changed ----- ");

        let mut addr = tokio::time::timeout(Duration::from_secs(10), async move {
            let mut stream = addr_watcher.stream();
            while let Some(addr) = stream.next().await {
                if addr.relay_urls().next() != Some(&relay_url) {
                    return addr;
                }
            }
            panic!("failed to change relay");
        })
        .await
        .anyerr()?;

        println!("round2: {:?}", addr);
        assert_eq!(addr.relay_urls().next(), Some(&new_relay_url));

        // remove direct addrs to force relay usage
        addr.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));

        let conn = client.connect(addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(b"Hello, world!").await.anyerr()?;
        send.finish().anyerr()?;
        let data = recv.read_to_end(1000).await.anyerr()?;
        conn.close(0u32.into(), b"bye!");

        task.await.anyerr()??;

        client.close().await;
        server.close().await;

        assert_eq!(&data, b"Hello, world!");

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn endpoint_bidi_send_recv() -> Result {
        let disco = StaticProvider::new();
        let ep1 = Endpoint::empty_builder(RelayMode::Disabled)
            .discovery(disco.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        let ep2 = Endpoint::empty_builder(RelayMode::Disabled)
            .discovery(disco.clone())
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        disco.add_endpoint_info(ep1.addr());
        disco.add_endpoint_info(ep2.addr());

        let ep1_endpointid = ep1.id();
        let ep2_endpointid = ep2.id();
        eprintln!("endpoint id 1 {ep1_endpointid}");
        eprintln!("endpoint id 2 {ep2_endpointid}");

        async fn connect_hello(ep: Endpoint, dst: EndpointId) -> Result {
            let conn = ep.connect(dst, TEST_ALPN).await?;
            let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
            info!("sending hello");
            send.write_all(b"hello").await.anyerr()?;
            send.finish().anyerr()?;
            info!("receiving world");
            let m = recv.read_to_end(100).await.anyerr()?;
            assert_eq!(m, b"world");
            conn.close(1u8.into(), b"done");
            Ok(())
        }

        async fn accept_world(ep: Endpoint, src: EndpointId) -> Result {
            let incoming = ep.accept().await.anyerr()?;
            let mut iconn = incoming.accept().anyerr()?;
            let alpn = iconn.alpn().await?;
            let conn = iconn.await.anyerr()?;
            let endpoint_id = conn.remote_id();
            assert_eq!(endpoint_id, src);
            assert_eq!(alpn, TEST_ALPN);
            let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
            info!("receiving hello");
            let m = recv.read_to_end(100).await.anyerr()?;
            assert_eq!(m, b"hello");
            info!("sending hello");
            send.write_all(b"world").await.anyerr()?;
            send.finish().anyerr()?;
            match conn.closed().await {
                ConnectionError::ApplicationClosed(closed) => {
                    assert_eq!(closed.error_code, 1u8.into());
                    Ok(())
                }
                _ => panic!("wrong close error"),
            }
        }

        let p1_accept = tokio::spawn(accept_world(ep1.clone(), ep2_endpointid).instrument(
            info_span!(
                "p1_accept",
                ep1 = %ep1.id().fmt_short(),
                dst = %ep2_endpointid.fmt_short(),
            ),
        ));
        let p2_accept = tokio::spawn(accept_world(ep2.clone(), ep1_endpointid).instrument(
            info_span!(
                "p2_accept",
                ep2 = %ep2.id().fmt_short(),
                dst = %ep1_endpointid.fmt_short(),
            ),
        ));
        let p1_connect = tokio::spawn(connect_hello(ep1.clone(), ep2_endpointid).instrument(
            info_span!(
                "p1_connect",
                ep1 = %ep1.id().fmt_short(),
                dst = %ep2_endpointid.fmt_short(),
            ),
        ));
        let p2_connect = tokio::spawn(connect_hello(ep2.clone(), ep1_endpointid).instrument(
            info_span!(
                "p2_connect",
                ep2 = %ep2.id().fmt_short(),
                dst = %ep1_endpointid.fmt_short(),
            ),
        ));

        p1_accept.await.anyerr()??;
        p2_accept.await.anyerr()??;
        p1_connect.await.anyerr()??;
        p2_connect.await.anyerr()??;

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
        let ep1 = Endpoint::empty_builder(RelayMode::Custom(relay_map.clone()))
            .secret_key(ep1_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let ep2 = Endpoint::empty_builder(RelayMode::Custom(relay_map))
            .secret_key(ep2_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;

        async fn wait_for_conn_type_direct(ep: &Endpoint, endpoint_id: EndpointId) -> Result {
            let mut stream = ep
                .conn_type(endpoint_id)
                .expect("connection exists")
                .stream();
            let src = ep.id().fmt_short();
            let dst = endpoint_id.fmt_short();
            while let Some(conn_type) = stream.next().await {
                tracing::info!(me = %src, dst = %dst, conn_type = ?conn_type);
                if matches!(conn_type, ConnectionType::Direct(_)) {
                    return Ok(());
                }
            }
            n0_error::bail_any!("conn_type stream ended before `ConnectionType::Direct`");
        }

        async fn accept(ep: &Endpoint) -> Result<Connection> {
            let incoming = ep.accept().await.expect("ep closed");
            let conn = incoming.await.anyerr()?;
            let endpoint_id = conn.remote_id();
            tracing::info!(endpoint_id=%endpoint_id.fmt_short(), "accepted connection");
            Ok(conn)
        }

        let ep1_endpointid = ep1.id();
        let ep2_endpointid = ep2.id();

        let ep1_endpointaddr = ep1.addr();
        tracing::info!(
            "endpoint id 1 {ep1_endpointid}, relay URL {:?}",
            ep1_endpointaddr.relay_urls().next()
        );
        tracing::info!("endpoint id 2 {ep2_endpointid}");

        let ep1_side = tokio::time::timeout(TIMEOUT, async move {
            let conn = accept(&ep1).await?;
            let mut send = conn.open_uni().await.anyerr()?;
            wait_for_conn_type_direct(&ep1, ep2_endpointid).await?;
            send.write_all(b"Conn is direct").await.anyerr()?;
            send.finish().anyerr()?;
            conn.closed().await;
            Ok::<(), Error>(())
        });

        let ep2_side = tokio::time::timeout(TIMEOUT, async move {
            let conn = ep2.connect(ep1_endpointaddr, TEST_ALPN).await?;
            let mut recv = conn.accept_uni().await.anyerr()?;
            wait_for_conn_type_direct(&ep2, ep1_endpointid).await?;
            let read = recv.read_to_end(100).await.anyerr()?;
            assert_eq!(read, b"Conn is direct".to_vec());
            conn.close(0u32.into(), b"done");
            conn.closed().await;
            Ok::<(), Error>(())
        });

        let res_ep1 = AbortOnDropHandle::new(tokio::spawn(ep1_side));
        let res_ep2 = AbortOnDropHandle::new(tokio::spawn(ep2_side));

        let (r1, r2) = tokio::try_join!(res_ep1, res_ep2).anyerr()?;
        r1.anyerr()??;
        r2.anyerr()??;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_direct_addresses_no_qad_relay() -> Result {
        let (relay_map, _, _guard) = run_relay_server_with(false).await.unwrap();

        let ep = Endpoint::empty_builder(RelayMode::Custom(relay_map))
            .alpns(vec![TEST_ALPN.to_vec()])
            .insecure_skip_relay_cert_verify(true)
            .bind()
            .await?;

        assert!(ep.addr().ip_addrs().count() > 0);

        Ok(())
    }

    #[cfg_attr(target_os = "windows", ignore = "flaky")]
    #[tokio::test]
    #[traced_test]
    async fn graceful_close() -> Result {
        let client = Endpoint::empty_builder(RelayMode::Disabled).bind().await?;
        let server = Endpoint::empty_builder(RelayMode::Disabled)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let server_addr = server.addr();
        let server_task = tokio::spawn(async move {
            let incoming = server.accept().await.anyerr()?;
            let conn = incoming.await.anyerr()?;
            let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
            let msg = recv.read_to_end(1_000).await.anyerr()?;
            send.write_all(&msg).await.anyerr()?;
            send.finish().anyerr()?;
            let close_reason = conn.closed().await;
            Ok::<_, Error>(close_reason)
        });

        let conn = client.connect(server_addr, TEST_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        send.write_all(b"Hello, world!").await.anyerr()?;
        send.finish().anyerr()?;
        recv.read_to_end(1_000).await.anyerr()?;
        conn.close(42u32.into(), b"thanks, bye!");
        client.close().await;

        let close_err = server_task.await.anyerr()??;
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
        let client = Endpoint::empty_builder(RelayMode::Disabled)
            .secret_key(secret_key)
            .bind()
            .await?;
        let secret_key = SecretKey::from_bytes(&[1u8; 32]);
        let server = Endpoint::empty_builder(RelayMode::Disabled)
            .secret_key(secret_key)
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind()
            .await?;
        let server_addr = server.addr();
        let server_task = tokio::task::spawn(async move {
            let conn = server.accept().await.anyerr()?.await.anyerr()?;
            let mut uni = conn.accept_uni().await.anyerr()?;
            uni.read_to_end(10).await.anyerr()?;
            drop(conn);
            Ok::<_, Error>(server)
        });
        let conn = client.connect(server_addr, TEST_ALPN).await?;
        let mut uni = conn.open_uni().await.anyerr()?;
        uni.write_all(b"helloworld").await.anyerr()?;
        uni.finish().anyerr()?;
        conn.closed().await;
        drop(conn);
        let server = server_task.await.anyerr()??;

        let m = client.metrics();
        assert_eq!(m.magicsock.num_direct_conns_added.get(), 1);
        assert_eq!(m.magicsock.connection_became_direct.get(), 1);
        assert_eq!(m.magicsock.connection_handshake_success.get(), 1);
        assert_eq!(m.magicsock.endpoints_contacted_directly.get(), 1);
        assert!(m.magicsock.recv_datagrams.get() > 0);

        let m = server.metrics();
        assert_eq!(m.magicsock.num_direct_conns_added.get(), 1);
        assert_eq!(m.magicsock.connection_became_direct.get(), 1);
        assert_eq!(m.magicsock.endpoints_contacted_directly.get(), 1);
        assert_eq!(m.magicsock.connection_handshake_success.get(), 1);
        assert!(m.magicsock.recv_datagrams.get() > 0);

        // test openmetrics encoding with labeled subregistries per endpoint
        fn register_endpoint(registry: &mut Registry, endpoint: &Endpoint) {
            let id = endpoint.id().fmt_short();
            let sub_registry = registry.sub_registry_with_label("id", id.to_string());
            sub_registry.register_all(endpoint.metrics());
        }
        let mut registry = Registry::default();
        register_endpoint(&mut registry, &client);
        register_endpoint(&mut registry, &server);
        let s = registry.encode_openmetrics_to_string().anyerr()?;
        assert!(s.contains(r#"magicsock_endpoints_contacted_directly_total{id="3b6a27bcce"} 1"#));
        assert!(s.contains(r#"magicsock_endpoints_contacted_directly_total{id="8a88e3dd74"} 1"#));
        Ok(())
    }

    /// Configures the accept side to take `accept_alpns` ALPNs, then connects to it with `primary_connect_alpn`
    /// with `secondary_connect_alpns` set, and finally returns the negotiated ALPN.
    async fn alpn_connection_test(
        accept_alpns: Vec<Vec<u8>>,
        primary_connect_alpn: &[u8],
        secondary_connect_alpns: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let client = Endpoint::empty_builder(RelayMode::Disabled).bind().await?;
        let server = Endpoint::empty_builder(RelayMode::Disabled)
            .alpns(accept_alpns)
            .bind()
            .await?;
        let server_addr = server.addr();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.accept().await.anyerr()?;
                let conn = incoming.await.anyerr()?;
                conn.close(0u32.into(), b"bye!");
                n0_error::Ok(conn.alpn().to_vec())
            }
        });

        let conn = client
            .connect_with_opts(
                server_addr,
                primary_connect_alpn,
                ConnectOptions::new().with_additional_alpns(secondary_connect_alpns),
            )
            .await?;
        let conn = conn.await.anyerr()?;
        let client_alpn = conn.alpn();
        conn.closed().await;
        client.close().await;
        server.close().await;

        let server_alpn = server_task.await.anyerr()??;

        assert_eq!(client_alpn, server_alpn);

        Ok(server_alpn.to_vec())
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
            ALPN_TWO.to_vec(),
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
            ALPN_ONE.to_vec(),
            "accept side only supports the old version"
        );

        assert_eq!(
            alpn_connection_test(
                vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()],
                ALPN_ONE,
                vec![ALPN_TWO.to_vec()],
            )
            .await?,
            ALPN_TWO.to_vec(),
            "connect side ALPN order doesn't matter"
        );

        assert_eq!(
            alpn_connection_test(vec![ALPN_TWO.to_vec(), ALPN_ONE.to_vec()], ALPN_ONE, vec![],)
                .await?,
            ALPN_ONE.to_vec(),
            "connect side only supports the old version"
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn watch_net_report() -> Result {
        let endpoint = Endpoint::empty_builder(RelayMode::Staging).bind().await?;

        // can get a first report
        endpoint.net_report().updated().await.anyerr()?;

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

        async fn noop_server() -> Result<(Router, EndpointAddr)> {
            let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
                .bind()
                .await
                .anyerr()?;
            let addr = endpoint.addr();
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
            .anyerr()?;

        let addrs = routers
            .iter()
            .map(|(_, addr)| addr.clone())
            .collect::<Vec<_>>();
        let ids = addrs.iter().map(|addr| addr.id).collect::<Vec<_>>();
        let discovery = StaticProvider::from_endpoint_info(addrs);
        let endpoint = Endpoint::empty_builder(RelayMode::Disabled)
            .discovery(discovery)
            .bind()
            .await
            .anyerr()?;
        // wait for the endpoint to be initialized. This should not be needed,
        // but we don't want to measure endpoint init time but connection time
        // from a fully initialized endpoint.
        endpoint.addr();
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
