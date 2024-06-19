//! The [`Endpoint`] allows establishing connections to other iroh-net nodes.
//!
//! The [`Endpoint`] is the main API interface to manage a local iroh-net node.  It allows
//! connecting to and accepting connections from other nodes.  See the [module docs] for
//! more details on how iroh-net connections work.
//!
//! The main items in this module are:
//!
//! - [`Endpoint`] to establish iroh-net connections with other nodes.
//! - [`Builder`] to create an [`Endpoint`].
//!
//! [module docs]: crate

use std::any::Any;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use derive_more::Debug;
use futures_lite::{Stream, StreamExt};
use tokio_util::sync::{CancellationToken, WaitForCancellationFuture};
use tracing::{debug, info_span, trace, warn};
use url::Url;

use crate::{
    defaults::default_relay_map,
    discovery::{Discovery, DiscoveryTask},
    dns::{default_resolver, DnsResolver},
    key::{PublicKey, SecretKey},
    magicsock::{self, Handle},
    relay::{RelayMap, RelayMode, RelayUrl},
    tls, NodeId,
};

mod rtt_actor;

use self::rtt_actor::RttMessage;

pub use quinn::{
    Connection, ConnectionError, ReadError, RecvStream, SendStream, TransportConfig, VarInt,
    WriteError,
};

pub use super::magicsock::{
    ConnectionInfo, ConnectionType, ConnectionTypeStream, ControlMsg, DirectAddr, DirectAddrInfo,
    DirectAddrType, DirectAddrsStream,
};

pub use iroh_base::node_addr::{AddrInfo, NodeAddr};

/// The delay to fall back to discovery when direct addresses fail.
///
/// When a connection is attempted with a [`NodeAddr`] containing direct addresses the
/// [`Endpoint`] assumes one of those addresses probably works.  If after this delay there
/// is still no connection the configured [`Discovery`] will be used however.
const DISCOVERY_WAIT_PERIOD: Duration = Duration::from_millis(500);

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
    transport_config: Option<quinn::TransportConfig>,
    concurrent_connections: Option<u32>,
    keylog: bool,
    discovery: Option<Box<dyn Discovery>>,
    proxy_url: Option<Url>,
    /// Path for known peers. See [`Builder::peers_data_path`].
    peers_path: Option<PathBuf>,
    dns_resolver: Option<DnsResolver>,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            secret_key: Default::default(),
            relay_mode: RelayMode::Default,
            alpn_protocols: Default::default(),
            transport_config: Default::default(),
            concurrent_connections: Default::default(),
            keylog: Default::default(),
            discovery: Default::default(),
            proxy_url: None,
            peers_path: None,
            dns_resolver: None,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
        }
    }
}

impl Builder {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users.

    // # The final constructor that everyone needs.

    /// Binds the magic endpoint on the specified socket address.
    ///
    /// The *bind_port* is the port that should be bound locally.
    /// The port will be used to bind an IPv4 and, if supported, and IPv6 socket.
    /// You can pass `0` to let the operating system choose a free port for you.
    ///
    /// NOTE: This will be improved soon to add support for binding on specific addresses.
    pub async fn bind(self, bind_port: u16) -> Result<Endpoint> {
        let relay_map = match self.relay_mode {
            RelayMode::Disabled => RelayMap::empty(),
            RelayMode::Default => default_relay_map(),
            RelayMode::Custom(relay_map) => {
                ensure!(!relay_map.is_empty(), "Empty custom relay server map",);
                relay_map
            }
        };
        let secret_key = self.secret_key.unwrap_or_else(SecretKey::generate);
        let static_config = StaticConfig {
            transport_config: Arc::new(self.transport_config.unwrap_or_default()),
            keylog: self.keylog,
            concurrent_connections: self.concurrent_connections,
            secret_key: secret_key.clone(),
        };
        let dns_resolver = self
            .dns_resolver
            .unwrap_or_else(|| default_resolver().clone());

        let msock_opts = magicsock::Options {
            port: bind_port,
            secret_key,
            relay_map,
            nodes_path: self.peers_path,
            discovery: self.discovery,
            proxy_url: self.proxy_url,
            dns_resolver,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: self.insecure_skip_relay_cert_verify,
        };
        Endpoint::bind(static_config, msock_opts, self.alpn_protocols).await
    }

    // # The very common methods everyone basically needs.

    /// Sets a secret key to authenticate with other peers.
    ///
    /// This secret key's public key will be the [`PublicKey`] of this endpoint and thus
    /// also its [`NodeId`]
    ///
    /// If not set, a new secret key will be generated.
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
    /// Relay servers are used to establish initial connection with another iroh-net node.
    /// They also perform various functions related to hole punching, see the [crate docs]
    /// for more details.
    ///
    /// By default the Number0 relay servers are used.
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`RelayMap`] is provided [`bind`]
    /// will result in an error.
    ///
    /// [`bind`]: Builder::bind
    /// [crate docs]: crate
    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        self.relay_mode = relay_mode;
        self
    }

    /// Optionally sets a discovery mechanism for this endpoint.
    ///
    /// If you want to combine multiple discovery services, you can pass a
    /// [`crate::discovery::ConcurrentDiscovery`].
    ///
    /// If no discovery service is set, connecting to a node without providing its
    /// direct addresses or relay URLs will fail.
    ///
    /// See the documentation of the [`Discovery`] trait for details.
    pub fn discovery(mut self, discovery: Box<dyn Discovery>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Optionally sets the path where peer info should be stored.
    ///
    /// If the file exists, it will be used to populate an initial set of peers. Peers will
    /// be saved periodically and on shutdown to this path.
    pub fn peers_data_path(mut self, path: PathBuf) -> Self {
        self.peers_path = Some(path);
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
    pub fn transport_config(mut self, transport_config: quinn::TransportConfig) -> Self {
        self.transport_config = Some(transport_config);
        self
    }

    /// Optionally sets a custom DNS resolver to use for this endpoint.
    ///
    /// The DNS resolver is used to resolve relay hostnames, and node addresses if
    /// [`crate::discovery::dns::DnsDiscovery`] is configured.
    ///
    /// By default, all endpoints share a DNS resolver, which is configured to use the
    /// host system's DNS configuration. You can pass a custom instance of [`DnsResolver`]
    /// here to use a differently configured DNS resolver for this endpoint.
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
    /// If *keylog* is `true` then setting the `KEYLOGFILE` environment variable to a
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

    /// Maximum number of simultaneous connections to accept.
    ///
    /// New incoming connections are only accepted if the total number of incoming or
    /// outgoing connections is less than this. Outgoing connections are unaffected.
    pub fn concurrent_connections(mut self, concurrent_connections: u32) -> Self {
        self.concurrent_connections = Some(concurrent_connections);
        self
    }
}

/// Configuration for a [`quinn::Endpoint`] that cannot be changed at runtime.
#[derive(Debug)]
struct StaticConfig {
    secret_key: SecretKey,
    transport_config: Arc<quinn::TransportConfig>,
    keylog: bool,
    concurrent_connections: Option<u32>,
}

impl StaticConfig {
    /// Create a [`quinn::ServerConfig`] with the specified ALPN protocols.
    fn create_server_config(&self, alpn_protocols: Vec<Vec<u8>>) -> Result<quinn::ServerConfig> {
        let mut server_config = make_server_config(
            &self.secret_key,
            alpn_protocols,
            self.transport_config.clone(),
            self.keylog,
        )?;
        if let Some(c) = self.concurrent_connections {
            server_config.concurrent_connections(c);
        }
        Ok(server_config)
    }
}

/// Creates a [`quinn::ServerConfig`] with the given secret key and limits.
pub fn make_server_config(
    secret_key: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Arc<quinn::TransportConfig>,
    keylog: bool,
) -> Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(secret_key, alpn_protocols, keylog)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    server_config.transport_config(transport_config);
    Ok(server_config)
}

/// Controls an iroh-net node, establishing connections with other nodes.
///
/// This is the main API interface to create connections to, and accept connections from
/// other iroh-net nodes.  The connections are peer-to-peer and encrypted, a Relay server is
/// used to make the connections reliable.  See the [crate docs] for a more detailed
/// overview of iroh-net.
///
/// It is recommended to only create a single instance per application.  This ensures all
/// the connections made share the same peer-to-peer connections to other iroh-net nodes,
/// while still remaining independent connections.  This will result in more optimal network
/// behaviour.
///
/// New connections are typically created using the [`Endpoint::connect`] and
/// [`Endpoint::accept`] methods.  Once established, the [`Connection`] gives access to most
/// [QUIC] features.  Individual streams to send data to the peer are created using the
/// [`Connection::open_bi`], [`Connection::accept_bi`], [`Connection::open_uni`] and
/// [`Connection::open_bi`] functions.
///
/// Note that due to the light-weight properties of streams a stream will only be accepted
/// once the initiating peer has sent some data on it.
///
/// [QUIC]: https://quicwg.org
#[derive(Clone, Debug)]
pub struct Endpoint {
    msock: Handle,
    endpoint: quinn::Endpoint,
    rtt_actor: Arc<rtt_actor::RttHandle>,
    cancel_token: CancellationToken,
    static_config: Arc<StaticConfig>,
}

impl Endpoint {
    // The ordering of public methods is reflected directly in the documentation.  This is
    // roughly ordered by what is most commonly needed by users, but grouped in similar
    // items.

    // # Methods relating to construction.

    /// Returns the builder for an [`Endpoint`].
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Creates a quinn endpoint backed by a magicsock.
    ///
    /// This is for internal use, the public interface is the [`Builder`] obtained from
    /// [Self::builder]. See the methods on the builder for documentation of the parameters.
    async fn bind(
        static_config: StaticConfig,
        msock_opts: magicsock::Options,
        initial_alpns: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let span = info_span!("magic_ep", me = %static_config.secret_key.public().fmt_short());
        let _guard = span.enter();
        let msock = magicsock::MagicSock::spawn(msock_opts).await?;
        trace!("created magicsock");

        let server_config = static_config.create_server_config(initial_alpns)?;

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Setting this to false means that quinn will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to quinn. We set the first byte of the packet to zero, which makes quinn ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            msock.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        trace!("created quinn endpoint");

        Ok(Self {
            msock,
            endpoint,
            rtt_actor: Arc::new(rtt_actor::RttHandle::new()),
            cancel_token: CancellationToken::new(),
            static_config: Arc::new(static_config),
        })
    }

    /// Sets the list of accepted ALPN protocols.
    ///
    /// This will only affect new incoming connections.
    /// Note that this *overrides* the current list of ALPNs.
    pub fn set_alpns(&self, alpns: Vec<Vec<u8>>) -> Result<()> {
        let server_config = self.static_config.create_server_config(alpns)?;
        self.endpoint.set_server_config(Some(server_config));
        Ok(())
    }

    // # Methods for establishing connectivity.

    /// Connects to a remote [`Endpoint`].
    ///
    /// A [`NodeAddr`] is required. It must contain the [`NodeId`] to dial and may also
    /// contain a [`RelayUrl`] and direct addresses. If direct addresses are provided, they
    /// will be used to try and establish a direct connection without involving a relay
    /// server.
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
    pub async fn connect(&self, node_addr: NodeAddr, alpn: &[u8]) -> Result<quinn::Connection> {
        // Connecting to ourselves is not supported.
        if node_addr.node_id == self.node_id() {
            bail!(
                "Connecting to ourself is not supported ({} is the node id of this node)",
                node_addr.node_id.fmt_short()
            );
        }

        if !node_addr.info.is_empty() {
            self.add_node_addr(node_addr.clone())?;
        }

        let NodeAddr { node_id, info } = node_addr.clone();

        // Get the mapped IPv6 address from the magic socket. Quinn will connect to this address.
        // Start discovery for this node if it's enabled and we have no valid or verified
        // address information for this node.
        let (addr, discovery) = self
            .get_mapping_addr_and_maybe_start_discovery(node_addr)
            .await?;

        debug!(
            "connecting to {}: (via {} - {:?})",
            node_id, addr, info.direct_addresses
        );

        // Start connecting via quinn. This will time out after 10 seconds if no reachable address
        // is available.
        let conn = self.connect_quinn(&node_id, alpn, addr).await;

        // Cancel the node discovery task (if still running).
        if let Some(discovery) = discovery {
            discovery.cancel();
        }

        conn
    }

    /// Connects to a remote endpoint, using just the nodes's [`NodeId`].
    ///
    /// This is a convenience function for [`Endpoint::connect`].  It relies on addressing
    /// information being provided by either the discovery service or using
    /// [`Endpoint::add_node_addr`].  See [`Endpoint::connect`] for the details of how it
    /// uses the discovery service to establish a connection to a remote node.
    pub async fn connect_by_node_id(
        &self,
        node_id: &NodeId,
        alpn: &[u8],
    ) -> Result<quinn::Connection> {
        let addr = NodeAddr::new(*node_id);
        self.connect(addr, alpn).await
    }

    async fn connect_quinn(
        &self,
        node_id: &PublicKey,
        alpn: &[u8],
        addr: SocketAddr,
    ) -> Result<quinn::Connection> {
        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let tls_client_config = tls::make_client_config(
                &self.static_config.secret_key,
                Some(*node_id),
                alpn_protocols,
                self.static_config.keylog,
            )?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

        // TODO: We'd eventually want to replace "localhost" with something that makes more sense.
        let connect = self
            .endpoint
            .connect_with(client_config, addr, "localhost")?;

        let connection = connect.await.context("failed connecting to provider")?;

        let rtt_msg = RttMessage::NewConnection {
            connection: connection.weak_handle(),
            conn_type_changes: self.conn_type_stream(*node_id)?,
            node_id: *node_id,
        };
        if let Err(err) = self.rtt_actor.msg_tx.send(rtt_msg).await {
            // If this actor is dead, that's not great but we can still function.
            warn!("rtt-actor not reachable: {err:#}");
        }

        Ok(connection)
    }

    /// Accepts an incoming connection on the endpoint.
    ///
    /// Only connections with the ALPNs configured in [`Builder::alpns`] will be accepted.
    /// If multiple ALPNs have been configured the ALPN can be inspected before accepting
    /// the connection using [`Connecting::alpn`].
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            inner: self.endpoint.accept(),
            magic_ep: self.clone(),
        }
    }

    // # Methods for manipulating the internal state about other nodes.

    /// Informs this [`Endpoint`] about addresses of the iroh-net node.
    ///
    /// This updates the local state for the remote node.  If the provided [`NodeAddr`]
    /// contains a [`RelayUrl`] this will be used as the new relay server for this node.  If
    /// it contains any new IP endpoints they will also be stored and tried when next
    /// connecting to this node. Any address that matches this node's direct addresses will be
    /// silently ignored.
    ///
    /// See also [`Endpoint::add_node_addr_with_source`].
    ///
    /// # Errors
    ///
    /// Will return an error if we attempt to add our own [`PublicKey`] to the node map or if the
    /// direct addresses are a subset of ours.
    pub fn add_node_addr(&self, node_addr: NodeAddr) -> Result<()> {
        self.add_node_addr_inner(node_addr, magicsock::Source::App)
    }

    /// Informs this [`Endpoint`] about addresses of the iroh-net node, noting the source.
    ///
    /// This updates the local state for the remote node.  If the provided [`NodeAddr`] contains a
    /// [`RelayUrl`] this will be used as the new relay server for this node.  If it contains any
    /// new IP endpoints they will also be stored and tried when next connecting to this node. Any
    /// address that matches this node's direct addresses will be silently ignored. The *source* is
    /// used for logging exclusively and will not be stored.
    ///
    /// # Errors
    ///
    /// Will return an error if we attempt to add our own [`PublicKey`] to the node map or if the
    /// direct addresses are a subset of ours.
    pub fn add_node_addr_with_source(
        &self,
        node_addr: NodeAddr,
        source: &'static str,
    ) -> Result<()> {
        self.add_node_addr_inner(node_addr, magicsock::Source::NamedApp { name: source })
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
    /// The returned [`NodeAddr`] will have the current [`RelayUrl`] and local IP endpoints
    /// as they would be returned by [`Endpoint::home_relay`] and
    /// [`Endpoint::direct_addresses`].
    pub async fn node_addr(&self) -> Result<NodeAddr> {
        let addrs = self
            .direct_addresses()
            .next()
            .await
            .ok_or(anyhow!("No IP endpoints found"))?;
        let relay = self.home_relay();
        let addrs = addrs.into_iter().map(|x| x.addr).collect();
        Ok(NodeAddr::from_parts(self.node_id(), relay, addrs))
    }

    /// Returns the [`RelayUrl`] of the Relay server used as home relay.
    ///
    /// Every endpoint has a home Relay server which it chooses as the server with the
    /// lowest latency out of the configured servers provided by [`Builder::relay_mode`].
    /// This is the server other iroh-net nodes can use to reliably establish a connection
    /// to this node.
    ///
    /// Returns `None` if we are not connected to any Relay server.
    ///
    /// Note that this will be `None` right after the [`Endpoint`] is created since it takes
    /// some time to connect to find and connect to the home relay server.  Use
    /// [`Endpoint::watch_home_relay`] to wait until the home relay server is available.
    pub fn home_relay(&self) -> Option<RelayUrl> {
        self.msock.my_relay()
    }

    /// Watches for changes to the home relay.
    ///
    /// If there is currently a home relay it will be yielded immediately as the first item
    /// in the stream.  This makes it possible to use this function to wait for the initial
    /// home relay to be known.
    ///
    /// Note that it is not guaranteed that a home relay will ever become available.  If no
    /// servers are configured with [`Builder::relay_mode`] this stream will never yield an
    /// item.
    pub fn watch_home_relay(&self) -> impl Stream<Item = RelayUrl> {
        self.msock.watch_home_relay()
    }

    /// Returns the direct addresses of this [`Endpoint`].
    ///
    /// The direct addresses of the [`Endpoint`] are those that could be used by other
    /// iroh-net nodes to establish direct connectivity, depending on the network
    /// situation. The yielded lists of direct addresses contain both the locally-bound
    /// addresses and the [`Endpoint`]'s publicly reachable addresses discovered through
    /// mechanisms such as [STUN] and port mapping.  Hence usually only a subset of these
    /// will be applicable to a certain remote iroh-net node.
    ///
    /// The [`Endpoint`] continuously monitors the direct addresses for changes as its own
    /// location in the network might change.  Whenever changes are detected this stream
    /// will yield a new list of direct addresses.
    ///
    /// When issuing the first call to this method the first direct address discovery might
    /// still be underway, in this case the first item of the returned stream will not be
    /// immediately available.  Once this first set of local IP endpoints are discovered the
    /// stream will always return the first set of IP endpoints immediately, which are the
    /// most recently discovered IP endpoints.
    ///
    /// # Examples
    ///
    /// To get the current endpoints, drop the stream after the first item was received:
    /// ```
    /// use futures_lite::StreamExt;
    /// use iroh_net::Endpoint;
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let mep =  Endpoint::builder().bind(0).await.unwrap();
    /// let _addrs = mep.direct_addresses().next().await;
    /// # });
    /// ```
    ///
    /// [STUN]: https://en.wikipedia.org/wiki/STUN
    pub fn direct_addresses(&self) -> DirectAddrsStream {
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

    /// Returns connection information about a specific node.
    ///
    /// Then [`Endpoint`] stores some information about all the other iroh-net nodes it has
    /// information about.  This includes information about the relay server in use, any
    /// known direct addresses, when there was last any conact with this node and what kind
    /// of connection this was.
    pub fn connection_info(&self, node_id: NodeId) -> Option<ConnectionInfo> {
        self.msock.connection_info(node_id)
    }

    /// Returns information on all the nodes we have connection information about.
    ///
    /// This returns the same information as [`Endpoint::connection_info`] for each node
    /// known to this [`Endpoint`].
    ///
    /// Connections are currently only pruned on user action when using
    /// [`Endpoint::add_node_addr`] so these connections are not necessarily active
    /// connections.
    pub fn connection_infos(&self) -> Vec<ConnectionInfo> {
        self.msock.connection_infos()
    }

    // # Methods for less common getters.
    //
    // Partially they return things passed into the builder.

    /// Returns a stream that reports connection type changes for the remote node.
    ///
    /// This returns a stream of [`ConnectionType`] items, each time the underlying
    /// connection to a remote node changes it yields an item.  These connection changes are
    /// when the connection switches between using the Relay server and a direct connection.
    ///
    /// If there is currently a connection with the remote node the first item in the stream
    /// will yield immediately returning the current connection type.
    ///
    /// Note that this does not guarantee each connection change is yielded in the stream.
    /// If the connection type changes several times before this stream is polled only the
    /// last recorded state is returned.  This can be observed e.g. right at the start of a
    /// connection when the switch from a relayed to a direct connection can be so fast that
    /// the relayed state is never exposed.
    ///
    /// # Errors
    ///
    /// Will error if we do not have any address information for the given `node_id`.
    pub fn conn_type_stream(&self, node_id: NodeId) -> Result<ConnectionTypeStream> {
        self.msock.conn_type_stream(node_id)
    }

    /// Returns the DNS resolver used in this [`Endpoint`].
    ///
    /// See [`Builder::discovery`].
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.msock.dns_resolver()
    }

    /// Returns the discovery mechanism, if configured.
    ///
    /// See [`Builder::dns_resolver`].
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

    // # Methods for terminating the endpoint.

    /// Closes the QUIC endpoint and the magic socket.
    ///
    /// This will close all open QUIC connections with the provided error_code and
    /// reason. See [`quinn::Connection`] for details on how these are interpreted.
    ///
    /// It will then wait for all connections to actually be shutdown, and afterwards
    /// close the magic socket.
    ///
    /// Returns an error if closing the magic socket failed.
    /// TODO: Document error cases.
    pub async fn close(self, error_code: VarInt, reason: &[u8]) -> Result<()> {
        let Endpoint {
            msock,
            endpoint,
            cancel_token,
            ..
        } = self;
        cancel_token.cancel();
        tracing::debug!("Closing connections");
        endpoint.close(error_code, reason);
        endpoint.wait_idle().await;
        // In case this is the last clone of `Endpoint`, dropping the `quinn::Endpoint` will
        // make it more likely that the underlying socket is not polled by quinn anymore after this
        drop(endpoint);
        tracing::debug!("Connections closed");

        msock.close().await?;
        Ok(())
    }

    // # Remaining private methods

    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.cancel_token.cancelled()
    }

    /// Return the quic mapped address for this `node_id` and possibly start discovery
    /// services if discovery is enabled on this magic endpoint.
    ///
    /// This will launch discovery in all cases except if:
    /// 1) we do not have discovery enabled
    /// 2) we have discovery enabled, but already have at least one verified, unexpired
    /// addresses for this `node_id`
    ///
    /// # Errors
    ///
    /// This method may fail if we have no way of dialing the node. This can occur if
    /// we were given no dialing information in the [`NodeAddr`] and no discovery
    /// services were configured or if discovery failed to fetch any dialing information.
    async fn get_mapping_addr_and_maybe_start_discovery(
        &self,
        node_addr: NodeAddr,
    ) -> Result<(SocketAddr, Option<DiscoveryTask>)> {
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
                let delay = (!node_addr.info.is_empty()).then_some(DISCOVERY_WAIT_PERIOD);
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
                let mut discovery = DiscoveryTask::start(self.clone(), node_id)?;
                discovery.first_arrived().await?;
                if self.msock.has_send_address(node_id) {
                    let addr = self.msock.get_mapping_addr(node_id).expect("checked");
                    Ok((addr, Some(discovery)))
                } else {
                    bail!("Failed to retrieve the mapped address from the magic socket. Unable to dial node {node_id:?}");
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
        &self.endpoint
    }
}

/// Future produced by [`Endpoint::accept`].
#[derive(Debug)]
#[pin_project::pin_project]
pub struct Accept<'a> {
    #[pin]
    inner: quinn::Accept<'a>,
    magic_ep: Endpoint,
}

impl<'a> Future for Accept<'a> {
    type Output = Option<Connecting>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(inner)) => Poll::Ready(Some(Connecting {
                inner,
                magic_ep: this.magic_ep.clone(),
            })),
        }
    }
}

/// In-progress connection attempt future
#[derive(Debug)]
#[pin_project::pin_project]
pub struct Connecting {
    #[pin]
    inner: quinn::Connecting,
    magic_ep: Endpoint,
}

impl Connecting {
    /// Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security.
    pub fn into_0rtt(self) -> Result<(quinn::Connection, quinn::ZeroRttAccepted), Self> {
        match self.inner.into_0rtt() {
            Ok((conn, zrtt_accepted)) => {
                try_send_rtt_msg(&conn, &self.magic_ep);
                Ok((conn, zrtt_accepted))
            }
            Err(inner) => Err(Self {
                inner,
                magic_ep: self.magic_ep,
            }),
        }
    }

    /// Parameters negotiated during the handshake
    pub async fn handshake_data(&mut self) -> Result<Box<dyn Any>, quinn::ConnectionError> {
        self.inner.handshake_data().await
    }

    /// The local IP address which was used when the peer established the connection.
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.inner.local_ip()
    }

    /// The peer's UDP address.
    pub fn remote_address(&self) -> SocketAddr {
        self.inner.remote_address()
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
    type Output = Result<quinn::Connection, quinn::ConnectionError>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(conn)) => {
                try_send_rtt_msg(&conn, this.magic_ep);
                Poll::Ready(Ok(conn))
            }
        }
    }
}

/// Extract the [`PublicKey`] from the peer's TLS certificate.
pub fn get_remote_node_id(connection: &quinn::Connection) -> Result<PublicKey> {
    let data = connection.peer_identity();
    match data {
        None => bail!("no peer certificate found"),
        Some(data) => match data.downcast::<Vec<rustls::Certificate>>() {
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

/// Try send a message to the rtt-actor.
///
/// If we can't notify the actor that will impact performance a little, but we can still
/// function.
fn try_send_rtt_msg(conn: &quinn::Connection, magic_ep: &Endpoint) {
    // If we can't notify the rtt-actor that's not great but not critical.
    let Ok(peer_id) = get_remote_node_id(conn) else {
        warn!(?conn, "failed to get remote node id");
        return;
    };
    let Ok(conn_type_changes) = magic_ep.conn_type_stream(peer_id) else {
        warn!(?conn, "failed to create conn_type_stream");
        return;
    };
    let rtt_msg = RttMessage::NewConnection {
        connection: conn.weak_handle(),
        conn_type_changes,
        node_id: peer_id,
    };
    if let Err(err) = magic_ep.rtt_actor.msg_tx.try_send(rtt_msg) {
        warn!(?conn, "rtt-actor not reachable: {err:#}");
    }
}

/// Read a proxy url from the environemnt, in this order
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

    use iroh_test::CallOnDrop;
    use rand_core::SeedableRng;
    use tracing::{error_span, info, info_span, Instrument};

    use crate::test_utils::run_relay_server;

    use super::*;

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[test]
    fn test_addr_info_debug() {
        let info = AddrInfo {
            relay_url: Some("https://relay.example.com".parse().unwrap()),
            direct_addresses: vec![SocketAddr::from(([1, 2, 3, 4], 1234))]
                .into_iter()
                .collect(),
        };
        assert_eq!(
            format!("{:?}", info),
            r#"AddrInfo { relay_url: Some(RelayUrl("https://relay.example.com./")), direct_addresses: {1.2.3.4:1234} }"#
        );
    }

    #[tokio::test]
    async fn test_connect_self() {
        let _guard = iroh_test::logging::setup();
        let ep = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .bind(0)
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
    async fn endpoint_connect_close() {
        let _guard = iroh_test::logging::setup();
        let (relay_map, relay_url, _guard) = run_relay_server().await.unwrap();
        let server_secret_key = SecretKey::generate();
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
                        .bind(0)
                        .await
                        .unwrap();
                    info!("accepting connection");
                    let incoming = ep.accept().await.unwrap();
                    let conn = incoming.await.unwrap();
                    let mut stream = conn.accept_uni().await.unwrap();
                    let mut buf = [0u8, 5];
                    stream.read_exact(&mut buf).await.unwrap();
                    info!("Accepted 1 stream, received {buf:?}.  Closing now.");
                    // close the stream
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
                    .bind(0)
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

                // Remote now closes the connection, we should see an error sometime soon.
                let err = conn.closed().await;
                let expected_err =
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code: 7u8.into(),
                        reason: b"bye".to_vec().into(),
                    });
                assert_eq!(err, expected_err);

                let res = stream.finish().await;
                assert_eq!(
                    res.unwrap_err(),
                    quinn::WriteError::ConnectionLost(expected_err.clone())
                );

                let res = conn.open_uni().await;
                assert_eq!(res.unwrap_err(), expected_err);
                info!("client test completed");
            }
            .instrument(info_span!("test-client")),
        );

        let (server, client) = tokio::join!(server, client);
        server.unwrap();
        client.unwrap();
    }

    /// Test that peers saved on shutdown are correctly loaded
    #[tokio::test]
    #[cfg_attr(target_os = "windows", ignore = "flaky")]
    async fn save_load_peers() {
        let _guard = iroh_test::logging::setup();

        let secret_key = SecretKey::generate();
        let root = testdir::testdir!();
        let path = root.join("peers");

        /// Create an endpoint for the test.
        async fn new_endpoint(secret_key: SecretKey, peers_path: PathBuf) -> Endpoint {
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            Endpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .peers_data_path(peers_path)
                .alpns(vec![TEST_ALPN.to_vec()])
                .bind(0)
                .await
                .unwrap()
        }

        // create the peer that will be added to the peer map
        let peer_id = SecretKey::generate().public();
        let direct_addr: SocketAddr =
            (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8758u16).into();
        let node_addr = NodeAddr::new(peer_id).with_direct_addresses([direct_addr]);

        info!("setting up first endpoint");
        // first time, create a magic endpoint without peers but a peers file and add addressing
        // information for a peer
        let endpoint = new_endpoint(secret_key.clone(), path.clone()).await;
        assert!(endpoint.connection_infos().is_empty());
        endpoint.add_node_addr(node_addr).unwrap();

        info!("closing endpoint");
        // close the endpoint and restart it
        endpoint.close(0u32.into(), b"done").await.unwrap();

        info!("restarting endpoint");
        // now restart it and check the addressing info of the peer
        let endpoint = new_endpoint(secret_key, path).await;
        let ConnectionInfo { mut addrs, .. } = endpoint.connection_info(peer_id).unwrap();
        let conn_addr = addrs.pop().unwrap().addr;
        assert_eq!(conn_addr, direct_addr);
    }

    #[tokio::test]
    async fn endpoint_relay_connect_loop() {
        let _logging_guard = iroh_test::logging::setup();
        let start = Instant::now();
        let n_clients = 5;
        let n_chunks_per_client = 2;
        let chunk_size = 10;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let (relay_map, relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let server_secret_key = SecretKey::generate_with_rng(&mut rng);
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
                        .bind(0)
                        .await
                        .unwrap();
                    let eps = ep.bound_sockets();
                    info!(me = %ep.node_id().fmt_short(), ipv4=%eps.0, ipv6=?eps.1, "server bound");
                    for i in 0..n_clients {
                        let now = Instant::now();
                        println!("[server] round {}", i + 1);
                        let incoming = ep.accept().await.unwrap();
                        let conn = incoming.await.unwrap();
                        let peer_id = get_remote_node_id(&conn).unwrap();
                        info!(%i, peer = %peer_id.fmt_short(), "accepted connection");
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; chunk_size];
                        for _i in 0..n_chunks_per_client {
                            recv.read_exact(&mut buf).await.unwrap();
                            send.write_all(&buf).await.unwrap();
                        }
                        send.finish().await.unwrap();
                        recv.read_to_end(0).await.unwrap();
                        info!(%i, peer = %peer_id.fmt_short(), "finished");
                        println!("[server] round {} done in {:?}", i + 1, now.elapsed());
                    }
                }
                .instrument(error_span!("server")),
            )
        };
        let abort_handle = server.abort_handle();
        let _server_guard = CallOnDrop::new(move || {
            abort_handle.abort();
        });

        for i in 0..n_clients {
            let now = Instant::now();
            println!("[client] round {}", i + 1);
            let relay_map = relay_map.clone();
            let client_secret_key = SecretKey::generate_with_rng(&mut rng);
            let relay_url = relay_url.clone();
            async {
                info!("client binding");
                let ep = Endpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .insecure_skip_relay_cert_verify(true)
                    .relay_mode(RelayMode::Custom(relay_map))
                    .secret_key(client_secret_key)
                    .bind(0)
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
                send.finish().await.unwrap();
                recv.read_to_end(0).await.unwrap();
                info!("client finished");
                ep.close(0u32.into(), &[]).await.unwrap();
                info!("client closed");
            }
            .instrument(error_span!("client", %i))
            .await;
            println!("[client] round {} done in {:?}", i + 1, now.elapsed());
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
    async fn endpoint_bidi_send_recv() {
        let _logging_guard = iroh_test::logging::setup();
        let ep1 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind(0)
            .await
            .unwrap();
        let ep2 = Endpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind(0)
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
            send.write_all(b"hello").await.unwrap();
            send.finish().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"world");
        }

        async fn accept_world(ep: Endpoint, src: NodeId) {
            let mut incoming = ep.accept().await.unwrap();
            let alpn = incoming.alpn().await.unwrap();
            let conn = incoming.await.unwrap();
            let node_id = get_remote_node_id(&conn).unwrap();
            assert_eq!(node_id, src);
            assert_eq!(alpn, TEST_ALPN);
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"hello");
            send.write_all(b"world").await.unwrap();
            send.finish().await.unwrap();
        }

        let p1_accept = tokio::spawn(accept_world(ep1.clone(), ep2_nodeid));
        let p2_accept = tokio::spawn(accept_world(ep2.clone(), ep1_nodeid));
        let p1_connect = tokio::spawn(connect_hello(ep1.clone(), ep2_nodeaddr));
        let p2_connect = tokio::spawn(connect_hello(ep2.clone(), ep1_nodeaddr));

        p1_accept.await.unwrap();
        p2_accept.await.unwrap();
        p1_connect.await.unwrap();
        p2_connect.await.unwrap();
    }

    #[tokio::test]
    async fn endpoint_conn_type_stream() {
        const TIMEOUT: Duration = std::time::Duration::from_secs(15);
        let _logging_guard = iroh_test::logging::setup();
        let (relay_map, _relay_url, _relay_guard) = run_relay_server().await.unwrap();
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let ep1_secret_key = SecretKey::generate_with_rng(&mut rng);
        let ep2_secret_key = SecretKey::generate_with_rng(&mut rng);
        let ep1 = Endpoint::builder()
            .secret_key(ep1_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .bind(0)
            .await
            .unwrap();
        let ep2 = Endpoint::builder()
            .secret_key(ep2_secret_key)
            .insecure_skip_relay_cert_verify(true)
            .alpns(vec![TEST_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .bind(0)
            .await
            .unwrap();

        async fn handle_direct_conn(ep: &Endpoint, node_id: PublicKey) -> Result<()> {
            let mut stream = ep.conn_type_stream(node_id)?;
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
            let node_id = get_remote_node_id(&conn).unwrap();
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

        let ep1_abort_handle = res_ep1.abort_handle();
        let _ep1_guard = CallOnDrop::new(move || {
            ep1_abort_handle.abort();
        });

        let res_ep2 = tokio::spawn(tokio::time::timeout(TIMEOUT, ep2_side));
        let ep2_abort_handle = res_ep2.abort_handle();
        let _ep2_guard = CallOnDrop::new(move || {
            ep2_abort_handle.abort();
        });

        let (r1, r2) = tokio::try_join!(res_ep1, res_ep2).unwrap();
        r1.expect("ep1 timeout").unwrap();
        r2.expect("ep2 timeout").unwrap();
    }
}
