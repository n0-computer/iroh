//! An endpoint that leverages a [`quinn::Endpoint`] and transparently routes packages via direct
//! conenctions or a relay when necessary, optimizing the path to target nodes to ensure maximum
//! connectivity.

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
    config,
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
    ConnectionInfo, ConnectionType, ConnectionTypeStream, ControlMsg, DirectAddrInfo,
    LocalEndpointsStream,
};

pub use iroh_base::node_addr::{AddrInfo, NodeAddr};

/// The delay we add before starting a discovery in [`Endpoint::connect`] if the user provided
/// new direct addresses (to try these addresses before starting the discovery).
const DISCOVERY_WAIT_PERIOD: Duration = Duration::from_millis(500);

/// Builder for [Endpoint]
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
    /// Set a secret key to authenticate with other peers.
    ///
    /// This secret key's public key will be the [PublicKey] of this endpoint.
    ///
    /// If not set, a new secret key will be generated.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Set the ALPN protocols that this endpoint will accept on incoming connections.
    pub fn alpns(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    /// Set an explicit proxy url to proxy all HTTP(S) traffic through.
    pub fn proxy_url(mut self, url: Url) -> Self {
        self.proxy_url.replace(url);
        self
    }

    /// Set the proxy url from the environment, in this order:
    ///
    /// - `HTTP_PROXY`
    /// - `http_proxy`
    /// - `HTTPS_PROXY`
    /// - `https_proxy`
    pub fn proxy_from_env(mut self) -> Self {
        self.proxy_url = proxy_url_from_env();
        self
    }

    /// If *keylog* is `true` and the KEYLOGFILE environment variable is present it will be
    /// considered a filename to which the TLS pre-master keys are logged.  This can be useful
    /// to be able to decrypt captured traffic for debugging purposes.
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

    /// Sets the relay servers to assist in establishing connectivity.
    ///
    /// relay servers are used to discover other peers by [`PublicKey`] and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [RelayMode::Custom], the provided `relay_map` must contain at least one
    /// configured relay node.  If an invalid [`RelayMap`] is provided [`bind`]
    /// will result in an error.
    ///
    /// [`bind`]: Builder::bind
    pub fn relay_mode(mut self, relay_mode: RelayMode) -> Self {
        self.relay_mode = relay_mode;
        self
    }

    /// Set a custom [quinn::TransportConfig] for this endpoint.
    ///
    /// The transport config contains parameters governing the QUIC state machine.
    ///
    /// If unset, the default config is used. Default values should be suitable for most internet
    /// applications. Applications protocols which forbid remotely-initiated streams should set
    /// `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` to zero.
    pub fn transport_config(mut self, transport_config: quinn::TransportConfig) -> Self {
        self.transport_config = Some(transport_config);
        self
    }

    /// Maximum number of simultaneous connections to accept.
    ///
    /// New incoming connections are only accepted if the total number of incoming or outgoing
    /// connections is less than this. Outgoing connections are unaffected.
    pub fn concurrent_connections(mut self, concurrent_connections: u32) -> Self {
        self.concurrent_connections = Some(concurrent_connections);
        self
    }

    /// Optionally set the path where peer info should be stored.
    ///
    /// If the file exists, it will be used to populate an initial set of peers. Peers will be
    /// saved periodically and on shutdown to this path.
    pub fn peers_data_path(mut self, path: PathBuf) -> Self {
        self.peers_path = Some(path);
        self
    }

    /// Optionally set a discovery mechanism for this endpoint.
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

    /// Optionally set a custom DNS resolver to use for this endpoint.
    ///
    /// The DNS resolver is used to resolve relay hostnames, and node addresses if
    /// [`crate::discovery::dns::DnsDiscovery`] is configured.
    ///
    /// By default, all magic endpoints share a DNS resolver, which is configured to use the
    /// host system's DNS configuration. You can pass a custom instance of [`DnsResolver`]
    /// here to use a differently configured DNS resolver for this endpoint.
    pub fn dns_resolver(mut self, dns_resolver: DnsResolver) -> Self {
        self.dns_resolver = Some(dns_resolver);
        self
    }

    /// Bind the magic endpoint on the specified socket address.
    ///
    /// The *bind_port* is the port that should be bound locally.
    /// The port will be used to bind an IPv4 and, if supported, and IPv6 socket.
    /// You can pass `0` to let the operating system choose a free port for you.
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
        let mut server_config = make_server_config(
            &secret_key,
            self.alpn_protocols,
            self.transport_config,
            self.keylog,
        )?;
        if let Some(c) = self.concurrent_connections {
            server_config.concurrent_connections(c);
        }
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
        Endpoint::bind(Some(server_config), msock_opts, self.keylog).await
    }
}

/// Create a [`quinn::ServerConfig`] with the given secret key and limits.
pub fn make_server_config(
    secret_key: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    keylog: bool,
) -> Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(secret_key, alpn_protocols, keylog)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    server_config.transport_config(Arc::new(transport_config.unwrap_or_default()));

    Ok(server_config)
}

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to nodes based on node IDs, it will initially route
/// packets via a relay and transparently try and establish a node-to-node connection and upgrade
/// to it.  It will also keep looking for better connections as the network details of both nodes
/// change.
///
/// It is usually only necessary to use a single [`Endpoint`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about nodes as possible.
#[derive(Clone, Debug)]
pub struct Endpoint {
    secret_key: Arc<SecretKey>,
    msock: Handle,
    endpoint: quinn::Endpoint,
    rtt_actor: Arc<rtt_actor::RttHandle>,
    keylog: bool,
    cancel_token: CancellationToken,
}

impl Endpoint {
    /// Build an [`Endpoint`]
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Create a quinn endpoint backed by a magicsock.
    ///
    /// This is for internal use, the public interface is the [`Builder`] obtained from
    /// [Self::builder]. See the methods on the builder for documentation of the parameters.
    async fn bind(
        server_config: Option<quinn::ServerConfig>,
        msock_opts: magicsock::Options,
        keylog: bool,
    ) -> Result<Self> {
        let secret_key = msock_opts.secret_key.clone();
        let span = info_span!("magic_ep", me = %secret_key.public().fmt_short());
        let _guard = span.enter();
        let msock = magicsock::MagicSock::spawn(msock_opts).await?;
        trace!("created magicsock");

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Setting this to false means that quinn will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to quinn. We set the first byte of the packet to zero, which makes quinn ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            server_config,
            msock.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        trace!("created quinn endpoint");

        Ok(Self {
            secret_key: Arc::new(secret_key),
            msock,
            endpoint,
            rtt_actor: Arc::new(rtt_actor::RttHandle::new()),
            keylog,
            cancel_token: CancellationToken::new(),
        })
    }

    /// Accept an incoming connection on the socket.
    pub fn accept(&self) -> Accept<'_> {
        Accept {
            inner: self.endpoint.accept(),
            magic_ep: self.clone(),
        }
    }

    /// Get the node id of this endpoint.
    pub fn node_id(&self) -> NodeId {
        self.secret_key.public()
    }

    /// Get the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Optional reference to the discovery mechanism.
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.msock.discovery()
    }

    /// Get the local endpoint addresses on which the underlying magic socket is bound.
    ///
    /// Returns a tuple of the IPv4 and the optional IPv6 address.
    pub fn local_addr(&self) -> (SocketAddr, Option<SocketAddr>) {
        self.msock.local_addr()
    }

    /// Returns the local endpoints as a stream.
    ///
    /// The [`Endpoint`] continuously monitors the local endpoints, the network
    /// addresses it can listen on, for changes.  Whenever changes are detected this stream
    /// will yield a new list of endpoints.
    ///
    /// Upon the first creation, the first local endpoint discovery might still be underway, in
    /// this case the first item of the stream will not be immediately available.  Once this first
    /// set of local endpoints are discovered the stream will always return the first set of
    /// endpoints immediately, which are the most recently discovered endpoints.
    ///
    /// The list of endpoints yielded contains both the locally-bound addresses and the
    /// endpoint's publicly-reachable addresses, if they could be discovered through STUN or
    /// port mapping.
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
    /// let _endpoints = mep.local_endpoints().next().await;
    /// # });
    /// ```
    pub fn local_endpoints(&self) -> LocalEndpointsStream {
        self.msock.local_endpoints()
    }

    /// Get the relay url we are connected to with the lowest latency.
    ///
    /// Returns `None` if we are not connected to any relayer.
    pub fn my_relay(&self) -> Option<RelayUrl> {
        self.msock.my_relay()
    }

    /// Get the [`NodeAddr`] for this endpoint.
    pub async fn my_addr(&self) -> Result<NodeAddr> {
        let addrs = self
            .local_endpoints()
            .next()
            .await
            .ok_or(anyhow!("No endpoints found"))?;
        let relay = self.my_relay();
        let addrs = addrs.into_iter().map(|x| x.addr).collect();
        Ok(NodeAddr::from_parts(self.node_id(), relay, addrs))
    }

    /// Get the [`NodeAddr`] for this endpoint, while providing the endpoints.
    pub fn my_addr_with_endpoints(&self, eps: Vec<config::Endpoint>) -> Result<NodeAddr> {
        let relay = self.my_relay();
        let addrs = eps.into_iter().map(|x| x.addr).collect();
        Ok(NodeAddr::from_parts(self.node_id(), relay, addrs))
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known. If the home
    /// relay is known at this point, it will be the first item in the stream.
    pub fn watch_home_relay(&self) -> impl Stream<Item = RelayUrl> {
        self.msock.watch_home_relay()
    }

    /// Get information on all the nodes we have connection information about.
    ///
    /// Includes the node's [`PublicKey`], potential relay Url, its addresses with any known
    /// latency, and its [`ConnectionType`], which let's us know if we are currently communicating
    /// with that node over a `Direct` (UDP) or `Relay` (relay) connection.
    ///
    /// Connections are currently only pruned on user action (when we explicitly add a new address
    /// to the internal addressbook through [`Endpoint::add_node_addr`]), so these connections
    /// are not necessarily active connections.
    pub fn connection_infos(&self) -> Vec<ConnectionInfo> {
        self.msock.connection_infos()
    }

    /// Get connection information about a specific node.
    ///
    /// Includes the node's [`PublicKey`], potential relay Url, its addresses with any known
    /// latency, and its [`ConnectionType`], which let's us know if we are currently communicating
    /// with that node over a `Direct` (UDP) or `Relay` (relay) connection.
    pub fn connection_info(&self, node_id: PublicKey) -> Option<ConnectionInfo> {
        self.msock.connection_info(node_id)
    }

    pub(crate) fn cancelled(&self) -> WaitForCancellationFuture<'_> {
        self.cancel_token.cancelled()
    }

    /// Connect to a remote endpoint, using just the nodes's [`PublicKey`].
    pub async fn connect_by_node_id(
        &self,
        node_id: &PublicKey,
        alpn: &[u8],
    ) -> Result<quinn::Connection> {
        let addr = NodeAddr::new(*node_id);
        self.connect(addr, alpn).await
    }

    /// Returns a stream that reports changes in the [`ConnectionType`] for the given `node_id`.
    ///
    /// # Errors
    ///
    /// Will error if we do not have any address information for the given `node_id`
    pub fn conn_type_stream(&self, node_id: &PublicKey) -> Result<ConnectionTypeStream> {
        self.msock.conn_type_stream(node_id)
    }

    /// Connect to a remote endpoint.
    ///
    /// A [`NodeAddr`] is required. It must contain the [`NodeId`] to dial and may also contain a
    /// relay URL and direct addresses. If direct addresses are provided, they will be used to
    /// try and establish a direct connection without involving a relay server.
    ///
    /// The `alpn`, or application-level protocol identifier, is also required. The remote endpoint
    /// must support this `alpn`, otherwise the connection attempt will fail with an error.
    ///
    /// If the [`NodeAddr`] contains only [`NodeId`] and no direct addresses and no relay servers,
    /// a discovery service will be invoked, if configured, to try and discover the node's
    /// addressing information. The discovery services must be configured globally per [`Endpoint`]
    /// with [`Builder::discovery`]. The discovery service will also be invoked if
    /// none of the existing or provided direct addresses are reachable.
    ///
    /// If addresses or relay servers are neither provided nor can be discovered, the connection
    /// attempt will fail with an error.
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

    async fn connect_quinn(
        &self,
        node_id: &PublicKey,
        alpn: &[u8],
        addr: SocketAddr,
    ) -> Result<quinn::Connection> {
        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let tls_client_config = tls::make_client_config(
                &self.secret_key,
                Some(*node_id),
                alpn_protocols,
                self.keylog,
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
            conn_type_changes: self.conn_type_stream(node_id)?,
            node_id: *node_id,
        };
        if let Err(err) = self.rtt_actor.msg_tx.send(rtt_msg).await {
            // If this actor is dead, that's not great but we can still function.
            warn!("rtt-actor not reachable: {err:#}");
        }

        Ok(connection)
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
            self.msock.get_mapping_addr(&node_id)
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
                    let addr = self.msock.get_mapping_addr(&node_id).expect("checked");
                    Ok((addr, Some(discovery)))
                } else {
                    bail!("Failed to retrieve the mapped address from the magic socket. Unable to dial node {node_id:?}");
                }
            }
        }
    }

    /// Inform the magic socket about addresses of the peer.
    ///
    /// This updates the magic socket's *netmap* with these addresses, which are used as candidates
    /// when connecting to this peer (in addition to addresses obtained from a relay server).
    ///
    /// Note: updating the magic socket's *netmap* will also prune any connections that are *not*
    /// present in the netmap.
    ///
    /// # Errors
    /// Will return an error if we attempt to add our own [`PublicKey`] to the node map.
    pub fn add_node_addr(&self, node_addr: NodeAddr) -> Result<()> {
        // Connecting to ourselves is not supported.
        if node_addr.node_id == self.node_id() {
            bail!(
                "Adding our own address is not supported ({} is the node id of this node)",
                node_addr.node_id.fmt_short()
            );
        }
        self.msock.add_node_addr(node_addr);
        Ok(())
    }

    /// Get a reference to the DNS resolver used in this [`Endpoint`].
    pub fn dns_resolver(&self) -> &DnsResolver {
        self.msock.dns_resolver()
    }

    /// Close the QUIC endpoint and the magic socket.
    ///
    /// This will close all open QUIC connections with the provided error_code and reason. See
    /// [quinn::Connection] for details on how these are interpreted.
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

    /// Call to notify the system of potential network changes.
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
    pub async fn alpn(&mut self) -> Result<String> {
        let data = self.handshake_data().await?;
        match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
            Ok(data) => match data.protocol {
                Some(protocol) => std::string::String::from_utf8(protocol).map_err(Into::into),
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
    let Ok(conn_type_changes) = magic_ep.conn_type_stream(&peer_id) else {
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
        let my_addr = ep.my_addr().await.unwrap();
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
                    let eps = ep.local_addr();
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
                let eps = ep.local_addr();
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
        let ep1_nodeaddr = ep1.my_addr().await.unwrap();
        let ep2_nodeaddr = ep2.my_addr().await.unwrap();
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
            assert_eq!(alpn.as_bytes(), TEST_ALPN);
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
        let _logging_guard = iroh_test::logging::setup();
        let (relay_map, relay_url, _relay_guard) = run_relay_server().await.unwrap();
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

        async fn handle_direct_conn(ep: Endpoint, node_id: PublicKey) -> Result<()> {
            let node_addr = NodeAddr::new(node_id);
            ep.add_node_addr(node_addr)?;
            let stream = ep.conn_type_stream(&node_id)?;
            async fn get_direct_event(
                src: &PublicKey,
                dst: &PublicKey,
                mut stream: ConnectionTypeStream,
            ) -> Result<()> {
                let src = src.fmt_short();
                let dst = dst.fmt_short();
                while let Some(conn_type) = stream.next().await {
                    tracing::info!(me = %src, dst = %dst, conn_type = ?conn_type);
                    if matches!(conn_type, ConnectionType::Direct(_)) {
                        return Ok(());
                    }
                }
                anyhow::bail!("conn_type stream ended before `ConnectionType::Direct`");
            }
            tokio::time::timeout(
                Duration::from_secs(15),
                get_direct_event(&ep.node_id(), &node_id, stream),
            )
            .await??;
            Ok(())
        }

        let ep1_nodeid = ep1.node_id();
        let ep2_nodeid = ep2.node_id();

        let ep1_nodeaddr = ep1.my_addr().await.unwrap();
        tracing::info!(
            "node id 1 {ep1_nodeid}, relay URL {:?}",
            ep1_nodeaddr.relay_url()
        );
        tracing::info!("node id 2 {ep2_nodeid}");

        let res_ep1 = tokio::spawn(handle_direct_conn(ep1.clone(), ep2_nodeid));

        let ep1_abort_handle = res_ep1.abort_handle();
        let _ep1_guard = CallOnDrop::new(move || {
            ep1_abort_handle.abort();
        });

        let res_ep2 = tokio::spawn(handle_direct_conn(ep2.clone(), ep1_nodeid));
        let ep2_abort_handle = res_ep2.abort_handle();
        let _ep2_guard = CallOnDrop::new(move || {
            ep2_abort_handle.abort();
        });
        async fn accept(ep: Endpoint) -> NodeId {
            let incoming = ep.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            get_remote_node_id(&conn).unwrap()
        }

        // create a node addr with no direct connections
        let ep1_nodeaddr = NodeAddr::from_parts(ep1_nodeid, Some(relay_url), vec![]);

        let accept_res = tokio::spawn(accept(ep1.clone()));
        let accept_abort_handle = accept_res.abort_handle();
        let _accept_guard = CallOnDrop::new(move || {
            accept_abort_handle.abort();
        });

        let _conn_2 = ep2.connect(ep1_nodeaddr, TEST_ALPN).await.unwrap();

        let got_id = accept_res.await.unwrap();
        assert_eq!(ep2_nodeid, got_id);

        res_ep1.await.unwrap().unwrap();
        res_ep2.await.unwrap().unwrap();
    }
}
