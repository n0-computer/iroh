//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock
//!
//! ### `RelayOnly` path selection:
//! When set this will force all packets to be sent over
//! the relay connection, regardless of whether or
//! not we have a direct UDP address for the given node.
//!
//! The intended use is for testing the relay protocol inside the MagicSock
//! to ensure that we can rely on the relay to send packets when two nodes
//! are unable to find direct UDP connections to each other.
//!
//! This also prevent this node from attempting to hole punch and prevents it
//! from responding to any hole punching attempts. This node will still,
//! however, read any packets that come off the UDP sockets.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    task::{Context, Poll, Waker},
};

use anyhow::{anyhow, Context as _, Result};
use atomic_waker::AtomicWaker;
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use data_encoding::HEXLOWER;
use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_metrics::{inc, inc_by};
use iroh_relay::{protos::stun, RelayMap};
use n0_future::{
    boxed::BoxStream,
    task::{self, JoinSet},
    time::{self, Duration, Instant},
    FutureExt, StreamExt,
};
use net_report::{IpMappedAddr, IpMappedAddresses, QuicConfig, MAPPED_ADDR_PORT};
#[cfg(not(wasm_browser))]
use netwatch::{interfaces, ip::LocalAddresses, netmon, UdpSocket};
use quinn::{AsyncUdpSocket, ServerConfig};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use relay_actor::RelaySendItem;
use smallvec::{smallvec, SmallVec};
use tokio::sync::{self, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{
    debug, error, error_span, event, info, info_span, instrument, trace, trace_span, warn,
    Instrument, Level, Span,
};
use url::Url;

#[cfg(not(wasm_browser))]
use self::udp_conn::UdpConn;
use self::{
    metrics::Metrics as MagicsockMetrics,
    node_map::{NodeMap, PingAction, PingRole, SendPing},
    relay_actor::{RelayActor, RelayActorMessage, RelayRecvDatagram},
};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;
use crate::{
    defaults::timeouts::NET_REPORT_TIMEOUT,
    disco::{self, CallMeMaybe, SendAddr},
    discovery::{Discovery, DiscoveryItem, NodeData},
    key::{public_ed_box, secret_ed_box, DecryptionError, SharedSecret},
    watchable::{Watchable, Watcher},
};

mod metrics;
mod node_map;
mod relay_actor;
#[cfg(not(wasm_browser))]
mod udp_conn;

pub use node_map::Source;

pub use self::{
    metrics::Metrics,
    node_map::{ConnectionType, ControlMsg, DirectAddrInfo, RemoteInfo},
};

/// How long we consider a STUN-derived endpoint valid for. UDP NAT mappings typically
/// expire at 30 seconds, so this is a few seconds shy of that.
const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Contains options for `MagicSock::listen`.
#[derive(derive_more::Debug)]
pub(crate) struct Options {
    /// The IPv4 address to listen on.
    ///
    /// If set to `None` it will choose a random port and listen on `0.0.0.0:0`.
    pub(crate) addr_v4: Option<SocketAddrV4>,
    /// The IPv6 address to listen on.
    ///
    /// If set to `None` it will choose a random port and listen on `[::]:0`.
    pub(crate) addr_v6: Option<SocketAddrV6>,

    /// Secret key for this node.
    pub(crate) secret_key: SecretKey,

    /// The [`RelayMap`] to use, leave empty to not use a relay server.
    pub(crate) relay_map: RelayMap,

    /// An optional [`NodeMap`], to restore information about nodes.
    pub(crate) node_map: Option<Vec<NodeAddr>>,

    /// Optional node discovery mechanism.
    pub(crate) discovery: Option<Box<dyn Discovery>>,

    /// A DNS resolver to use for resolving relay URLs.
    ///
    /// You can use [`crate::dns::DnsResolver::new`] for a resolver
    /// that uses the system's DNS configuration.
    #[cfg(not(wasm_browser))]
    pub(crate) dns_resolver: DnsResolver,

    /// Proxy configuration.
    pub(crate) proxy_url: Option<Url>,

    /// ServerConfig for the internal QUIC endpoint
    pub(crate) server_config: ServerConfig,

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) insecure_skip_relay_cert_verify: bool,

    /// Configuration for what path selection to use
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) path_selection: PathSelection,
}

#[cfg(test)]
impl Default for Options {
    fn default() -> Self {
        let secret_key = SecretKey::generate(rand::rngs::OsRng);
        let server_config = make_default_server_config(&secret_key);
        Options {
            addr_v4: None,
            addr_v6: None,
            secret_key,
            relay_map: RelayMap::empty(),
            node_map: None,
            discovery: None,
            proxy_url: None,
            #[cfg(not(wasm_browser))]
            dns_resolver: DnsResolver::new(),
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection: PathSelection::default(),
        }
    }
}

/// Generate a server config with no ALPNS and a default transport configuration
#[cfg(test)]
fn make_default_server_config(secret_key: &SecretKey) -> ServerConfig {
    let quic_server_config = crate::tls::make_server_config(secret_key, vec![], false)
        .expect("should generate valid config");
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
    server_config.transport_config(Arc::new(quinn::TransportConfig::default()));
    server_config
}

/// Contents of a relay message. Use a SmallVec to avoid allocations for the very
/// common case of a single packet.
type RelayContents = SmallVec<[Bytes; 1]>;

/// Handle for [`MagicSock`].
///
/// Dereferences to [`MagicSock`], and handles closing.
#[derive(Clone, Debug, derive_more::Deref)]
pub(crate) struct Handle {
    #[deref(forward)]
    msock: Arc<MagicSock>,
    // Empty when closed
    actor_tasks: Arc<Mutex<JoinSet<()>>>,
    // quinn endpoint
    endpoint: quinn::Endpoint,
}

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to nodes based on node IDs, it will initially
/// route packets via a relay and transparently try and establish a node-to-node
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both nodes change.
///
/// It is usually only necessary to use a single [`MagicSock`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about nodes as
/// possible.
#[derive(derive_more::Debug)]
pub(crate) struct MagicSock {
    actor_sender: mpsc::Sender<ActorMessage>,
    /// String representation of the node_id of this node.
    me: String,
    /// Proxy
    proxy_url: Option<Url>,
    /// Queue to receive datagrams from relays for [`AsyncUdpSocket::poll_recv`].
    ///
    /// Relay datagrams received by relays are put into this queue and consumed by
    /// [`AsyncUdpSocket`].  This queue takes care of the wakers needed by
    /// [`AsyncUdpSocket::poll_recv`].
    relay_datagram_recv_queue: Arc<RelayDatagramRecvQueue>,
    /// Channel on which to send datagrams via a relay server.
    relay_datagram_send_channel: RelayDatagramSendChannelSender,
    /// Counter for ordering of [`MagicSock::poll_recv`] polling order.
    poll_recv_counter: AtomicUsize,

    /// The DNS resolver to be used in this magicsock.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,

    /// Key for this node.
    secret_key: SecretKey,
    /// Encryption key for this node.
    secret_encryption_key: crypto_box::SecretKey,

    /// Cached version of the Ipv4 and Ipv6 addrs of the current connection.
    #[cfg(not(wasm_browser))]
    local_addrs: std::sync::RwLock<(SocketAddr, Option<SocketAddr>)>,

    /// Preferred port from `Options::port`; 0 means auto.
    port: AtomicU16,

    /// Close is in progress (or done)
    closing: AtomicBool,
    /// Close was called.
    closed: AtomicBool,
    /// If the last net_report report, reports IPv6 to be available.
    ipv6_reported: Arc<AtomicBool>,

    /// None (or zero nodes) means relay is disabled.
    relay_map: RelayMap,
    /// Nearest relay node ID; 0 means none/unknown.
    my_relay: Watchable<Option<RelayUrl>>,
    /// Tracks the networkmap node entity for each node discovery key.
    node_map: NodeMap,
    /// Tracks the mapped IP addresses
    ip_mapped_addrs: IpMappedAddresses,
    /// UDP IPv4 socket
    #[cfg(not(wasm_browser))]
    pconn4: UdpConn,
    /// UDP IPv6 socket
    #[cfg(not(wasm_browser))]
    pconn6: Option<UdpConn>,
    /// NetReport client
    net_reporter: net_report::Addr,
    /// The state for an active DiscoKey.
    disco_secrets: DiscoSecrets,

    /// UDP disco (ping) queue
    udp_disco_sender: mpsc::Sender<(SocketAddr, PublicKey, disco::Message)>,

    /// Optional discovery service
    discovery: Option<Box<dyn Discovery>>,

    /// Our discovered direct addresses.
    direct_addrs: DiscoveredDirectAddrs,

    /// List of CallMeMaybe disco messages that should be sent out after the next endpoint update
    /// completes
    pending_call_me_maybes: std::sync::Mutex<HashMap<PublicKey, RelayUrl>>,

    /// Indicates the direct addr update state.
    direct_addr_update_state: DirectAddrUpdateState,

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
}

impl MagicSock {
    /// Creates a magic [`MagicSock`] listening on [`Options::addr_v4`] and [`Options::addr_v6`].
    pub(crate) async fn spawn(opts: Options) -> Result<Handle> {
        Handle::new(opts).await
    }

    /// Returns the relay node we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any relay nodes.
    pub(crate) fn my_relay(&self) -> Option<RelayUrl> {
        self.my_relay.get()
    }

    /// Get the current proxy configuration.
    pub(crate) fn proxy_url(&self) -> Option<&Url> {
        self.proxy_url.as_ref()
    }

    /// Sets the relay node with the best latency.
    ///
    /// If we are not connected to any relay nodes, set this to `None`.
    fn set_my_relay(&self, my_relay: Option<RelayUrl>) -> Option<RelayUrl> {
        self.my_relay.set(my_relay).unwrap_or_else(|e| e)
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn public_key(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Get the cached version of the Ipv4 and Ipv6 addrs of the current connection.
    #[cfg(not(wasm_browser))]
    pub(crate) fn local_addr(&self) -> (SocketAddr, Option<SocketAddr>) {
        *self.local_addrs.read().expect("not poisoned")
    }

    /// Returns `true` if we have at least one candidate address where we can send packets to.
    pub(crate) fn has_send_address(&self, node_key: PublicKey) -> bool {
        self.remote_info(node_key)
            .map(|info| info.has_send_address())
            .unwrap_or(false)
    }

    /// Return the [`RemoteInfo`]s of all nodes in the node map.
    pub(crate) fn list_remote_infos(&self) -> Vec<RemoteInfo> {
        self.node_map.list_remote_infos(Instant::now())
    }

    /// Return the [`RemoteInfo`] for a single node in the node map.
    pub(crate) fn remote_info(&self, node_id: NodeId) -> Option<RemoteInfo> {
        self.node_map.remote_info(node_id)
    }

    /// Returns a [`Watcher`] for this socket's direct addresses.
    ///
    /// The [`MagicSock`] continuously monitors the direct addresses, the network addresses
    /// it might be able to be contacted on, for changes.  Whenever changes are detected
    /// this [`Watcher`] will yield a new list of addresses.
    ///
    /// Upon the first creation on the [`MagicSock`] it may not yet have completed a first
    /// direct addresses discovery, in this case the current item in this [`Watcher`] will be
    /// [`None`].  Once the first set of direct addresses are discovered the [`Watcher`] will
    /// store [`Some`] set of addresses.
    ///
    /// To get the current direct addresses, use [`Watcher::initialized`].
    pub(crate) fn direct_addresses(&self) -> Watcher<Option<BTreeSet<DirectAddr>>> {
        self.direct_addrs.addrs.watch()
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known using
    /// [`Watcher::initialized`].
    pub(crate) fn home_relay(&self) -> Watcher<Option<RelayUrl>> {
        self.my_relay.watch()
    }

    /// Returns a [`Watcher`] that reports the [`ConnectionType`] we have to the
    /// given `node_id`.
    ///
    /// This gets us a copy of the [`Watcher`] for the [`Watchable`] with a [`ConnectionType`]
    /// that the `NodeMap` stores for each `node_id`'s endpoint.
    ///
    /// # Errors
    ///
    /// Will return an error if there is no address information known about the
    /// given `node_id`.
    pub(crate) fn conn_type(&self, node_id: NodeId) -> Result<Watcher<ConnectionType>> {
        self.node_map.conn_type(node_id)
    }

    /// Returns the socket address which can be used by the QUIC layer to dial this node.
    pub(crate) fn get_mapping_addr(&self, node_id: NodeId) -> Option<NodeIdMappedAddr> {
        self.node_map.get_quic_mapped_addr_for_node_key(node_id)
    }

    /// Add addresses for a node to the magic socket's addresbook.
    #[instrument(skip_all, fields(me = %self.me))]
    pub fn add_node_addr(&self, mut addr: NodeAddr, source: node_map::Source) -> Result<()> {
        let mut pruned = 0;
        for my_addr in self.direct_addrs.sockaddrs() {
            if addr.direct_addresses.remove(&my_addr) {
                warn!( node_id=addr.node_id.fmt_short(), %my_addr, %source, "not adding our addr for node");
                pruned += 1;
            }
        }
        if !addr.is_empty() {
            self.node_map.add_node_addr(addr, source);
            Ok(())
        } else if pruned != 0 {
            Err(anyhow::anyhow!(
                "empty addressing info, {pruned} direct addresses have been pruned"
            ))
        } else {
            Err(anyhow::anyhow!("empty addressing info"))
        }
    }

    /// Stores a new set of direct addresses.
    ///
    /// If the direct addresses have changed from the previous set, they are published to
    /// discovery.
    pub(super) fn store_direct_addresses(&self, addrs: BTreeSet<DirectAddr>) {
        let updated = self.direct_addrs.update(addrs);
        if updated {
            self.node_map
                .on_direct_addr_discovered(self.direct_addrs.sockaddrs());
            self.publish_my_addr();
        }
    }

    /// Get a reference to the DNS resolver used in this [`MagicSock`].
    #[cfg(not(wasm_browser))]
    pub(crate) fn dns_resolver(&self) -> &DnsResolver {
        &self.dns_resolver
    }

    /// Reference to optional discovery service
    pub(crate) fn discovery(&self) -> Option<&dyn Discovery> {
        self.discovery.as_ref().map(Box::as_ref)
    }

    /// Call to notify the system of potential network changes.
    pub(crate) async fn network_change(&self) {
        self.actor_sender
            .send(ActorMessage::NetworkChange)
            .await
            .ok();
    }

    #[cfg(test)]
    async fn force_network_change(&self, is_major: bool) {
        self.actor_sender
            .send(ActorMessage::ForceNetworkChange(is_major))
            .await
            .ok();
    }

    #[cfg(not(wasm_browser))]
    #[cfg_attr(windows, allow(dead_code))]
    fn normalized_local_addr(&self) -> io::Result<SocketAddr> {
        let (v4, v6) = self.local_addr();
        let addr = if let Some(v6) = v6 { v6 } else { v4 };
        Ok(addr)
    }

    /// Implementation for AsyncUdpSocket::try_send
    #[instrument(skip_all)]
    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        inc_by!(MagicsockMetrics, send_data, transmit.contents.len() as _);

        if self.is_closed() {
            inc_by!(
                MagicsockMetrics,
                send_data_network_down,
                transmit.contents.len() as _
            );
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }
        match MappedAddr::from(transmit.destination) {
            MappedAddr::None(dest) => {
                error!(%dest, "Cannot convert to a mapped address, voiding transmit.");
                // Returning Ok here means we let QUIC timeout.
                // Returning an error would immediately fail a connection.
                // The philosophy of quinn-udp is that a UDP connection could
                // come back at any time or missing should be transient so chooses to let
                // these kind of errors time out.  See test_try_send_no_send_addr to try
                // this out.
                Ok(())
            }
            MappedAddr::NodeId(dest) => {
                trace!(
                    dst = %dest,
                    src = ?transmit.src_ip,
                    len = %transmit.contents.len(),
                    "sending",
                );

                // Get the node's relay address and best direct address, as well
                // as any pings that need to be sent for hole-punching purposes.
                let mut transmit = transmit.clone();
                match self
                    .node_map
                    .get_send_addrs(dest, self.ipv6_reported.load(Ordering::Relaxed))
                {
                    Some((node_id, udp_addr, relay_url, msgs)) => {
                        let mut pings_sent = false;
                        // If we have pings to send, we *have* to send them out first.
                        if !msgs.is_empty() {
                            if let Err(err) = self.try_send_ping_actions(msgs) {
                                warn!(
                                    node = %node_id.fmt_short(),
                                    "failed to handle ping actions: {err:#}",
                                );
                            }
                            pings_sent = true;
                        }

                        let mut udp_sent = false;
                        let mut udp_error = None;
                        let mut relay_sent = false;
                        let mut relay_error = None;

                        // send udp
                        #[cfg(not(wasm_browser))]
                        if let Some(addr) = udp_addr {
                            // rewrite target address
                            transmit.destination = addr;
                            match self.try_send_udp(addr, &transmit) {
                                Ok(()) => {
                                    trace!(node = %node_id.fmt_short(), dst = %addr,
                                   "sent transmit over UDP");
                                    udp_sent = true;
                                }
                                Err(err) => {
                                    // No need to print "WouldBlock" errors to the console
                                    if err.kind() != io::ErrorKind::WouldBlock {
                                        warn!(
                                            node = %node_id.fmt_short(),
                                            dst = %addr,
                                            "failed to send udp: {err:#}"
                                        );
                                    }
                                    udp_error = Some(err);
                                }
                            }
                        }

                        // send relay
                        if let Some(ref relay_url) = relay_url {
                            match self.try_send_relay(relay_url, node_id, split_packets(&transmit))
                            {
                                Ok(()) => {
                                    relay_sent = true;
                                }
                                Err(err) => {
                                    relay_error = Some(err);
                                }
                            }
                        }

                        #[cfg(not(wasm_browser))]
                        let udp_pending = udp_error
                            .as_ref()
                            .map(|err| err.kind() == io::ErrorKind::WouldBlock)
                            .unwrap_or_default();
                        #[cfg(wasm_browser)]
                        let udp_pending = false;
                        let relay_pending = relay_error
                            .as_ref()
                            .map(|err| err.kind() == io::ErrorKind::WouldBlock)
                            .unwrap_or_default();
                        if udp_pending && relay_pending {
                            // Handle backpressure.
                            return Err(io::Error::new(io::ErrorKind::WouldBlock, "pending"));
                        } else {
                            if relay_sent || udp_sent {
                                trace!(
                                    node = %node_id.fmt_short(),
                                    send_udp = ?udp_addr,
                                    send_relay = ?relay_url,
                                    "sent transmit",
                                );
                            } else if !pings_sent {
                                // Returning Ok here means we let QUIC handle a timeout for a lost
                                // packet, same would happen if we returned any errors.  The
                                // philosophy of quinn-udp is that a UDP connection could come back
                                // at any time so these errors should be treated as transient and
                                // are just timeouts.  Hence we opt for returning Ok.  See
                                // test_try_send_no_udp_addr_or_relay_url to explore this further.
                                debug!(
                                    node = %node_id.fmt_short(),
                                    "no UDP or relay paths available for node, voiding transmit",
                                );
                                // We log this as debug instead of error, because this is a
                                // situation that comes up under normal operation. If this were an
                                // error log, it would unnecessarily pollute logs.
                                // This situation happens essentially when `pings_sent` is false,
                                // `relay_url` is `None`, so `relay_sent` is false, and the UDP
                                // path is blocking, so `udp_sent` is false and `udp_pending` is
                                // true.
                                // Alternatively returning a WouldBlock error here would
                                // potentially needlessly block sending on the relay path for the
                                // next datagram.
                            }
                            return Ok(());
                        }
                    }
                    None => {
                        error!(%dest, "no NodeState for mapped address, dropping transmit");
                        // Returning Ok here means we let QUIC timeout.  Returning WouldBlock
                        // triggers a hot loop.  Returning an error would immediately fail a
                        // connection.  The philosophy of quinn-udp is that a UDP connection could
                        // come back at any time or missing should be transient so chooses to let
                        // these kind of errors time out.  See test_try_send_no_send_addr to try
                        // this out.
                        return Ok(());
                    }
                }
            }
            MappedAddr::Ip(dest) => {
                trace!(
                    dst = %dest,
                    src = ?transmit.src_ip,
                    len = %transmit.contents.len(),
                    "sending",
                );

                // Check if this is a known IpMappedAddr, and if so, send over UDP
                let mut transmit = transmit.clone();

                // Get the socket addr
                match self.ip_mapped_addrs.get_ip_addr(&dest) {
                    Some(addr) => {
                        // rewrite target address
                        transmit.destination = addr;
                        // send udp
                        match self.try_send_udp(addr, &transmit) {
                            Ok(()) => {
                                trace!(dst = %addr,
                               "sent IpMapped transmit over UDP");
                            }
                            Err(err) => {
                                // No need to print "WouldBlock" errors to the console
                                if err.kind() == io::ErrorKind::WouldBlock {
                                    return Err(io::Error::new(
                                        io::ErrorKind::WouldBlock,
                                        "pending",
                                    ));
                                } else {
                                    warn!(
                                        dst = %addr,
                                        "failed to send IpMapped message over udp: {err:#}"
                                    );
                                }
                            }
                        }
                        return Ok(());
                    }
                    None => {
                        error!(%dest, "unknown mapped address, dropping transmit");
                        // Returning Ok here means we let QUIC timeout.
                        // Returning an error would immediately fail a connection.
                        // The philosophy of quinn-udp is that a UDP connection could
                        // come back at any time or missing should be transient so chooses to let
                        // these kind of errors time out.  See test_try_send_no_send_addr to try
                        // this out.
                        return Ok(());
                    }
                }
            }
        }
    }

    fn try_send_relay(
        &self,
        url: &RelayUrl,
        node: NodeId,
        contents: RelayContents,
    ) -> io::Result<()> {
        trace!(
            node = %node.fmt_short(),
            relay_url = %url,
            count = contents.len(),
            len = contents.iter().map(|c| c.len()).sum::<usize>(),
            "send relay",
        );
        let msg = RelaySendItem {
            remote_node: node,
            url: url.clone(),
            datagrams: contents,
        };
        match self.relay_datagram_send_channel.try_send(msg) {
            Ok(_) => {
                trace!(node = %node.fmt_short(), relay_url = %url,
                       "send relay: message queued");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(node = %node.fmt_short(), relay_url = %url,
                      "send relay: message dropped, channel to actor is closed");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                ))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %node.fmt_short(), relay_url = %url,
                      "send relay: message dropped, channel to actor is full");
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "channel to actor is full",
                ))
            }
        }
    }

    #[cfg(not(wasm_browser))]
    fn try_send_udp(&self, addr: SocketAddr, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        let conn = self.conn_for_addr(addr)?;
        conn.try_send(transmit)?;
        let total_bytes: u64 = transmit.contents.len() as u64;
        if addr.is_ipv6() {
            inc_by!(MagicsockMetrics, send_ipv6, total_bytes);
        } else {
            inc_by!(MagicsockMetrics, send_ipv4, total_bytes);
        }
        Ok(())
    }

    #[cfg(not(wasm_browser))]
    fn conn_for_addr(&self, addr: SocketAddr) -> io::Result<&UdpConn> {
        let sock = match addr {
            SocketAddr::V4(_) => &self.pconn4,
            SocketAddr::V6(_) => self
                .pconn6
                .as_ref()
                .ok_or(io::Error::new(io::ErrorKind::Other, "no IPv6 connection"))?,
        };
        Ok(sock)
    }

    /// NOTE: Receiving on a [`Self::closed`] socket will return [`Poll::Pending`] indefinitely.
    #[instrument(skip_all)]
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        if self.is_closed() {
            return Poll::Pending;
        }

        // Three macros to help polling: they return if they get a result, execution
        // continues if they were Pending and we need to poll others (or finally return
        // Pending).
        #[cfg(not(wasm_browser))]
        macro_rules! poll_ipv4 {
            () => {
                match self.pconn4.poll_recv(cx, bufs, metas)? {
                    Poll::Pending | Poll::Ready(0) => {}
                    Poll::Ready(n) => {
                        self.process_udp_datagrams(true, &mut bufs[..n], &mut metas[..n]);
                        return Poll::Ready(Ok(n));
                    }
                }
            };
        }
        #[cfg(not(wasm_browser))]
        macro_rules! poll_ipv6 {
            () => {
                if let Some(ref pconn) = self.pconn6 {
                    match pconn.poll_recv(cx, bufs, metas)? {
                        Poll::Pending | Poll::Ready(0) => {}
                        Poll::Ready(n) => {
                            self.process_udp_datagrams(false, &mut bufs[..n], &mut metas[..n]);
                            return Poll::Ready(Ok(n));
                        }
                    }
                }
            };
        }
        macro_rules! poll_relay {
            () => {
                match self.poll_recv_relay(cx, bufs, metas) {
                    Poll::Pending => {}
                    Poll::Ready(n) => return Poll::Ready(n),
                }
            };
        }

        #[cfg(not(wasm_browser))]
        let counter = self.poll_recv_counter.fetch_add(1, Ordering::Relaxed);
        #[cfg(not(wasm_browser))]
        match counter % 3 {
            0 => {
                // order of polling: UDPv4, UDPv6, relay
                poll_ipv4!();
                poll_ipv6!();
                poll_relay!();
                Poll::Pending
            }
            1 => {
                // order of polling: UDPv6, relay, UDPv4
                poll_ipv6!();
                poll_relay!();
                poll_ipv4!();
                Poll::Pending
            }
            _ => {
                // order of polling: relay, UDPv4, UDPv6
                poll_relay!();
                poll_ipv4!();
                poll_ipv6!();
                Poll::Pending
            }
        }
        #[cfg(wasm_browser)]
        {
            poll_relay!();
            Poll::Pending
        }
    }

    /// Process datagrams received from UDP sockets.
    ///
    /// All the `bufs` and `metas` should have initialized packets in them.
    ///
    /// This fixes up the datagrams to use the correct [`NodeIdMappedAddr`] and extracts DISCO
    /// packets, processing them inside the magic socket.
    #[cfg(not(wasm_browser))]
    fn process_udp_datagrams(
        &self,
        from_ipv4: bool,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");

        // Adding the IP address we received something on results in Quinn using this
        // address on the send path to send from.  However we let Quinn use a
        // NodeIdMappedAddress, not a real address.  So we used to substitute our bind address
        // here so that Quinn would send on the right address.  But that would sometimes
        // result in the wrong address family and Windows trips up on that.
        //
        // What should be done is that this dst_ip from the RecvMeta is stored in the
        // NodeState/PathState.  Then on the send path it should be retrieved from the
        // NodeState/PathSate together with the send address and substituted at send time.
        // This is relevant for IPv6 link-local addresses where the OS otherwise does not
        // know which intervace to send from.
        #[cfg(not(windows))]
        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());
        // Reasoning for this here:
        // https://github.com/n0-computer/iroh/pull/2595#issuecomment-2290947319
        #[cfg(windows)]
        let dst_ip = None;

        let mut quic_packets_total = 0;

        for (meta, buf) in metas.iter_mut().zip(bufs.iter_mut()) {
            let mut buf_contains_quic_datagrams = false;
            let mut quic_datagram_count = 0;
            if meta.len > meta.stride {
                trace!(%meta.len, %meta.stride, "GRO datagram received");
                inc!(MagicsockMetrics, recv_gro_datagrams);
            }

            // Chunk through the datagrams in this GRO payload to find disco and stun
            // packets and forward them to the actor
            for datagram in buf[..meta.len].chunks_mut(meta.stride) {
                if datagram.len() < meta.stride {
                    trace!(
                        len = %datagram.len(),
                        %meta.stride,
                        "Last GRO datagram smaller than stride",
                    );
                }

                // Detect DISCO and STUN datagrams and process them.  Overwrite the first
                // byte of those packets with zero to make Quinn ignore the packet.  This
                // relies on quinn::EndpointConfig::grease_quic_bit being set to `false`,
                // which we do in Endpoint::bind.
                if stun::is(datagram) {
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: stun packet");
                    let packet2 = Bytes::copy_from_slice(datagram);
                    self.net_reporter.receive_stun_packet(packet2, meta.addr);
                    datagram[0] = 0u8;
                } else if let Some((sender, sealed_box)) = disco::source_and_box(datagram) {
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: disco packet");
                    self.handle_disco_message(
                        sender,
                        sealed_box,
                        DiscoMessageSource::Udp(meta.addr),
                    );
                    datagram[0] = 0u8;
                } else {
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: quic packet");
                    if from_ipv4 {
                        inc_by!(MagicsockMetrics, recv_data_ipv4, datagram.len() as _);
                    } else {
                        inc_by!(MagicsockMetrics, recv_data_ipv6, datagram.len() as _);
                    }
                    quic_datagram_count += 1;
                    buf_contains_quic_datagrams = true;
                };
            }

            if buf_contains_quic_datagrams {
                // Update the NodeMap and remap RecvMeta to the NodeIdMappedAddr.
                match self.node_map.receive_udp(meta.addr) {
                    None => {
                        // Check if this address is mapped to an IpMappedAddr
                        if let Some(ip_mapped_addr) =
                            self.ip_mapped_addrs.get_mapped_addr(&meta.addr)
                        {
                            trace!(
                                src = ?meta.addr,
                                count = %quic_datagram_count,
                                len = meta.len,
                                "UDP recv QUIC address discovery packets",
                            );
                            quic_packets_total += quic_datagram_count;
                            meta.addr = ip_mapped_addr.socket_addr();
                        } else {
                            warn!(
                                src = ?meta.addr,
                                count = %quic_datagram_count,
                                len = meta.len,
                                "UDP recv quic packets: no node state found, skipping",
                            );
                            // If we have no node state for the from addr, set len to 0 to make
                            // quinn skip the buf completely.
                            meta.len = 0;
                        }
                    }
                    Some((node_id, quic_mapped_addr)) => {
                        trace!(
                            src = ?meta.addr,
                            node = %node_id.fmt_short(),
                            count = %quic_datagram_count,
                            len = meta.len,
                            "UDP recv quic packets",
                        );
                        quic_packets_total += quic_datagram_count;
                        meta.addr = quic_mapped_addr.socket_addr();
                    }
                }
            } else {
                // If all datagrams in this buf are DISCO or STUN, set len to zero to make
                // Quinn skip the buf completely.
                meta.len = 0;
            }
            // Normalize local_ip
            meta.dst_ip = dst_ip;
        }

        if quic_packets_total > 0 {
            inc_by!(MagicsockMetrics, recv_datagrams, quic_packets_total as _);
            trace!("UDP recv: {} packets", quic_packets_total);
        }
    }

    #[instrument(skip_all)]
    fn poll_recv_relay(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;
        'outer: for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
            if self.is_closed() {
                break;
            }

            // For each output buffer keep polling the datagrams from the relay until one is
            // a QUIC datagram to be placed into the output buffer.  Or the channel is empty.
            loop {
                let recv = match self.relay_datagram_recv_queue.poll_recv(cx) {
                    Poll::Ready(Ok(recv)) => recv,
                    Poll::Ready(Err(err)) => {
                        error!("relay_recv_channel closed: {err:#}");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "connection closed",
                        )));
                    }
                    Poll::Pending => {
                        break 'outer;
                    }
                };
                match self.process_relay_read_result(recv) {
                    None => {
                        // Received a DISCO or STUN datagram that was handled internally.
                        continue;
                    }
                    Some((node_id, meta, buf)) => {
                        inc_by!(MagicsockMetrics, recv_data_relay, buf.len() as _);
                        trace!(
                            src = %meta.addr,
                            node = %node_id.fmt_short(),
                            count = meta.len / meta.stride,
                            len = meta.len,
                            "recv quic packets from relay",
                        );
                        buf_out[..buf.len()].copy_from_slice(&buf);
                        *meta_out = meta;
                        num_msgs += 1;
                        break;
                    }
                }
            }
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs > 0 {
            inc_by!(MagicsockMetrics, recv_datagrams, num_msgs as _);
            Poll::Ready(Ok(num_msgs))
        } else {
            Poll::Pending
        }
    }

    /// Process datagrams received from the relay server into incoming Quinn datagrams.
    ///
    /// This will transform datagrams received from the relay server into Quinn datagrams to
    /// receive, adding the [`quinn_udp::RecvMeta`].
    ///
    /// If the incoming datagram is a DISCO packet it will be handled internally and `None`
    /// is returned.
    fn process_relay_read_result(
        &self,
        dm: RelayRecvDatagram,
    ) -> Option<(NodeId, quinn_udp::RecvMeta, Bytes)> {
        trace!("process_relay_read {} bytes", dm.buf.len());
        if dm.buf.is_empty() {
            warn!("received empty relay packet");
            return None;
        }

        if self.handle_relay_disco_message(&dm.buf, &dm.url, dm.src) {
            // DISCO messages are handled internally in the MagicSock, do not pass to Quinn.
            return None;
        }

        let quic_mapped_addr = self.node_map.receive_relay(&dm.url, dm.src);

        // Normalize local_ip
        #[cfg(not(any(windows, wasm_browser)))]
        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());
        // Reasoning for this here:
        // https://github.com/n0-computer/iroh/pull/2595#issuecomment-2290947319
        #[cfg(any(windows, wasm_browser))]
        let dst_ip = None;

        let meta = quinn_udp::RecvMeta {
            len: dm.buf.len(),
            stride: dm.buf.len(),
            addr: quic_mapped_addr.socket_addr(),
            dst_ip,
            ecn: None,
        };
        Some((dm.src, meta, dm.buf))
    }

    fn handle_relay_disco_message(
        &self,
        msg: &[u8],
        url: &RelayUrl,
        relay_node_src: PublicKey,
    ) -> bool {
        match disco::source_and_box(msg) {
            Some((source, sealed_box)) => {
                if relay_node_src != source {
                    // TODO: return here?
                    warn!("Received relay disco message from connection for {}, but with message from {}", relay_node_src.fmt_short(), source.fmt_short());
                }
                self.handle_disco_message(
                    source,
                    sealed_box,
                    DiscoMessageSource::Relay {
                        url: url.clone(),
                        key: relay_node_src,
                    },
                );
                true
            }
            None => false,
        }
    }

    /// Handles a discovery message.
    #[instrument("disco_in", skip_all, fields(node = %sender.fmt_short(), %src))]
    fn handle_disco_message(&self, sender: PublicKey, sealed_box: &[u8], src: DiscoMessageSource) {
        trace!("handle_disco_message start");
        if self.is_closed() {
            return;
        }

        // We're now reasonably sure we're expecting communication from
        // this node, do the heavy crypto lifting to see what they want.
        let dm = match self.disco_secrets.unseal_and_decode(
            &self.secret_encryption_key,
            sender,
            sealed_box.to_vec(),
        ) {
            Ok(dm) => dm,
            Err(DiscoBoxError::Open(err)) => {
                warn!(?err, "failed to open disco box");
                inc!(MagicsockMetrics, recv_disco_bad_key);
                return;
            }
            Err(DiscoBoxError::Parse(err)) => {
                // Couldn't parse it, but it was inside a correctly
                // signed box, so just ignore it, assuming it's from a
                // newer version of Tailscale that we don't
                // understand. Not even worth logging about, lest it
                // be too spammy for old clients.

                inc!(MagicsockMetrics, recv_disco_bad_parse);
                debug!(?err, "failed to parse disco message");
                return;
            }
        };

        if src.is_relay() {
            inc!(MagicsockMetrics, recv_disco_relay);
        } else {
            inc!(MagicsockMetrics, recv_disco_udp);
        }

        let span = trace_span!("handle_disco", ?dm);
        let _guard = span.enter();
        trace!("receive disco message");
        match dm {
            disco::Message::Ping(ping) => {
                inc!(MagicsockMetrics, recv_disco_ping);
                self.handle_ping(ping, sender, src);
            }
            disco::Message::Pong(pong) => {
                inc!(MagicsockMetrics, recv_disco_pong);
                self.node_map.handle_pong(sender, &src, pong);
            }
            disco::Message::CallMeMaybe(cm) => {
                inc!(MagicsockMetrics, recv_disco_call_me_maybe);
                match src {
                    DiscoMessageSource::Relay { url, .. } => {
                        event!(
                            target: "iroh::_events::call-me-maybe::recv",
                            Level::DEBUG,
                            remote_node = sender.fmt_short(),
                            via = ?url,
                            their_addrs = ?cm.my_numbers,
                        );
                    }
                    _ => {
                        warn!("call-me-maybe packets should only come via relay");
                        return;
                    }
                }
                let ping_actions = self.node_map.handle_call_me_maybe(sender, cm);
                for action in ping_actions {
                    match action {
                        PingAction::SendCallMeMaybe { .. } => {
                            warn!("Unexpected CallMeMaybe as response of handling a CallMeMaybe");
                        }
                        PingAction::SendPing(ping) => {
                            self.send_ping_queued(ping);
                        }
                    }
                }
            }
        }
        trace!("disco message handled");
    }

    /// Handle a ping message.
    fn handle_ping(&self, dm: disco::Ping, sender: NodeId, src: DiscoMessageSource) {
        // Insert the ping into the node map, and return whether a ping with this tx_id was already
        // received.
        let addr: SendAddr = src.clone().into();
        let handled = self.node_map.handle_ping(sender, addr.clone(), dm.tx_id);
        match handled.role {
            PingRole::Duplicate => {
                debug!(%src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: path already confirmed, skip");
                return;
            }
            PingRole::LikelyHeartbeat => {}
            PingRole::NewPath => {
                debug!(%src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: new path");
            }
            PingRole::Activate => {
                debug!(%src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: path active");
            }
        }

        // Send a pong.
        debug!(tx = %HEXLOWER.encode(&dm.tx_id), %addr, dstkey = %sender.fmt_short(),
               "sending pong");
        let pong = disco::Message::Pong(disco::Pong {
            tx_id: dm.tx_id,
            ping_observed_addr: addr.clone(),
        });
        event!(
            target: "iroh::_events::pong::sent",
            Level::DEBUG,
            remote_node = %sender.fmt_short(),
            dst = ?addr,
            txn = ?dm.tx_id,
        );

        if !self.send_disco_message_queued(addr.clone(), sender, pong) {
            warn!(%addr, "failed to queue pong");
        }

        if let Some(ping) = handled.needs_ping_back {
            debug!(
                %addr,
                dstkey = %sender.fmt_short(),
                "sending direct ping back",
            );
            self.send_ping_queued(ping);
        }
    }

    fn encode_disco_message(&self, dst_key: PublicKey, msg: &disco::Message) -> Bytes {
        self.disco_secrets.encode_and_seal(
            &self.secret_encryption_key,
            self.secret_key.public(),
            dst_key,
            msg,
        )
    }

    fn send_ping_queued(&self, ping: SendPing) {
        let SendPing {
            id,
            dst,
            dst_node,
            tx_id,
            purpose,
        } = ping;
        let msg = disco::Message::Ping(disco::Ping {
            tx_id,
            node_key: self.public_key(),
        });
        let sent = match dst {
            #[cfg(not(wasm_browser))]
            SendAddr::Udp(addr) => self
                .udp_disco_sender
                .try_send((addr, dst_node, msg))
                .is_ok(),
            #[cfg(wasm_browser)]
            SendAddr::Udp(_) => {
                // Ignoring sending pings over UDP. We don't have a UDP socket.
                return;
            }
            SendAddr::Relay(ref url) => self.send_disco_message_relay(url, dst_node, msg),
        };
        if sent {
            let msg_sender = self.actor_sender.clone();
            trace!(%dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "ping sent (queued)");
            self.node_map
                .notify_ping_sent(id, dst, tx_id, purpose, msg_sender);
        } else {
            warn!(dst = ?dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "failed to send ping: queues full");
        }
    }

    /// Tries to send the ping actions.
    ///
    /// Note that on failure the (remaining) ping actions are simply dropped.  That's bad!
    /// The Endpoint will think a full ping was done and not request a new full-ping for a
    /// while.  We should probably be buffering the pings.
    fn try_send_ping_actions(&self, msgs: Vec<PingAction>) -> io::Result<()> {
        for msg in msgs {
            // Abort sending as soon as we know we are shutting down.
            if self.is_closing() || self.is_closed() {
                return Ok(());
            }
            match msg {
                PingAction::SendCallMeMaybe {
                    ref relay_url,
                    dst_node,
                } => {
                    self.send_or_queue_call_me_maybe(relay_url, dst_node);
                }
                PingAction::SendPing(ping) => {
                    self.try_send_ping(ping)?;
                }
            }
        }
        Ok(())
    }

    /// Send a disco message. UDP messages will be queued.
    ///
    /// If `dst` is [`SendAddr::Relay`], the message will be pushed into the relay client channel.
    /// If `dst` is [`SendAddr::Udp`], the message will be pushed into the udp disco send channel.
    ///
    /// Returns true if the channel had capacity for the message, and false if the message was
    /// dropped.
    fn send_disco_message_queued(
        &self,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> bool {
        match dst {
            SendAddr::Udp(addr) => self.udp_disco_sender.try_send((addr, dst_key, msg)).is_ok(),
            SendAddr::Relay(ref url) => self.send_disco_message_relay(url, dst_key, msg),
        }
    }

    /// Send a disco message. UDP messages will be polled to send directly on the UDP socket.
    fn try_send_disco_message(
        &self,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> io::Result<()> {
        match dst {
            #[cfg(not(wasm_browser))]
            SendAddr::Udp(addr) => {
                self.try_send_disco_message_udp(addr, dst_key, &msg)?;
            }
            #[cfg(wasm_browser)]
            SendAddr::Udp(addr) => {
                error!(?addr, "Asked to send on UDP in browser code");
            }
            SendAddr::Relay(ref url) => {
                if !self.send_disco_message_relay(url, dst_key, msg) {
                    return Err(io::Error::new(io::ErrorKind::Other, "Relay channel full"));
                }
            }
        }
        Ok(())
    }

    fn send_disco_message_relay(&self, url: &RelayUrl, dst: NodeId, msg: disco::Message) -> bool {
        debug!(node = %dst.fmt_short(), %url, %msg, "send disco message (relay)");
        let pkt = self.encode_disco_message(dst, &msg);
        inc!(MagicsockMetrics, send_disco_relay);
        match self.try_send_relay(url, dst, smallvec![pkt]) {
            Ok(()) => {
                if let disco::Message::CallMeMaybe(CallMeMaybe { ref my_numbers }) = msg {
                    event!(
                        target: "iroh::_events::call-me-maybe::sent",
                        Level::DEBUG,
                        remote_node = %dst.fmt_short(),
                        via = ?url,
                        addrs = ?my_numbers,
                    );
                }
                inc!(MagicsockMetrics, sent_disco_relay);
                disco_message_sent(&msg);
                true
            }
            Err(_) => false,
        }
    }

    #[cfg(not(wasm_browser))]
    async fn send_disco_message_udp(
        &self,
        dst: SocketAddr,
        dst_node: NodeId,
        msg: &disco::Message,
    ) -> io::Result<()> {
        n0_future::future::poll_fn(move |cx| {
            loop {
                match self.try_send_disco_message_udp(dst, dst_node, msg) {
                    Ok(()) => return Poll::Ready(Ok(())),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        // This is the socket .try_send_disco_message_udp used.
                        let sock = self.conn_for_addr(dst)?;
                        match sock.as_socket_ref().poll_writable(cx) {
                            Poll::Ready(Ok(())) => continue,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    Err(err) => return Poll::Ready(Err(err)),
                }
            }
        })
        .await
    }

    #[cfg(not(wasm_browser))]
    fn try_send_disco_message_udp(
        &self,
        dst: SocketAddr,
        dst_node: NodeId,
        msg: &disco::Message,
    ) -> std::io::Result<()> {
        trace!(%dst, %msg, "send disco message (UDP)");
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }
        let pkt = self.encode_disco_message(dst_node, msg);
        // TODO: These metrics will be wrong with the poll impl
        // Also - do we need it? I'd say the `sent_disco_udp` below is enough.
        inc!(MagicsockMetrics, send_disco_udp);
        let transmit = quinn_udp::Transmit {
            destination: dst,
            contents: &pkt,
            ecn: None,
            segment_size: None,
            src_ip: None, // TODO
        };
        let sent = self.try_send_udp(dst, &transmit);
        match sent {
            Ok(()) => {
                trace!(%dst, node = %dst_node.fmt_short(), %msg, "sent disco message");
                inc!(MagicsockMetrics, sent_disco_udp);
                disco_message_sent(msg);
                Ok(())
            }
            Err(err) => {
                warn!(%dst, node = %dst_node.fmt_short(), ?msg, ?err,
                      "failed to send disco message");
                Err(err)
            }
        }
    }

    #[instrument(skip_all)]
    async fn handle_ping_actions(&mut self, msgs: Vec<PingAction>) {
        // TODO: This used to make sure that all ping actions are sent.  Though on the
        // poll_send/try_send path we also do fire-and-forget.  try_send_ping_actions()
        // really should store any unsent pings on the Inner and send them at the next
        // possible time.
        if let Err(err) = self.try_send_ping_actions(msgs) {
            warn!("Not all ping actions were sent: {err:#}");
        }
    }

    fn try_send_ping(&self, ping: SendPing) -> io::Result<()> {
        let SendPing {
            id,
            dst,
            dst_node,
            tx_id,
            purpose,
        } = ping;
        let msg = disco::Message::Ping(disco::Ping {
            tx_id,
            node_key: self.public_key(),
        });
        self.try_send_disco_message(dst.clone(), dst_node, msg)?;
        debug!(%dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "ping sent (polled)");
        let msg_sender = self.actor_sender.clone();
        self.node_map
            .notify_ping_sent(id, dst.clone(), tx_id, purpose, msg_sender);
        Ok(())
    }

    fn send_queued_call_me_maybes(&self) {
        let msg = self.direct_addrs.to_call_me_maybe_message();
        let msg = disco::Message::CallMeMaybe(msg);
        for (public_key, url) in self
            .pending_call_me_maybes
            .lock()
            .expect("poisoned")
            .drain()
        {
            if !self.send_disco_message_relay(&url, public_key, msg.clone()) {
                warn!(node = %public_key.fmt_short(), "relay channel full, dropping call-me-maybe");
            }
        }
    }

    /// Sends the call-me-maybe DISCO message, queuing if addresses are too stale.
    ///
    /// To send the call-me-maybe message, we need to know our current direct addresses.  If
    /// this information is too stale, the call-me-maybe is queued while a net_report run is
    /// scheduled.  Once this run finishes, the call-me-maybe will be sent.
    fn send_or_queue_call_me_maybe(&self, url: &RelayUrl, dst_node: NodeId) {
        match self.direct_addrs.fresh_enough() {
            Ok(()) => {
                let msg = self.direct_addrs.to_call_me_maybe_message();
                let msg = disco::Message::CallMeMaybe(msg);
                if !self.send_disco_message_relay(url, dst_node, msg) {
                    warn!(dstkey = %dst_node.fmt_short(), relayurl = %url,
                      "relay channel full, dropping call-me-maybe");
                } else {
                    debug!(dstkey = %dst_node.fmt_short(), relayurl = %url, "call-me-maybe sent");
                }
            }
            Err(last_refresh_ago) => {
                self.pending_call_me_maybes
                    .lock()
                    .expect("poisoned")
                    .insert(dst_node, url.clone());
                debug!(
                    ?last_refresh_ago,
                    "want call-me-maybe but direct addrs stale; queuing after restun",
                );
                self.re_stun("refresh-for-peering");
            }
        }
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    #[instrument(skip_all)]
    fn re_stun(&self, why: &'static str) {
        debug!("re_stun: {}", why);
        inc!(MagicsockMetrics, re_stun_calls);
        self.direct_addr_update_state.schedule_run(why);
    }

    /// Publishes our address to a discovery service, if configured.
    ///
    /// Called whenever our addresses or home relay node changes.
    fn publish_my_addr(&self) {
        if let Some(ref discovery) = self.discovery {
            let relay_url = self.my_relay();
            let direct_addrs = self.direct_addrs.sockaddrs();
            let data = NodeData::new(relay_url, direct_addrs);
            discovery.publish(&data);
        }
    }
}

#[derive(Clone, Debug)]
enum MappedAddr {
    NodeId(NodeIdMappedAddr),
    Ip(IpMappedAddr),
    None(SocketAddr),
}

impl From<SocketAddr> for MappedAddr {
    fn from(value: SocketAddr) -> Self {
        match value.ip() {
            IpAddr::V4(_) => MappedAddr::None(value),
            IpAddr::V6(addr) => {
                if let Ok(node_id_mapped_addr) = NodeIdMappedAddr::try_from(addr) {
                    MappedAddr::NodeId(node_id_mapped_addr)
                } else if let Ok(ip_mapped_addr) = IpMappedAddr::try_from(addr) {
                    MappedAddr::Ip(ip_mapped_addr)
                } else {
                    MappedAddr::None(value)
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
enum DiscoMessageSource {
    Udp(SocketAddr),
    Relay { url: RelayUrl, key: PublicKey },
}

impl Display for DiscoMessageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "Udp({addr})"),
            Self::Relay { ref url, key } => write!(f, "Relay({url}, {})", key.fmt_short()),
        }
    }
}

impl From<DiscoMessageSource> for SendAddr {
    fn from(value: DiscoMessageSource) -> Self {
        match value {
            DiscoMessageSource::Udp(addr) => SendAddr::Udp(addr),
            DiscoMessageSource::Relay { url, .. } => SendAddr::Relay(url),
        }
    }
}

impl From<&DiscoMessageSource> for SendAddr {
    fn from(value: &DiscoMessageSource) -> Self {
        match value {
            DiscoMessageSource::Udp(addr) => SendAddr::Udp(*addr),
            DiscoMessageSource::Relay { url, .. } => SendAddr::Relay(url.clone()),
        }
    }
}

impl DiscoMessageSource {
    fn is_relay(&self) -> bool {
        matches!(self, DiscoMessageSource::Relay { .. })
    }
}

/// Manages currently running direct addr discovery, aka net_report runs.
///
/// Invariants:
/// - only one direct addr update must be running at a time
/// - if an update is scheduled while another one is running, remember that
///   and start a new one when the current one has finished
#[derive(Debug)]
struct DirectAddrUpdateState {
    /// If running, set to the reason for the currently the update.
    running: sync::watch::Sender<Option<&'static str>>,
    /// If set, start a new update as soon as the current one is finished.
    want_update: std::sync::Mutex<Option<&'static str>>,
}

impl DirectAddrUpdateState {
    fn new() -> Self {
        let (running, _) = sync::watch::channel(None);
        DirectAddrUpdateState {
            running,
            want_update: Default::default(),
        }
    }

    /// Schedules a new run, either starting it immediately if none is running or
    /// scheduling it for later.
    fn schedule_run(&self, why: &'static str) {
        if self.is_running() {
            let _ = self.want_update.lock().expect("poisoned").insert(why);
        } else {
            self.run(why);
        }
    }

    /// Returns `true` if an update is currently in progress.
    fn is_running(&self) -> bool {
        self.running.borrow().is_some()
    }

    /// Trigger a new run.
    fn run(&self, why: &'static str) {
        self.running.send(Some(why)).ok();
    }

    /// Clears the current running state.
    fn finish_run(&self) {
        self.running.send(None).ok();
    }

    /// Returns the next update, if one is set.
    fn next_update(&self) -> Option<&'static str> {
        self.want_update.lock().expect("poisoned").take()
    }
}

impl Handle {
    /// Creates a magic [`MagicSock`] listening on [`Options::addr_v4`] and [`Options::addr_v6`].
    async fn new(opts: Options) -> Result<Self> {
        let me = opts.secret_key.public().fmt_short();

        Self::with_name(me, opts)
            .instrument(error_span!("magicsock"))
            .await
    }

    async fn with_name(me: String, opts: Options) -> Result<Self> {
        #[cfg(not(wasm_browser))]
        let port_mapper = portmapper::Client::default();

        let Options {
            addr_v4,
            addr_v6,
            secret_key,
            relay_map,
            node_map,
            discovery,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection,
        } = opts;

        #[cfg(not(wasm_browser))]
        let (pconn4, pconn6) = bind(addr_v4, addr_v6)?;
        #[cfg(not(wasm_browser))]
        let port = pconn4.port();
        #[cfg(wasm_browser)]
        let port = 0;

        // NOTE: we can end up with a zero port if `std::net::UdpSocket::socket_addr` fails
        #[cfg(not(wasm_browser))]
        match port.try_into() {
            Ok(non_zero_port) => {
                port_mapper.update_local_port(non_zero_port);
            }
            Err(_zero_port) => debug!("Skipping port mapping with zero local port"),
        }
        #[cfg(not(wasm_browser))]
        let ipv4_addr = pconn4.local_addr()?;
        #[cfg(not(wasm_browser))]
        let ipv6_addr = pconn6.as_ref().and_then(|c| c.local_addr().ok());

        #[cfg(not(wasm_browser))]
        let ip_mapped_addrs = IpMappedAddresses::default();

        let net_reporter = net_report::Client::new(
            #[cfg(not(wasm_browser))]
            Some(port_mapper.clone()),
            #[cfg(not(wasm_browser))]
            dns_resolver.clone(),
            #[cfg(not(wasm_browser))]
            Some(ip_mapped_addrs.clone()),
        )?;

        #[cfg(not(wasm_browser))]
        let pconn4_sock = pconn4.as_socket();
        #[cfg(not(wasm_browser))]
        let pconn6_sock = pconn6.as_ref().map(|p| p.as_socket());

        let (actor_sender, actor_receiver) = mpsc::channel(256);
        let (relay_actor_sender, relay_actor_receiver) = mpsc::channel(256);
        let (relay_datagram_send_tx, relay_datagram_send_rx) = relay_datagram_send_channel();
        let relay_datagram_recv_queue = Arc::new(RelayDatagramRecvQueue::new());
        let (udp_disco_sender, mut udp_disco_receiver) = mpsc::channel(256);

        // load the node data
        let node_map = node_map.unwrap_or_default();
        #[cfg(any(test, feature = "test-utils"))]
        let node_map = NodeMap::load_from_vec(node_map, path_selection);
        #[cfg(not(any(test, feature = "test-utils")))]
        let node_map = NodeMap::load_from_vec(node_map);

        let secret_encryption_key = secret_ed_box(secret_key.secret());

        let inner = Arc::new(MagicSock {
            me,
            port: AtomicU16::new(port),
            secret_key,
            secret_encryption_key,
            proxy_url,
            #[cfg(not(wasm_browser))]
            local_addrs: std::sync::RwLock::new((ipv4_addr, ipv6_addr)),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            relay_datagram_recv_queue: relay_datagram_recv_queue.clone(),
            relay_datagram_send_channel: relay_datagram_send_tx,
            poll_recv_counter: AtomicUsize::new(0),
            actor_sender: actor_sender.clone(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            relay_map,
            my_relay: Default::default(),
            net_reporter: net_reporter.addr(),
            #[cfg(not(wasm_browser))]
            pconn4,
            #[cfg(not(wasm_browser))]
            pconn6,
            disco_secrets: DiscoSecrets::default(),
            node_map,
            ip_mapped_addrs,
            udp_disco_sender,
            discovery,
            direct_addrs: Default::default(),
            pending_call_me_maybes: Default::default(),
            direct_addr_update_state: DirectAddrUpdateState::new(),
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
        });

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
            inner.clone(),
            #[cfg(not(wasm_browser))]
            Arc::new(quinn::TokioRuntime),
            #[cfg(wasm_browser)]
            Arc::new(crate::web_runtime::WebRuntime),
        )?;

        let mut actor_tasks = JoinSet::default();

        let relay_actor = RelayActor::new(inner.clone(), relay_datagram_recv_queue);
        let relay_actor_cancel_token = relay_actor.cancel_token();
        actor_tasks.spawn(
            async move {
                relay_actor
                    .run(relay_actor_receiver, relay_datagram_send_rx)
                    .await;
            }
            .instrument(info_span!("relay-actor")),
        );

        #[cfg(not(wasm_browser))]
        {
            actor_tasks.spawn({
                let inner = inner.clone();
                async move {
                    while let Some((dst, dst_key, msg)) = udp_disco_receiver.recv().await {
                        if let Err(err) = inner.send_disco_message_udp(dst, dst_key, &msg).await {
                            warn!(%dst, node = %dst_key.fmt_short(), ?err, "failed to send disco message (UDP)");
                        }
                    }
                }
            });
        }

        let inner2 = inner.clone();
        #[cfg(not(wasm_browser))]
        let network_monitor = netmon::Monitor::new().await?;
        let qad_endpoint = endpoint.clone();

        // create a client config for the endpoint to use for QUIC address discovery
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let client_config = rustls::client::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports these")
        .with_root_certificates(root_store)
        .with_no_client_auth();
        let quic_config = Some(QuicConfig {
            ep: qad_endpoint,
            client_config,
            ipv4: true,
            ipv6: pconn6_sock.is_some(),
        });
        #[cfg(not(wasm_browser))]
        let net_report_config = net_report::Options::default()
            .stun_v4(Some(pconn4_sock.clone()))
            .stun_v6(pconn6_sock.clone())
            .quic_config(quic_config);
        #[cfg(wasm_browser)]
        let net_report_config = net_report::Options::default();

        actor_tasks.spawn(
            async move {
                let actor = Actor {
                    msg_receiver: actor_receiver,
                    msg_sender: actor_sender,
                    relay_actor_sender,
                    relay_actor_cancel_token,
                    msock: inner2,
                    periodic_re_stun_timer: new_re_stun_timer(false),
                    net_info_last: None,
                    #[cfg(not(wasm_browser))]
                    port_mapper,
                    #[cfg(not(wasm_browser))]
                    pconn4: pconn4_sock,
                    #[cfg(not(wasm_browser))]
                    pconn6: pconn6_sock,
                    no_v4_send: false,
                    net_reporter,
                    #[cfg(not(wasm_browser))]
                    network_monitor,
                    net_report_config,
                };

                if let Err(err) = actor.run().await {
                    warn!("relay handler errored: {:?}", err);
                }
            }
            .instrument(info_span!("actor")),
        );

        let c = Handle {
            msock: inner,
            actor_tasks: Arc::new(Mutex::new(actor_tasks)),
            endpoint,
        };

        Ok(c)
    }

    /// The underlying [`quinn::Endpoint`]
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.
    /// Polling the socket ([`AsyncUdpSocket::poll_recv`]) will return [`Poll::Pending`]
    /// indefinitely after this call.
    #[instrument(skip_all, fields(me = %self.msock.me))]
    pub(crate) async fn close(&self) {
        trace!("magicsock closing...");
        // Initiate closing all connections, and refuse future connections.
        self.endpoint.close(0u16.into(), b"");

        // In the history of this code, this call had been
        // - removed: https://github.com/n0-computer/iroh/pull/1753
        // - then added back in: https://github.com/n0-computer/iroh/pull/2227/files#diff-ba27e40e2986a3919b20f6b412ad4fe63154af648610ea5d9ed0b5d5b0e2d780R573
        // - then removed again: https://github.com/n0-computer/iroh/pull/3165
        // and finally added back in together with this comment.
        // So before removing this call, please consider carefully.
        // Among other things, this call tries its best to make sure that any queued close frames
        // (e.g. via the call to `endpoint.close(...)` above), are flushed out to the sockets
        // *and acknowledged* (or time out with the "probe timeout" of usually 3 seconds).
        // This allows the other endpoints for these connections to be notified to release
        // their resources, or - depending on the protocol - that all data was received.
        // With the current quinn API, this is the only way to ensure protocol code can use
        // connection close codes, and close the endpoint properly.
        // If this call is skipped, then connections that protocols close just shortly before the
        // call to `Endpoint::close` will in most cases cause connection time-outs on remote ends.
        self.endpoint.wait_idle().await;

        if self.msock.is_closed() {
            return;
        }
        self.msock.closing.store(true, Ordering::Relaxed);
        // If this fails, then there's no receiver listening for shutdown messages,
        // so nothing to shut down anyways.
        self.msock
            .actor_sender
            .send(ActorMessage::Shutdown)
            .await
            .ok();
        self.msock.closed.store(true, Ordering::SeqCst);

        let mut tasks = self.actor_tasks.lock().await;

        // give the tasks a moment to shutdown cleanly
        let tasks_ref = &mut tasks;
        let shutdown_done = time::timeout(Duration::from_millis(100), async move {
            while let Some(task) = tasks_ref.join_next().await {
                if let Err(err) = task {
                    warn!("unexpected error in task shutdown: {:?}", err);
                }
            }
        })
        .await;
        if shutdown_done.is_ok() {
            warn!("tasks shutdown complete");
            // shutdown all tasks
            warn!("aborting remaining {}/3 tasks", tasks.len());
            tasks.shutdown().await;
        }
        trace!("magicsock closed");
    }
}

#[derive(Debug, Default)]
struct DiscoSecrets(std::sync::Mutex<HashMap<PublicKey, SharedSecret>>);

impl DiscoSecrets {
    fn get<F, T>(&self, secret: &crypto_box::SecretKey, node_id: PublicKey, cb: F) -> T
    where
        F: FnOnce(&mut SharedSecret) -> T,
    {
        let mut inner = self.0.lock().expect("poisoned");
        let x = inner.entry(node_id).or_insert_with(|| {
            let public_key = public_ed_box(&node_id.public());
            SharedSecret::new(secret, &public_key)
        });
        cb(x)
    }

    fn encode_and_seal(
        &self,
        this_secret_key: &crypto_box::SecretKey,
        this_node_id: NodeId,
        other_node_id: NodeId,
        msg: &disco::Message,
    ) -> Bytes {
        let mut seal = msg.as_bytes();
        self.get(this_secret_key, other_node_id, |secret| {
            secret.seal(&mut seal)
        });
        disco::encode_message(&this_node_id, seal).into()
    }
    fn unseal_and_decode(
        &self,
        secret: &crypto_box::SecretKey,
        node_id: PublicKey,
        mut sealed_box: Vec<u8>,
    ) -> Result<disco::Message, DiscoBoxError> {
        self.get(secret, node_id, |secret| secret.open(&mut sealed_box))?;
        disco::Message::from_bytes(&sealed_box).map_err(DiscoBoxError::Parse)
    }
}

#[derive(Debug, thiserror::Error)]
enum DiscoBoxError {
    #[error("Failed to open crypto box")]
    Open(#[from] DecryptionError),
    #[error("Failed to parse disco message")]
    Parse(anyhow::Error),
}

/// Creates a sender and receiver pair for sending datagrams to the [`RelayActor`].
///
/// These includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
fn relay_datagram_send_channel() -> (
    RelayDatagramSendChannelSender,
    RelayDatagramSendChannelReceiver,
) {
    let (sender, receiver) = mpsc::channel(256);
    let wakers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let tx = RelayDatagramSendChannelSender {
        sender,
        wakers: wakers.clone(),
    };
    let rx = RelayDatagramSendChannelReceiver { receiver, wakers };
    (tx, rx)
}

/// Sender to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
#[derive(Debug, Clone)]
struct RelayDatagramSendChannelSender {
    sender: mpsc::Sender<RelaySendItem>,
    wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
}

impl RelayDatagramSendChannelSender {
    fn try_send(
        &self,
        item: RelaySendItem,
    ) -> Result<(), mpsc::error::TrySendError<RelaySendItem>> {
        self.sender.try_send(item)
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.sender.capacity() {
            0 => {
                let mut wakers = self.wakers.lock().expect("poisoned");
                if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    wakers.push(cx.waker().clone());
                }
                drop(wakers);
                if self.sender.capacity() != 0 {
                    // We "risk" a spurious wake-up in this case, but rather that
                    // than potentially skipping a receive.
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            _ => Poll::Ready(Ok(())),
        }
    }
}

/// Receiver to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
#[derive(Debug)]
struct RelayDatagramSendChannelReceiver {
    receiver: mpsc::Receiver<RelaySendItem>,
    wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
}

impl RelayDatagramSendChannelReceiver {
    async fn recv(&mut self) -> Option<RelaySendItem> {
        let item = self.receiver.recv().await;
        let mut wakers = self.wakers.lock().expect("poisoned");
        wakers.drain(..).for_each(Waker::wake);
        item
    }
}

/// A queue holding [`RelayRecvDatagram`]s that can be polled in async
/// contexts, and wakes up tasks when something adds items using [`try_send`].
///
/// This is used to transfer relay datagrams between the [`RelayActor`]
/// and [`MagicSock`].
///
/// [`try_send`]: Self::try_send
/// [`RelayActor`]: crate::magicsock::RelayActor
/// [`MagicSock`]: crate::magicsock::MagicSock
#[derive(Debug)]
struct RelayDatagramRecvQueue {
    queue: ConcurrentQueue<RelayRecvDatagram>,
    waker: AtomicWaker,
}

impl RelayDatagramRecvQueue {
    /// Creates a new, empty queue with a fixed size bound of 512 items.
    fn new() -> Self {
        Self {
            queue: ConcurrentQueue::bounded(512),
            waker: AtomicWaker::new(),
        }
    }

    /// Sends an item into this queue and wakes a potential task
    /// that's registered its waker with a [`poll_recv`] call.
    ///
    /// [`poll_recv`]: Self::poll_recv
    fn try_send(
        &self,
        item: RelayRecvDatagram,
    ) -> Result<(), concurrent_queue::PushError<RelayRecvDatagram>> {
        self.queue.push(item).inspect(|_| {
            self.waker.wake();
        })
    }

    /// Polls for new items in the queue.
    ///
    /// Although this method is available from `&self`, it must not be
    /// polled concurrently between tasks.
    ///
    /// Calling this will replace the current waker used. So if another task
    /// waits for this, that task's waker will be replaced and it won't be
    /// woken up for new items.
    ///
    /// The reason this method is made available as `&self` is because
    /// the interface for quinn's [`AsyncUdpSocket::poll_recv`] requires us
    /// to be able to poll from `&self`.
    fn poll_recv(&self, cx: &mut Context) -> Poll<Result<RelayRecvDatagram>> {
        match self.queue.pop() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(concurrent_queue::PopError::Empty) => {
                self.waker.register(cx.waker());

                match self.queue.pop() {
                    Ok(value) => {
                        self.waker.take();
                        Poll::Ready(Ok(value))
                    }
                    Err(concurrent_queue::PopError::Empty) => Poll::Pending,
                    Err(concurrent_queue::PopError::Closed) => {
                        self.waker.take();
                        Poll::Ready(Err(anyhow!("Queue closed")))
                    }
                }
            }
            Err(concurrent_queue::PopError::Closed) => Poll::Ready(Err(anyhow!("Queue closed"))),
        }
    }
}

impl AsyncUdpSocket for MagicSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        // To do this properly the MagicSock would need a registry of pollers.  For each
        // node we would look up the poller or create one.  Then on each try_send we can
        // look up the correct poller and configure it to poll the paths it needs.
        //
        // Note however that the current quinn impl calls UdpPoller::poll_writable()
        // **before** it calls try_send(), as opposed to how it is documented.  That is a
        // problem as we would not yet know the path that needs to be polled.  To avoid such
        // ambiguity the API could be changed to a .poll_send(&self, cx: &mut Context,
        // io_poller: Pin<&mut dyn UdpPoller>, transmit: &Transmit) -> Poll<io::Result<()>>
        // instead of the existing .try_send() because then we would have control over this.
        //
        // Right now however we have one single poller behaving the same for each
        // connection.  It checks all paths and returns Poll::Ready as soon as any path is
        // ready.
        #[cfg(not(wasm_browser))]
        let ipv4_poller = self.pconn4.create_io_poller();
        #[cfg(not(wasm_browser))]
        let ipv6_poller = self.pconn6.as_ref().map(|sock| sock.create_io_poller());
        let relay_sender = self.relay_datagram_send_channel.clone();
        Box::pin(IoPoller {
            #[cfg(not(wasm_browser))]
            ipv4_poller,
            #[cfg(not(wasm_browser))]
            ipv6_poller,
            relay_sender,
        })
    }

    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
        self.try_send(transmit)
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.poll_recv(cx, bufs, metas)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        #[cfg(not(wasm_browser))]
        match &*self.local_addrs.read().expect("not poisoned") {
            (ipv4, None) => {
                // Pretend to be IPv6, because our QuinnMappedAddrs
                // need to be IPv6.
                let ip: IpAddr = match ipv4.ip() {
                    IpAddr::V4(ip) => ip.to_ipv6_mapped().into(),
                    IpAddr::V6(ip) => ip.into(),
                };
                Ok(SocketAddr::new(ip, ipv4.port()))
            }
            (_, Some(ipv6)) => Ok(*ipv6),
        }
        // Again, we need to pretend we're IPv6, because of our QuinnMappedAddrs.
        #[cfg(wasm_browser)]
        return Ok(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0));
    }

    #[cfg(not(wasm_browser))]
    fn max_transmit_segments(&self) -> usize {
        if let Some(pconn6) = self.pconn6.as_ref() {
            std::cmp::min(
                pconn6.max_transmit_segments(),
                self.pconn4.max_transmit_segments(),
            )
        } else {
            self.pconn4.max_transmit_segments()
        }
    }

    #[cfg(wasm_browser)]
    fn max_transmit_segments(&self) -> usize {
        1
    }

    #[cfg(not(wasm_browser))]
    fn max_receive_segments(&self) -> usize {
        if let Some(pconn6) = self.pconn6.as_ref() {
            // `max_receive_segments` controls the size of the `RecvMeta` buffer
            // that quinn creates. Having buffers slightly bigger than necessary
            // isn't terrible, and makes sure a single socket can read the maximum
            // amount with a single poll. We considered adding these numbers instead,
            // but we never get data from both sockets at the same time in `poll_recv`
            // and it's impossible and unnecessary to be refactored that way.
            std::cmp::max(
                pconn6.max_receive_segments(),
                self.pconn4.max_receive_segments(),
            )
        } else {
            self.pconn4.max_receive_segments()
        }
    }

    #[cfg(wasm_browser)]
    fn max_receive_segments(&self) -> usize {
        1
    }

    #[cfg(not(wasm_browser))]
    fn may_fragment(&self) -> bool {
        if let Some(pconn6) = self.pconn6.as_ref() {
            pconn6.may_fragment() || self.pconn4.may_fragment()
        } else {
            self.pconn4.may_fragment()
        }
    }

    #[cfg(wasm_browser)]
    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct IoPoller {
    #[cfg(not(wasm_browser))]
    ipv4_poller: Pin<Box<dyn quinn::UdpPoller>>,
    #[cfg(not(wasm_browser))]
    ipv6_poller: Option<Pin<Box<dyn quinn::UdpPoller>>>,
    relay_sender: RelayDatagramSendChannelSender,
}

impl quinn::UdpPoller for IoPoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        // This version returns Ready as soon as any of them are ready.
        let this = &mut *self;
        #[cfg(not(wasm_browser))]
        match this.ipv4_poller.as_mut().poll_writable(cx) {
            Poll::Ready(_) => return Poll::Ready(Ok(())),
            Poll::Pending => (),
        }
        #[cfg(not(wasm_browser))]
        if let Some(ref mut ipv6_poller) = this.ipv6_poller {
            match ipv6_poller.as_mut().poll_writable(cx) {
                Poll::Ready(_) => return Poll::Ready(Ok(())),
                Poll::Pending => (),
            }
        }
        this.relay_sender.poll_writable(cx)
    }
}

#[derive(Debug)]
enum ActorMessage {
    Shutdown,
    EndpointPingExpired(usize, stun_rs::TransactionId),
    NetReport(Result<Option<Arc<net_report::Report>>>, &'static str),
    NetworkChange,
    #[cfg(test)]
    ForceNetworkChange(bool),
}

struct Actor {
    msock: Arc<MagicSock>,
    msg_receiver: mpsc::Receiver<ActorMessage>,
    msg_sender: mpsc::Sender<ActorMessage>,
    relay_actor_sender: mpsc::Sender<RelayActorMessage>,
    relay_actor_cancel_token: CancellationToken,
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<NetInfo>,

    // The underlying UDP sockets used to send/rcv packets.
    #[cfg(not(wasm_browser))]
    pconn4: Arc<UdpSocket>,
    #[cfg(not(wasm_browser))]
    pconn6: Option<Arc<UdpSocket>>,

    /// Configuration for net report
    net_report_config: net_report::Options,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    #[cfg(not(wasm_browser))]
    port_mapper: portmapper::Client,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: bool,

    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_reporter: net_report::Client,

    #[cfg(not(wasm_browser))]
    network_monitor: netmon::Monitor,
}

impl Actor {
    async fn run(mut self) -> Result<()> {
        // Setup network monitoring
        #[cfg(not(wasm_browser))]
        let (link_change_s, mut link_change_r) = mpsc::channel(8);
        #[cfg(not(wasm_browser))]
        let _token = self
            .network_monitor
            .subscribe(move |is_major| {
                let link_change_s = link_change_s.clone();
                async move {
                    link_change_s.send(is_major).await.ok();
                }
                .boxed()
            })
            .await?;

        // Let the the heartbeat only start a couple seconds later
        #[cfg(not(wasm_browser))]
        let mut direct_addr_heartbeat_timer = time::interval_at(
            time::Instant::now() + HEARTBEAT_INTERVAL,
            HEARTBEAT_INTERVAL,
        );
        let mut direct_addr_update_receiver =
            self.msock.direct_addr_update_state.running.subscribe();
        #[cfg(not(wasm_browser))]
        let mut portmap_watcher = self.port_mapper.watch_external_address();

        let mut discovery_events: BoxStream<DiscoveryItem> = Box::pin(n0_future::stream::empty());
        if let Some(d) = self.msock.discovery() {
            if let Some(events) = d.subscribe() {
                discovery_events = events;
            }
        }

        let mut receiver_closed = false;
        #[cfg_attr(wasm_browser, allow(unused_mut))]
        let mut portmap_watcher_closed = false;
        let mut link_change_closed = false;
        loop {
            inc!(Metrics, actor_tick_main);
            #[cfg(not(wasm_browser))]
            let portmap_watcher_changed = portmap_watcher.changed();
            #[cfg(wasm_browser)]
            let portmap_watcher_changed = futures_lite::future::pending();

            #[cfg(not(wasm_browser))]
            let direct_addr_heartbeat_timer_tick = direct_addr_heartbeat_timer.tick();
            #[cfg(wasm_browser)]
            let direct_addr_heartbeat_timer_tick = futures_lite::future::pending();

            #[cfg(not(wasm_browser))]
            let link_change_r_recv = link_change_r.recv();
            #[cfg(wasm_browser)]
            let link_change_r_recv = futures_lite::future::pending();

            tokio::select! {
                msg = self.msg_receiver.recv(), if !receiver_closed => {
                    let Some(msg) = msg else {
                        trace!("tick: magicsock receiver closed");
                        inc!(Metrics, actor_tick_other);

                        receiver_closed = true;
                        continue;
                    };

                    trace!(?msg, "tick: msg");
                    inc!(Metrics, actor_tick_msg);
                    if self.handle_actor_message(msg).await {
                        return Ok(());
                    }
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    inc!(Metrics, actor_tick_re_stun);
                    self.msock.re_stun("periodic");
                }
                change = portmap_watcher_changed, if !portmap_watcher_closed => {
                    #[cfg(not(wasm_browser))]
                    {
                        if change.is_err() {
                            trace!("tick: portmap watcher closed");
                            inc!(Metrics, actor_tick_other);

                            portmap_watcher_closed = true;
                            continue;
                        }

                        trace!("tick: portmap changed");
                        inc!(Metrics, actor_tick_portmap_changed);
                        let new_external_address = *portmap_watcher.borrow();
                        debug!("external address updated: {new_external_address:?}");
                        self.msock.re_stun("portmap_updated");
                    }
                    #[cfg(wasm_browser)]
                    let _unused_in_browsers = change;
                },
                _ = direct_addr_heartbeat_timer_tick => {
                    #[cfg(not(wasm_browser))]
                    {
                        trace!(
                            "tick: direct addr heartbeat {} direct addrs",
                            self.msock.node_map.node_count(),
                        );
                        inc!(Metrics, actor_tick_direct_addr_heartbeat);
                        // TODO: this might trigger too many packets at once, pace this

                        self.msock.node_map.prune_inactive();
                        let msgs = self.msock.node_map.nodes_stayin_alive();
                        self.handle_ping_actions(msgs).await;
                    }
                }
                _ = direct_addr_update_receiver.changed() => {
                    let reason = *direct_addr_update_receiver.borrow();
                    trace!("tick: direct addr update receiver {:?}", reason);
                    inc!(Metrics, actor_tick_direct_addr_update_receiver);
                    if let Some(reason) = reason {
                        self.refresh_direct_addrs(reason).await;
                    }
                }
                is_major = link_change_r_recv, if !link_change_closed => {
                    #[cfg(not(wasm_browser))]
                    {
                        let Some(is_major) = is_major else {
                            trace!("tick: link change receiver closed");
                            inc!(Metrics, actor_tick_other);

                            link_change_closed = true;
                            continue;
                        };

                        trace!("tick: link change {}", is_major);
                        inc!(Metrics, actor_link_change);
                        self.handle_network_change(is_major).await;
                    }
                    #[cfg(wasm_browser)]
                    let _unused_in_browsers = is_major;
                }
                // Even if `discovery_events` yields `None`, it could begin to yield
                // `Some` again in the future, so we don't want to disable this branch
                // forever like we do with the other branches that yield `Option`s
                Some(discovery_item) = discovery_events.next() => {
                    trace!("tick: discovery event, address discovered: {discovery_item:?}");
                    let provenance = discovery_item.provenance();
                    let node_addr = discovery_item.into_node_addr();
                    if let Err(e) = self.msock.add_node_addr(
                        node_addr.clone(),
                        Source::Discovery {
                            name: provenance.to_string()
                        }) {
                        warn!(?node_addr, "unable to add discovered node address to the node map: {e:?}");
                    }
                }
            }
        }
    }

    #[cfg(not(wasm_browser))]
    async fn handle_network_change(&mut self, is_major: bool) {
        debug!("link change detected: major? {}", is_major);

        if is_major {
            if let Err(err) = self.pconn4.rebind() {
                warn!("failed to rebind Udp IPv4 socket: {:?}", err);
            };
            if let Some(ref pconn6) = self.pconn6 {
                if let Err(err) = pconn6.rebind() {
                    warn!("failed to rebind Udp IPv6 socket: {:?}", err);
                };
            }
            self.msock.dns_resolver.clear_cache();
            self.msock.re_stun("link-change-major");
            self.close_stale_relay_connections().await;
            self.reset_endpoint_states();
        } else {
            self.msock.re_stun("link-change-minor");
        }
    }

    #[instrument(skip_all)]
    async fn handle_ping_actions(&mut self, msgs: Vec<PingAction>) {
        // TODO: This used to make sure that all ping actions are sent.  Though on the
        // poll_send/try_send path we also do fire-and-forget.  try_send_ping_actions()
        // really should store any unsent pings on the Inner and send them at the next
        // possible time.
        if let Err(err) = self.msock.try_send_ping_actions(msgs) {
            warn!("Not all ping actions were sent: {err:#}");
        }
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage) -> bool {
        match msg {
            ActorMessage::Shutdown => {
                debug!("shutting down");

                self.msock.node_map.notify_shutdown();
                #[cfg(not(wasm_browser))]
                self.port_mapper.deactivate();
                self.relay_actor_cancel_token.cancel();

                debug!("shutdown complete");
                return true;
            }
            ActorMessage::EndpointPingExpired(id, txid) => {
                self.msock.node_map.notify_ping_timeout(id, txid);
            }
            ActorMessage::NetReport(report, why) => {
                match report {
                    Ok(report) => {
                        self.handle_net_report_report(report).await;
                    }
                    Err(err) => {
                        warn!(
                            "failed to generate net_report report for: {}: {:?}",
                            why, err
                        );
                    }
                }
                self.finalize_direct_addrs_update(why);
            }
            ActorMessage::NetworkChange => {
                #[cfg(not(wasm_browser))]
                self.network_monitor.network_change().await.ok();
            }
            #[cfg(test)]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major).await;
            }
        }

        false
    }

    /// Refreshes knowledge about our direct addresses.
    ///
    /// In other words, this triggers a net_report run.
    ///
    /// Note that invoking this is managed by the [`DirectAddrUpdateState`] and this should
    /// never be invoked directly.  Some day this will be refactored to not allow this easy
    /// mistake to be made.
    #[instrument(level = "debug", skip_all)]
    async fn refresh_direct_addrs(&mut self, why: &'static str) {
        inc!(MagicsockMetrics, update_direct_addrs);

        debug!("starting direct addr update ({})", why);
        #[cfg(not(wasm_browser))]
        self.port_mapper.procure_mapping();
        self.update_net_info(why).await;
    }

    /// Updates the direct addresses of this magic socket.
    ///
    /// Updates the [`DiscoveredDirectAddrs`] of this [`MagicSock`] with the current set of
    /// direct addresses from:
    ///
    /// - The portmapper.
    /// - A net_report report.
    /// - The local interfaces IP addresses.
    #[cfg(not(wasm_browser))]
    fn update_direct_addresses(&mut self, net_report_report: Option<Arc<net_report::Report>>) {
        let portmap_watcher = self.port_mapper.watch_external_address();

        // We only want to have one DirectAddr for each SocketAddr we have.  So we store
        // this as a map of SocketAddr -> DirectAddrType.  At the end we will construct a
        // DirectAddr from each entry.
        let mut addrs: BTreeMap<SocketAddr, DirectAddrType> = BTreeMap::new();

        // First add PortMapper provided addresses.
        let maybe_port_mapped = *portmap_watcher.borrow();
        if let Some(portmap_ext) = maybe_port_mapped.map(SocketAddr::V4) {
            addrs
                .entry(portmap_ext)
                .or_insert(DirectAddrType::Portmapped);
            self.set_net_info_have_port_map();
        }

        // Next add STUN addresses from the net_report report.
        if let Some(net_report_report) = net_report_report {
            if let Some(global_v4) = net_report_report.global_v4 {
                addrs
                    .entry(global_v4.into())
                    .or_insert(DirectAddrType::Stun);

                // If they're behind a hard NAT and are using a fixed
                // port locally, assume they might've added a static
                // port mapping on their router to the same explicit
                // port that we are running with. Worst case it's an invalid candidate mapping.
                let port = self.msock.port.load(Ordering::Relaxed);
                if net_report_report
                    .mapping_varies_by_dest_ip
                    .unwrap_or_default()
                    && port != 0
                {
                    let mut addr = global_v4;
                    addr.set_port(port);
                    addrs
                        .entry(addr.into())
                        .or_insert(DirectAddrType::Stun4LocalPort);
                }
            }
            if let Some(global_v6) = net_report_report.global_v6 {
                addrs
                    .entry(global_v6.into())
                    .or_insert(DirectAddrType::Stun);
            }
        }

        let local_addr_v4 = self.pconn4.local_addr().ok();
        let local_addr_v6 = self.pconn6.as_ref().and_then(|c| c.local_addr().ok());

        let is_unspecified_v4 = local_addr_v4
            .map(|a| a.ip().is_unspecified())
            .unwrap_or(false);
        let is_unspecified_v6 = local_addr_v6
            .map(|a| a.ip().is_unspecified())
            .unwrap_or(false);

        let msock = self.msock.clone();

        // The following code can be slow, we do not want to block the caller since it would
        // block the actor loop.
        task::spawn(
            async move {
                // If a socket is bound to the unspecified address, create SocketAddrs for
                // each local IP address by pairing it with the port the socket is bound on.
                if is_unspecified_v4 || is_unspecified_v6 {
                    // Depending on the OS and network interfaces attached and their state
                    // enumerating the local interfaces can take a long time.  Especially
                    // Windows is very slow.
                    let LocalAddresses {
                        regular: mut ips,
                        loopback,
                    } = tokio::task::spawn_blocking(LocalAddresses::new)
                        .await
                        .expect("spawn panicked");
                    if ips.is_empty() && addrs.is_empty() {
                        // Include loopback addresses only if there are no other interfaces
                        // or public addresses, this allows testing offline.
                        ips = loopback;
                    }
                    for ip in ips {
                        let port_if_unspecified = match ip {
                            IpAddr::V4(_) if is_unspecified_v4 => {
                                local_addr_v4.map(|addr| addr.port())
                            }
                            IpAddr::V6(_) if is_unspecified_v6 => {
                                local_addr_v6.map(|addr| addr.port())
                            }
                            _ => None,
                        };
                        if let Some(port) = port_if_unspecified {
                            let addr = SocketAddr::new(ip, port);
                            addrs.entry(addr).or_insert(DirectAddrType::Local);
                        }
                    }
                }

                // If a socket is bound to a specific address, add it.
                if !is_unspecified_v4 {
                    if let Some(addr) = local_addr_v4 {
                        addrs.entry(addr).or_insert(DirectAddrType::Local);
                    }
                }
                if !is_unspecified_v6 {
                    if let Some(addr) = local_addr_v6 {
                        addrs.entry(addr).or_insert(DirectAddrType::Local);
                    }
                }

                // Finally create and store store all these direct addresses and send any
                // queued call-me-maybe messages.
                msock.store_direct_addresses(
                    addrs
                        .iter()
                        .map(|(addr, typ)| DirectAddr {
                            addr: *addr,
                            typ: *typ,
                        })
                        .collect(),
                );
                msock.send_queued_call_me_maybes();
            }
            .instrument(Span::current()),
        );
    }

    /// Called when a direct addr update is done, no matter if it was successful or not.
    fn finalize_direct_addrs_update(&mut self, why: &'static str) {
        let new_why = self.msock.direct_addr_update_state.next_update();
        if !self.msock.is_closed() {
            if let Some(new_why) = new_why {
                self.msock.direct_addr_update_state.run(new_why);
                return;
            }
            #[cfg(not(wasm_browser))]
            {
                self.periodic_re_stun_timer = new_re_stun_timer(true);
            }
        }

        self.msock.direct_addr_update_state.finish_run();
        debug!("direct addr update done ({})", why);
    }

    /// Updates `NetInfo.HavePortMap` to true.
    #[instrument(level = "debug", skip_all)]
    fn set_net_info_have_port_map(&mut self) {
        if let Some(ref mut net_info_last) = self.net_info_last {
            if net_info_last.have_port_map {
                // No change.
                return;
            }
            net_info_last.have_port_map = true;
            self.net_info_last = Some(net_info_last.clone());
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn call_net_info_callback(&mut self, ni: NetInfo) {
        if let Some(ref net_info_last) = self.net_info_last {
            if ni.basically_equal(net_info_last) {
                return;
            }
        }

        self.net_info_last = Some(ni);
    }

    /// Calls net_report.
    ///
    /// Note that invoking this is managed by [`DirectAddrUpdateState`] via
    /// [`Actor::refresh_direct_addrs`] and this should never be invoked directly.  Some day
    /// this will be refactored to not allow this easy mistake to be made.
    #[instrument(level = "debug", skip_all)]
    async fn update_net_info(&mut self, why: &'static str) {
        // Don't start a net report probe if we know
        // we are shutting down
        if self.msock.is_closing() || self.msock.is_closed() {
            debug!("skipping net_report, socket is shutting down");
            return;
        }
        if self.msock.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            self.msg_sender
                .send(ActorMessage::NetReport(Ok(None), why))
                .await
                .ok();
            return;
        }

        let relay_map = self.msock.relay_map.clone();
        let opts = self.net_report_config.clone();

        debug!("requesting net_report report");
        match self.net_reporter.get_report_channel(relay_map, opts).await {
            Ok(rx) => {
                let msg_sender = self.msg_sender.clone();
                task::spawn(async move {
                    let report = time::timeout(NET_REPORT_TIMEOUT, rx).await;
                    let report: anyhow::Result<_> = match report {
                        Ok(Ok(Ok(report))) => Ok(Some(report)),
                        Ok(Ok(Err(err))) => Err(err),
                        Ok(Err(_)) => Err(anyhow!("net_report report not received")),
                        Err(err) => Err(anyhow!("net_report report timeout: {:?}", err)),
                    };
                    msg_sender
                        .send(ActorMessage::NetReport(report, why))
                        .await
                        .ok();
                    // The receiver of the NetReport message will call
                    // .finalize_direct_addrs_update().
                });
            }
            Err(err) => {
                warn!("unable to start net_report generation: {:?}", err);
                self.finalize_direct_addrs_update(why);
            }
        }
    }

    async fn handle_net_report_report(&mut self, report: Option<Arc<net_report::Report>>) {
        if let Some(ref report) = report {
            self.msock
                .ipv6_reported
                .store(report.ipv6, Ordering::Relaxed);
            let r = &report;
            trace!(
                "setting no_v4_send {} -> {}",
                self.no_v4_send,
                !r.ipv4_can_send
            );
            self.no_v4_send = !r.ipv4_can_send;

            #[cfg(not(wasm_browser))]
            let have_port_map = self.port_mapper.watch_external_address().borrow().is_some();
            #[cfg(wasm_browser)]
            let have_port_map = false;

            let mut ni = NetInfo {
                relay_latency: Default::default(),
                mapping_varies_by_dest_ip: r.mapping_varies_by_dest_ip,
                hair_pinning: r.hair_pinning,
                #[cfg(not(wasm_browser))]
                portmap_probe: r.portmap_probe.clone(),
                have_port_map,
                working_ipv6: Some(r.ipv6),
                os_has_ipv6: Some(r.os_has_ipv6),
                working_udp: Some(r.udp),
                working_icmp_v4: r.icmpv4,
                working_icmp_v6: r.icmpv6,
                preferred_relay: r.preferred_relay.clone(),
            };
            for (rid, d) in r.relay_v4_latency.iter() {
                ni.relay_latency
                    .insert(format!("{rid}-v4"), d.as_secs_f64());
            }
            for (rid, d) in r.relay_v6_latency.iter() {
                ni.relay_latency
                    .insert(format!("{rid}-v6"), d.as_secs_f64());
            }

            if ni.preferred_relay.is_none() {
                // Perhaps UDP is blocked. Pick a deterministic but arbitrary one.
                ni.preferred_relay = self.pick_relay_fallback();
            }

            if !self.set_nearest_relay(ni.preferred_relay.clone()) {
                ni.preferred_relay = None;
            }

            // TODO: set link type
            self.call_net_info_callback(ni).await;
        }
        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(report);
    }

    fn set_nearest_relay(&mut self, relay_url: Option<RelayUrl>) -> bool {
        let my_relay = self.msock.my_relay();
        if relay_url == my_relay {
            // No change.
            return true;
        }
        let old_relay = self.msock.set_my_relay(relay_url.clone());

        if let Some(ref relay_url) = relay_url {
            inc!(MagicsockMetrics, relay_home_change);

            // On change, notify all currently connected relay servers and
            // start connecting to our home relay if we are not already.
            info!("home is now relay {}, was {:?}", relay_url, old_relay);
            self.msock.publish_my_addr();

            self.send_relay_actor(RelayActorMessage::SetHome {
                url: relay_url.clone(),
            });
        }

        true
    }

    /// Returns a deterministic relay node to connect to. This is only used if net_report
    /// couldn't find the nearest one, for instance, if UDP is blocked and thus STUN
    /// latency checks aren't working.
    ///
    /// If no the [`RelayMap`] is empty, returns `0`.
    fn pick_relay_fallback(&self) -> Option<RelayUrl> {
        // TODO: figure out which relay node most of our nodes are using,
        // and use that region as our fallback.
        //
        // If we already had selected something in the past and it has any
        // nodes, we want to stay on it. If there are no nodes at all,
        // stay on whatever relay we previously picked. If we need to pick
        // one and have no node info, pick a node randomly.
        //
        // We used to do the above for legacy clients, but never updated it for disco.

        let my_relay = self.msock.my_relay();
        if my_relay.is_some() {
            return my_relay;
        }

        let ids = self.msock.relay_map.urls().collect::<Vec<_>>();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        ids.choose(&mut rng).map(|c| (*c).clone())
    }

    /// Resets the preferred address for all nodes.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    #[instrument(skip_all, fields(me = %self.msock.me))]
    fn reset_endpoint_states(&mut self) {
        self.msock.node_map.reset_node_states()
    }

    /// Tells the relay actor to close stale relay connections.
    ///
    /// The relay connections who's local endpoints no longer exist after a network change
    /// will error out soon enough.  Closing them eagerly speeds this up however and allows
    /// re-establishing a relay connection faster.
    #[cfg(not(wasm_browser))]
    async fn close_stale_relay_connections(&self) {
        let ifs = interfaces::State::new().await;
        let local_ips = ifs
            .interfaces
            .values()
            .flat_map(|netif| netif.addrs())
            .map(|ipnet| ipnet.addr())
            .collect();
        self.send_relay_actor(RelayActorMessage::MaybeCloseRelaysOnRebind(local_ips));
    }

    fn send_relay_actor(&self, msg: RelayActorMessage) {
        match self.relay_actor_sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to relay actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for relay actor, channel is full");
            }
        }
    }
}

fn new_re_stun_timer(initial_delay: bool) -> time::Interval {
    // Pick a random duration between 20 and 26 seconds (just under 30s,
    // a common UDP NAT timeout on Linux,etc)
    let mut rng = rand::thread_rng();
    let d: Duration = rng.gen_range(Duration::from_secs(20)..=Duration::from_secs(26));
    if initial_delay {
        debug!("scheduling periodic_stun to run in {}s", d.as_secs());
        time::interval_at(time::Instant::now() + d, d)
    } else {
        debug!(
            "scheduling periodic_stun to run immediately and in {}s",
            d.as_secs()
        );
        time::interval(d)
    }
}

/// Initial connection setup.
#[cfg(not(wasm_browser))]
fn bind(
    addr_v4: Option<SocketAddrV4>,
    addr_v6: Option<SocketAddrV6>,
) -> Result<(UdpConn, Option<UdpConn>)> {
    let addr_v4 = addr_v4.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    let pconn4 = UdpConn::bind(SocketAddr::V4(addr_v4)).context("bind IPv4 failed")?;

    let ip4_port = pconn4.local_addr()?.port();
    let ip6_port = ip4_port.checked_add(1).unwrap_or(ip4_port - 1);
    let addr_v6 =
        addr_v6.unwrap_or_else(|| SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, ip6_port, 0, 0));
    let pconn6 = match UdpConn::bind(SocketAddr::V6(addr_v6)) {
        Ok(conn) => Some(conn),
        Err(err) => {
            info!("bind ignoring IPv6 bind failure: {:?}", err);
            None
        }
    };

    Ok((pconn4, pconn6))
}

/// The discovered direct addresses of this [`MagicSock`].
///
/// These are all the [`DirectAddr`]s that this [`MagicSock`] is aware of for itself.
/// They include all locally bound ones as well as those discovered by other mechanisms like
/// STUN.
#[derive(derive_more::Debug, Default, Clone)]
struct DiscoveredDirectAddrs {
    /// The last set of discovered direct addresses.
    addrs: Watchable<Option<BTreeSet<DirectAddr>>>,

    /// The last time the direct addresses were updated, even if there was no change.
    ///
    /// This is only ever None at startup.
    updated_at: Arc<RwLock<Option<Instant>>>,
}

impl DiscoveredDirectAddrs {
    /// Updates the direct addresses, returns `true` if they changed, `false` if not.
    fn update(&self, addrs: BTreeSet<DirectAddr>) -> bool {
        *self.updated_at.write().expect("poisoned") = Some(Instant::now());
        let updated = self.addrs.set(Some(addrs)).is_ok();
        if updated {
            event!(
                target: "iroh::_events::direct_addrs",
                Level::DEBUG,
                addrs = ?self.addrs.get(),
            );
        }
        updated
    }

    fn sockaddrs(&self) -> BTreeSet<SocketAddr> {
        self.addrs
            .get()
            .unwrap_or_default()
            .into_iter()
            .map(|da| da.addr)
            .collect()
    }

    /// Whether the direct addr information is considered "fresh".
    ///
    /// If not fresh you should probably update the direct addresses before using this info.
    ///
    /// Returns `Ok(())` if fresh enough and `Err(elapsed)` if not fresh enough.
    /// `elapsed` is the time elapsed since the direct addresses were last updated.
    ///
    /// If there is no direct address information `Err(Duration::ZERO)` is returned.
    fn fresh_enough(&self) -> Result<(), Duration> {
        match *self.updated_at.read().expect("poisoned") {
            None => Err(Duration::ZERO),
            Some(time) => {
                let elapsed = time.elapsed();
                if elapsed <= ENDPOINTS_FRESH_ENOUGH_DURATION {
                    Ok(())
                } else {
                    Err(elapsed)
                }
            }
        }
    }

    fn to_call_me_maybe_message(&self) -> disco::CallMeMaybe {
        let my_numbers = self
            .addrs
            .get()
            .unwrap_or_default()
            .into_iter()
            .map(|da| da.addr)
            .collect();
        disco::CallMeMaybe { my_numbers }
    }
}

/// Split a transmit containing a GSO payload into individual packets.
///
/// This allocates the data.
///
/// If the transmit has a segment size it contains multiple GSO packets.  It will be split
/// into multiple packets according to that segment size.  If it does not have a segment
/// size, the contents will be sent as a single packet.
// TODO: If quinn stayed on bytes this would probably be much cheaper, probably.  Need to
// figure out where they allocate the Vec.
fn split_packets(transmit: &quinn_udp::Transmit) -> RelayContents {
    let mut res = SmallVec::with_capacity(1);
    let contents = transmit.contents;
    if let Some(segment_size) = transmit.segment_size {
        for chunk in contents.chunks(segment_size) {
            res.push(Bytes::from(chunk.to_vec()));
        }
    } else {
        res.push(Bytes::from(contents.to_vec()));
    }
    res
}

/// The fake address used by the QUIC layer to address a node.
///
/// You can consider this as nothing more than a lookup key for a node the [`MagicSock`] knows
/// about.
///
/// [`MagicSock`] can reach a node by several real socket addresses, or maybe even via the relay
/// node.  The QUIC layer however needs to address a node by a stable [`SocketAddr`] so
/// that normal socket APIs can function.  Thus when a new node is introduced to a [`MagicSock`]
/// it is given a new fake address.  This is the type of that address.
///
/// It is but a newtype.  And in our QUIC-facing socket APIs like [`AsyncUdpSocket`] it
/// comes in as the inner [`Ipv6Addr`], in those interfaces we have to be careful to do
/// the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NodeIdMappedAddr(Ipv6Addr);

/// Can occur when converting a [`SocketAddr`] to an [`NodeIdMappedAddr`]
#[derive(Debug, thiserror::Error)]
#[error("Failed to convert")]
pub struct NodeIdMappedAddrError;

/// Counter to always generate unique addresses for [`NodeIdMappedAddr`].
static NODE_ID_ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

impl NodeIdMappedAddr {
    /// The Prefix/L of our Unique Local Addresses.
    const ADDR_PREFIXL: u8 = 0xfd;
    /// The Global ID used in our Unique Local Addresses.
    const ADDR_GLOBAL_ID: [u8; 5] = [21, 7, 10, 81, 11];
    /// The Subnet ID used in our Unique Local Addresses.
    const ADDR_SUBNET: [u8; 2] = [0; 2];

    /// Generates a globally unique fake UDP address.
    ///
    /// This generates and IPv6 Unique Local Address according to RFC 4193.
    pub(crate) fn generate() -> Self {
        let mut addr = [0u8; 16];
        addr[0] = Self::ADDR_PREFIXL;
        addr[1..6].copy_from_slice(&Self::ADDR_GLOBAL_ID);
        addr[6..8].copy_from_slice(&Self::ADDR_SUBNET);

        let counter = NODE_ID_ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(Ipv6Addr::from(addr))
    }

    /// Return the [`SocketAddr`] from the [`NodeIdMappedAddr`]
    pub(crate) fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), MAPPED_ADDR_PORT)
    }
}

impl TryFrom<Ipv6Addr> for NodeIdMappedAddr {
    type Error = NodeIdMappedAddrError;

    fn try_from(value: Ipv6Addr) -> std::result::Result<Self, Self::Error> {
        let octets = value.octets();
        if octets[0] == Self::ADDR_PREFIXL
            && octets[1..6] == Self::ADDR_GLOBAL_ID
            && octets[6..8] == Self::ADDR_SUBNET
        {
            return Ok(Self(value));
        }
        Err(NodeIdMappedAddrError)
    }
}

impl std::fmt::Display for NodeIdMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "NodeIdMappedAddr({})", self.0)
    }
}

fn disco_message_sent(msg: &disco::Message) {
    match msg {
        disco::Message::Ping(_) => {
            inc!(MagicsockMetrics, sent_disco_ping);
        }
        disco::Message::Pong(_) => {
            inc!(MagicsockMetrics, sent_disco_pong);
        }
        disco::Message::CallMeMaybe(_) => {
            inc!(MagicsockMetrics, sent_disco_call_me_maybe);
        }
    }
}

/// A *direct address* on which an iroh-node might be contactable.
///
/// Direct addresses are UDP socket addresses on which an iroh node could potentially be
/// contacted.  These can come from various sources depending on the network topology of the
/// iroh node, see [`DirectAddrType`] for the several kinds of sources.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectAddr {
    /// The address.
    pub addr: SocketAddr,
    /// The origin of this direct address.
    pub typ: DirectAddrType,
}

/// The type of direct address.
///
/// These are the various sources or origins from which an iroh node might have found a
/// possible [`DirectAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirectAddrType {
    /// Not yet determined..
    Unknown,
    /// A locally bound socket address.
    Local,
    /// Public internet address discovered via STUN.
    ///
    /// When possible an iroh node will perform STUN to discover which is the address
    /// from which it sends data on the public internet.  This can be different from locally
    /// bound addresses when the node is on a local network which performs NAT or similar.
    Stun,
    /// An address assigned by the router using port mapping.
    ///
    /// When possible an iroh node will request a port mapping from the local router to
    /// get a publicly routable direct address.
    Portmapped,
    /// Hard NAT: STUN'ed IPv4 address + local fixed port.
    ///
    /// It is possible to configure iroh to bound to a specific port and independently
    /// configure the router to forward this port to the iroh node.  This indicates a
    /// situation like this, which still uses STUN to discover the public address.
    Stun4LocalPort,
}

impl Display for DirectAddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectAddrType::Unknown => write!(f, "?"),
            DirectAddrType::Local => write!(f, "local"),
            DirectAddrType::Stun => write!(f, "stun"),
            DirectAddrType::Portmapped => write!(f, "portmap"),
            DirectAddrType::Stun4LocalPort => write!(f, "stun4localport"),
        }
    }
}

/// Contains information about the host's network state.
#[derive(Debug, Clone, PartialEq)]
struct NetInfo {
    /// Says whether the host's NAT mappings vary based on the destination IP.
    mapping_varies_by_dest_ip: Option<bool>,

    /// If their router does hairpinning. It reports true even if there's no NAT involved.
    hair_pinning: Option<bool>,

    /// Whether the host has IPv6 internet connectivity.
    working_ipv6: Option<bool>,

    /// Whether the OS supports IPv6 at all, regardless of whether IPv6 internet connectivity is available.
    os_has_ipv6: Option<bool>,

    /// Whether the host has UDP internet connectivity.
    working_udp: Option<bool>,

    /// Whether ICMPv4 works, `None` means not checked.
    working_icmp_v4: Option<bool>,

    /// Whether ICMPv6 works, `None` means not checked.
    working_icmp_v6: Option<bool>,

    /// Whether we have an existing portmap open (UPnP, PMP, or PCP).
    have_port_map: bool,

    /// Probe indicating the presence of port mapping protocols on the LAN.
    #[cfg(not(wasm_browser))]
    portmap_probe: Option<portmapper::ProbeOutput>,

    /// This node's preferred relay server for incoming traffic.
    ///
    /// The node might be be temporarily connected to multiple relay servers (to send to
    /// other nodes) but this is the relay on which you can always contact this node.  Also
    /// known as home relay.
    preferred_relay: Option<RelayUrl>,

    /// The fastest recent time to reach various relay STUN servers, in seconds.
    ///
    /// This should only be updated rarely, or when there's a
    /// material change, as any change here also gets uploaded to the control plane.
    relay_latency: BTreeMap<String, f64>,
}

impl NetInfo {
    /// Checks if this is probably still the same network as *other*.
    ///
    /// This tries to compare the network situation, without taking into account things
    /// expected to change a little like e.g. latency to the relay server.
    fn basically_equal(&self, other: &Self) -> bool {
        let eq_icmp_v4 = match (self.working_icmp_v4, other.working_icmp_v4) {
            (Some(slf), Some(other)) => slf == other,
            _ => true, // ignore for comparison if only one report had this info
        };
        let eq_icmp_v6 = match (self.working_icmp_v6, other.working_icmp_v6) {
            (Some(slf), Some(other)) => slf == other,
            _ => true, // ignore for comparison if only one report had this info
        };

        #[cfg(not(wasm_browser))]
        let probe_eq = self.portmap_probe == other.portmap_probe;
        #[cfg(wasm_browser)]
        let probe_eq = true;

        self.mapping_varies_by_dest_ip == other.mapping_varies_by_dest_ip
            && self.hair_pinning == other.hair_pinning
            && self.working_ipv6 == other.working_ipv6
            && self.os_has_ipv6 == other.os_has_ipv6
            && self.working_udp == other.working_udp
            && eq_icmp_v4
            && eq_icmp_v6
            && self.have_port_map == other.have_port_map
            && probe_eq
            && self.preferred_relay == other.preferred_relay
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use rand::RngCore;
    use tokio_util::task::AbortOnDropHandle;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        defaults::staging::{self, EU_RELAY_HOSTNAME},
        dns::DnsResolver,
        tls, Endpoint, RelayMode,
    };

    const ALPN: &[u8] = b"n0/test/1";

    impl MagicSock {
        #[track_caller]
        pub fn add_test_addr(&self, node_addr: NodeAddr) {
            self.add_node_addr(
                node_addr,
                Source::NamedApp {
                    name: "test".into(),
                },
            )
            .unwrap()
        }
    }

    /// Magicsock plus wrappers for sending packets
    #[derive(Clone)]
    struct MagicStack {
        secret_key: SecretKey,
        endpoint: Endpoint,
    }

    impl MagicStack {
        async fn new(relay_mode: RelayMode) -> Result<Self> {
            let secret_key = SecretKey::generate(rand::thread_rng());

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let endpoint = Endpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .relay_mode(relay_mode)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await?;

            Ok(Self {
                secret_key,
                endpoint,
            })
        }

        fn tracked_endpoints(&self) -> Vec<PublicKey> {
            self.endpoint
                .magic_sock()
                .list_remote_infos()
                .into_iter()
                .map(|ep| ep.node_id)
                .collect()
        }

        fn public(&self) -> PublicKey {
            self.secret_key.public()
        }
    }

    /// Monitors endpoint changes and plumbs things together.
    ///
    /// This is a way of connecting endpoints without a relay server.  Whenever the local
    /// endpoints of a magic endpoint change this address is added to the other magic
    /// sockets.  This function will await until the endpoints are connected the first time
    /// before returning.
    ///
    /// When the returned drop guard is dropped, the tasks doing this updating are stopped.
    #[instrument(skip_all)]
    async fn mesh_stacks(stacks: Vec<MagicStack>) -> Result<JoinSet<()>> {
        /// Registers endpoint addresses of a node to all other nodes.
        fn update_direct_addrs(
            stacks: &[MagicStack],
            my_idx: usize,
            new_addrs: BTreeSet<DirectAddr>,
        ) {
            let me = &stacks[my_idx];
            for (i, m) in stacks.iter().enumerate() {
                if i == my_idx {
                    continue;
                }

                let addr = NodeAddr {
                    node_id: me.public(),
                    relay_url: None,
                    direct_addresses: new_addrs.iter().map(|ep| ep.addr).collect(),
                };
                m.endpoint.magic_sock().add_test_addr(addr);
            }
        }

        // For each node, start a task which monitors its local endpoints and registers them
        // with the other nodes as local endpoints become known.
        let mut tasks = JoinSet::new();
        for (my_idx, m) in stacks.iter().enumerate() {
            let m = m.clone();
            let stacks = stacks.clone();
            tasks.spawn(async move {
                let me = m.endpoint.node_id().fmt_short();
                let mut stream = m.endpoint.direct_addresses().stream().filter_map(|i| i);
                while let Some(new_eps) = stream.next().await {
                    info!(%me, "conn{} endpoints update: {:?}", my_idx + 1, new_eps);
                    update_direct_addrs(&stacks, my_idx, new_eps);
                }
            });
        }

        // Wait for all nodes to be registered with each other.
        time::timeout(Duration::from_secs(10), async move {
            let all_node_ids: Vec<_> = stacks.iter().map(|ms| ms.endpoint.node_id()).collect();
            loop {
                let mut ready = Vec::with_capacity(stacks.len());
                for ms in stacks.iter() {
                    let endpoints = ms.tracked_endpoints();
                    let my_node_id = ms.endpoint.node_id();
                    let all_nodes_meshed = all_node_ids
                        .iter()
                        .filter(|node_id| **node_id != my_node_id)
                        .all(|node_id| endpoints.contains(node_id));
                    ready.push(all_nodes_meshed);
                }
                if ready.iter().all(|meshed| *meshed) {
                    break;
                }
                time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("failed to connect nodes")?;
        info!("all nodes meshed");
        Ok(tasks)
    }

    #[instrument(skip_all, fields(me = %ep.endpoint.node_id().fmt_short()))]
    async fn echo_receiver(ep: MagicStack, loss: ExpectedLoss) -> Result<()> {
        info!("accepting conn");
        let conn = ep.endpoint.accept().await.expect("no conn");

        info!("connecting");
        let conn = conn.await.context("[receiver] connecting")?;
        info!("accepting bi");
        let (mut send_bi, mut recv_bi) =
            conn.accept_bi().await.context("[receiver] accepting bi")?;

        info!("reading");
        let val = recv_bi
            .read_to_end(usize::MAX)
            .await
            .context("[receiver] reading to end")?;

        info!("replying");
        for chunk in val.chunks(12) {
            send_bi
                .write_all(chunk)
                .await
                .context("[receiver] sending chunk")?;
        }

        info!("finishing");
        send_bi.finish().context("[receiver] finishing")?;
        send_bi.stopped().await.context("[receiver] stopped")?;

        let stats = conn.stats();
        info!("stats: {:#?}", stats);
        // TODO: ensure panics in this function are reported ok
        if matches!(loss, ExpectedLoss::AlmostNone) {
            assert!(
                stats.path.lost_packets < 10,
                "[receiver] should not loose many packets",
            );
        }

        info!("close");
        conn.close(0u32.into(), b"done");
        info!("wait idle");
        ep.endpoint.endpoint().wait_idle().await;

        Ok(())
    }

    #[instrument(skip_all, fields(me = %ep.endpoint.node_id().fmt_short()))]
    async fn echo_sender(
        ep: MagicStack,
        dest_id: PublicKey,
        msg: &[u8],
        loss: ExpectedLoss,
    ) -> Result<()> {
        info!("connecting to {}", dest_id.fmt_short());
        let dest = NodeAddr::new(dest_id);
        let conn = ep
            .endpoint
            .connect(dest, ALPN)
            .await
            .context("[sender] connect")?;

        info!("opening bi");
        let (mut send_bi, mut recv_bi) = conn.open_bi().await.context("[sender] open bi")?;

        info!("writing message");
        send_bi.write_all(msg).await.context("[sender] write all")?;

        info!("finishing");
        send_bi.finish().context("[sender] finish")?;
        send_bi.stopped().await.context("[sender] stopped")?;

        info!("reading_to_end");
        let val = recv_bi.read_to_end(usize::MAX).await.context("[sender]")?;
        assert_eq!(
            val,
            msg,
            "[sender] expected {}, got {}",
            HEXLOWER.encode(msg),
            HEXLOWER.encode(&val)
        );

        let stats = conn.stats();
        info!("stats: {:#?}", stats);
        if matches!(loss, ExpectedLoss::AlmostNone) {
            assert!(
                stats.path.lost_packets < 10,
                "[sender] should not loose many packets",
            );
        }

        info!("close");
        conn.close(0u32.into(), b"done");
        info!("wait idle");
        ep.endpoint.endpoint().wait_idle().await;
        Ok(())
    }

    #[derive(Debug, Copy, Clone)]
    enum ExpectedLoss {
        AlmostNone,
        YeahSure,
    }

    /// Runs a roundtrip between the [`echo_sender`] and [`echo_receiver`].
    async fn run_roundtrip(
        sender: MagicStack,
        receiver: MagicStack,
        payload: &[u8],
        loss: ExpectedLoss,
    ) {
        let send_node_id = sender.endpoint.node_id();
        let recv_node_id = receiver.endpoint.node_id();
        info!("\nroundtrip: {send_node_id:#} -> {recv_node_id:#}");

        let receiver_task = tokio::spawn(echo_receiver(receiver, loss));
        let sender_res = echo_sender(sender, recv_node_id, payload, loss).await;
        let sender_is_err = match sender_res {
            Ok(()) => false,
            Err(err) => {
                eprintln!("[sender] Error:\n{err:#?}");
                true
            }
        };
        let receiver_is_err = match receiver_task.await {
            Ok(Ok(())) => false,
            Ok(Err(err)) => {
                eprintln!("[receiver] Error:\n{err:#?}");
                true
            }
            Err(joinerr) => {
                if joinerr.is_panic() {
                    std::panic::resume_unwind(joinerr.into_panic());
                } else {
                    eprintln!("[receiver] Error:\n{joinerr:#?}");
                }
                true
            }
        };
        if sender_is_err || receiver_is_err {
            panic!("Sender or receiver errored");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_quinn_magic() -> Result<()> {
        let m1 = MagicStack::new(RelayMode::Disabled).await?;
        let m2 = MagicStack::new(RelayMode::Disabled).await?;

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

        for i in 0..5 {
            info!("\n-- round {i}");
            run_roundtrip(
                m1.clone(),
                m2.clone(),
                b"hello m1",
                ExpectedLoss::AlmostNone,
            )
            .await;
            run_roundtrip(
                m2.clone(),
                m1.clone(),
                b"hello m2",
                ExpectedLoss::AlmostNone,
            )
            .await;

            info!("\n-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::AlmostNone).await;
            run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::AlmostNone).await;
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_regression_network_change_rebind_wakes_connection_driver(
    ) -> testresult::TestResult {
        let m1 = MagicStack::new(RelayMode::Disabled).await?;
        let m2 = MagicStack::new(RelayMode::Disabled).await?;

        println!("Net change");
        m1.endpoint.magic_sock().force_network_change(true).await;
        tokio::time::sleep(Duration::from_secs(1)).await; // wait for socket rebinding

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

        let _handle = AbortOnDropHandle::new(tokio::spawn({
            let endpoint = m2.endpoint.clone();
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    println!("Incoming first conn!");
                    let conn = incoming.await?;
                    conn.closed().await;
                }

                testresult::TestResult::Ok(())
            }
        }));

        println!("first conn!");
        let conn = m1
            .endpoint
            .connect(m2.endpoint.node_addr().await?, ALPN)
            .await?;
        println!("Closing first conn");
        conn.close(0u32.into(), b"bye lolz");
        conn.closed().await;
        println!("Closed first conn");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_network_change() -> Result<()> {
        time::timeout(
            Duration::from_secs(90),
            test_two_devices_roundtrip_network_change_impl(),
        )
        .await?
    }

    /// Same structure as `test_two_devices_roundtrip_quinn_magic`, but interrupts regularly
    /// with (simulated) network changes.
    async fn test_two_devices_roundtrip_network_change_impl() -> Result<()> {
        let m1 = MagicStack::new(RelayMode::Disabled).await?;
        let m2 = MagicStack::new(RelayMode::Disabled).await?;

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

        let offset = || {
            let delay = rand::thread_rng().gen_range(10..=500);
            Duration::from_millis(delay)
        };
        let rounds = 5;

        // Regular network changes to m1 only.
        let m1_network_change_guard = {
            let m1 = m1.clone();
            let task = tokio::spawn(async move {
                loop {
                    println!("[m1] network change");
                    m1.endpoint.magic_sock().force_network_change(true).await;
                    time::sleep(offset()).await;
                }
            });
            AbortOnDropHandle::new(task)
        };

        for i in 0..rounds {
            println!("-- [m1 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), b"hello m1", ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), b"hello m2", ExpectedLoss::YeahSure).await;

            println!("-- [m1 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await;
        }

        std::mem::drop(m1_network_change_guard);

        // Regular network changes to m2 only.
        let m2_network_change_guard = {
            let m2 = m2.clone();
            let task = tokio::spawn(async move {
                loop {
                    println!("[m2] network change");
                    m2.endpoint.magic_sock().force_network_change(true).await;
                    time::sleep(offset()).await;
                }
            });
            AbortOnDropHandle::new(task)
        };

        for i in 0..rounds {
            println!("-- [m2 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), b"hello m1", ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), b"hello m2", ExpectedLoss::YeahSure).await;

            println!("-- [m2 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await;
        }

        std::mem::drop(m2_network_change_guard);

        // Regular network changes to both m1 and m2 only.
        let m1_m2_network_change_guard = {
            let m1 = m1.clone();
            let m2 = m2.clone();
            let task = tokio::spawn(async move {
                println!("-- [m1] network change");
                m1.endpoint.magic_sock().force_network_change(true).await;
                println!("-- [m2] network change");
                m2.endpoint.magic_sock().force_network_change(true).await;
                time::sleep(offset()).await;
            });
            AbortOnDropHandle::new(task)
        };

        for i in 0..rounds {
            println!("-- [m1 & m2 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), b"hello m1", ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), b"hello m2", ExpectedLoss::YeahSure).await;

            println!("-- [m1 & m2 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await;
            run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await;
        }

        std::mem::drop(m1_m2_network_change_guard);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_setup_teardown() -> Result<()> {
        for i in 0..10 {
            println!("-- round {i}");
            println!("setting up magic stack");
            let m1 = MagicStack::new(RelayMode::Disabled).await?;
            let m2 = MagicStack::new(RelayMode::Disabled).await?;

            let _guard = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

            println!("closing endpoints");
            let msock1 = m1.endpoint.magic_sock();
            let msock2 = m2.endpoint.magic_sock();
            m1.endpoint.close().await;
            m2.endpoint.close().await;

            assert!(msock1.msock.is_closed());
            assert!(msock2.msock.is_closed());
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_two_devices_roundtrip_quinn_raw() -> Result<()> {
        let make_conn = |addr: SocketAddr| -> anyhow::Result<quinn::Endpoint> {
            let key = SecretKey::generate(rand::thread_rng());
            let conn = std::net::UdpSocket::bind(addr)?;

            let quic_server_config = tls::make_server_config(&key, vec![ALPN.to_vec()], false)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            server_config.transport_config(Arc::new(transport_config));
            let mut quic_ep = quinn::Endpoint::new(
                quinn::EndpointConfig::default(),
                Some(server_config),
                conn,
                Arc::new(quinn::TokioRuntime),
            )?;

            let quic_client_config =
                tls::make_client_config(&key, None, vec![ALPN.to_vec()], None, false)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            client_config.transport_config(Arc::new(transport_config));
            quic_ep.set_default_client_config(client_config);

            Ok(quic_ep)
        };

        let m1 = make_conn("127.0.0.1:0".parse().unwrap())?;
        let m2 = make_conn("127.0.0.1:0".parse().unwrap())?;

        // msg from  a -> b
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());

                let a_addr = a.local_addr()?;
                let b_addr = b.local_addr()?;

                println!("{}: {}, {}: {}", a_name, a_addr, b_name, b_addr);

                let b_task = tokio::task::spawn(async move {
                    println!("[{b_name}] accepting conn");
                    let conn = b.accept().await.expect("no conn");
                    println!("[{}] connecting", b_name);
                    let conn = conn
                        .await
                        .with_context(|| format!("[{b_name}] connecting"))?;
                    println!("[{}] accepting bi", b_name);
                    let (mut send_bi, mut recv_bi) = conn
                        .accept_bi()
                        .await
                        .with_context(|| format!("[{b_name}] accepting bi"))?;

                    println!("[{b_name}] reading");
                    let val = recv_bi
                        .read_to_end(usize::MAX)
                        .await
                        .with_context(|| format!("[{b_name}] reading to end"))?;
                    println!("[{b_name}] finishing");
                    send_bi
                        .finish()
                        .with_context(|| format!("[{b_name}] finishing"))?;
                    send_bi
                        .stopped()
                        .await
                        .with_context(|| format!("[b_name] stopped"))?;

                    println!("[{b_name}] close");
                    conn.close(0u32.into(), b"done");
                    println!("[{b_name}] closed");

                    Ok::<_, anyhow::Error>(val)
                });

                println!("[{a_name}] connecting to {b_addr}");
                let conn = a
                    .connect(b_addr, "localhost")?
                    .await
                    .with_context(|| format!("[{a_name}] connect"))?;

                println!("[{a_name}] opening bi");
                let (mut send_bi, mut recv_bi) = conn
                    .open_bi()
                    .await
                    .with_context(|| format!("[{a_name}] open bi"))?;
                println!("[{a_name}] writing message");
                send_bi
                    .write_all(&$msg[..])
                    .await
                    .with_context(|| format!("[{a_name}] write all"))?;

                println!("[{a_name}] finishing");
                send_bi
                    .finish()
                    .with_context(|| format!("[{a_name}] finish"))?;
                send_bi
                    .stopped()
                    .await
                    .with_context(|| format!("[{a_name}] stopped"))?;

                println!("[{a_name}] reading_to_end");
                let _ = recv_bi
                    .read_to_end(usize::MAX)
                    .await
                    .with_context(|| format!("[{a_name}] reading_to_end"))?;
                println!("[{a_name}] close");
                conn.close(0u32.into(), b"done");
                println!("[{a_name}] wait idle");
                a.wait_idle().await;

                drop(send_bi);

                // make sure the right values arrived
                println!("[{a_name}] waiting for channel");
                let val = b_task.await??;
                anyhow::ensure!(
                    val == $msg,
                    "expected {}, got {}",
                    HEXLOWER.encode(&$msg[..]),
                    HEXLOWER.encode(&val)
                );
            };
        }

        for i in 0..10 {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);
            roundtrip!(m2, m1, data);
        }

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_two_devices_roundtrip_quinn_rebinding_conn() -> Result<()> {
        fn make_conn(addr: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
            let key = SecretKey::generate(rand::thread_rng());
            let conn = UdpConn::bind(addr)?;

            let quic_server_config = tls::make_server_config(&key, vec![ALPN.to_vec()], false)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            server_config.transport_config(Arc::new(transport_config));
            let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                Arc::new(conn),
                Arc::new(quinn::TokioRuntime),
            )?;

            let quic_client_config =
                tls::make_client_config(&key, None, vec![ALPN.to_vec()], None, false)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            client_config.transport_config(Arc::new(transport_config));
            quic_ep.set_default_client_config(client_config);

            Ok(quic_ep)
        }

        let m1 = make_conn("127.0.0.1:7770".parse().unwrap())?;
        let m2 = make_conn("127.0.0.1:7771".parse().unwrap())?;

        // msg from  a -> b
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());

                let a_addr: SocketAddr = format!("127.0.0.1:{}", a.local_addr()?.port())
                    .parse()
                    .unwrap();
                let b_addr: SocketAddr = format!("127.0.0.1:{}", b.local_addr()?.port())
                    .parse()
                    .unwrap();

                println!("{}: {}, {}: {}", a_name, a_addr, b_name, b_addr);

                let b_task = tokio::task::spawn(async move {
                    println!("[{}] accepting conn", b_name);
                    let conn = b.accept().await.expect("no conn");
                    println!("[{}] connecting", b_name);
                    let conn = conn
                        .await
                        .with_context(|| format!("[{}] connecting", b_name))?;
                    println!("[{}] accepting bi", b_name);
                    let (mut send_bi, mut recv_bi) = conn
                        .accept_bi()
                        .await
                        .with_context(|| format!("[{}] accepting bi", b_name))?;

                    println!("[{}] reading", b_name);
                    let val = recv_bi
                        .read_to_end(usize::MAX)
                        .await
                        .with_context(|| format!("[{}] reading to end", b_name))?;
                    println!("[{}] finishing", b_name);
                    send_bi
                        .finish()
                        .with_context(|| format!("[{}] finishing", b_name))?;
                    send_bi
                        .stopped()
                        .await
                        .with_context(|| format!("[{b_name}] stopped"))?;

                    println!("[{}] close", b_name);
                    conn.close(0u32.into(), b"done");
                    println!("[{}] closed", b_name);

                    Ok::<_, anyhow::Error>(val)
                });

                println!("[{}] connecting to {}", a_name, b_addr);
                let conn = a
                    .connect(b_addr, "localhost")?
                    .await
                    .with_context(|| format!("[{}] connect", a_name))?;

                println!("[{}] opening bi", a_name);
                let (mut send_bi, mut recv_bi) = conn
                    .open_bi()
                    .await
                    .with_context(|| format!("[{}] open bi", a_name))?;
                println!("[{}] writing message", a_name);
                send_bi
                    .write_all(&$msg[..])
                    .await
                    .with_context(|| format!("[{}] write all", a_name))?;

                println!("[{}] finishing", a_name);
                send_bi
                    .finish()
                    .with_context(|| format!("[{}] finish", a_name))?;
                send_bi
                    .stopped()
                    .await
                    .with_context(|| format!("[{a_name}] stopped"))?;

                println!("[{}] reading_to_end", a_name);
                let _ = recv_bi
                    .read_to_end(usize::MAX)
                    .await
                    .with_context(|| format!("[{}]", a_name))?;
                println!("[{}] close", a_name);
                conn.close(0u32.into(), b"done");
                println!("[{}] wait idle", a_name);
                a.wait_idle().await;

                drop(send_bi);

                // make sure the right values arrived
                println!("[{}] waiting for channel", a_name);
                let val = b_task.await??;
                anyhow::ensure!(
                    val == $msg,
                    "expected {}, got {}",
                    HEXLOWER.encode(&$msg[..]),
                    HEXLOWER.encode(&val)
                );
            };
        }

        for i in 0..10 {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);
            roundtrip!(m2, m1, data);
        }

        Ok(())
    }

    #[test]
    fn test_split_packets() {
        fn mk_transmit(contents: &[u8], segment_size: Option<usize>) -> quinn_udp::Transmit<'_> {
            let destination = "127.0.0.1:0".parse().unwrap();
            quinn_udp::Transmit {
                destination,
                ecn: None,
                contents,
                segment_size,
                src_ip: None,
            }
        }
        fn mk_expected(parts: impl IntoIterator<Item = &'static str>) -> RelayContents {
            parts
                .into_iter()
                .map(|p| p.as_bytes().to_vec().into())
                .collect()
        }
        // no split
        assert_eq!(
            split_packets(&mk_transmit(b"hello", None)),
            mk_expected(["hello"])
        );
        // split without rest
        assert_eq!(
            split_packets(&mk_transmit(b"helloworld", Some(5))),
            mk_expected(["hello", "world"])
        );
        // split with rest and second transmit
        assert_eq!(
            split_packets(&mk_transmit(b"hello world", Some(5))),
            mk_expected(["hello", " worl", "d"]) // spellchecker:disable-line
        );
        // split that results in 1 packet
        assert_eq!(
            split_packets(&mk_transmit(b"hello world", Some(1000))),
            mk_expected(["hello world"])
        );
    }

    #[tokio::test]
    #[traced_test]
    async fn test_local_endpoints() {
        let ms = Handle::new(Default::default()).await.unwrap();

        // See if we can get endpoints.
        let eps0 = ms.direct_addresses().initialized().await.unwrap();
        println!("{eps0:?}");
        assert!(!eps0.is_empty());

        // Getting the endpoints again immediately should give the same results.
        let eps1 = ms.direct_addresses().initialized().await.unwrap();
        println!("{eps1:?}");
        assert_eq!(eps0, eps1);
    }

    #[tokio::test]
    async fn test_watch_home_relay() {
        // use an empty relay map to get full control of the changes during the test
        let ops = Options {
            relay_map: RelayMap::empty(),
            ..Default::default()
        };
        let msock = MagicSock::spawn(ops).await.unwrap();
        let mut relay_stream = msock.home_relay().stream().filter_map(|r| r);

        // no relay, nothing to report
        assert_eq!(
            n0_future::future::poll_once(relay_stream.next()).await,
            None
        );

        let url: RelayUrl = format!("https://{}", EU_RELAY_HOSTNAME).parse().unwrap();
        msock.set_my_relay(Some(url.clone()));

        assert_eq!(relay_stream.next().await, Some(url.clone()));

        // drop the stream and query it again, the result should be immediately available

        let mut relay_stream = msock.home_relay().stream().filter_map(|r| r);
        assert_eq!(
            n0_future::future::poll_once(relay_stream.next()).await,
            Some(Some(url))
        );
    }

    /// Creates a new [`quinn::Endpoint`] hooked up to a [`MagicSock`].
    ///
    /// This is without involving [`crate::endpoint::Endpoint`].  The socket will accept
    /// connections using [`ALPN`].
    ///
    /// Use [`magicsock_connect`] to establish connections.
    #[instrument(name = "ep", skip_all, fields(me = secret_key.public().fmt_short()))]
    async fn magicsock_ep(secret_key: SecretKey) -> anyhow::Result<Handle> {
        let server_config = crate::endpoint::make_server_config(
            &secret_key,
            vec![ALPN.to_vec()],
            Arc::new(quinn::TransportConfig::default()),
            true,
        )?;
        let dns_resolver = DnsResolver::new();
        let opts = Options {
            addr_v4: None,
            addr_v6: None,
            secret_key: secret_key.clone(),
            relay_map: RelayMap::empty(),
            node_map: None,
            discovery: None,
            dns_resolver,
            proxy_url: None,
            server_config,
            insecure_skip_relay_cert_verify: true,
            path_selection: PathSelection::default(),
        };
        let msock = MagicSock::spawn(opts).await?;
        Ok(msock)
    }

    /// Connects from `ep` returned by [`magicsock_ep`] to the `node_id`.
    ///
    /// Uses [`ALPN`], `node_id`, must match `addr`.
    #[instrument(name = "connect", skip_all, fields(me = ep_secret_key.public().fmt_short()))]
    async fn magicsock_connect(
        ep: &quinn::Endpoint,
        ep_secret_key: SecretKey,
        addr: NodeIdMappedAddr,
        node_id: NodeId,
    ) -> Result<quinn::Connection> {
        // Endpoint::connect sets this, do the same to have similar behaviour.
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

        magicsock_connect_with_transport_config(
            ep,
            ep_secret_key,
            addr,
            node_id,
            Arc::new(transport_config),
        )
        .await
    }

    /// Connects from `ep` returned by [`magicsock_ep`] to the `node_id`.
    ///
    /// This version allows customising the transport config.
    ///
    /// Uses [`ALPN`], `node_id`, must match `addr`.
    #[instrument(name = "connect", skip_all, fields(me = ep_secret_key.public().fmt_short()))]
    async fn magicsock_connect_with_transport_config(
        ep: &quinn::Endpoint,
        ep_secret_key: SecretKey,
        mapped_addr: NodeIdMappedAddr,
        node_id: NodeId,
        transport_config: Arc<quinn::TransportConfig>,
    ) -> Result<quinn::Connection> {
        let alpns = vec![ALPN.to_vec()];
        let quic_client_config =
            tls::make_client_config(&ep_secret_key, Some(node_id), alpns, None, true)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(transport_config);
        let connect = ep.connect_with(client_config, mapped_addr.socket_addr(), "localhost")?;
        let connection = connect.await?;
        Ok(connection)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_try_send_no_send_addr() {
        // Regression test: if there is no send_addr we should keep being able to use the
        // Endpoint.
        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let node_id_2 = secret_key_2.public();
        let secret_key_missing_node = SecretKey::from_bytes(&[255u8; 32]);
        let node_id_missing_node = secret_key_missing_node.public();

        let msock_1 = magicsock_ep(secret_key_1.clone()).await.unwrap();

        // Generate an address not present in the NodeMap.
        let bad_addr = NodeIdMappedAddr::generate();

        // 500ms is rather fast here.  Running this locally it should always be the correct
        // timeout.  If this is too slow however the test will not become flaky as we are
        // expecting the timeout, we might just get the timeout for the wrong reason.  But
        // this speeds up the test.
        let res = tokio::time::timeout(
            Duration::from_millis(500),
            magicsock_connect(
                msock_1.endpoint(),
                secret_key_1.clone(),
                bad_addr,
                node_id_missing_node,
            ),
        )
        .await;
        assert!(res.is_err(), "expecting timeout");

        // Now check we can still create another connection with this endpoint.
        let msock_2 = magicsock_ep(secret_key_2.clone()).await.unwrap();
        let ep_2 = msock_2.endpoint().clone();
        // This needs an accept task
        let accept_task = tokio::spawn({
            async fn accept(ep: quinn::Endpoint) -> Result<()> {
                let incoming = ep.accept().await.ok_or(anyhow!("no incoming"))?;
                let _conn = incoming.accept()?.await?;

                // Keep this connection alive for a while
                tokio::time::sleep(Duration::from_secs(10)).await;
                info!("accept finished");
                Ok(())
            }
            async move {
                if let Err(err) = accept(ep_2).await {
                    error!("{err:#}");
                }
            }
            .instrument(info_span!("ep2.accept, me = node_id_2.fmt_short()"))
        });
        let _accept_task = AbortOnDropHandle::new(accept_task);

        let node_addr_2 = NodeAddr {
            node_id: node_id_2,
            relay_url: None,
            direct_addresses: msock_2
                .direct_addresses()
                .initialized()
                .await
                .expect("no direct addrs")
                .into_iter()
                .map(|x| x.addr)
                .collect(),
        };
        msock_1
            .add_node_addr(
                node_addr_2,
                Source::NamedApp {
                    name: "test".into(),
                },
            )
            .unwrap();
        let addr = msock_1.get_mapping_addr(node_id_2).unwrap();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            magicsock_connect(msock_1.endpoint(), secret_key_1.clone(), addr, node_id_2),
        )
        .await
        .expect("timeout while connecting");

        // aka assert!(res.is_ok()) but with nicer error reporting.
        res.unwrap();

        // TODO: Now check if we can connect to a repaired ep_3, but we can't modify that
        // much internal state for now.
    }

    #[tokio::test]
    #[traced_test]
    async fn test_try_send_no_udp_addr_or_relay_url() {
        // This specifically tests the `if udp_addr.is_none() && relay_url.is_none()`
        // behaviour of MagicSock::try_send.
        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let node_id_2 = secret_key_2.public();

        let msock_1 = magicsock_ep(secret_key_1.clone()).await.unwrap();
        let msock_2 = magicsock_ep(secret_key_2.clone()).await.unwrap();
        let ep_2 = msock_2.endpoint().clone();

        // We need a task to accept the connection.
        let accept_task = tokio::spawn({
            async fn accept(ep: quinn::Endpoint) -> Result<()> {
                let incoming = ep.accept().await.ok_or(anyhow!("no incoming"))?;
                let conn = incoming.accept()?.await?;
                let mut stream = conn.accept_uni().await?;
                stream.read_to_end(1 << 16).await?;
                info!("accept finished");
                Ok(())
            }
            async move {
                if let Err(err) = accept(ep_2).await {
                    error!("{err:#}");
                }
            }
            .instrument(info_span!("ep2.accept", me = node_id_2.fmt_short()))
        });
        let _accept_task = AbortOnDropHandle::new(accept_task);

        // Add an empty entry in the NodeMap of ep_1
        msock_1.node_map.add_node_addr(
            NodeAddr {
                node_id: node_id_2,
                relay_url: None,
                direct_addresses: Default::default(),
            },
            Source::NamedApp {
                name: "test".into(),
            },
        );
        let addr_2 = msock_1.get_mapping_addr(node_id_2).unwrap();

        // Set a low max_idle_timeout so quinn gives up on this quickly and our test does
        // not take forever.  You need to check the log output to verify this is really
        // triggering the correct error.
        // In test_try_send_no_send_addr() above you may have noticed we used
        // tokio::time::timeout() on the connection attempt instead.  Here however we want
        // Quinn itself to have fully given up on the connection attempt because we will
        // later connect to **the same** node.  If Quinn did not give up on the connection
        // we'd close it on drop, and the retransmits of the close packets would interfere
        // with the next handshake, closing it during the handshake.  This makes the test a
        // little slower though.
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
        let res = magicsock_connect_with_transport_config(
            msock_1.endpoint(),
            secret_key_1.clone(),
            addr_2,
            node_id_2,
            Arc::new(transport_config),
        )
        .await;
        assert!(res.is_err(), "expected timeout");
        info!("first connect timed out as expected");

        // Provide correct addressing information
        msock_1.node_map.add_node_addr(
            NodeAddr {
                node_id: node_id_2,
                relay_url: None,
                direct_addresses: msock_2
                    .direct_addresses()
                    .initialized()
                    .await
                    .expect("no direct addrs")
                    .into_iter()
                    .map(|x| x.addr)
                    .collect(),
            },
            Source::NamedApp {
                name: "test".into(),
            },
        );

        // We can now connect
        tokio::time::timeout(Duration::from_secs(10), async move {
            info!("establishing new connection");
            let conn =
                magicsock_connect(msock_1.endpoint(), secret_key_1.clone(), addr_2, node_id_2)
                    .await
                    .unwrap();
            info!("have connection");
            let mut stream = conn.open_uni().await.unwrap();
            stream.write_all(b"hello").await.unwrap();
            stream.finish().unwrap();
            stream.stopped().await.unwrap();
            info!("finished stream");
        })
        .await
        .expect("connection timed out");

        // TODO: could remove the addresses again, send, add it back and see it recover.
        // But we don't have that much private access to the NodeMap.  This will do for now.
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relay_datagram_queue() {
        let queue = Arc::new(RelayDatagramRecvQueue::new());
        let url = staging::default_na_relay_node().url;
        let capacity = queue.queue.capacity().unwrap();

        let mut tasks = JoinSet::new();

        tasks.spawn({
            let queue = queue.clone();
            async move {
                let mut expected_msgs: BTreeSet<usize> = (0..capacity).collect();
                while !expected_msgs.is_empty() {
                    let datagram = n0_future::future::poll_fn(|cx| {
                        queue.poll_recv(cx).map(|result| result.unwrap())
                    })
                    .await;

                    let msg_num = usize::from_le_bytes(datagram.buf.as_ref().try_into().unwrap());
                    debug!("Received {msg_num}");

                    if !expected_msgs.remove(&msg_num) {
                        panic!("Received message number {msg_num} twice or more, but expected it only exactly once.");
                    }
                }
            }
        });

        for i in 0..capacity {
            tasks.spawn({
                let queue = queue.clone();
                let url = url.clone();
                async move {
                    debug!("Sending {i}");
                    queue
                        .try_send(RelayRecvDatagram {
                            url,
                            src: PublicKey::from_bytes(&[0u8; 32]).unwrap(),
                            buf: Bytes::copy_from_slice(&i.to_le_bytes()),
                        })
                        .unwrap();
                }
            });
        }

        // We expect all of this work to be done in 10 seconds max.
        if tokio::time::timeout(Duration::from_secs(10), tasks.join_all())
            .await
            .is_err()
        {
            panic!("Timeout - not all messages between 0 and {capacity} received.");
        }
    }

    #[tokio::test]
    async fn test_add_node_addr() -> Result<()> {
        let stack = MagicStack::new(RelayMode::Default).await?;
        let mut rng = rand::thread_rng();

        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 0);

        // Empty
        let empty_addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: None,
            direct_addresses: Default::default(),
        };
        let err = stack
            .endpoint
            .magic_sock()
            .add_node_addr(empty_addr, node_map::Source::App)
            .unwrap_err();
        assert!(err.to_string().contains("empty addressing info"));

        // relay url only
        let addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: Some("http://my-relay.com".parse()?),
            direct_addresses: Default::default(),
        };
        stack
            .endpoint
            .magic_sock()
            .add_node_addr(addr, node_map::Source::App)?;
        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 1);

        // addrs only
        let addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: None,
            direct_addresses: ["127.0.0.1:1234".parse()?].into_iter().collect(),
        };
        stack
            .endpoint
            .magic_sock()
            .add_node_addr(addr, node_map::Source::App)?;
        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 2);

        // both
        let addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: Some("http://my-relay.com".parse()?),
            direct_addresses: ["127.0.0.1:1234".parse()?].into_iter().collect(),
        };
        stack
            .endpoint
            .magic_sock()
            .add_node_addr(addr, node_map::Source::App)?;
        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 3);

        Ok(())
    }
}
