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
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use data_encoding::HEXLOWER;
use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_relay::RelayMap;
use n0_future::{
    StreamExt,
    boxed::BoxStream,
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::{self, Watchable, Watcher};
use nested_enum_utils::common_fields;
use netwatch::netmon;
#[cfg(not(wasm_browser))]
use netwatch::{UdpSocket, ip::LocalAddresses};
use quinn::{AsyncUdpSocket, ServerConfig};
use rand::Rng;
use smallvec::SmallVec;
use snafu::{ResultExt, Snafu};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{
    Instrument, Level, debug, error, event, info, info_span, instrument, trace, trace_span, warn,
};
use transports::LocalAddrsWatch;
use url::Url;

#[cfg(not(wasm_browser))]
use self::transports::IpTransport;
use self::{
    metrics::Metrics as MagicsockMetrics,
    node_map::{NodeMap, PingAction, PingRole, SendPing},
    transports::{RelayActorConfig, RelayTransport, Transports, UdpSender},
};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(any(test, feature = "test-utils"))]
use crate::endpoint::PathSelection;
#[cfg(not(wasm_browser))]
use crate::net_report::{IpMappedAddr, QuicConfig};
use crate::{
    defaults::timeouts::NET_REPORT_TIMEOUT,
    disco::{self, SendAddr},
    discovery::{Discovery, DiscoveryEvent, DiscoverySubscribers, NodeData, UserData},
    key::{DecryptionError, SharedSecret, public_ed_box, secret_ed_box},
    metrics::EndpointMetrics,
    net_report::{self, IfStateDetails, IpMappedAddresses, Report},
};

mod metrics;
mod node_map;

pub(crate) mod transports;

pub use node_map::Source;

pub use self::{
    metrics::Metrics,
    node_map::{ConnectionType, ControlMsg, DirectAddrInfo, RemoteInfo},
};

/// How long we consider a QAD-derived endpoint valid for. UDP NAT mappings typically
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

    /// Optional user-defined discovery data.
    pub(crate) discovery_user_data: Option<UserData>,

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

    pub(crate) metrics: EndpointMetrics,
}

/// Handle for [`MagicSock`].
///
/// Dereferences to [`MagicSock`], and handles closing.
#[derive(Clone, Debug, derive_more::Deref)]
pub(crate) struct Handle {
    #[deref(forward)]
    msock: Arc<MagicSock>,
    // empty when shutdown
    actor_task: Arc<Mutex<Option<AbortOnDropHandle<()>>>>,
    /// Token to cancel the actor task.
    actor_token: CancellationToken,
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
#[derive(Debug)]
pub(crate) struct MagicSock {
    /// Channel to send to the internal actor.
    actor_sender: mpsc::Sender<ActorMessage>,
    /// NodeId of this node.
    public_key: PublicKey,

    // - State Management
    /// Close is in progress (or done)
    closing: AtomicBool,
    /// Close was called.
    closed: AtomicBool,

    // - Networking Info
    /// Our discovered direct addresses.
    direct_addrs: DiscoveredDirectAddrs,
    /// Our latest net-report
    net_report: Watchable<(Option<Report>, UpdateReason)>,
    /// If the last net_report report, reports IPv6 to be available.
    ipv6_reported: Arc<AtomicBool>,
    /// Tracks the networkmap node entity for each node discovery key.
    node_map: NodeMap,
    /// Tracks the mapped IP addresses
    ip_mapped_addrs: IpMappedAddresses,
    /// Local addresses
    local_addrs_watch: LocalAddrsWatch,
    /// Currently bound IP addresses of all sockets
    #[cfg(not(wasm_browser))]
    ip_bind_addrs: Vec<SocketAddr>,
    /// The DNS resolver to be used in this magicsock.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,

    /// Disco
    disco: DiscoState,

    // - Discovery
    /// Optional discovery service
    discovery: Option<Box<dyn Discovery>>,
    /// Optional user-defined discover data.
    discovery_user_data: RwLock<Option<UserData>>,
    /// Broadcast channel for listening to discovery updates.
    discovery_subscribers: DiscoverySubscribers,

    /// Metrics
    pub(crate) metrics: EndpointMetrics,
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub enum AddNodeAddrError {
    #[snafu(display("Empty addressing info"))]
    Empty {},
    #[snafu(display("Empty addressing info, {pruned} direct address have been pruned"))]
    EmptyPruned { pruned: usize },
    #[snafu(display("Adding our own address is not supported"))]
    OwnAddress {},
}

impl MagicSock {
    /// Creates a magic [`MagicSock`] listening on [`Options::addr_v4`] and [`Options::addr_v6`].
    pub(crate) async fn spawn(opts: Options) -> Result<Handle, CreateHandleError> {
        Handle::new(opts).await
    }

    /// Returns the relay node we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any relay nodes.
    pub(crate) fn my_relay(&self) -> Option<RelayUrl> {
        self.local_addr().into_iter().find_map(|a| {
            if let transports::Addr::Relay(url, _) = a {
                Some(url)
            } else {
                None
            }
        })
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Get the cached version of addresses.
    pub(crate) fn local_addr(&self) -> Vec<transports::Addr> {
        self.local_addrs_watch.get().expect("disconnected")
    }

    #[cfg(not(wasm_browser))]
    fn ip_bind_addrs(&self) -> &[SocketAddr] {
        &self.ip_bind_addrs
    }

    fn ip_local_addrs(&self) -> impl Iterator<Item = SocketAddr> + use<> {
        self.local_addr()
            .into_iter()
            .filter_map(|addr| addr.into_socket_addr())
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
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    pub(crate) fn direct_addresses(&self) -> n0_watcher::Direct<Option<BTreeSet<DirectAddr>>> {
        self.direct_addrs.addrs.watch()
    }

    /// Returns a [`Watcher`] for this socket's net-report.
    ///
    /// The [`MagicSock`] continuously monitors the network conditions for changes.
    /// Whenever changes are detected this [`Watcher`] will yield a new report.
    ///
    /// Upon the first creation on the [`MagicSock`] it may not yet have completed
    /// a first net-report. In this case, the current item in this [`Watcher`] will
    /// be [`None`].  Once the first report has been run, the [`Watcher`] will
    /// store [`Some`] report.
    ///
    /// To get the current `net-report`, use [`Watcher::initialized`].
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    pub(crate) fn net_report(&self) -> impl Watcher<Value = Option<Report>> + use<> {
        self.net_report
            .watch()
            .map(|(r, _)| r)
            .expect("disconnected")
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known using
    /// [`Watcher::initialized`].
    pub(crate) fn home_relay(&self) -> impl Watcher<Value = Vec<RelayUrl>> + use<> {
        let res = self.local_addrs_watch.clone().map(|addrs| {
            addrs
                .into_iter()
                .filter_map(|addr| {
                    if let transports::Addr::Relay(url, _) = addr {
                        Some(url)
                    } else {
                        None
                    }
                })
                .collect()
        });
        res.expect("disconnected")
    }

    /// Returns a [`n0_watcher::Direct`] that reports the [`ConnectionType`] we have to the
    /// given `node_id`.
    ///
    /// This gets us a copy of the [`n0_watcher::Direct`] for the [`Watchable`] with a [`ConnectionType`]
    /// that the `NodeMap` stores for each `node_id`'s endpoint.
    ///
    /// # Errors
    ///
    /// Will return `None` if there is no address information known about the
    /// given `node_id`.
    pub(crate) fn conn_type(&self, node_id: NodeId) -> Option<n0_watcher::Direct<ConnectionType>> {
        self.node_map.conn_type(node_id)
    }

    /// Returns the socket address which can be used by the QUIC layer to dial this node.
    pub(crate) fn get_mapping_addr(&self, node_id: NodeId) -> Option<NodeIdMappedAddr> {
        self.node_map.get_quic_mapped_addr_for_node_key(node_id)
    }

    /// Add addresses for a node to the magic socket's addresbook.
    #[instrument(skip_all)]
    pub fn add_node_addr(
        &self,
        mut addr: NodeAddr,
        source: node_map::Source,
    ) -> Result<(), AddNodeAddrError> {
        let mut pruned: usize = 0;
        for my_addr in self.direct_addrs.sockaddrs() {
            if addr.direct_addresses.remove(&my_addr) {
                warn!( node_id=addr.node_id.fmt_short(), %my_addr, %source, "not adding our addr for node");
                pruned += 1;
            }
        }
        if !addr.is_empty() {
            self.node_map
                .add_node_addr(addr, source, &self.metrics.magicsock);
            Ok(())
        } else if pruned != 0 {
            Err(EmptyPrunedSnafu { pruned }.build())
        } else {
            Err(EmptySnafu.build())
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

    /// Updates the user-defined discovery data for this node.
    pub(crate) fn set_user_data_for_discovery(&self, user_data: Option<UserData>) {
        let mut guard = self.discovery_user_data.write().expect("lock poisened");
        if *guard != user_data {
            *guard = user_data;
            drop(guard);
            self.publish_my_addr();
        }
    }

    /// Call to notify the system of potential network changes.
    pub(crate) async fn network_change(&self) {
        self.actor_sender
            .send(ActorMessage::NetworkChange)
            .await
            .ok();
    }

    /// Returns a reference to the subscribers channel for discovery events.
    pub(crate) fn discovery_subscribers(&self) -> &DiscoverySubscribers {
        &self.discovery_subscribers
    }

    #[cfg(test)]
    async fn force_network_change(&self, is_major: bool) {
        self.actor_sender
            .send(ActorMessage::ForceNetworkChange(is_major))
            .await
            .ok();
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn normalized_local_addr(&self) -> io::Result<SocketAddr> {
        let addrs = self.local_addrs_watch.get().expect("disconnected");

        let mut ipv4_addr = None;
        for addr in addrs {
            let Some(addr) = addr.into_socket_addr() else {
                continue;
            };
            if addr.is_ipv6() {
                return Ok(addr);
            }
            if addr.is_ipv4() && ipv4_addr.is_none() {
                ipv4_addr.replace(addr);
            }
        }
        match ipv4_addr {
            Some(addr) => Ok(addr),
            None => Err(io::Error::other("no valid socket available")),
        }
    }

    /// Searches the `node_map` to determine the current transports to be used.
    #[instrument(skip_all)]
    fn prepare_send(
        &self,
        transmit: &quinn_udp::Transmit,
    ) -> io::Result<SmallVec<[transports::Addr; 3]>> {
        self.metrics
            .magicsock
            .send_data
            .inc_by(transmit.contents.len() as _);

        if self.is_closed() {
            self.metrics
                .magicsock
                .send_data_network_down
                .inc_by(transmit.contents.len() as _);
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }

        let mut active_paths = SmallVec::<[_; 3]>::new();

        match MappedAddr::from(transmit.destination) {
            MappedAddr::None(dest) => {
                error!(%dest, "Cannot convert to a mapped address.");
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
                match self.node_map.get_send_addrs(
                    dest,
                    self.ipv6_reported.load(Ordering::Relaxed),
                    &self.metrics.magicsock,
                ) {
                    Some((node_id, udp_addr, relay_url, ping_actions)) => {
                        if !ping_actions.is_empty() {
                            self.actor_sender
                                .try_send(ActorMessage::PingActions(ping_actions))
                                .ok();
                        }
                        if let Some(addr) = udp_addr {
                            active_paths.push(transports::Addr::from(addr));
                        }
                        if let Some(url) = relay_url {
                            active_paths.push(transports::Addr::Relay(url, node_id));
                        }
                    }
                    None => {
                        error!(%dest, "no NodeState for mapped address");
                    }
                }
            }
            #[cfg(not(wasm_browser))]
            MappedAddr::Ip(dest) => {
                trace!(
                    dst = %dest,
                    src = ?transmit.src_ip,
                    len = %transmit.contents.len(),
                    "sending",
                );

                // Check if this is a known IpMappedAddr, and if so, send over UDP
                // Get the socket addr
                match self.ip_mapped_addrs.get_ip_addr(&dest) {
                    Some(addr) => {
                        active_paths.push(transports::Addr::from(addr));
                    }
                    None => {
                        error!(%dest, "unknown mapped address");
                    }
                }
            }
        }

        Ok(active_paths)
    }

    /// Process datagrams received from UDP sockets.
    ///
    /// All the `bufs` and `metas` should have initialized packets in them.
    ///
    /// This fixes up the datagrams to use the correct [`NodeIdMappedAddr`] and extracts DISCO
    /// packets, processing them inside the magic socket.
    fn process_datagrams(
        &self,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &[transports::Addr],
    ) {
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        debug_assert_eq!(
            bufs.len(),
            source_addrs.len(),
            "non matching bufs & source_addrs"
        );

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
        // know which interface to send from.
        #[cfg(not(windows))]
        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());
        // Reasoning for this here:
        // https://github.com/n0-computer/iroh/pull/2595#issuecomment-2290947319
        #[cfg(windows)]
        let dst_ip = None;

        let mut quic_packets_total = 0;

        for ((quinn_meta, buf), source_addr) in metas
            .iter_mut()
            .zip(bufs.iter_mut())
            .zip(source_addrs.iter())
        {
            let mut buf_contains_quic_datagrams = false;
            let mut quic_datagram_count = 0;
            if quinn_meta.len > quinn_meta.stride {
                trace!(%quinn_meta.len, %quinn_meta.stride, "GRO datagram received");
                self.metrics.magicsock.recv_gro_datagrams.inc();
            }

            // Chunk through the datagrams in this GRO payload to find disco
            // packets and forward them to the actor
            for datagram in buf[..quinn_meta.len].chunks_mut(quinn_meta.stride) {
                if datagram.len() < quinn_meta.stride {
                    trace!(
                        len = %datagram.len(),
                        %quinn_meta.stride,
                        "Last GRO datagram smaller than stride",
                    );
                }

                // Detect DISCO datagrams and process them.  Overwrite the first
                // byte of those packets with zero to make Quinn ignore the packet.  This
                // relies on quinn::EndpointConfig::grease_quic_bit being set to `false`,
                // which we do in Endpoint::bind.
                if let Some((sender, sealed_box)) = disco::source_and_box(datagram) {
                    trace!(src = ?source_addr, len = %quinn_meta.stride, "UDP recv: disco packet");
                    self.handle_disco_message(sender, sealed_box, source_addr);
                    datagram[0] = 0u8;
                } else {
                    trace!(src = ?source_addr, len = %quinn_meta.stride, "UDP recv: quic packet");
                    match source_addr {
                        transports::Addr::Ip(SocketAddr::V4(..)) => {
                            self.metrics
                                .magicsock
                                .recv_data_ipv4
                                .inc_by(datagram.len() as _);
                        }
                        transports::Addr::Ip(SocketAddr::V6(..)) => {
                            self.metrics
                                .magicsock
                                .recv_data_ipv6
                                .inc_by(datagram.len() as _);
                        }
                        transports::Addr::Relay(..) => {
                            self.metrics
                                .magicsock
                                .recv_data_relay
                                .inc_by(datagram.len() as _);
                        }
                    }

                    quic_datagram_count += 1;
                    buf_contains_quic_datagrams = true;
                }
            }

            if buf_contains_quic_datagrams {
                match source_addr {
                    #[cfg(wasm_browser)]
                    transports::Addr::Ip(_addr) => {
                        panic!("cannot use IP based addressing in the browser");
                    }
                    #[cfg(not(wasm_browser))]
                    transports::Addr::Ip(addr) => {
                        // UDP

                        // Update the NodeMap and remap RecvMeta to the NodeIdMappedAddr.
                        match self.node_map.receive_udp(*addr) {
                            None => {
                                // Check if this address is mapped to an IpMappedAddr
                                if let Some(ip_mapped_addr) =
                                    self.ip_mapped_addrs.get_mapped_addr(addr)
                                {
                                    trace!(
                                        src = %addr,
                                        count = %quic_datagram_count,
                                        len = quinn_meta.len,
                                        "UDP recv QUIC address discovery packets",
                                    );
                                    quic_packets_total += quic_datagram_count;
                                    quinn_meta.addr = ip_mapped_addr.private_socket_addr();
                                } else {
                                    warn!(
                                        src = %addr,
                                        count = %quic_datagram_count,
                                        len = quinn_meta.len,
                                        "UDP recv quic packets: no node state found, skipping",
                                    );
                                    // If we have no node state for the from addr, set len to 0 to make
                                    // quinn skip the buf completely.
                                    quinn_meta.len = 0;
                                }
                            }
                            Some((node_id, quic_mapped_addr)) => {
                                trace!(
                                    src = %addr,
                                    node = %node_id.fmt_short(),
                                    count = %quic_datagram_count,
                                    len = quinn_meta.len,
                                    "UDP recv quic packets",
                                );
                                quic_packets_total += quic_datagram_count;
                                quinn_meta.addr = quic_mapped_addr.private_socket_addr();
                            }
                        }
                    }
                    transports::Addr::Relay(src_url, src_node) => {
                        // Relay
                        let quic_mapped_addr = self.node_map.receive_relay(src_url, *src_node);
                        quinn_meta.addr = quic_mapped_addr.private_socket_addr();
                    }
                }
            } else {
                // If all datagrams in this buf are DISCO, set len to zero to make
                // Quinn skip the buf completely.
                quinn_meta.len = 0;
            }
            // Normalize local_ip
            quinn_meta.dst_ip = dst_ip;
        }

        if quic_packets_total > 0 {
            self.metrics
                .magicsock
                .recv_datagrams
                .inc_by(quic_packets_total as _);
            trace!("UDP recv: {} packets", quic_packets_total);
        }
    }

    /// Handles a discovery message.
    #[instrument("disco_in", skip_all, fields(node = %sender.fmt_short(), ?src))]
    fn handle_disco_message(&self, sender: PublicKey, sealed_box: &[u8], src: &transports::Addr) {
        trace!("handle_disco_message start");
        if self.is_closed() {
            return;
        }

        if let transports::Addr::Relay(_, node_id) = src {
            if node_id != &sender {
                // TODO: return here?
                warn!(
                    "Received relay disco message from connection for {}, but with message from {}",
                    node_id.fmt_short(),
                    sender.fmt_short()
                );
            }
        }

        // We're now reasonably sure we're expecting communication from
        // this node, do the heavy crypto lifting to see what they want.
        let dm = match self.disco.unseal_and_decode(sender, sealed_box) {
            Ok(dm) => dm,
            Err(DiscoBoxError::Open { source, .. }) => {
                warn!(?source, "failed to open disco box");
                self.metrics.magicsock.recv_disco_bad_key.inc();
                return;
            }
            Err(DiscoBoxError::Parse { source, .. }) => {
                // Couldn't parse it, but it was inside a correctly
                // signed box, so just ignore it, assuming it's from a
                // newer version of Tailscale that we don't
                // understand. Not even worth logging about, lest it
                // be too spammy for old clients.

                self.metrics.magicsock.recv_disco_bad_parse.inc();
                debug!(?source, "failed to parse disco message");
                return;
            }
        };

        if src.is_relay() {
            self.metrics.magicsock.recv_disco_relay.inc();
        } else {
            self.metrics.magicsock.recv_disco_udp.inc();
        }

        let span = trace_span!("handle_disco", ?dm);
        let _guard = span.enter();
        trace!("receive disco message");
        match dm {
            disco::Message::Ping(ping) => {
                self.metrics.magicsock.recv_disco_ping.inc();
                self.handle_ping(ping, sender, src);
            }
            disco::Message::Pong(pong) => {
                self.metrics.magicsock.recv_disco_pong.inc();
                self.node_map.handle_pong(sender, src, pong);
            }
            disco::Message::CallMeMaybe(cm) => {
                self.metrics.magicsock.recv_disco_call_me_maybe.inc();
                match src {
                    transports::Addr::Relay(url, _) => {
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
                let ping_actions =
                    self.node_map
                        .handle_call_me_maybe(sender, cm, &self.metrics.magicsock);
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
    fn handle_ping(&self, dm: disco::Ping, sender: NodeId, src: &transports::Addr) {
        // Insert the ping into the node map, and return whether a ping with this tx_id was already
        // received.
        let addr: SendAddr = src.clone().into();
        let handled = self.node_map.handle_ping(sender, addr.clone(), dm.tx_id);
        match handled.role {
            PingRole::Duplicate => {
                debug!(?src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: path already confirmed, skip");
                return;
            }
            PingRole::LikelyHeartbeat => {}
            PingRole::NewPath => {
                debug!(?src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: new path");
            }
            PingRole::Activate => {
                debug!(?src, tx = %HEXLOWER.encode(&dm.tx_id), "received ping: path active");
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

        if !self.disco.try_send(addr.clone(), sender, pong) {
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
            node_key: self.public_key,
        });
        let sent = self.disco.try_send(dst.clone(), dst_node, msg);
        if sent {
            let msg_sender = self.actor_sender.clone();
            trace!(%dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "ping sent (queued)");
            self.node_map
                .notify_ping_sent(id, dst, tx_id, purpose, msg_sender);
        } else {
            warn!(dst = ?dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "failed to send ping: queues full");
        }
    }

    /// Send the given ping actions out.
    async fn send_ping_actions(&self, sender: &UdpSender, msgs: Vec<PingAction>) -> io::Result<()> {
        for msg in msgs {
            // Abort sending as soon as we know we are shutting down.
            if self.is_closing() || self.is_closed() {
                return Ok(());
            }
            match msg {
                PingAction::SendCallMeMaybe {
                    relay_url,
                    dst_node,
                } => {
                    // Sends the call-me-maybe DISCO message, queuing if addresses are too stale.
                    //
                    // To send the call-me-maybe message, we need to know our current direct addresses.  If
                    // this information is too stale, the call-me-maybe is queued while a net_report run is
                    // scheduled.  Once this run finishes, the call-me-maybe will be sent.
                    match self.direct_addrs.fresh_enough() {
                        Ok(()) => {
                            let msg = disco::Message::CallMeMaybe(
                                self.direct_addrs.to_call_me_maybe_message(),
                            );
                            if !self.disco.try_send(
                                SendAddr::Relay(relay_url.clone()),
                                dst_node,
                                msg.clone(),
                            ) {
                                warn!(dstkey = %dst_node.fmt_short(), %relay_url, "relay channel full, dropping call-me-maybe");
                            } else {
                                debug!(dstkey = %dst_node.fmt_short(), %relay_url, "call-me-maybe sent");
                            }
                        }
                        Err(last_refresh_ago) => {
                            debug!(
                                ?last_refresh_ago,
                                "want call-me-maybe but direct addrs stale; queuing after restun",
                            );
                            self.actor_sender
                                .try_send(ActorMessage::ScheduleDirectAddrUpdate(
                                    UpdateReason::RefreshForPeering,
                                    Some((dst_node, relay_url)),
                                ))
                                .ok();
                        }
                    }
                }
                PingAction::SendPing(SendPing {
                    id,
                    dst,
                    dst_node,
                    tx_id,
                    purpose,
                }) => {
                    let msg = disco::Message::Ping(disco::Ping {
                        tx_id,
                        node_key: self.public_key,
                    });

                    self.send_disco_message(sender, dst.clone(), dst_node, msg)
                        .await?;
                    debug!(%dst, tx = %HEXLOWER.encode(&tx_id), ?purpose, "ping sent");
                    let msg_sender = self.actor_sender.clone();
                    self.node_map
                        .notify_ping_sent(id, dst, tx_id, purpose, msg_sender);
                }
            }
        }
        Ok(())
    }

    /// Sends out a disco message.
    async fn send_disco_message(
        &self,
        sender: &UdpSender,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> io::Result<()> {
        let dst = match dst {
            SendAddr::Udp(addr) => transports::Addr::Ip(addr),
            SendAddr::Relay(url) => transports::Addr::Relay(url, dst_key),
        };

        trace!(?dst, %msg, "send disco message (UDP)");
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }

        let pkt = self.disco.encode_and_seal(self.public_key, dst_key, &msg);

        let transmit = transports::Transmit {
            contents: &pkt,
            ecn: None,
            segment_size: None,
        };

        let dst2 = dst.clone();
        match sender.send(&dst2, None, &transmit).await {
            Ok(()) => {
                trace!(?dst, %msg, "sent disco message");
                self.metrics.magicsock.sent_disco_udp.inc();
                disco_message_sent(&msg, &self.metrics.magicsock);
                Ok(())
            }
            Err(err) => {
                warn!(?dst, ?msg, ?err, "failed to send disco message");
                Err(err)
            }
        }
    }

    /// Publishes our address to a discovery service, if configured.
    ///
    /// Called whenever our addresses or home relay node changes.
    fn publish_my_addr(&self) {
        if let Some(ref discovery) = self.discovery {
            let relay_url = self.my_relay();
            let direct_addrs = self.direct_addrs.sockaddrs();

            let user_data = self
                .discovery_user_data
                .read()
                .expect("lock poisened")
                .clone();
            if relay_url.is_none() && direct_addrs.is_empty() && user_data.is_none() {
                // do not bother publishing if we don't have any information
                return;
            }

            let data = NodeData::new(relay_url, direct_addrs).with_user_data(user_data);
            discovery.publish(&data);
        }
    }
}

#[derive(Clone, Debug)]
enum MappedAddr {
    NodeId(NodeIdMappedAddr),
    #[cfg(not(wasm_browser))]
    Ip(IpMappedAddr),
    None(SocketAddr),
}

impl From<SocketAddr> for MappedAddr {
    fn from(value: SocketAddr) -> Self {
        match value.ip() {
            IpAddr::V4(_) => MappedAddr::None(value),
            IpAddr::V6(addr) => {
                if let Ok(node_id_mapped_addr) = NodeIdMappedAddr::try_from(addr) {
                    return MappedAddr::NodeId(node_id_mapped_addr);
                }
                #[cfg(not(wasm_browser))]
                if let Ok(ip_mapped_addr) = IpMappedAddr::try_from(addr) {
                    return MappedAddr::Ip(ip_mapped_addr);
                }
                MappedAddr::None(value)
            }
        }
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
    /// If set, start a new update as soon as the current one is finished.
    want_update: Option<UpdateReason>,
    msock: Arc<MagicSock>,
    #[cfg(not(wasm_browser))]
    port_mapper: portmapper::Client,
    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_reporter: Arc<AsyncMutex<net_report::Client>>,
    relay_map: RelayMap,
    run_done: mpsc::Sender<()>,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
enum UpdateReason {
    /// Initial state
    #[default]
    None,
    RefreshForPeering,
    Periodic,
    PortmapUpdated,
    LinkChangeMajor,
    LinkChangeMinor,
}

impl UpdateReason {
    fn is_major(self) -> bool {
        matches!(self, Self::LinkChangeMajor)
    }
}

impl DirectAddrUpdateState {
    fn new(
        msock: Arc<MagicSock>,
        #[cfg(not(wasm_browser))] port_mapper: portmapper::Client,
        net_reporter: Arc<AsyncMutex<net_report::Client>>,
        relay_map: RelayMap,
        run_done: mpsc::Sender<()>,
    ) -> Self {
        DirectAddrUpdateState {
            want_update: Default::default(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            net_reporter,
            msock,
            relay_map,
            run_done,
        }
    }

    /// Schedules a new run, either starting it immediately if none is running or
    /// scheduling it for later.
    fn schedule_run(&mut self, why: UpdateReason, if_state: IfStateDetails) {
        match self.net_reporter.clone().try_lock_owned() {
            Ok(net_reporter) => {
                self.run(why, if_state, net_reporter);
            }
            Err(_) => {
                let _ = self.want_update.insert(why);
            }
        }
    }

    /// If another run is needed, triggers this run, otherwise does nothing.
    fn try_run(&mut self, if_state: IfStateDetails) {
        match self.net_reporter.clone().try_lock_owned() {
            Ok(net_reporter) => {
                if let Some(why) = self.want_update.take() {
                    self.run(why, if_state, net_reporter);
                }
            }
            Err(_) => {
                // do nothing
            }
        }
    }

    /// Trigger a new run.
    fn run(
        &mut self,
        why: UpdateReason,
        if_state: IfStateDetails,
        mut net_reporter: tokio::sync::OwnedMutexGuard<net_report::Client>,
    ) {
        debug!("starting direct addr update ({:?})", why);
        #[cfg(not(wasm_browser))]
        self.port_mapper.procure_mapping();
        // Don't start a net report probe if we know
        // we are shutting down
        if self.msock.is_closing() || self.msock.is_closed() {
            debug!("skipping net_report, socket is shutting down");
            return;
        }
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            self.msock.net_report.set((None, why)).ok();
            return;
        }

        debug!("requesting net_report report");
        let msock = self.msock.clone();

        let run_done = self.run_done.clone();
        task::spawn(
            async move {
                let fut = time::timeout(
                    NET_REPORT_TIMEOUT,
                    net_reporter.get_report(if_state, why.is_major()),
                );
                match fut.await {
                    Ok(report) => {
                        msock.net_report.set((Some(report), why)).ok();
                    }
                    Err(time::Elapsed { .. }) => {
                        warn!("net_report report timed out");
                    }
                }

                // mark run as finished
                debug!("direct addr update done ({:?})", why);
                run_done.send(()).await.ok();
            }
            .instrument(tracing::Span::current()),
        );
    }
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CreateHandleError {
    #[snafu(display("Failed to create bind sockets"))]
    BindSockets { source: io::Error },
    #[snafu(display("Failed to create internal quinn endpoint"))]
    CreateQuinnEndpoint { source: io::Error },
    #[snafu(display("Failed to create socket state"))]
    CreateSocketState { source: io::Error },
    #[snafu(display("Failed to create netmon monitor"))]
    CreateNetmonMonitor { source: netmon::Error },
    #[snafu(display("Failed to subscribe netmon monitor"))]
    SubscribeNetmonMonitor { source: netmon::Error },
}

impl Handle {
    /// Creates a magic [`MagicSock`] listening on [`Options::addr_v4`] and [`Options::addr_v6`].
    async fn new(opts: Options) -> Result<Self, CreateHandleError> {
        let Options {
            addr_v4,
            addr_v6,
            secret_key,
            relay_map,
            node_map,
            discovery,
            discovery_user_data,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            #[cfg(any(test, feature = "test-utils"))]
            path_selection,
            metrics,
        } = opts;

        let addr_v4 = addr_v4.unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

        #[cfg(not(wasm_browser))]
        let (ip_transports, port_mapper) =
            bind_ip(addr_v4, addr_v6, &metrics).context(BindSocketsSnafu)?;

        let ip_mapped_addrs = IpMappedAddresses::default();

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        // load the node data
        let node_map = node_map.unwrap_or_default();
        #[cfg(any(test, feature = "test-utils"))]
        let node_map = NodeMap::load_from_vec(node_map, path_selection, &metrics.magicsock);
        #[cfg(not(any(test, feature = "test-utils")))]
        let node_map = NodeMap::load_from_vec(node_map, &metrics.magicsock);

        let my_relay = Watchable::new(None);
        let ipv6_reported = Arc::new(AtomicBool::new(false));

        let relay_transport = RelayTransport::new(RelayActorConfig {
            my_relay: my_relay.clone(),
            secret_key: secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            proxy_url: proxy_url.clone(),
            ipv6_reported: ipv6_reported.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            metrics: metrics.magicsock.clone(),
        });
        let relay_transports = vec![relay_transport];

        let secret_encryption_key = secret_ed_box(secret_key.secret());
        #[cfg(not(wasm_browser))]
        let ipv6 = ip_transports.iter().any(|t| t.bind_addr().is_ipv6());

        #[cfg(not(wasm_browser))]
        let transports = Transports::new(ip_transports, relay_transports);
        #[cfg(wasm_browser)]
        let transports = Transports::new(relay_transports);

        let (disco, disco_receiver) = DiscoState::new(secret_encryption_key);

        let msock = Arc::new(MagicSock {
            public_key: secret_key.public(),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            disco,
            actor_sender: actor_sender.clone(),
            ipv6_reported,
            node_map,
            ip_mapped_addrs: ip_mapped_addrs.clone(),
            discovery,
            discovery_user_data: RwLock::new(discovery_user_data),
            direct_addrs: Default::default(),
            net_report: Watchable::new((None, UpdateReason::None)),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            discovery_subscribers: DiscoverySubscribers::new(),
            metrics: metrics.clone(),
            local_addrs_watch: transports.local_addrs_watch(),
            #[cfg(not(wasm_browser))]
            ip_bind_addrs: transports.ip_bind_addrs(),
        });

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Setting this to false means that quinn will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to quinn. We set the first byte of the packet to zero, which makes quinn ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let sender = transports.create_sender(msock.clone());
        let local_addrs_watch = transports.local_addrs_watch();
        let network_change_sender = transports.create_network_change_sender();

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Box::new(MagicUdpSocket {
                socket: msock.clone(),
                transports,
            }),
            #[cfg(not(wasm_browser))]
            Arc::new(quinn::TokioRuntime),
            #[cfg(wasm_browser)]
            Arc::new(crate::web_runtime::WebRuntime),
        )
        .context(CreateQuinnEndpointSnafu)?;

        let network_monitor = netmon::Monitor::new()
            .await
            .context(CreateNetmonMonitorSnafu)?;

        let qad_endpoint = endpoint.clone();

        #[cfg(any(test, feature = "test-utils"))]
        let client_config = if insecure_skip_relay_cert_verify {
            iroh_relay::client::make_dangerous_client_config()
        } else {
            default_quic_client_config()
        };
        #[cfg(not(any(test, feature = "test-utils")))]
        let client_config = default_quic_client_config();

        let net_report_config = net_report::Options::default();
        #[cfg(not(wasm_browser))]
        let net_report_config = net_report_config.quic_config(Some(QuicConfig {
            ep: qad_endpoint,
            client_config,
            ipv4: true,
            ipv6,
        }));

        #[cfg(any(test, feature = "test-utils"))]
        let net_report_config =
            net_report_config.insecure_skip_relay_cert_verify(insecure_skip_relay_cert_verify);

        let net_reporter = net_report::Client::new(
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            Some(ip_mapped_addrs),
            relay_map.clone(),
            net_report_config,
            metrics.net_report.clone(),
        );

        let (direct_addr_done_tx, direct_addr_done_rx) = mpsc::channel(8);
        let direct_addr_update_state = DirectAddrUpdateState::new(
            msock.clone(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            Arc::new(AsyncMutex::new(net_reporter)),
            relay_map,
            direct_addr_done_tx,
        );

        let netmon_watcher = network_monitor.interface_state();
        let actor = Actor {
            msg_receiver: actor_receiver,
            msock: msock.clone(),
            periodic_re_stun_timer: new_re_stun_timer(false),
            network_monitor,
            netmon_watcher,
            direct_addr_update_state,
            network_change_sender,
            direct_addr_done_rx,
            pending_call_me_maybes: Default::default(),
            disco_receiver,
        };

        let actor_token = CancellationToken::new();
        let token = actor_token.clone();
        let actor_task = task::spawn(
            actor
                .run(token, local_addrs_watch, sender)
                .instrument(info_span!("actor")),
        );

        let actor_task = Arc::new(Mutex::new(Some(AbortOnDropHandle::new(actor_task))));

        Ok(Handle {
            msock,
            actor_task,
            endpoint,
            actor_token,
        })
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
    #[instrument(skip_all)]
    pub(crate) async fn close(&self) {
        trace!(me = ?self.public_key, "magicsock closing...");
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
        self.actor_token.cancel();

        // MutexGuard is not held across await points
        let task = self.actor_task.lock().expect("poisoned").take();
        if let Some(task) = task {
            // give the tasks a moment to shutdown cleanly
            let shutdown_done = time::timeout(Duration::from_millis(100), async move {
                if let Err(err) = task.await {
                    warn!("unexpected error in task shutdown: {:?}", err);
                }
            })
            .await;
            match shutdown_done {
                Ok(_) => trace!("tasks finished in time, shutdown complete"),
                Err(time::Elapsed { .. }) => {
                    // Dropping the task will abort itt
                    warn!("tasks didn't finish in time, aborting");
                }
            }
        }

        self.msock.closed.store(true, Ordering::SeqCst);

        trace!("magicsock closed");
    }
}

fn default_quic_client_config() -> rustls::ClientConfig {
    // create a client config for the endpoint to use for QUIC address discovery
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::client::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("ring supports these")
    .with_root_certificates(root_store)
    .with_no_client_auth()
}

#[derive(Debug)]
struct DiscoState {
    /// Encryption key for this node.
    secret_encryption_key: crypto_box::SecretKey,
    /// The state for an active DiscoKey.
    secrets: Mutex<HashMap<PublicKey, SharedSecret>>,
    /// Disco (ping) queue
    sender: mpsc::Sender<(SendAddr, PublicKey, disco::Message)>,
}

impl DiscoState {
    fn new(
        secret_encryption_key: crypto_box::SecretKey,
    ) -> (Self, mpsc::Receiver<(SendAddr, PublicKey, disco::Message)>) {
        let (disco_sender, disco_receiver) = mpsc::channel(256);

        (
            Self {
                secret_encryption_key,
                secrets: Default::default(),
                sender: disco_sender,
            },
            disco_receiver,
        )
    }

    fn try_send(&self, dst: SendAddr, node_id: PublicKey, msg: disco::Message) -> bool {
        self.sender.try_send((dst, node_id, msg)).is_ok()
    }

    fn encode_and_seal(
        &self,
        this_node_id: NodeId,
        other_node_id: NodeId,
        msg: &disco::Message,
    ) -> Bytes {
        let mut seal = msg.as_bytes();
        self.get_secret(other_node_id, |secret| secret.seal(&mut seal));
        disco::encode_message(&this_node_id, seal).into()
    }

    fn unseal_and_decode(
        &self,
        node_id: PublicKey,
        sealed_box: &[u8],
    ) -> Result<disco::Message, DiscoBoxError> {
        let mut sealed_box = sealed_box.to_vec();
        self.get_secret(node_id, |secret| secret.open(&mut sealed_box))
            .context(OpenSnafu)?;
        disco::Message::from_bytes(&sealed_box).context(ParseSnafu)
    }

    fn get_secret<F, T>(&self, node_id: PublicKey, cb: F) -> T
    where
        F: FnOnce(&mut SharedSecret) -> T,
    {
        let mut inner = self.secrets.lock().expect("poisoned");
        let x = inner.entry(node_id).or_insert_with(|| {
            let public_key = public_ed_box(&node_id.public());
            SharedSecret::new(&self.secret_encryption_key, &public_key)
        });
        cb(x)
    }
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
enum DiscoBoxError {
    #[snafu(display("Failed to open crypto box"))]
    Open {
        #[snafu(source(from(DecryptionError, Box::new)))]
        source: Box<DecryptionError>,
    },
    #[snafu(display("Failed to parse disco message"))]
    Parse {
        #[snafu(source(from(disco::ParseError, Box::new)))]
        source: Box<disco::ParseError>,
    },
}

#[derive(Debug)]
struct MagicUdpSocket {
    socket: Arc<MagicSock>,
    transports: Transports,
}

impl AsyncUdpSocket for MagicUdpSocket {
    fn create_sender(&self) -> Pin<Box<dyn quinn::UdpSender>> {
        Box::pin(self.transports.create_sender(self.socket.clone()))
    }

    /// NOTE: Receiving on a closed socket will return [`Poll::Pending`] indefinitely.
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.transports.poll_recv(cx, bufs, metas, &self.socket)
    }

    #[cfg(not(wasm_browser))]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let addrs: Vec<_> = self
            .transports
            .local_addrs()
            .into_iter()
            .filter_map(|addr| {
                let addr: SocketAddr = addr.into_socket_addr()?;
                Some(addr)
            })
            .collect();

        if let Some(addr) = addrs.iter().find(|addr| addr.is_ipv6()) {
            return Ok(*addr);
        }
        if let Some(SocketAddr::V4(addr)) = addrs.first() {
            // Pretend to be IPv6, because our `MappedAddr`s need to be IPv6.
            let ip = addr.ip().to_ipv6_mapped().into();
            return Ok(SocketAddr::new(ip, addr.port()));
        }

        Err(io::Error::other("no valid address available"))
    }

    #[cfg(wasm_browser)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        // Again, we need to pretend we're IPv6, because of our `MappedAddr`s.
        Ok(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0))
    }

    fn max_receive_segments(&self) -> usize {
        self.transports.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.transports.may_fragment()
    }
}

#[derive(Debug)]
enum ActorMessage {
    PingActions(Vec<PingAction>),
    EndpointPingExpired(usize, stun_rs::TransactionId),
    NetworkChange,
    ScheduleDirectAddrUpdate(UpdateReason, Option<(NodeId, RelayUrl)>),
    #[cfg(test)]
    ForceNetworkChange(bool),
}

struct Actor {
    msock: Arc<MagicSock>,
    msg_receiver: mpsc::Receiver<ActorMessage>,
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,

    network_monitor: netmon::Monitor,
    netmon_watcher: n0_watcher::Direct<netmon::State>,
    network_change_sender: transports::NetworkChangeSender,
    /// Indicates the direct addr update state.
    direct_addr_update_state: DirectAddrUpdateState,
    direct_addr_done_rx: mpsc::Receiver<()>,

    /// List of CallMeMaybe disco messages that should be sent out after
    /// the next endpoint update completes
    pending_call_me_maybes: HashMap<PublicKey, RelayUrl>,
    disco_receiver: mpsc::Receiver<(SendAddr, PublicKey, disco::Message)>,
}

#[cfg(not(wasm_browser))]
fn bind_ip(
    addr_v4: SocketAddrV4,
    addr_v6: Option<SocketAddrV6>,
    metrics: &EndpointMetrics,
) -> io::Result<(Vec<IpTransport>, portmapper::Client)> {
    let port_mapper =
        portmapper::Client::with_metrics(Default::default(), metrics.portmapper.clone());

    let v4 = Arc::new(bind_with_fallback(SocketAddr::V4(addr_v4))?);
    let ip4_port = v4.local_addr()?.port();
    let ip6_port = ip4_port.checked_add(1).unwrap_or(ip4_port - 1);

    let addr_v6 =
        addr_v6.unwrap_or_else(|| SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, ip6_port, 0, 0));

    let v6 = match bind_with_fallback(SocketAddr::V6(addr_v6)) {
        Ok(sock) => Some(Arc::new(sock)),
        Err(err) => {
            info!("bind ignoring IPv6 bind failure: {:?}", err);
            None
        }
    };

    let port = v4.local_addr().map_or(0, |p| p.port());

    let mut ip = vec![IpTransport::new(
        addr_v4.into(),
        v4,
        metrics.magicsock.clone(),
    )];
    if let Some(v6) = v6 {
        ip.push(IpTransport::new(
            addr_v6.into(),
            v6,
            metrics.magicsock.clone(),
        ))
    }

    // NOTE: we can end up with a zero port if `netwatch::UdpSocket::socket_addr` fails
    match port.try_into() {
        Ok(non_zero_port) => {
            port_mapper.update_local_port(non_zero_port);
        }
        Err(_zero_port) => debug!("Skipping port mapping with zero local port"),
    }

    Ok((ip, port_mapper))
}

impl Actor {
    async fn run(
        mut self,
        shutdown_token: CancellationToken,
        mut watcher: impl Watcher<Value = Vec<transports::Addr>> + Send + Sync,
        sender: UdpSender,
    ) {
        // Initialize addresses
        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(None);

        // Setup network monitoring
        let mut current_netmon_state = self.netmon_watcher.get().expect("missing network state");

        #[cfg(not(wasm_browser))]
        let mut direct_addr_heartbeat_timer = time::interval(HEARTBEAT_INTERVAL);

        #[cfg(not(wasm_browser))]
        let mut portmap_watcher = self
            .direct_addr_update_state
            .port_mapper
            .watch_external_address();

        let mut discovery_events: BoxStream<DiscoveryEvent> = Box::pin(n0_future::stream::empty());
        if let Some(d) = self.msock.discovery() {
            if let Some(events) = d.subscribe() {
                discovery_events = events;
            }
        }

        let mut receiver_closed = false;
        #[cfg_attr(wasm_browser, allow(unused_mut))]
        let mut portmap_watcher_closed = false;

        let mut net_report_watcher = self.msock.net_report.watch();

        loop {
            self.msock.metrics.magicsock.actor_tick_main.inc();
            #[cfg(not(wasm_browser))]
            let portmap_watcher_changed = portmap_watcher.changed();
            #[cfg(wasm_browser)]
            let portmap_watcher_changed = n0_future::future::pending();

            #[cfg(not(wasm_browser))]
            let direct_addr_heartbeat_timer_tick = direct_addr_heartbeat_timer.tick();
            #[cfg(wasm_browser)]
            let direct_addr_heartbeat_timer_tick = n0_future::future::pending();

            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    debug!("shutting down");
                    return;
                }
                msg = self.msg_receiver.recv(), if !receiver_closed => {
                    let Some(msg) = msg else {
                        trace!("tick: magicsock receiver closed");
                        self.msock.metrics.magicsock.actor_tick_other.inc();

                        receiver_closed = true;
                        continue;
                    };

                    trace!(?msg, "tick: msg");
                    self.msock.metrics.magicsock.actor_tick_msg.inc();
                    self.handle_actor_message(msg, &sender).await;
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    self.msock.metrics.magicsock.actor_tick_re_stun.inc();
                    self.re_stun(UpdateReason::Periodic);
                }
                new_addr = watcher.updated() => {
                    match new_addr {
                        Ok(addrs) => {
                            if !addrs.is_empty() {
                                trace!(?addrs, "local addrs");
                                self.msock.publish_my_addr();
                            }
                        }
                        Err(_) => {
                            warn!("local addr watcher stopped");
                        }
                    }
                }
                report = net_report_watcher.updated() => {
                    match report {
                        Ok((report, _)) => {
                            self.handle_net_report_report(report);
                            #[cfg(not(wasm_browser))]
                            {
                                self.periodic_re_stun_timer = new_re_stun_timer(true);
                            }
                        }
                        Err(_) => {
                            warn!("net report watcher stopped");
                        }
                    }
                }
                reason = self.direct_addr_done_rx.recv() => {
                    match reason {
                        Some(()) => {
                            // check if a new run needs to be scheduled
                            let state = self.netmon_watcher.get().expect("disconnected");
                            self.direct_addr_update_state.try_run(state.into());
                        }
                        None => {
                            warn!("direct addr watcher died");
                        }
                    }
                }
                change = portmap_watcher_changed, if !portmap_watcher_closed => {
                    #[cfg(not(wasm_browser))]
                    {
                        if change.is_err() {
                            trace!("tick: portmap watcher closed");
                            self.msock.metrics.magicsock.actor_tick_other.inc();

                            portmap_watcher_closed = true;
                            continue;
                        }

                        trace!("tick: portmap changed");
                        self.msock.metrics.magicsock.actor_tick_portmap_changed.inc();
                        let new_external_address = *portmap_watcher.borrow();
                        debug!("external address updated: {new_external_address:?}");
                        self.re_stun(UpdateReason::PortmapUpdated);
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
                        self.msock.metrics.magicsock.actor_tick_direct_addr_heartbeat.inc();
                        // TODO: this might trigger too many packets at once, pace this

                        self.msock.node_map.prune_inactive();
                        let msgs = self.msock.node_map.nodes_stayin_alive();
                        self.handle_ping_actions(&sender, msgs).await;
                    }
                }
                state = self.netmon_watcher.updated() => {
                    let Ok(state) = state else {
                        trace!("tick: link change receiver closed");
                        self.msock.metrics.magicsock.actor_tick_other.inc();
                        continue;
                    };
                    let is_major = state.is_major_change(&current_netmon_state);
                    current_netmon_state = state;
                    trace!("tick: link change {}", is_major);
                    self.msock.metrics.magicsock.actor_link_change.inc();
                    self.handle_network_change(is_major).await;
                }
                // Even if `discovery_events` yields `None`, it could begin to yield
                // `Some` again in the future, so we don't want to disable this branch
                // forever like we do with the other branches that yield `Option`s
                Some(discovery_item) = discovery_events.next() => {
                    trace!("tick: discovery event, address discovered: {discovery_item:?}");
                    if let DiscoveryEvent::Discovered(discovery_item) = &discovery_item {
                        let provenance = discovery_item.provenance();
                        let node_addr = discovery_item.to_node_addr();
                        if let Err(e) = self.msock.add_node_addr(
                            node_addr,
                            Source::Discovery {
                                name: provenance.to_string()
                            }) {
                            let node_addr = discovery_item.to_node_addr();
                            warn!(?node_addr, "unable to add discovered node address to the node map: {e:?}");
                        }
                    }

                    // Send the discovery item to the subscribers of the discovery broadcast stream.
                    self.msock.discovery_subscribers.send(discovery_item);
                }
                Some((dst, dst_key, msg)) = self.disco_receiver.recv() => {
                    if let Err(err) = self.msock.send_disco_message(&sender, dst.clone(), dst_key, msg).await {
                        warn!(%dst, node = %dst_key.fmt_short(), ?err, "failed to send disco message (UDP)");
                    }
                }
            }
        }
    }

    async fn handle_network_change(&mut self, is_major: bool) {
        debug!("link change detected: major? {}", is_major);

        if is_major {
            if let Err(err) = self.network_change_sender.rebind() {
                warn!("failed to rebind transports: {:?}", err);
            }

            #[cfg(not(wasm_browser))]
            self.msock.dns_resolver.reset().await;
            self.re_stun(UpdateReason::LinkChangeMajor);
            self.reset_endpoint_states();
        } else {
            self.re_stun(UpdateReason::LinkChangeMinor);
        }
    }

    fn re_stun(&mut self, why: UpdateReason) {
        let state = self.netmon_watcher.get().expect("disconnected");
        self.direct_addr_update_state
            .schedule_run(why, state.into());
    }

    #[instrument(skip_all)]
    async fn handle_ping_actions(&mut self, sender: &UdpSender, msgs: Vec<PingAction>) {
        if let Err(err) = self.msock.send_ping_actions(sender, msgs).await {
            warn!("Failed to send ping actions: {err:#}");
        }
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage, sender: &UdpSender) {
        match msg {
            ActorMessage::EndpointPingExpired(id, txid) => {
                self.msock.node_map.notify_ping_timeout(id, txid);
            }
            ActorMessage::NetworkChange => {
                self.network_monitor.network_change().await.ok();
            }
            ActorMessage::ScheduleDirectAddrUpdate(why, data) => {
                if let Some((node, url)) = data {
                    self.pending_call_me_maybes.insert(node, url);
                }
                let state = self.netmon_watcher.get().expect("disconnected");
                self.direct_addr_update_state
                    .schedule_run(why, state.into());
            }
            #[cfg(test)]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major).await;
            }
            ActorMessage::PingActions(ping_actions) => {
                self.handle_ping_actions(sender, ping_actions).await;
            }
        }
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
    fn update_direct_addresses(&mut self, net_report_report: Option<&net_report::Report>) {
        let portmap_watcher = self
            .direct_addr_update_state
            .port_mapper
            .watch_external_address();

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
        }

        // Next add STUN addresses from the net_report report.
        if let Some(net_report_report) = net_report_report {
            if let Some(global_v4) = net_report_report.global_v4 {
                addrs.entry(global_v4.into()).or_insert(DirectAddrType::Qad);

                // If they're behind a hard NAT and are using a fixed
                // port locally, assume they might've added a static
                // port mapping on their router to the same explicit
                // port that we are running with. Worst case it's an invalid candidate mapping.
                let port = self.msock.ip_bind_addrs().iter().find_map(|addr| {
                    if addr.port() != 0 {
                        Some(addr.port())
                    } else {
                        None
                    }
                });

                if let Some(port) = port {
                    if net_report_report
                        .mapping_varies_by_dest()
                        .unwrap_or_default()
                    {
                        let mut addr = global_v4;
                        addr.set_port(port);
                        addrs
                            .entry(addr.into())
                            .or_insert(DirectAddrType::Qad4LocalPort);
                    }
                }
            }
            if let Some(global_v6) = net_report_report.global_v6 {
                addrs.entry(global_v6.into()).or_insert(DirectAddrType::Qad);
            }
        }

        let local_addrs: Vec<(SocketAddr, SocketAddr)> = self
            .msock
            .ip_bind_addrs()
            .iter()
            .copied()
            .zip(self.msock.ip_local_addrs())
            .collect();

        let has_ipv4_unspecified = local_addrs.iter().find_map(|(_, a)| {
            if a.is_ipv4() && a.ip().is_unspecified() {
                Some(a.port())
            } else {
                None
            }
        });
        let has_ipv6_unspecified = local_addrs.iter().find_map(|(_, a)| {
            if a.is_ipv6() && a.ip().is_unspecified() {
                Some(a.port())
            } else {
                None
            }
        });

        // If a socket is bound to the unspecified address, create SocketAddrs for
        // each local IP address by pairing it with the port the socket is bound on.
        if local_addrs
            .iter()
            .any(|(_, local)| local.ip().is_unspecified())
        {
            let LocalAddresses {
                regular: mut ips,
                loopback,
            } = self
                .netmon_watcher
                .get()
                .expect("netmon disconnected")
                .local_addresses;
            if ips.is_empty() && addrs.is_empty() {
                // Include loopback addresses only if there are no other interfaces
                // or public addresses, this allows testing offline.
                ips = loopback;
            }

            for ip in ips {
                let port_if_unspecified = match ip {
                    IpAddr::V4(_) => has_ipv4_unspecified,
                    IpAddr::V6(_) => has_ipv6_unspecified,
                };
                if let Some(port) = port_if_unspecified {
                    let addr = SocketAddr::new(ip, port);
                    addrs.entry(addr).or_insert(DirectAddrType::Local);
                }
            }
        }

        // If a socket is bound to a specific address, add it.
        for (bound, local) in local_addrs {
            if !bound.ip().is_unspecified() {
                addrs.entry(local).or_insert(DirectAddrType::Local);
            }
        }

        // Finally create and store store all these direct addresses and send any
        // queued call-me-maybe messages.
        self.msock.store_direct_addresses(
            addrs
                .iter()
                .map(|(addr, typ)| DirectAddr {
                    addr: *addr,
                    typ: *typ,
                })
                .collect(),
        );
        self.send_queued_call_me_maybes();
    }

    fn send_queued_call_me_maybes(&mut self) {
        let msg = self.msock.direct_addrs.to_call_me_maybe_message();
        let msg = disco::Message::CallMeMaybe(msg);
        // allocate, to minimize locking duration

        for (public_key, url) in self.pending_call_me_maybes.drain() {
            if !self
                .msock
                .disco
                .try_send(SendAddr::Relay(url), public_key, msg.clone())
            {
                warn!(node = %public_key.fmt_short(), "relay channel full, dropping call-me-maybe");
            }
        }
    }

    fn handle_net_report_report(&mut self, mut report: Option<net_report::Report>) {
        if let Some(ref mut r) = report {
            self.msock.ipv6_reported.store(r.udp_v6, Ordering::Relaxed);
            if r.preferred_relay.is_none() {
                if let Some(my_relay) = self.msock.my_relay() {
                    r.preferred_relay.replace(my_relay);
                }
            }

            // Notify all transports
            self.network_change_sender.on_network_change(r);
        }

        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(report.as_ref());
    }

    /// Resets the preferred address for all nodes.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    #[instrument(skip_all)]
    fn reset_endpoint_states(&mut self) {
        self.msock.node_map.reset_node_states()
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

#[cfg(not(wasm_browser))]
fn bind_with_fallback(mut addr: SocketAddr) -> io::Result<UdpSocket> {
    debug!(%addr, "binding");

    // First try binding a preferred port, if specified
    match UdpSocket::bind_full(addr) {
        Ok(socket) => {
            let local_addr = socket.local_addr()?;
            debug!(%addr, %local_addr, "successfully bound");
            return Ok(socket);
        }
        Err(err) => {
            debug!(%addr, "failed to bind: {err:#}");
            // If that was already the fallback port, then error out
            if addr.port() == 0 {
                return Err(err);
            }
        }
    }

    // Otherwise, try binding with port 0
    addr.set_port(0);
    UdpSocket::bind_full(addr)
}

/// The discovered direct addresses of this [`MagicSock`].
///
/// These are all the [`DirectAddr`]s that this [`MagicSock`] is aware of for itself.
/// They include all locally bound ones as well as those discovered by other mechanisms like
/// QAD.
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
#[derive(Debug, Snafu)]
#[snafu(display("Failed to convert"))]
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

    /// The dummy port used for all [`NodeIdMappedAddr`]s.
    const NODE_ID_MAPPED_PORT: u16 = 12345;

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

    /// Returns a consistent [`SocketAddr`] for the [`NodeIdMappedAddr`].
    ///
    /// This socket address does not have a routable IP address.
    ///
    /// This uses a made-up port number, since the port does not play a role in looking up
    /// the node in the [`NodeMap`].  This socket address is only to be used to pass into
    /// Quinn.
    pub(crate) fn private_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::from(self.0), Self::NODE_ID_MAPPED_PORT)
    }
}

impl TryFrom<Ipv6Addr> for NodeIdMappedAddr {
    type Error = NodeIdMappedAddrError;

    fn try_from(value: Ipv6Addr) -> Result<Self, Self::Error> {
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

fn disco_message_sent(msg: &disco::Message, metrics: &MagicsockMetrics) {
    match msg {
        disco::Message::Ping(_) => {
            metrics.sent_disco_ping.inc();
        }
        disco::Message::Pong(_) => {
            metrics.sent_disco_pong.inc();
        }
        disco::Message::CallMeMaybe(_) => {
            metrics.sent_disco_call_me_maybe.inc();
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
    /// Public internet address discovered via QAD.
    ///
    /// When possible an iroh node will perform QAD to discover which is the address
    /// from which it sends data on the public internet.  This can be different from locally
    /// bound addresses when the node is on a local network which performs NAT or similar.
    Qad,
    /// An address assigned by the router using port mapping.
    ///
    /// When possible an iroh node will request a port mapping from the local router to
    /// get a publicly routable direct address.
    Portmapped,
    /// Hard NAT: QAD'ed IPv4 address + local fixed port.
    ///
    /// It is possible to configure iroh to bound to a specific port and independently
    /// configure the router to forward this port to the iroh node.  This indicates a
    /// situation like this, which still uses QAD to discover the public address.
    Qad4LocalPort,
}

impl Display for DirectAddrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectAddrType::Unknown => write!(f, "?"),
            DirectAddrType::Local => write!(f, "local"),
            DirectAddrType::Qad => write!(f, "qad"),
            DirectAddrType::Portmapped => write!(f, "portmap"),
            DirectAddrType::Qad4LocalPort => write!(f, "qad4localport"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc, time::Duration};

    use data_encoding::HEXLOWER;
    use iroh_base::{NodeAddr, NodeId, PublicKey};
    use n0_future::{StreamExt, time};
    use n0_snafu::{Result, ResultExt};
    use n0_watcher::Watcher;
    use quinn::ServerConfig;
    use rand::{Rng, RngCore};
    use tokio::task::JoinSet;
    use tokio_util::task::AbortOnDropHandle;
    use tracing::{Instrument, error, info, info_span, instrument};
    use tracing_test::traced_test;

    use super::{NodeIdMappedAddr, Options};
    use crate::{
        Endpoint, RelayMap, RelayMode, SecretKey,
        dns::DnsResolver,
        endpoint::{DirectAddr, PathSelection, Source},
        magicsock::{Handle, MagicSock, node_map},
        tls,
    };

    const ALPN: &[u8] = b"n0/test/1";

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
                dns_resolver: DnsResolver::new(),
                server_config,
                #[cfg(any(test, feature = "test-utils"))]
                insecure_skip_relay_cert_verify: false,
                #[cfg(any(test, feature = "test-utils"))]
                path_selection: PathSelection::default(),
                discovery_user_data: None,
                metrics: Default::default(),
            }
        }
    }

    /// Generate a server config with no ALPNS and a default transport configuration
    fn make_default_server_config(secret_key: &SecretKey) -> ServerConfig {
        let quic_server_config =
            crate::tls::TlsConfig::new(secret_key.clone()).make_server_config(vec![], false);
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        server_config
    }

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
        async fn new(relay_mode: RelayMode) -> Self {
            let secret_key = SecretKey::generate(rand::thread_rng());

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let endpoint = Endpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .relay_mode(relay_mode)
                .alpns(vec![ALPN.to_vec()])
                .bind()
                .await
                .unwrap();

            Self {
                secret_key,
                endpoint,
            }
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
        .context("timeout")?;
        info!("all nodes meshed");
        Ok(tasks)
    }

    #[instrument(skip_all, fields(me = %ep.endpoint.node_id().fmt_short()))]
    async fn echo_receiver(ep: MagicStack, loss: ExpectedLoss) -> Result {
        info!("accepting conn");
        let conn = ep.endpoint.accept().await.expect("no conn");

        info!("connecting");
        let conn = conn.await.context("connecting")?;
        info!("accepting bi");
        let (mut send_bi, mut recv_bi) = conn.accept_bi().await.context("accept bi")?;

        info!("reading");
        let val = recv_bi
            .read_to_end(usize::MAX)
            .await
            .context("read to end")?;

        info!("replying");
        for chunk in val.chunks(12) {
            send_bi.write_all(chunk).await.context("write all")?;
        }

        info!("finishing");
        send_bi.finish().context("finish")?;
        send_bi.stopped().await.context("stopped")?;

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
    ) -> Result {
        info!("connecting to {}", dest_id.fmt_short());
        let dest = NodeAddr::new(dest_id);
        let conn = ep.endpoint.connect(dest, ALPN).await?;

        info!("opening bi");
        let (mut send_bi, mut recv_bi) = conn.open_bi().await.context("open bi")?;

        info!("writing message");
        send_bi.write_all(msg).await.context("write all")?;

        info!("finishing");
        send_bi.finish().context("finish")?;
        send_bi.stopped().await.context("stopped")?;

        info!("reading_to_end");
        let val = recv_bi
            .read_to_end(usize::MAX)
            .await
            .context("read to end")?;
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
    async fn test_two_devices_roundtrip_quinn_magic() -> Result {
        let m1 = MagicStack::new(RelayMode::Disabled).await;
        let m2 = MagicStack::new(RelayMode::Disabled).await;

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
    async fn test_regression_network_change_rebind_wakes_connection_driver() -> n0_snafu::Result {
        let m1 = MagicStack::new(RelayMode::Disabled).await;
        let m2 = MagicStack::new(RelayMode::Disabled).await;

        println!("Net change");
        m1.endpoint.magic_sock().force_network_change(true).await;
        tokio::time::sleep(Duration::from_secs(1)).await; // wait for socket rebinding

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

        let _handle = AbortOnDropHandle::new(tokio::spawn({
            let endpoint = m2.endpoint.clone();
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    println!("Incoming first conn!");
                    let conn = incoming.await.e()?;
                    conn.closed().await;
                }

                Ok::<_, n0_snafu::Error>(())
            }
        }));

        println!("first conn!");
        let conn = m1
            .endpoint
            .connect(m2.endpoint.node_addr().initialized().await?, ALPN)
            .await?;
        println!("Closing first conn");
        conn.close(0u32.into(), b"bye lolz");
        conn.closed().await;
        println!("Closed first conn");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_network_change() -> Result {
        time::timeout(
            Duration::from_secs(90),
            test_two_devices_roundtrip_network_change_impl(),
        )
        .await
        .context("timeout")?
    }

    /// Same structure as `test_two_devices_roundtrip_quinn_magic`, but interrupts regularly
    /// with (simulated) network changes.
    async fn test_two_devices_roundtrip_network_change_impl() -> Result {
        let m1 = MagicStack::new(RelayMode::Disabled).await;
        let m2 = MagicStack::new(RelayMode::Disabled).await;

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
    async fn test_two_devices_setup_teardown() -> Result {
        for i in 0..10 {
            println!("-- round {i}");
            println!("setting up magic stack");
            let m1 = MagicStack::new(RelayMode::Disabled).await;
            let m2 = MagicStack::new(RelayMode::Disabled).await;

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

    /// Creates a new [`quinn::Endpoint`] hooked up to a [`MagicSock`].
    ///
    /// This is without involving [`crate::endpoint::Endpoint`].  The socket will accept
    /// connections using [`ALPN`].
    ///
    /// Use [`magicsock_connect`] to establish connections.
    #[instrument(name = "ep", skip_all, fields(me = secret_key.public().fmt_short()))]
    async fn magicsock_ep(secret_key: SecretKey) -> Result<Handle> {
        let quic_server_config =
            tls::TlsConfig::new(secret_key.clone()).make_server_config(vec![ALPN.to_vec()], true);
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(quinn::TransportConfig::default()));

        let dns_resolver = DnsResolver::new();
        let opts = Options {
            addr_v4: None,
            addr_v6: None,
            secret_key: secret_key.clone(),
            relay_map: RelayMap::empty(),
            node_map: None,
            discovery: None,
            discovery_user_data: None,
            dns_resolver,
            proxy_url: None,
            server_config,
            insecure_skip_relay_cert_verify: false,
            path_selection: PathSelection::default(),
            metrics: Default::default(),
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
            tls::TlsConfig::new(ep_secret_key.clone()).make_client_config(alpns, true);
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(transport_config);
        let connect = ep
            .connect_with(
                client_config,
                mapped_addr.private_socket_addr(),
                &tls::name::encode(node_id),
            )
            .context("connect")?;
        let connection = connect.await.e()?;
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

        // This needs an accept task
        let accept_task = tokio::spawn({
            async fn accept(ep: quinn::Endpoint) -> Result<()> {
                let incoming = ep.accept().await.context("no incoming")?;
                let _conn = incoming
                    .accept()
                    .context("accept")?
                    .await
                    .context("connecting")?;

                // Keep this connection alive for a while
                tokio::time::sleep(Duration::from_secs(10)).await;
                info!("accept finished");
                Ok(())
            }
            let ep = msock_2.endpoint().clone();
            async move {
                if let Err(err) = accept(ep).await {
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
                let incoming = ep.accept().await.context("no incoming")?;
                let conn = incoming
                    .accept()
                    .context("accept")?
                    .await
                    .context("connecting")?;
                let mut stream = conn.accept_uni().await.context("accept uni")?;
                stream.read_to_end(1 << 16).await.context("read to end")?;
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
            &msock_1.metrics.magicsock,
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
            &msock_1.metrics.magicsock,
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

    #[tokio::test]
    async fn test_add_node_addr() -> Result {
        let stack = MagicStack::new(RelayMode::Default).await;
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
        assert!(
            err.to_string()
                .to_lowercase()
                .contains("empty addressing info")
        );

        // relay url only
        let addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: Some("http://my-relay.com".parse().unwrap()),
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
            direct_addresses: ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        };
        stack
            .endpoint
            .magic_sock()
            .add_node_addr(addr, node_map::Source::App)?;
        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 2);

        // both
        let addr = NodeAddr {
            node_id: SecretKey::generate(&mut rng).public(),
            relay_url: Some("http://my-relay.com".parse().unwrap()),
            direct_addresses: ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        };
        stack
            .endpoint
            .magic_sock()
            .add_node_addr(addr, node_map::Source::App)?;
        assert_eq!(stack.endpoint.magic_sock().node_map.node_count(), 3);

        Ok(())
    }
}
