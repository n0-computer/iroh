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
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    task::{Context, Poll},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use data_encoding::HEXLOWER;
use iroh_base::{NodeAddr, NodeId, PublicKey, RelayUrl, SecretKey};
use iroh_relay::{protos::stun, RelayMap};
use n0_future::{
    boxed::BoxStream,
    task::{self, JoinSet},
    time::{self, Duration, Instant},
    FutureExt, StreamExt,
};
use netwatch::netmon;
#[cfg(not(wasm_browser))]
use netwatch::{ip::LocalAddresses, UdpSocket};
use quinn::{AsyncUdpSocket, ServerConfig};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use smallvec::SmallVec;
use tokio::sync::{self, mpsc, Mutex};
use tracing::{
    debug, error, error_span, event, info, info_span, instrument, trace, trace_span, warn,
    Instrument, Level, Span,
};
use url::Url;

#[cfg(not(wasm_browser))]
use self::transports::IpTransport;
#[cfg(not(wasm_browser))]
use self::udp_conn::UdpConn;
use self::{
    metrics::Metrics as MagicsockMetrics,
    node_map::{NodeMap, PingAction, PingRole, SendPing},
    transports::{relay::RelayActorConfig, RelayTransport, Transports},
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
    discovery::{Discovery, DiscoveryItem, DiscoverySubscribers, NodeData, UserData},
    key::{public_ed_box, secret_ed_box, DecryptionError, SharedSecret},
    metrics::EndpointMetrics,
    net_report::{self, IpMappedAddresses, Report},
    watchable::{DirectWatcher, Watchable, Watcher},
};

mod metrics;
mod node_map;
#[cfg(not(wasm_browser))]
mod udp_conn;

pub(crate) mod transports;

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

    /// Whether to use websockets or the nonstandard legacy protocol to connect to relays
    pub(crate) relay_protocol: iroh_relay::http::Protocol,

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

    /// The DNS resolver to be used in this magicsock.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,

    /// Key for this node.
    secret_key: SecretKey,
    /// Encryption key for this node.
    secret_encryption_key: crypto_box::SecretKey,

    /// Transports, IP and Relay
    transports: Transports,

    /// Close is in progress (or done)
    closing: AtomicBool,
    /// Close was called.
    closed: AtomicBool,
    /// If the last net_report report, reports IPv6 to be available.
    ipv6_reported: Arc<AtomicBool>,

    /// Zero nodes means relay is disabled.
    relay_map: RelayMap,
    /// Tracks the networkmap node entity for each node discovery key.
    node_map: NodeMap,
    /// Tracks the mapped IP addresses
    ip_mapped_addrs: IpMappedAddresses,
    /// NetReport client
    net_reporter: net_report::Addr,
    /// The state for an active DiscoKey.
    disco_secrets: DiscoSecrets,

    /// Disco (ping) queue
    disco_sender: mpsc::Sender<(SendAddr, PublicKey, disco::Message)>,

    /// Optional discovery service
    discovery: Option<Box<dyn Discovery>>,

    /// Optional user-defined discover data.
    discovery_user_data: RwLock<Option<UserData>>,

    /// Our discovered direct addresses.
    direct_addrs: DiscoveredDirectAddrs,

    /// Our latest net-report
    net_report: Watchable<Option<Arc<Report>>>,

    /// List of CallMeMaybe disco messages that should be sent out after the next endpoint update
    /// completes
    pending_call_me_maybes: std::sync::Mutex<HashMap<PublicKey, RelayUrl>>,

    /// Indicates the direct addr update state.
    direct_addr_update_state: DirectAddrUpdateState,

    /// Broadcast channel for listening to discovery updates.
    discovery_subscribers: DiscoverySubscribers,

    pub(crate) metrics: EndpointMetrics,
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
        self.local_addr().into_iter().find_map(|a| {
            if let transports::Addr::RelayUrl(url, _) = a {
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

    fn public_key(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Get the cached version of addresses.
    pub(crate) fn local_addr(&self) -> Vec<transports::Addr> {
        self.transports.local_addrs()
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
    pub(crate) fn direct_addresses(&self) -> impl Watcher<Value = Option<BTreeSet<DirectAddr>>> {
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
    pub(crate) fn net_report(&self) -> impl Watcher<Value = Option<Arc<Report>>> {
        self.net_report.watch()
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known using
    /// [`Watcher::initialized`].
    pub(crate) fn home_relay(&self) -> impl Watcher<Value = Vec<RelayUrl>> + '_ {
        let res = self.transports.local_addrs_watch().map(|addrs| {
            addrs
                .into_iter()
                .filter_map(|addr| {
                    if let transports::Addr::RelayUrl(url, _) = addr {
                        Some(url)
                    } else {
                        None
                    }
                })
                .collect()
        });
        res.expect("disconnected")
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
    pub(crate) fn conn_type(&self, node_id: NodeId) -> Result<DirectWatcher<ConnectionType>> {
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
            self.node_map
                .add_node_addr(addr, source, &self.metrics.magicsock);
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
        let addrs: Vec<_> = self
            .transports
            .local_addrs()
            .into_iter()
            .filter_map(|addr| {
                let addr: SocketAddr = addr.try_into().ok()?;
                Some(addr)
            })
            .collect();

        if let Some(addr) = addrs.iter().find(|a| a.is_ipv6()) {
            return Ok(*addr);
        }
        if let Some(addr) = addrs.first() {
            return Ok(*addr);
        }

        Err(io::Error::other("no valid socket available"))
    }

    /// Implementation for AsyncUdpSocket::try_send
    #[instrument(skip_all)]
    fn try_send(&self, transmit: &quinn_udp::Transmit) -> io::Result<()> {
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

        let mut available_paths = Vec::new();

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
                    Some((node_id, udp_addr, relay_url, msgs)) => {
                        // If we have pings to send, we *have* to send them out first.
                        if !msgs.is_empty() {
                            if let Err(err) = self.try_send_ping_actions(msgs) {
                                warn!(
                                    node = %node_id.fmt_short(),
                                    "failed to handle ping actions: {err:#}",
                                );
                            }
                        }

                        if let Some(addr) = udp_addr {
                            available_paths.push(transports::Addr::from(addr));
                        }
                        if let Some(url) = relay_url {
                            available_paths.push(transports::Addr::RelayUrl(url, node_id));
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
                        available_paths.push(transports::Addr::from(addr));
                    }
                    None => {
                        error!(%dest, "unknown mapped address");
                    }
                }
            }
        }

        if available_paths.is_empty() {
            // Returning Ok here means we let QUIC timeout.
            // Returning an error would immediately fail a connection.
            // The philosophy of quinn-udp is that a UDP connection could
            // come back at any time or missing should be transient so chooses to let
            // these kind of errors time out.  See test_try_send_no_send_addr to try
            // this out.
            error!("no paths available for node, voiding transmit");
            return Ok(());
        }

        let mut results = Vec::with_capacity(available_paths.len());

        trace!(?available_paths, "attempting to send");

        for destination in available_paths {
            let transmit = transports::Transmit {
                ecn: transmit.ecn,
                contents: transmit.contents,
                segment_size: transmit.segment_size,
                src_ip: transmit.src_ip.map(Into::into),
            };

            let res = self.transports.poll_send(&destination, &transmit);
            match res {
                Poll::Ready(Ok(())) => {
                    trace!(dst = ?destination, "sent transmit");
                }
                Poll::Ready(Err(ref err)) => {
                    warn!(dst = ?destination, "failed to send: {err:#}");
                }
                Poll::Pending => {}
            }
            results.push(res);
        }

        if results.iter().all(|p| matches!(p, Poll::Pending)) {
            // Handle backpressure.
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "pending"));
        }
        Ok(())
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

        let mut source_addrs = vec![transports::Addr::default(); metas.len()];
        match self
            .transports
            .poll_recv(cx, bufs, metas, &mut source_addrs)?
        {
            Poll::Pending | Poll::Ready(0) => Poll::Pending,
            Poll::Ready(n) => {
                self.process_datagrams(&mut bufs[..n], &mut metas[..n], &source_addrs[..n]);
                Poll::Ready(Ok(n))
            }
        }
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

            // Chunk through the datagrams in this GRO payload to find disco and stun
            // packets and forward them to the actor
            for datagram in buf[..quinn_meta.len].chunks_mut(quinn_meta.stride) {
                if datagram.len() < quinn_meta.stride {
                    trace!(
                        len = %datagram.len(),
                        %quinn_meta.stride,
                        "Last GRO datagram smaller than stride",
                    );
                }

                // Detect DISCO and STUN datagrams and process them.  Overwrite the first
                // byte of those packets with zero to make Quinn ignore the packet.  This
                // relies on quinn::EndpointConfig::grease_quic_bit being set to `false`,
                // which we do in Endpoint::bind.
                if source_addr.is_ip() && stun::is(datagram) {
                    trace!(src = ?source_addr, len = %quinn_meta.stride, "UDP recv: stun packet");
                    let packet2 = Bytes::copy_from_slice(datagram);
                    self.net_reporter.receive_stun_packet(
                        packet2,
                        source_addr.clone().try_into().expect("checked"),
                    );
                    datagram[0] = 0u8;
                } else if let Some((sender, sealed_box)) = disco::source_and_box(datagram) {
                    trace!(src = ?source_addr, len = %quinn_meta.stride, "UDP recv: disco packet");
                    self.handle_disco_message(sender, sealed_box, source_addr);
                    datagram[0] = 0u8;
                } else {
                    trace!(src = ?source_addr, len = %quinn_meta.stride, "UDP recv: quic packet");
                    match source_addr {
                        transports::Addr::Ipv4(..) => {
                            self.metrics
                                .magicsock
                                .recv_data_ipv4
                                .inc_by(datagram.len() as _);
                        }
                        transports::Addr::Ipv6(..) => {
                            self.metrics
                                .magicsock
                                .recv_data_ipv6
                                .inc_by(datagram.len() as _);
                        }
                        transports::Addr::RelayUrl(..) => {
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
                enum AddrOrUrl {
                    Addr(SocketAddr),
                    Url(RelayUrl, NodeId),
                }
                let addr = match source_addr {
                    transports::Addr::Ipv4(ipv4, port) => AddrOrUrl::Addr(SocketAddr::V4(
                        SocketAddrV4::new(*ipv4, port.unwrap_or_default()),
                    )),
                    transports::Addr::Ipv6(ipv6, port) => AddrOrUrl::Addr(SocketAddr::V6(
                        SocketAddrV6::new(*ipv6, port.unwrap_or_default(), 0, 0),
                    )),
                    transports::Addr::RelayUrl(ref url, id) => AddrOrUrl::Url(url.clone(), *id),
                };

                match addr {
                    #[cfg(wasm_browser)]
                    AddrOrUrl::Addr(addr) => {
                        panic!("cannot use IP based addressing in the browser");
                    }
                    #[cfg(not(wasm_browser))]
                    AddrOrUrl::Addr(addr) => {
                        // UDP

                        // Update the NodeMap and remap RecvMeta to the NodeIdMappedAddr.
                        match self.node_map.receive_udp(addr) {
                            None => {
                                // Check if this address is mapped to an IpMappedAddr
                                if let Some(ip_mapped_addr) =
                                    self.ip_mapped_addrs.get_mapped_addr(&addr)
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
                    AddrOrUrl::Url(src_url, src_node) => {
                        // Relay
                        let quic_mapped_addr = self.node_map.receive_relay(&src_url, src_node);
                        quinn_meta.addr = quic_mapped_addr.private_socket_addr();
                    }
                }
            } else {
                // If all datagrams in this buf are DISCO or STUN, set len to zero to make
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

        if let transports::Addr::RelayUrl(_, node_id) = src {
            if node_id != &sender {
                // TODO: return here?
                warn!("Received relay disco message from connection for {:?}, but with message from {}", node_id.fmt_short(), sender.fmt_short());
            }
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
                self.metrics.magicsock.recv_disco_bad_key.inc();
                return;
            }
            Err(DiscoBoxError::Parse(err)) => {
                // Couldn't parse it, but it was inside a correctly
                // signed box, so just ignore it, assuming it's from a
                // newer version of Tailscale that we don't
                // understand. Not even worth logging about, lest it
                // be too spammy for old clients.

                self.metrics.magicsock.recv_disco_bad_parse.inc();
                debug!(?err, "failed to parse disco message");
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
                    transports::Addr::RelayUrl(url, _) => {
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
        let sent = self
            .disco_sender
            .try_send((dst.clone(), dst_node, msg))
            .is_ok();

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
        self.disco_sender.try_send((dst, dst_key, msg)).is_ok()
    }

    /// Send a disco message. UDP messages will be polled to send directly on the UDP socket.
    async fn send_disco_message(
        &self,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> io::Result<()> {
        let dst = match dst {
            SendAddr::Udp(SocketAddr::V4(v4)) => transports::Addr::Ipv4(*v4.ip(), Some(v4.port())),
            SendAddr::Udp(SocketAddr::V6(v6)) => transports::Addr::Ipv6(*v6.ip(), Some(v6.port())),
            SendAddr::Relay(url) => transports::Addr::RelayUrl(url, dst_key),
        };

        n0_future::future::poll_fn(move |cx| loop {
            match self.try_send_disco_message(&dst, dst_key, &msg) {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    match self.transports.poll_writable(cx, &dst) {
                        Poll::Ready(Ok(())) => continue,
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Err(err) => return Poll::Ready(Err(err)),
            }
        })
        .await
    }

    fn try_send_disco_message(
        &self,
        dst: &transports::Addr,
        dst_key: PublicKey,
        msg: &disco::Message,
    ) -> std::io::Result<()> {
        trace!(?dst, %msg, "send disco message (UDP)");
        if self.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            ));
        }
        let pkt = self.encode_disco_message(dst_key, msg);

        let transmit = transports::Transmit {
            contents: &pkt,
            ecn: None,
            segment_size: None,
            src_ip: None, // TODO
        };

        match self.transports.poll_send(dst, &transmit) {
            Poll::Ready(Ok(())) => {
                trace!(?dst, %msg, "sent disco message");
                self.metrics.magicsock.sent_disco_udp.inc();
                disco_message_sent(msg, &self.metrics.magicsock);
                Ok(())
            }
            Poll::Ready(Err(err)) => {
                warn!(?dst, ?msg, ?err, "failed to send disco message");
                Err(err)
            }
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "pending")),
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

        let addr = match dst {
            SendAddr::Udp(SocketAddr::V4(v4)) => transports::Addr::Ipv4(*v4.ip(), Some(v4.port())),
            SendAddr::Udp(SocketAddr::V6(v6)) => transports::Addr::Ipv6(*v6.ip(), Some(v6.port())),
            SendAddr::Relay(ref url) => transports::Addr::RelayUrl(url.clone(), dst_node),
        };

        self.try_send_disco_message(&addr, dst_node, &msg)?;
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
            if !self.send_disco_message_queued(SendAddr::Relay(url), public_key, msg.clone()) {
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
                if !self.send_disco_message_queued(SendAddr::Relay(url.clone()), dst_node, msg) {
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
        self.metrics.magicsock.re_stun_calls.inc();
        self.direct_addr_update_state.schedule_run(why);
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
        let Options {
            addr_v4,
            addr_v6,
            secret_key,
            relay_map,
            relay_protocol,
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
        let (ip_transports, port_mapper) = bind_ip(addr_v4, addr_v6, metrics.portmapper.clone())?;

        #[cfg(not(wasm_browser))]
        let v4_socket = ip_transports
            .iter()
            .find(|t| t.bind_addr().is_ipv4())
            .expect("must bind a ipv4 socket")
            .socket();
        #[cfg(not(wasm_browser))]
        let v6_socket = ip_transports.iter().find_map(|t| {
            if t.bind_addr().is_ipv6() {
                Some(t.socket())
            } else {
                None
            }
        });

        let ip_mapped_addrs = IpMappedAddresses::default();

        let net_reporter = net_report::Client::new(
            #[cfg(not(wasm_browser))]
            Some(port_mapper.clone()),
            #[cfg(not(wasm_browser))]
            dns_resolver.clone(),
            #[cfg(not(wasm_browser))]
            Some(ip_mapped_addrs.clone()),
            metrics.net_report.clone(),
        )?;

        let (actor_sender, actor_receiver) = mpsc::channel(256);
        let (udp_disco_sender, mut udp_disco_receiver) = mpsc::channel(256);

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
            protocol: relay_protocol,
        });
        let relay_transports = vec![relay_transport];

        let secret_encryption_key = secret_ed_box(secret_key.secret());

        let ipv6 = ip_transports.iter().any(|t| t.bind_addr().is_ipv6());

        #[cfg(not(wasm_browser))]
        let transports = Transports::new(ip_transports, relay_transports);
        #[cfg(wasm_browser)]
        let transports = Transports::new(relay_transports);

        let msock = Arc::new(MagicSock {
            me,
            secret_key,
            secret_encryption_key,
            transports,
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            actor_sender: actor_sender.clone(),
            ipv6_reported,
            relay_map,
            net_reporter: net_reporter.addr(),
            disco_secrets: DiscoSecrets::default(),
            node_map,
            ip_mapped_addrs,
            disco_sender: udp_disco_sender,
            discovery,
            discovery_user_data: RwLock::new(discovery_user_data),
            direct_addrs: Default::default(),
            net_report: Default::default(),
            pending_call_me_maybes: Default::default(),
            direct_addr_update_state: DirectAddrUpdateState::new(),
            #[cfg(not(wasm_browser))]
            dns_resolver,
            discovery_subscribers: DiscoverySubscribers::new(),
            metrics,
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
            msock.clone(),
            #[cfg(not(wasm_browser))]
            Arc::new(quinn::TokioRuntime),
            #[cfg(wasm_browser)]
            Arc::new(crate::web_runtime::WebRuntime),
        )?;

        let mut actor_tasks = JoinSet::default();

        #[cfg(not(wasm_browser))]
        let _ = actor_tasks.spawn({
            let msock = msock.clone();
            async move {
                while let Some((dst, dst_key, msg)) = udp_disco_receiver.recv().await {
                    if let Err(err) = msock.send_disco_message(dst.clone(), dst_key, msg).await {
                        warn!(%dst, node = %dst_key.fmt_short(), ?err, "failed to send disco message (UDP)");
                    }
                }
            }
        });

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

        #[cfg(not(wasm_browser))]
        let net_report_config = net_report::Options::default()
            .stun_v4(Some(v4_socket))
            .stun_v6(v6_socket)
            .quic_config(Some(QuicConfig {
                ep: qad_endpoint,
                client_config,
                ipv4: true,
                ipv6,
            }));
        #[cfg(wasm_browser)]
        let net_report_config = net_report::Options::default();

        actor_tasks.spawn({
            let msock = msock.clone();
            async move {
                let actor = Actor {
                    msg_receiver: actor_receiver,
                    msg_sender: actor_sender,
                    msock,
                    periodic_re_stun_timer: new_re_stun_timer(false),
                    net_info_last: None,
                    #[cfg(not(wasm_browser))]
                    port_mapper,
                    no_v4_send: false,
                    net_reporter,
                    network_monitor,
                    net_report_config,
                };

                if let Err(err) = actor.run().await {
                    warn!("relay handler errored: {:?}", err);
                }
            }
            .instrument(info_span!("actor"))
        });

        let c = Handle {
            msock,
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
        match shutdown_done {
            Ok(_) => trace!("tasks finished in time, shutdown complete"),
            Err(_elapsed) => {
                // shutdown all tasks
                warn!(
                    "tasks didn't finish in time, aborting remaining {}/3 tasks",
                    tasks.len()
                );
                tasks.shutdown().await;
            }
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

impl AsyncUdpSocket for MagicSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        self.transports.create_io_poller()
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

    #[cfg(not(wasm_browser))]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let addrs: Vec<_> = self
            .transports
            .local_addrs()
            .into_iter()
            .filter_map(|addr| {
                let addr: SocketAddr = addr.try_into().ok()?;
                Some(addr)
            })
            .collect();

        if let Some(addr) = addrs.iter().find(|addr| addr.is_ipv6()) {
            return Ok(*addr);
        }
        if let Some(SocketAddr::V4(addr)) = addrs.first() {
            let ip = addr.ip().to_ipv6_mapped().into();
            return Ok(SocketAddr::new(ip, addr.port()));
        }

        Err(io::Error::other("no valid address available"))
    }

    #[cfg(wasm_browser)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), 0))
    }

    fn max_transmit_segments(&self) -> usize {
        self.transports.max_transmit_segments()
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
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<NetInfo>,

    #[cfg(not(wasm_browser))]
    port_mapper: portmapper::Client,

    /// Configuration for net report
    net_report_config: net_report::Options,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: bool,

    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_reporter: net_report::Client,

    network_monitor: netmon::Monitor,
}

#[cfg(not(wasm_browser))]
fn bind_ip(
    addr_v4: SocketAddrV4,
    addr_v6: Option<SocketAddrV6>,
    metrics: Arc<portmapper::Metrics>,
) -> Result<(Vec<IpTransport>, portmapper::Client)> {
    let port_mapper = portmapper::Client::with_metrics(Default::default(), metrics);
    let (v4, v6) = bind_sockets(addr_v4, addr_v6)?;

    let port = v4.local_addr().map_or(0, |p| p.port());
    let v4 = UdpConn::wrap(v4);
    let v6 = v6.map(UdpConn::wrap);

    let mut ip = vec![IpTransport::new(addr_v4.into(), v4)];
    if let (Some(v6), Some(addr)) = (v6, addr_v6) {
        ip.push(IpTransport::new(addr.into(), v6))
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

#[cfg(not(wasm_browser))]
fn bind_sockets(
    addr_v4: SocketAddrV4,
    addr_v6: Option<SocketAddrV6>,
) -> Result<(Arc<UdpSocket>, Option<Arc<UdpSocket>>)> {
    let v4 = Arc::new(bind_with_fallback(SocketAddr::V4(addr_v4)).context("bind IPv4 failed")?);

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

    Ok((v4, v6))
}

impl Actor {
    async fn run(mut self) -> Result<()> {
        // Setup network monitoring
        let (link_change_s, mut link_change_r) = mpsc::channel(8);
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

        let watcher = self.msock.transports.local_addrs_watch();
        let mut local_addr_changes = watcher.stream();

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
                msg = self.msg_receiver.recv(), if !receiver_closed => {
                    let Some(msg) = msg else {
                        trace!("tick: magicsock receiver closed");
                        self.msock.metrics.magicsock.actor_tick_other.inc();

                        receiver_closed = true;
                        continue;
                    };

                    trace!(?msg, "tick: msg");
                    self.msock.metrics.magicsock.actor_tick_msg.inc();
                    if self.handle_actor_message(msg).await {
                        return Ok(());
                    }
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    self.msock.metrics.magicsock.actor_tick_re_stun.inc();
                    self.msock.re_stun("periodic");
                }
                new_addr = local_addr_changes.next() => {
                    match new_addr {
                        Some(addrs) => {
                            trace!(?addrs, "local addrs");
                            self.msock.publish_my_addr();
                        }
                        None => {
                            warn!("local addr watcher stopped");
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
                        self.msock.metrics.magicsock.actor_tick_direct_addr_heartbeat.inc();
                        // TODO: this might trigger too many packets at once, pace this

                        self.msock.node_map.prune_inactive();
                        let msgs = self.msock.node_map.nodes_stayin_alive();
                        self.handle_ping_actions(msgs).await;
                    }
                }
                _ = direct_addr_update_receiver.changed() => {
                    let reason = *direct_addr_update_receiver.borrow();
                    trace!("tick: direct addr update receiver {:?}", reason);
                    self.msock.metrics.magicsock.actor_tick_direct_addr_update_receiver.inc();
                    if let Some(reason) = reason {
                        self.refresh_direct_addrs(reason).await;
                    }
                }
                is_major = link_change_r.recv(), if !link_change_closed => {
                    let Some(is_major) = is_major else {
                        trace!("tick: link change receiver closed");
                        self.msock.metrics.magicsock.actor_tick_other.inc();

                        link_change_closed = true;
                        continue;
                    };

                    trace!("tick: link change {}", is_major);
                    self.msock.metrics.magicsock.actor_link_change.inc();
                    self.handle_network_change(is_major);
                }
                // Even if `discovery_events` yields `None`, it could begin to yield
                // `Some` again in the future, so we don't want to disable this branch
                // forever like we do with the other branches that yield `Option`s
                Some(discovery_item) = discovery_events.next() => {
                    trace!("tick: discovery event, address discovered: {discovery_item:?}");
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
                    // Send the discovery item to the subscribers of the discovery broadcast stream.
                    self.msock.discovery_subscribers.send(discovery_item);
                }
            }
        }
    }

    fn handle_network_change(&mut self, is_major: bool) {
        debug!("link change detected: major? {}", is_major);

        if is_major {
            if let Err(err) = self.msock.transports.rebind() {
                warn!("failed to rebind transports: {:?}", err);
            }

            #[cfg(not(wasm_browser))]
            self.msock.dns_resolver.clear_cache();
            self.msock.re_stun("link-change-major");
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
                self.network_monitor.network_change().await.ok();
            }
            #[cfg(test)]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major);
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
        self.msock.metrics.magicsock.update_direct_addrs.inc();

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
                let port = self
                    .msock
                    .transports
                    .ip_bind_addrs()
                    .into_iter()
                    .find_map(|addr| {
                        if addr.port() != 0 {
                            Some(addr.port())
                        } else {
                            None
                        }
                    });

                if let Some(port) = port {
                    if net_report_report
                        .mapping_varies_by_dest_ip
                        .unwrap_or_default()
                    {
                        let mut addr = global_v4;
                        addr.set_port(port);
                        addrs
                            .entry(addr.into())
                            .or_insert(DirectAddrType::Stun4LocalPort);
                    }
                }
            }
            if let Some(global_v6) = net_report_report.global_v6 {
                addrs
                    .entry(global_v6.into())
                    .or_insert(DirectAddrType::Stun);
            }
        }

        let local_addrs: Vec<_> = self
            .msock
            .transports
            .ip_bind_addrs()
            .into_iter()
            .zip(self.msock.transports.ip_local_addrs())
            .collect();

        let msock = self.msock.clone();

        // The following code can be slow, we do not want to block the caller since it would
        // block the actor loop.
        task::spawn(
            async move {
                // If a socket is bound to the unspecified address, create SocketAddrs for
                // each local IP address by pairing it with the port the socket is bound on.
                if local_addrs
                    .iter()
                    .any(|(bound, _)| bound.ip().is_unspecified())
                {
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
                            IpAddr::V4(_) => local_addrs
                                .iter()
                                .find_map(|(_, a)| a.is_ipv4().then(|| a.port())),
                            IpAddr::V6(_) => local_addrs
                                .iter()
                                .find_map(|(_, a)| a.is_ipv6().then(|| a.port())),
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
            // only returns Err if the report hasn't changed.
            self.msock.net_report.set(Some(report.clone())).ok();
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

            // Notify all transports
            self.msock.transports.on_network_change(&ni);

            // TODO: set link type
            self.call_net_info_callback(ni).await;
        }
        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(report);
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
fn bind_with_fallback(mut addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    debug!(%addr, "binding");

    // First try binding a preferred port, if specified
    match UdpSocket::bind_full(addr) {
        Ok(socket) => {
            let local_addr = socket.local_addr().context("UDP socket not bound")?;
            debug!(%addr, %local_addr, "successfully bound");
            return Ok(socket);
        }
        Err(err) => {
            debug!(%addr, "failed to bind: {err:#}");
            // If that was already the fallback port, then error out
            if addr.port() == 0 {
                return Err(err.into());
            }
        }
    }

    // Otherwise, try binding with port 0
    addr.set_port(0);
    UdpSocket::bind_full(addr).context("failed to bind on fallback port")
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
pub(crate) struct NetInfo {
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
    use crate::{dns::DnsResolver, tls, Endpoint, RelayMode};

    const ALPN: &[u8] = b"n0/test/1";

    impl Default for Options {
        fn default() -> Self {
            let secret_key = SecretKey::generate(rand::rngs::OsRng);
            let tls_auth = crate::tls::Authentication::RawPublicKey;
            let server_config = make_default_server_config(&secret_key, tls_auth);
            Options {
                addr_v4: None,
                addr_v6: None,
                secret_key,
                relay_map: RelayMap::empty(),
                relay_protocol: iroh_relay::http::Protocol::default(),
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
    fn make_default_server_config(
        secret_key: &SecretKey,
        tls_auth: crate::tls::Authentication,
    ) -> ServerConfig {
        let quic_server_config = crate::tls::TlsConfig::new(tls_auth, secret_key.clone())
            .make_server_config(vec![], false);
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
    async fn magicsock_ep(
        secret_key: SecretKey,
        tls_auth: tls::Authentication,
    ) -> anyhow::Result<Handle> {
        let quic_server_config = tls::TlsConfig::new(tls_auth, secret_key.clone())
            .make_server_config(vec![ALPN.to_vec()], true);
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(quinn::TransportConfig::default()));

        let dns_resolver = DnsResolver::new();
        let opts = Options {
            addr_v4: None,
            addr_v6: None,
            secret_key: secret_key.clone(),
            relay_map: RelayMap::empty(),
            relay_protocol: iroh_relay::http::Protocol::default(),
            node_map: None,
            discovery: None,
            discovery_user_data: None,
            dns_resolver,
            proxy_url: None,
            server_config,
            insecure_skip_relay_cert_verify: true,
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
        tls_auth: tls::Authentication,
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
            tls_auth,
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
        tls_auth: tls::Authentication,
    ) -> Result<quinn::Connection> {
        let alpns = vec![ALPN.to_vec()];
        let quic_client_config =
            tls::TlsConfig::new(tls_auth, ep_secret_key.clone()).make_client_config(alpns, true);
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(transport_config);
        let connect = ep.connect_with(
            client_config,
            mapped_addr.private_socket_addr(),
            &tls::name::encode(node_id),
        )?;
        let connection = connect.await?;
        Ok(connection)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_try_send_no_send_addr() {
        // Regression test: if there is no send_addr we should keep being able to use the
        // Endpoint.

        let tls_auth = tls::Authentication::RawPublicKey;

        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let node_id_2 = secret_key_2.public();
        let secret_key_missing_node = SecretKey::from_bytes(&[255u8; 32]);
        let node_id_missing_node = secret_key_missing_node.public();

        let msock_1 = magicsock_ep(secret_key_1.clone(), tls_auth).await.unwrap();

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
                tls_auth,
            ),
        )
        .await;
        assert!(res.is_err(), "expecting timeout");

        // Now check we can still create another connection with this endpoint.
        let msock_2 = magicsock_ep(secret_key_2.clone(), tls_auth).await.unwrap();

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
            magicsock_connect(
                msock_1.endpoint(),
                secret_key_1.clone(),
                addr,
                node_id_2,
                tls_auth,
            ),
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

        let tls_auth = tls::Authentication::RawPublicKey;

        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let node_id_2 = secret_key_2.public();

        let msock_1 = magicsock_ep(secret_key_1.clone(), tls_auth).await.unwrap();
        let msock_2 = magicsock_ep(secret_key_2.clone(), tls_auth).await.unwrap();
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
            tls_auth,
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
            let conn = magicsock_connect(
                msock_1.endpoint(),
                secret_key_1.clone(),
                addr_2,
                node_id_2,
                tls_auth,
            )
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
