//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock
//!
//! ### `DEV_RELAY_ONLY` env var:
//! When present at *compile time*, this env var will force all packets
//! to be sent over the relay connection, regardless of whether or
//! not we have a direct UDP address for the given node.
//!
//! The intended use is for testing the relay protocol inside the MagicSock
//! to ensure that we can rely on the relay to send packets when two nodes
//! are unable to find direct UDP connections to each other.
//!
//! This also prevent this node from attempting to hole punch and prevents it
//! from responding to any hole punching attempts. This node will still,
//! however, read any packets that come off the UDP sockets.

// #[cfg(test)]
// pub(crate) use conn::tests as conn_tests;

use std::{
    collections::HashMap,
    fmt::Display,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc,
    },
    task::{ready, Context, Poll, Waker},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures::{FutureExt, Stream};
use iroh_metrics::{inc, inc_by};
use quinn::AsyncUdpSocket;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use smallvec::{smallvec, SmallVec};
use tokio::{
    sync::{self, mpsc, Mutex},
    task::JoinSet,
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{
    debug, error, error_span, info, info_span, instrument, trace, trace_span, warn, Instrument,
};
use watchable::Watchable;

use crate::{
    config,
    disco::{self, SendAddr},
    discovery::Discovery,
    dns::DnsResolver,
    key::{PublicKey, SecretKey, SharedSecret},
    magic_endpoint::NodeAddr,
    net::{interfaces, ip::LocalAddresses, netmon, IpFamily},
    netcheck, portmapper,
    relay::{RelayMap, RelayUrl},
    stun, AddrInfo,
};

use self::{
    metrics::Metrics as MagicsockMetrics,
    node_map::{NodeMap, PingAction, PingRole, SendPing},
    relay_actor::{RelayActor, RelayActorMessage, RelayReadResult},
    udp_conn::UdpConn,
};

mod metrics;
mod node_map;
mod relay_actor;
mod timer;
mod udp_conn;

pub use crate::net::UdpSocket;

pub use self::metrics::Metrics;
pub use self::node_map::{
    ConnectionType, ConnectionTypeStream, ControlMsg, DirectAddrInfo, EndpointInfo,
};
pub use self::timer::Timer;

/// How long we consider a STUN-derived endpoint valid for. UDP NAT mappings typically
/// expire at 30 seconds, so this is a few seconds shy of that.
const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How often to save node data.
const SAVE_NODES_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum duration to wait for a netcheck report.
const NETCHECK_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// Contains options for `MagicSock::listen`.
#[derive(derive_more::Debug)]
pub struct Options {
    /// The port to listen on.
    /// Zero means to pick one automatically.
    pub port: u16,

    /// Secret key for this node.
    pub secret_key: SecretKey,

    /// The [`RelayMap`] to use, leave empty to not use a relay server.
    pub relay_map: RelayMap,

    /// Path to store known nodes.
    pub nodes_path: Option<std::path::PathBuf>,

    /// Optional node discovery mechanism.
    pub discovery: Option<Box<dyn Discovery>>,

    /// A DNS resolver to use for resolving relay URLs.
    ///
    /// You can use [`crate::dns::default_resolver`] for a resolver that uses the system's DNS
    /// configuration.
    pub dns_resolver: DnsResolver,

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub insecure_skip_relay_cert_verify: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            port: 0,
            secret_key: SecretKey::generate(),
            relay_map: RelayMap::empty(),
            nodes_path: None,
            discovery: None,
            dns_resolver: crate::dns::default_resolver().clone(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
        }
    }
}

/// Contents of a relay message. Use a SmallVec to avoid allocations for the very
/// common case of a single packet.
pub(crate) type RelayContents = SmallVec<[Bytes; 1]>;

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to nodes based on node IDs, it will initially
/// route packets via a relay and transparently try and establish a node-to-node
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both endpoints change.
///
/// It is usually only necessary to use a single [`MagicSock`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about nodes as
/// possible.
#[derive(Clone, Debug)]
pub struct MagicSock {
    inner: Arc<MagicSockInner>,
    // Empty when closed
    actor_tasks: Arc<Mutex<JoinSet<()>>>,
}

/// The actual implementation of `MagicSock`.
#[derive(derive_more::Debug)]
pub(super) struct MagicSockInner {
    actor_sender: mpsc::Sender<ActorMessage>,
    relay_actor_sender: mpsc::Sender<RelayActorMessage>,
    /// String representation of the node_id of this node.
    me: String,
    /// Used for receiving relay messages.
    relay_recv_receiver: flume::Receiver<RelayRecvResult>,
    /// Stores wakers, to be called when relay_recv_ch receives new data.
    network_recv_wakers: parking_lot::Mutex<Option<Waker>>,
    network_send_wakers: parking_lot::Mutex<Option<Waker>>,

    /// The DNS resolver to be used in this magicsock.
    dns_resolver: DnsResolver,

    /// Key for this node.
    secret_key: SecretKey,

    /// Cached version of the Ipv4 and Ipv6 addrs of the current connection.
    local_addrs: std::sync::RwLock<(SocketAddr, Option<SocketAddr>)>,

    /// Preferred port from `Options::port`; 0 means auto.
    port: AtomicU16,

    /// Close is in progress (or done)
    closing: AtomicBool,
    /// Close was called.
    closed: AtomicBool,
    /// If the last netcheck report, reports IPv6 to be available.
    ipv6_reported: Arc<AtomicBool>,

    /// None (or zero nodes) means relay is disabled.
    relay_map: RelayMap,
    /// Nearest relay node ID; 0 means none/unknown.
    my_relay: std::sync::RwLock<Option<RelayUrl>>,
    /// Tracks the networkmap node entity for each node discovery key.
    node_map: NodeMap,
    /// UDP IPv4 socket
    pconn4: UdpConn,
    /// UDP IPv6 socket
    pconn6: Option<UdpConn>,
    /// Netcheck client
    net_checker: netcheck::Client,
    /// The state for an active DiscoKey.
    disco_secrets: DiscoSecrets,
    udp_state: quinn_udp::UdpState,

    /// Send buffer used in `poll_send_udp`
    send_buffer: parking_lot::Mutex<Vec<quinn_udp::Transmit>>,
    /// UDP disco (ping) queue
    udp_disco_sender: mpsc::Sender<(SocketAddr, PublicKey, disco::Message)>,

    /// Optional discovery service
    discovery: Option<Box<dyn Discovery>>,

    /// Our discovered endpoints
    endpoints: Watchable<DiscoveredEndpoints>,

    /// List of CallMeMaybe disco messages that should be sent out after the next endpoint update
    /// completes
    pending_call_me_maybes: parking_lot::Mutex<HashMap<PublicKey, RelayUrl>>,

    /// Indicates the update endpoint state.
    endpoints_update_state: EndpointUpdateState,

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
}

impl MagicSockInner {
    /// Returns the relay node we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any relay nodes.
    pub(super) fn my_relay(&self) -> Option<RelayUrl> {
        self.my_relay.read().expect("not poisoned").clone()
    }

    /// Sets the relay node with the best latency.
    ///
    /// If we are not connected to any relay nodes, set this to `None`.
    fn set_my_relay(&self, my_relay: Option<RelayUrl>) -> Option<RelayUrl> {
        let mut lock = self.my_relay.write().expect("not poisoned");
        let old = lock.take();
        *lock = my_relay;
        old
    }

    fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn public_key(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Reference to optional discovery service
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.discovery.as_ref().map(Box::as_ref)
    }

    /// Get the cached version of the Ipv4 and Ipv6 addrs of the current connection.
    pub(super) fn local_addr(&self) -> (SocketAddr, Option<SocketAddr>) {
        *self.local_addrs.read().expect("not poisoned")
    }

    pub(super) fn get_mapping_addr(&self, node_id: &PublicKey) -> Option<SocketAddr> {
        self.node_map
            .get_quic_mapped_addr_for_node_key(node_id)
            .map(|a| a.0)
    }

    pub(super) fn add_node_addr(&self, addr: NodeAddr) {
        self.node_map.add_node_addr(addr);
    }

    fn normalized_local_addr(&self) -> io::Result<SocketAddr> {
        let (v4, v6) = self.local_addr();
        let addr = if let Some(v6) = v6 { v6 } else { v4 };
        Ok(addr)
    }

    pub(super) fn local_endpoints(&self) -> LocalEndpointsStream {
        LocalEndpointsStream {
            initial: Some(self.endpoints.get()),
            inner: self.endpoints.watch().into_stream(),
        }
    }

    /// Retrieve connection information about nodes in the network.
    pub(super) fn tracked_endpoints(&self) -> Vec<EndpointInfo> {
        self.node_map.endpoint_infos(Instant::now())
    }

    /// Returns a stream that reports the [`ConnectionType`] we have to the
    /// given `node_id`.
    ///
    /// The `NodeMap` continuously monitors the `node_id`'s endpoint for
    /// [`ConnectionType`] changes, and sends the latest [`ConnectionType`]
    /// on the stream.
    ///
    /// The current [`ConnectionType`] will the the initial entry on the stream.
    ///
    /// # Errors
    ///
    /// Will return an error if there is no address information known about the
    /// given `node_id`.
    pub(super) fn conn_type_stream(&self, node_id: &PublicKey) -> Result<ConnectionTypeStream> {
        self.node_map.conn_type_stream(node_id)
    }

    /// Retrieve connection information about a node in the network.
    pub(super) fn tracked_endpoint(&self, node_key: PublicKey) -> Option<EndpointInfo> {
        self.node_map.endpoint_info(&node_key)
    }

    pub(super) async fn network_change(&self) {
        self.actor_sender
            .send(ActorMessage::NetworkChange)
            .await
            .ok();
    }

    #[instrument(skip_all, fields(me = %self.me))]
    fn poll_send(
        &self,
        cx: &mut Context,
        transmits: &[quinn_udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        let bytes_total: usize = transmits.iter().map(|t| t.contents.len()).sum();
        inc_by!(MagicsockMetrics, send_data, bytes_total as _);

        if self.is_closed() {
            inc_by!(MagicsockMetrics, send_data_network_down, bytes_total as _);
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            )));
        }

        let mut n = 0;
        if transmits.is_empty() {
            return Poll::Ready(Ok(n));
        }
        trace!(
            "sending:\n{}",
            transmits.iter().fold(
                String::with_capacity(transmits.len() * 50),
                |mut final_repr, t| {
                    final_repr.push_str(
                        format!(
                            "  dest: {}, src: {:?}, content_len: {}\n",
                            QuicMappedAddr(t.destination),
                            t.src_ip,
                            t.contents.len()
                        )
                        .as_str(),
                    );
                    final_repr
                }
            )
        );

        let dest = transmits[0].destination;
        for transmit in transmits.iter() {
            if transmit.destination != dest {
                break;
            }
            n += 1;
        }

        // Copy the transmits into an owned buffer, because we will have to modify the send
        // addresses to translate from the quic mapped address to the actual UDP address.
        // To avoid allocating on each call to `poll_send`, we use a fixed buffer.
        let mut transmits = {
            let mut buf = self.send_buffer.lock();
            buf.clear();
            buf.reserve(n);
            buf.extend_from_slice(&transmits[..n]);
            buf
        };

        let dest = QuicMappedAddr(dest);

        let mut transmits_sent = 0;
        match self
            .node_map
            .get_send_addrs_for_quic_mapped_addr(&dest, self.ipv6_reported.load(Ordering::Relaxed))
        {
            Some((public_key, udp_addr, relay_url, mut msgs)) => {
                let mut pings_sent = false;
                // If we have pings to send, we *have* to send them out first.
                if !msgs.is_empty() {
                    if let Err(err) = ready!(self.poll_handle_ping_actions(cx, &mut msgs)) {
                        warn!(node = %public_key.fmt_short(), "failed to handle ping actions: {err:?}");
                    }
                    pings_sent = true;
                }

                let mut udp_sent = false;
                let mut relay_sent = false;
                let mut udp_error = None;
                let mut udp_pending = false;
                let mut relay_pending = false;

                // send udp
                if let Some(addr) = udp_addr {
                    // rewrite target addresses.
                    for t in transmits.iter_mut() {
                        t.destination = addr;
                    }
                    match self.poll_send_udp(addr, &transmits, cx) {
                        Poll::Ready(Ok(n)) => {
                            trace!(node = %public_key.fmt_short(), dst = %addr, transmit_count=n, "sent transmits over UDP");
                            // truncate the transmits vec to `n`. these transmits will be sent to
                            // the relay further below. We only want to send those transmits to the relay that were
                            // sent to UDP, because the next transmits will be sent on the next
                            // call to poll_send, which will happen immediately after, because we
                            // are always returning Poll::Ready if poll_send_udp returned
                            // Poll::Ready.
                            transmits.truncate(n);
                            transmits_sent = transmits.len();
                            udp_sent = true;
                            // record metrics.
                        }
                        Poll::Ready(Err(err)) => {
                            error!(node = %public_key.fmt_short(), ?addr, "failed to send udp: {err:?}");
                            udp_error = Some(err);
                        }
                        Poll::Pending => {
                            udp_pending = true;
                        }
                    }
                }

                // send relay
                if let Some(ref relay_url) = relay_url {
                    match self.poll_send_relay(relay_url, public_key, split_packets(&transmits)) {
                        Poll::Ready(sent) => {
                            relay_sent = sent;
                            transmits_sent = transmits.len();
                        }
                        Poll::Pending => {
                            self.network_send_wakers.lock().replace(cx.waker().clone());
                            relay_pending = true;
                        }
                    }
                }

                if udp_addr.is_none() && relay_url.is_none() {
                    // Handle no addresses being available
                    warn!(node = %public_key.fmt_short(), "failed to send: no UDP or relay addr");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "no UDP or relay address available for node",
                    )));
                }

                if (udp_addr.is_none() || udp_pending) && (relay_url.is_none() || relay_pending) {
                    // Handle backpressure
                    // The explicit choice here is to only return pending, iff all available paths returned
                    // pending.
                    // This might result in one channel being backed up, without the system noticing, but
                    // for now this seems to be the best choice workable in the current implementation.
                    return Poll::Pending;
                }

                if !relay_sent && !udp_sent && !pings_sent {
                    warn!(node = %public_key.fmt_short(), "failed to send: no UDP or relay addr");
                    let err = udp_error.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no UDP or relay address available for node",
                        )
                    });
                    return Poll::Ready(Err(err));
                }

                trace!(
                    node = %public_key.fmt_short(),
                    transmit_count = %transmits_sent,
                    send_udp = ?udp_addr,
                    send_relay = ?relay_url,
                    "sent transmits"
                );
                Poll::Ready(Ok(transmits_sent))
            }
            None => {
                error!(dst=%dest, "no endpoint for mapped address");
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "trying to send to unknown endpoint",
                )))
            }
        }
    }

    fn poll_send_udp(
        &self,
        addr: SocketAddr,
        transmits: &[quinn_udp::Transmit],
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let conn = self.conn_for_addr(addr)?;
        let n = ready!(conn.poll_send(&self.udp_state, cx, transmits))?;
        let total_bytes: u64 = transmits
            .iter()
            .take(n)
            .map(|x| x.contents.len() as u64)
            .sum();
        if addr.is_ipv6() {
            inc_by!(MagicsockMetrics, send_ipv6, total_bytes);
        } else {
            inc_by!(MagicsockMetrics, send_ipv4, total_bytes);
        }
        Poll::Ready(Ok(n))
    }

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

    #[instrument(skip_all, fields(me = %self.me))]
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // FIXME: currently ipv4 load results in ipv6 traffic being ignored
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            )));
        }

        // order of polling is: UDPv4, UDPv6, relay
        let msgs = match self.pconn4.poll_recv(cx, bufs, metas)? {
            Poll::Pending | Poll::Ready(0) => match &self.pconn6 {
                Some(conn) => match conn.poll_recv(cx, bufs, metas)? {
                    Poll::Pending | Poll::Ready(0) => {
                        return self.poll_recv_relay(cx, bufs, metas);
                    }
                    Poll::Ready(n) => n,
                },
                None => {
                    return self.poll_recv_relay(cx, bufs, metas);
                }
            },
            Poll::Ready(n) => n,
        };

        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());

        let mut quic_packets_total = 0;

        for (meta, buf) in metas.iter_mut().zip(bufs.iter_mut()).take(msgs) {
            let mut start = 0;
            let mut is_quic = false;
            let mut quic_packets_count = 0;

            // find disco and stun packets and forward them to the actor
            loop {
                let end = start + meta.stride;
                if end > meta.len {
                    break;
                }
                let packet = &buf[start..end];
                let packet_is_quic = if stun::is(packet) {
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: stun packet");
                    let packet2 = Bytes::copy_from_slice(packet);
                    self.net_checker.receive_stun_packet(packet2, meta.addr);
                    false
                } else if let Some((sender, sealed_box)) = disco::source_and_box(packet) {
                    // Disco?
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: disco packet");
                    self.handle_disco_message(
                        sender,
                        sealed_box,
                        DiscoMessageSource::Udp(meta.addr),
                    );
                    false
                } else {
                    trace!(src = %meta.addr, len = %meta.stride, "UDP recv: quic packet");
                    true
                };

                if packet_is_quic {
                    quic_packets_count += 1;
                    is_quic = true;
                } else {
                    // overwrite the first byte of the packets with zero.
                    // this makes quinn reliably and quickly ignore the packet as long as
                    // [`quinn::EndpointConfig::grease_quic_bit`] is set to `false`
                    // (which we always do in MagicEndpoint::bind).
                    buf[start] = 0u8;
                }
                start = end;
            }

            if is_quic {
                // remap addr
                match self.node_map.receive_udp(meta.addr) {
                    None => {
                        warn!(src = ?meta.addr, count = %quic_packets_count, len = meta.len, "UDP recv quic packets: no node state found, skipping");
                        // if we have no node state for the from addr, set len to 0 to make quinn skip the buf completely.
                        meta.len = 0;
                    }
                    Some((node_id, quic_mapped_addr)) => {
                        trace!(src = ?meta.addr, node = %node_id.fmt_short(), count = %quic_packets_count, len = meta.len, "UDP recv quic packets");
                        quic_packets_total += quic_packets_count;
                        meta.addr = quic_mapped_addr.0;
                    }
                }
            } else {
                // if there is no non-stun,non-disco packet in the chunk, set len to zero to make
                // quinn skip the buf completely.
                meta.len = 0;
            }
            // Normalize local_ip
            meta.dst_ip = dst_ip;
        }

        if quic_packets_total > 0 {
            inc_by!(MagicsockMetrics, recv_datagrams, quic_packets_total as _);
            trace!("UDP recv: {} packets", quic_packets_total);
        }

        Poll::Ready(Ok(msgs))
    }

    #[instrument(skip_all, fields(name = %self.me))]
    fn poll_recv_relay(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;
        for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
            if self.is_closed() {
                break;
            }
            match self.relay_recv_receiver.try_recv() {
                Err(flume::TryRecvError::Empty) => {
                    self.network_recv_wakers.lock().replace(cx.waker().clone());
                    break;
                }
                Err(flume::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Ok(Ok((node_id, meta, bytes))) => {
                    inc_by!(MagicsockMetrics, recv_data_relay, bytes.len() as _);
                    trace!(src = %meta.addr, node = %node_id.fmt_short(), count = meta.len / meta.stride, len = meta.len, "recv quic packets from relay");
                    buf_out[..bytes.len()].copy_from_slice(&bytes);
                    *meta_out = meta;
                    num_msgs += 1;
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
            &self.secret_key,
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
                self.handle_ping(ping, &sender, src);
            }
            disco::Message::Pong(pong) => {
                inc!(MagicsockMetrics, recv_disco_pong);
                self.node_map.handle_pong(sender, &src, pong);
            }
            disco::Message::CallMeMaybe(cm) => {
                inc!(MagicsockMetrics, recv_disco_call_me_maybe);
                if !matches!(src, DiscoMessageSource::Relay { .. }) {
                    warn!("call-me-maybe packets should only come via relay");
                    return;
                };
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
    fn handle_ping(&self, dm: disco::Ping, sender: &PublicKey, src: DiscoMessageSource) {
        // Insert the ping into the node map, and return whether a ping with this tx_id was already
        // received.
        let addr: SendAddr = src.clone().into();
        let handled = self.node_map.handle_ping(*sender, addr.clone(), dm.tx_id);
        match handled.role {
            PingRole::Duplicate => {
                debug!(%src, tx = %hex::encode(dm.tx_id), "received ping: endpoint already confirmed, skip");
                return;
            }
            PingRole::LikelyHeartbeat => {}
            PingRole::NewEndpoint => {
                debug!(%src, tx = %hex::encode(dm.tx_id), "received ping: new endpoint");
            }
            PingRole::Reactivate => {
                debug!(%src, tx = %hex::encode(dm.tx_id), "received ping: endpoint active");
            }
        }

        // Send a pong.
        debug!(tx = %hex::encode(dm.tx_id), %addr, dstkey = %sender.fmt_short(),
               "sending pong");
        let pong = disco::Message::Pong(disco::Pong {
            tx_id: dm.tx_id,
            src: addr.clone(),
        });

        if !self.send_disco_message_queued(addr.clone(), *sender, pong) {
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
        self.disco_secrets
            .encode_and_seal(&self.secret_key, dst_key, msg)
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
            SendAddr::Udp(addr) => self
                .udp_disco_sender
                .try_send((addr, dst_node, msg))
                .is_ok(),
            SendAddr::Relay(ref url) => self.send_disco_message_relay(url, dst_node, msg),
        };
        if sent {
            let msg_sender = self.actor_sender.clone();
            trace!(%dst, tx = %hex::encode(tx_id), ?purpose, "ping sent (queued)");
            self.node_map
                .notify_ping_sent(id, dst, tx_id, purpose, msg_sender);
        } else {
            warn!(dst = ?dst, tx = %hex::encode(tx_id), ?purpose, "failed to send ping: queues full");
        }
    }

    fn poll_send_ping(&self, ping: &SendPing, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let SendPing {
            id,
            dst,
            dst_node,
            tx_id,
            purpose,
        } = ping;
        let msg = disco::Message::Ping(disco::Ping {
            tx_id: *tx_id,
            node_key: self.public_key(),
        });
        ready!(self.poll_send_disco_message(dst.clone(), *dst_node, msg, cx))?;
        let msg_sender = self.actor_sender.clone();
        debug!(%dst, tx = %hex::encode(tx_id), ?purpose, "ping sent (polled)");
        self.node_map
            .notify_ping_sent(*id, dst.clone(), *tx_id, *purpose, msg_sender);
        Poll::Ready(Ok(()))
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
    fn poll_send_disco_message(
        &self,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match dst {
            SendAddr::Udp(addr) => {
                ready!(self.poll_send_disco_message_udp(addr, dst_key, &msg, cx))?;
            }
            SendAddr::Relay(ref url) => {
                self.send_disco_message_relay(url, dst_key, msg);
            }
        }
        Poll::Ready(Ok(()))
    }

    fn send_disco_message_relay(
        &self,
        url: &RelayUrl,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> bool {
        debug!(node = %dst_key.fmt_short(), %url, %msg, "send disco message (relay)");
        let pkt = self.encode_disco_message(dst_key, &msg);
        inc!(MagicsockMetrics, send_disco_relay);
        match self.poll_send_relay(url, dst_key, smallvec![pkt]) {
            Poll::Ready(true) => {
                inc!(MagicsockMetrics, sent_disco_relay);
                disco_message_sent(&msg);
                true
            }
            _ => false,
        }
    }

    async fn send_disco_message_udp(
        &self,
        dst: SocketAddr,
        dst_key: PublicKey,
        msg: &disco::Message,
    ) -> io::Result<bool> {
        futures::future::poll_fn(move |cx| self.poll_send_disco_message_udp(dst, dst_key, msg, cx))
            .await
    }

    fn poll_send_disco_message_udp(
        &self,
        dst: SocketAddr,
        dst_key: PublicKey,
        msg: &disco::Message,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<bool>> {
        trace!(%dst, %msg, "send disco message (UDP)");
        if self.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            )));
        }
        let pkt = self.encode_disco_message(dst_key, msg);
        // TODO: These metrics will be wrong with the poll impl
        // Also - do we need it? I'd say the `sent_disco_udp` below is enough.
        inc!(MagicsockMetrics, send_disco_udp);
        let transmits = [quinn_udp::Transmit {
            destination: dst,
            contents: pkt,
            ecn: None,
            segment_size: None,
            src_ip: None, // TODO
        }];
        let sent = ready!(self.poll_send_udp(dst, &transmits, cx));
        Poll::Ready(match sent {
            Ok(0) => {
                // Can't send. (e.g. no IPv6 locally)
                warn!(%dst, node = %dst_key.fmt_short(), ?msg, "failed to send disco message");
                Ok(false)
            }
            Ok(_n) => {
                trace!(%dst, node = %dst_key.fmt_short(), %msg, "sent disco message");
                inc!(MagicsockMetrics, sent_disco_udp);
                disco_message_sent(msg);
                Ok(true)
            }
            Err(err) => {
                warn!(%dst, node = %dst_key.fmt_short(), ?msg, ?err, "failed to send disco message");
                Err(err)
            }
        })
    }

    fn poll_handle_ping_actions(
        &self,
        cx: &mut Context<'_>,
        msgs: &mut Vec<PingAction>,
    ) -> Poll<io::Result<()>> {
        if msgs.is_empty() {
            return Poll::Ready(Ok(()));
        }

        while let Some(msg) = msgs.pop() {
            if self.poll_handle_ping_action(cx, &msg)?.is_pending() {
                msgs.push(msg);
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
    }

    #[instrument("handle_ping_action", skip_all)]
    fn poll_handle_ping_action(
        &self,
        cx: &mut Context<'_>,
        msg: &PingAction,
    ) -> Poll<io::Result<()>> {
        // Abort sending as soon as we know we are shutting down.
        if self.is_closing() || self.is_closed() {
            return Poll::Ready(Ok(()));
        }
        match *msg {
            PingAction::SendCallMeMaybe {
                ref relay_url,
                dst_node,
            } => {
                self.send_or_queue_call_me_maybe(relay_url, dst_node);
            }
            PingAction::SendPing(ref ping) => {
                ready!(self.poll_send_ping(ping, cx))?;
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_send_relay(
        &self,
        url: &RelayUrl,
        node: PublicKey,
        contents: RelayContents,
    ) -> Poll<bool> {
        trace!(node = %node.fmt_short(), relay_url = %url, count = contents.len(), len = contents.iter().map(|c| c.len()).sum::<usize>(), "send relay");
        let msg = RelayActorMessage::Send {
            url: url.clone(),
            contents,
            peer: node,
        };
        match self.relay_actor_sender.try_send(msg) {
            Ok(_) => {
                trace!(node = %node.fmt_short(), relay_url = %url, "send relay: message queued");
                Poll::Ready(true)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(node = %node.fmt_short(), relay_url = %url, "send relay: message dropped, channel to actor is closed");
                Poll::Ready(false)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %node.fmt_short(), relay_url = %url, "send relay: message dropped, channel to actor is full");
                Poll::Pending
            }
        }
    }

    fn send_queued_call_me_maybes(&self) {
        let msg = self.endpoints.read().to_call_me_maybe_message();
        let msg = disco::Message::CallMeMaybe(msg);
        for (public_key, url) in self.pending_call_me_maybes.lock().drain() {
            if !self.send_disco_message_relay(&url, public_key, msg.clone()) {
                warn!(node = %public_key.fmt_short(), "relay channel full, dropping call-me-maybe");
            }
        }
    }

    fn send_or_queue_call_me_maybe(&self, url: &RelayUrl, dst_key: PublicKey) {
        let endpoints = self.endpoints.read();
        if endpoints.fresh_enough() {
            let msg = endpoints.to_call_me_maybe_message();
            let msg = disco::Message::CallMeMaybe(msg);
            if !self.send_disco_message_relay(url, dst_key, msg) {
                warn!(dstkey = %dst_key.fmt_short(), relayurl = ?url,
                      "relay channel full, dropping call-me-maybe");
            } else {
                debug!(dstkey = %dst_key.fmt_short(), relayurl = ?url, "call-me-maybe sent");
            }
        } else {
            self.pending_call_me_maybes
                .lock()
                .insert(dst_key, url.clone());
            debug!(
                last_refresh_ago = ?endpoints.last_endpoints_time.map(|x| x.elapsed()),
                "want call-me-maybe but endpoints stale; queuing after restun",
            );
            self.re_stun("refresh-for-peering");
        }
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    fn re_stun(&self, why: &'static str) {
        debug!("re_stun: {}", why);
        inc!(MagicsockMetrics, re_stun_calls);
        self.endpoints_update_state.schedule_run(why);
    }

    /// Publishes our address to a discovery service, if configured.
    ///
    /// Called whenever our addresses or home relay node changes.
    fn publish_my_addr(&self) {
        if let Some(ref discovery) = self.discovery {
            let eps = self.endpoints.read();
            let relay_url = self.my_relay();
            let direct_addresses = eps.iter().map(|ep| ep.addr).collect();
            let info = AddrInfo {
                relay_url,
                direct_addresses,
            };
            discovery.publish(&info);
        }
    }

    #[cfg(test)]
    async fn force_network_change(&self, is_major: bool) {
        self.actor_sender
            .send(ActorMessage::ForceNetworkChange(is_major))
            .await
            .ok();
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

/// Manages currently running endpoint updates, aka netcheck runs.
///
/// Invariants:
/// - only one endpoint update must be running at a time
/// - if an update is scheduled while another one is running, remember that
///   and start a new one when the current one has finished
#[derive(Debug)]
struct EndpointUpdateState {
    /// If running, set to the reason for the currently the update.
    running: sync::watch::Sender<Option<&'static str>>,
    /// If set, this means we will start a new endpoint update state as soon as the current one
    /// is finished.
    want_update: parking_lot::Mutex<Option<&'static str>>,
}

impl EndpointUpdateState {
    fn new() -> Self {
        let (running, _) = sync::watch::channel(None);
        EndpointUpdateState {
            running,
            want_update: Default::default(),
        }
    }

    /// Schedules a new run, either starting it immediately if none is running or
    /// scheduling it for later.
    fn schedule_run(&self, why: &'static str) {
        if self.is_running() {
            let _ = self.want_update.lock().insert(why);
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
        self.want_update.lock().take()
    }
}

impl MagicSock {
    /// Creates a magic `MagicSock` listening on `opts.port`.
    pub async fn new(opts: Options) -> Result<Self> {
        let me = opts.secret_key.public().fmt_short();
        if crate::util::relay_only_mode() {
            warn!(
                "creating a MagicSock that will only send packets over a relay relay connection."
            );
        }

        Self::with_name(me.clone(), opts)
            .instrument(error_span!("magicsock", %me))
            .await
    }

    async fn with_name(me: String, opts: Options) -> Result<Self> {
        let port_mapper = portmapper::Client::default();

        let Options {
            port,
            secret_key,
            relay_map,
            discovery,
            nodes_path,
            dns_resolver,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
        } = opts;

        let nodes_path = match nodes_path {
            Some(path) => {
                let path = path.canonicalize().unwrap_or(path);
                let parent = path.parent().ok_or_else(|| {
                    anyhow::anyhow!("no parent directory found for '{}'", path.display())
                })?;
                tokio::fs::create_dir_all(&parent).await?;
                Some(path)
            }
            None => None,
        };

        let (relay_recv_sender, relay_recv_receiver) = flume::bounded(128);

        let (pconn4, pconn6) = bind(port)?;
        let port = pconn4.port();

        // NOTE: we can end up with a zero port if `std::net::UdpSocket::socket_addr` fails
        match port.try_into() {
            Ok(non_zero_port) => {
                port_mapper.update_local_port(non_zero_port);
            }
            Err(_zero_port) => debug!("Skipping port mapping with zero local port"),
        }
        let ipv4_addr = pconn4.local_addr()?;
        let ipv6_addr = pconn6.as_ref().and_then(|c| c.local_addr().ok());

        let net_checker = netcheck::Client::new(Some(port_mapper.clone()), dns_resolver.clone())?;

        let (actor_sender, actor_receiver) = mpsc::channel(256);
        let (relay_actor_sender, relay_actor_receiver) = mpsc::channel(256);
        let (udp_disco_sender, mut udp_disco_receiver) = mpsc::channel(256);

        // load the node data
        let node_map = match nodes_path.as_ref() {
            Some(path) if path.exists() => match NodeMap::load_from_file(path) {
                Ok(node_map) => {
                    let count = node_map.node_count();
                    debug!(count, "loaded node map");
                    node_map
                }
                Err(e) => {
                    debug!(%e, "failed to load node map: using default");
                    NodeMap::default()
                }
            },
            _ => NodeMap::default(),
        };

        let udp_state = quinn_udp::UdpState::default();
        let msock = Arc::new(MagicSockInner {
            me,
            port: AtomicU16::new(port),
            secret_key,
            local_addrs: std::sync::RwLock::new((ipv4_addr, ipv6_addr)),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            relay_recv_receiver,
            network_recv_wakers: parking_lot::Mutex::new(None),
            network_send_wakers: parking_lot::Mutex::new(None),
            actor_sender: actor_sender.clone(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            relay_map,
            my_relay: Default::default(),
            pconn4: pconn4.clone(),
            pconn6: pconn6.clone(),
            net_checker: net_checker.clone(),
            disco_secrets: DiscoSecrets::default(),
            node_map,
            relay_actor_sender: relay_actor_sender.clone(),
            udp_state,
            send_buffer: Default::default(),
            udp_disco_sender,
            discovery,
            endpoints: Watchable::new(Default::default()),
            pending_call_me_maybes: Default::default(),
            endpoints_update_state: EndpointUpdateState::new(),
            dns_resolver,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
        });

        let mut actor_tasks = JoinSet::default();

        let relay_actor = RelayActor::new(msock.clone(), actor_sender.clone());
        let relay_actor_cancel_token = relay_actor.cancel_token();
        actor_tasks.spawn(
            async move {
                relay_actor.run(relay_actor_receiver).await;
            }
            .instrument(info_span!("relay-actor")),
        );

        let msock2 = msock.clone();
        actor_tasks.spawn(async move {
            while let Some((dst, dst_key, msg)) = udp_disco_receiver.recv().await {
                if let Err(err) = msock2.send_disco_message_udp(dst, dst_key, &msg).await {
                    warn!(%dst, node = %dst_key.fmt_short(), ?err, "failed to send disco message (UDP)");
                }
            }
        });

        let msock2 = msock.clone();
        let network_monitor = netmon::Monitor::new().await?;
        actor_tasks.spawn(
            async move {
                let actor = Actor {
                    msg_receiver: actor_receiver,
                    msg_sender: actor_sender,
                    relay_actor_sender,
                    relay_actor_cancel_token,
                    msock: msock2,
                    relay_recv_sender,
                    periodic_re_stun_timer: new_re_stun_timer(false),
                    net_info_last: None,
                    nodes_path,
                    port_mapper,
                    pconn4,
                    pconn6,
                    no_v4_send: false,
                    net_checker,
                    network_monitor,
                };

                if let Err(err) = actor.run().await {
                    warn!("relay handler errored: {:?}", err);
                }
            }
            .instrument(info_span!("actor")),
        );

        let c = MagicSock {
            inner: msock,
            actor_tasks: Arc::new(Mutex::new(actor_tasks)),
        };

        Ok(c)
    }

    pub(super) fn inner(&self) -> Arc<MagicSockInner> {
        self.inner.clone()
    }

    /// Retrieve connection information about nodes in the network.
    pub fn tracked_endpoints(&self) -> Vec<EndpointInfo> {
        self.inner.tracked_endpoints()
    }

    /// Retrieve connection information about a node in the network.
    pub fn tracked_endpoint(&self, node_id: PublicKey) -> Option<EndpointInfo> {
        self.inner.tracked_endpoint(node_id)
    }

    /// Returns the local endpoints as a stream.
    ///
    /// The [`MagicSock`] continuously monitors the local endpoints, the network addresses
    /// it can listen on, for changes.  Whenever changes are detected this stream will yield
    /// a new list of endpoints.
    ///
    /// Upon the first creation on the [`MagicSock`] it may not yet have completed a first
    /// local endpoint discovery, in this case the first item of the stream will not be
    /// immediately available.  Once this first set of local endpoints are discovered the
    /// stream will always return the first set of endpoints immediately, which are the most
    /// recently discovered endpoints.
    ///
    /// # Examples
    ///
    /// To get the current endpoints, drop the stream after the first item was received:
    /// ```
    /// use futures::StreamExt;
    /// use iroh_net::magicsock::MagicSock;
    ///
    /// # let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    /// # rt.block_on(async move {
    /// let ms = MagicSock::new(Default::default()).await.unwrap();
    /// let _endpoints = ms.local_endpoints().next().await;
    /// # });
    /// ```
    pub fn local_endpoints(&self) -> LocalEndpointsStream {
        self.inner.local_endpoints()
    }

    /// Returns a stream that reports the [`ConnectionType`] we have to the
    /// given `node_id`.
    ///
    /// The `NodeMap` continuously monitors the `node_id`'s endpoint for
    /// [`ConnectionType`] changes, and sends the latest [`ConnectionType`]
    /// on the stream.
    ///
    /// The current [`ConnectionType`] will the the initial entry on the stream.
    ///
    /// # Errors
    ///
    /// Will return an error if there is no address information known about the
    /// given `node_id`.
    pub fn conn_type_stream(&self, node_id: &PublicKey) -> Result<node_map::ConnectionTypeStream> {
        self.inner.conn_type_stream(node_id)
    }

    /// Get the cached version of the Ipv4 and Ipv6 addrs of the current connection.
    pub fn local_addr(&self) -> Result<(SocketAddr, Option<SocketAddr>)> {
        Ok(self.inner.local_addr())
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub fn re_stun(&self, why: &'static str) {
        self.inner.re_stun(why);
    }

    /// Returns the [`SocketAddr`] which can be used by the QUIC layer to dial this node.
    ///
    /// Note this is a user-facing API and does not wrap the [`SocketAddr`] in a
    /// `QuicMappedAddr` as we do internally.
    pub fn get_mapping_addr(&self, node_id: &PublicKey) -> Option<SocketAddr> {
        self.inner.get_mapping_addr(node_id)
    }

    /// Returns the relay node with the best latency.
    ///
    /// If `None`, then we currently have no verified connection to a relay node.
    pub fn my_relay(&self) -> Option<RelayUrl> {
        self.inner.my_relay()
    }

    /// Add addresses for a node to the magic socket's addresbook.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub fn add_node_addr(&self, addr: NodeAddr) {
        self.inner.add_node_addr(addr);
    }

    /// Closes the connection.
    ///
    /// Subsequent calls have no effect and will not error.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub async fn close(&self) -> Result<()> {
        if self.inner.is_closed() {
            return Ok(());
        }
        self.inner.closing.store(true, Ordering::Relaxed);
        self.inner.actor_sender.send(ActorMessage::Shutdown).await?;
        self.inner.closed.store(true, Ordering::SeqCst);
        self.inner.endpoints.shutdown();

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
            debug!("tasks shutdown complete");
        } else {
            // shutdown all tasks
            debug!("aborting remaining {}/3 tasks", tasks.len());
            tasks.shutdown().await;
        }

        Ok(())
    }

    /// Reference to optional discovery service
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.inner.discovery()
    }

    /// Call to notify the system of potential network changes.
    pub async fn network_change(&self) {
        self.inner.network_change().await
    }
}

/// Stream returning local endpoints of a [`MagicSock`] as they change.
#[derive(Debug)]
pub struct LocalEndpointsStream {
    initial: Option<DiscoveredEndpoints>,
    inner: watchable::WatcherStream<DiscoveredEndpoints>,
}

impl Stream for LocalEndpointsStream {
    type Item = Vec<config::Endpoint>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if let Some(initial_endpoints) = this.initial.take() {
            if !initial_endpoints.is_empty() {
                return Poll::Ready(Some(initial_endpoints.into_iter().collect()));
            }
        }
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => break Poll::Pending,
                Poll::Ready(Some(discovered)) => {
                    if discovered.is_empty() {
                        // When we start up we might initially have empty local endpoints as
                        // the magic socket has not yet figured this out.  Later on this set
                        // should never be emtpy.  However even if it was the magicsock
                        // would be in a state not very useable so skipping those events is
                        // probably fine.
                        // To make sure we install the right waker we loop rather than
                        // returning Poll::Pending immediately here.
                        continue;
                    } else {
                        break Poll::Ready(Some(discovered.into_iter().collect()));
                    }
                }
                Poll::Ready(None) => break Poll::Ready(None),
            }
        }
    }
}

#[derive(Debug, Default)]
struct DiscoSecrets(parking_lot::Mutex<HashMap<PublicKey, SharedSecret>>);

impl DiscoSecrets {
    fn get(
        &self,
        secret: &SecretKey,
        node_id: PublicKey,
    ) -> parking_lot::MappedMutexGuard<SharedSecret> {
        parking_lot::MutexGuard::map(self.0.lock(), |inner| {
            inner
                .entry(node_id)
                .or_insert_with(|| secret.shared(&node_id))
        })
    }

    pub fn encode_and_seal(
        &self,
        secret_key: &SecretKey,
        node_id: PublicKey,
        msg: &disco::Message,
    ) -> Bytes {
        let mut seal = msg.as_bytes();
        self.get(secret_key, node_id).seal(&mut seal);
        disco::encode_message(&secret_key.public(), seal).into()
    }

    pub fn unseal_and_decode(
        &self,
        secret: &SecretKey,
        node_id: PublicKey,
        mut sealed_box: Vec<u8>,
    ) -> Result<disco::Message, DiscoBoxError> {
        self.get(secret, node_id)
            .open(&mut sealed_box)
            .map_err(DiscoBoxError::Open)?;
        disco::Message::from_bytes(&sealed_box).map_err(DiscoBoxError::Parse)
    }
}

#[derive(Debug, thiserror::Error)]
enum DiscoBoxError {
    #[error("Failed to open crypto box")]
    Open(anyhow::Error),
    #[error("Failed to parse disco message")]
    Parse(anyhow::Error),
}

type RelayRecvResult = Result<(PublicKey, quinn_udp::RecvMeta, Bytes), io::Error>;

/// Reports whether x and y represent the same set of endpoints. The order doesn't matter.
fn endpoint_sets_equal(xs: &[config::Endpoint], ys: &[config::Endpoint]) -> bool {
    if xs.is_empty() && ys.is_empty() {
        return true;
    }
    if xs.len() == ys.len() {
        let mut order_matches = true;
        for (i, x) in xs.iter().enumerate() {
            if x != &ys[i] {
                order_matches = false;
                break;
            }
        }
        if order_matches {
            return true;
        }
    }
    let mut m: HashMap<&config::Endpoint, usize> = HashMap::new();
    for x in xs {
        *m.entry(x).or_default() |= 1;
    }
    for y in ys {
        *m.entry(y).or_default() |= 2;
    }

    m.values().all(|v| *v == 3)
}

impl AsyncUdpSocket for MagicSock {
    fn poll_send(
        &self,
        _udp_state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_send(cx, transmits)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, metas)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        match &*self.inner.local_addrs.read().expect("not poisoned") {
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
    }
}

#[derive(Debug)]
enum ActorMessage {
    Shutdown,
    ReceiveRelay(RelayReadResult),
    EndpointPingExpired(usize, stun::TransactionId),
    NetcheckReport(Result<Option<Arc<netcheck::Report>>>, &'static str),
    NetworkChange,
    #[cfg(test)]
    ForceNetworkChange(bool),
}

struct Actor {
    msock: Arc<MagicSockInner>,
    msg_receiver: mpsc::Receiver<ActorMessage>,
    msg_sender: mpsc::Sender<ActorMessage>,
    relay_actor_sender: mpsc::Sender<RelayActorMessage>,
    relay_actor_cancel_token: CancellationToken,
    /// Channel to send received relay messages on, for processing.
    relay_recv_sender: flume::Sender<RelayRecvResult>,
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<config::NetInfo>,
    /// Path where connection info from [`MagicSockInner::node_map`] is persisted.
    nodes_path: Option<PathBuf>,

    // The underlying UDP sockets used to send/rcv packets.
    pconn4: UdpConn,
    pconn6: Option<UdpConn>,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    port_mapper: portmapper::Client,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: bool,

    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_checker: netcheck::Client,

    network_monitor: netmon::Monitor,
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
        let mut endpoint_heartbeat_timer = time::interval_at(
            time::Instant::now() + HEARTBEAT_INTERVAL,
            HEARTBEAT_INTERVAL,
        );
        let mut endpoints_update_receiver = self.msock.endpoints_update_state.running.subscribe();
        let mut portmap_watcher = self.port_mapper.watch_external_address();
        let mut save_nodes_timer = if self.nodes_path.is_some() {
            tokio::time::interval_at(
                time::Instant::now() + SAVE_NODES_INTERVAL,
                SAVE_NODES_INTERVAL,
            )
        } else {
            tokio::time::interval(Duration::MAX)
        };

        loop {
            tokio::select! {
                Some(msg) = self.msg_receiver.recv() => {
                    trace!(?msg, "tick: msg");
                    if self.handle_actor_message(msg).await {
                        return Ok(());
                    }
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    self.msock.re_stun("periodic");
                }
                Ok(()) = portmap_watcher.changed() => {
                    trace!("tick: portmap changed");
                    let new_external_address = *portmap_watcher.borrow();
                    debug!("external address updated: {new_external_address:?}");
                    self.msock.re_stun("portmap_updated");
                },
                _ = endpoint_heartbeat_timer.tick() => {
                    trace!("tick: endpoint heartbeat {} endpoints", self.msock.node_map.node_count());
                    // TODO: this might trigger too many packets at once, pace this

                    self.msock.node_map.prune_inactive();
                    let msgs = self.msock.node_map.endpoints_stayin_alive();
                    self.handle_ping_actions(msgs).await;
                }
                _ = endpoints_update_receiver.changed() => {
                    let reason = *endpoints_update_receiver.borrow();
                    trace!("tick: endpoints update receiver {:?}", reason);
                    if let Some(reason) = reason {
                        self.update_endpoints(reason).await;
                    }
                }
                _ = save_nodes_timer.tick(), if self.nodes_path.is_some() => {
                    trace!("tick: nodes_timer");
                    let path = self.nodes_path.as_ref().expect("precondition: `is_some()`");

                    self.msock.node_map.prune_inactive();
                    match self.msock.node_map.save_to_file(path).await {
                        Ok(count) => debug!(count, "nodes persisted"),
                        Err(e) => debug!(%e, "failed to persist known nodes"),
                    }
                }
                Some(is_major) = link_change_r.recv() => {
                    trace!("tick: link change {}", is_major);
                    self.handle_network_change(is_major).await;
                }
                else => {
                    trace!("tick: other");
                }
            }
        }
    }

    async fn handle_network_change(&mut self, is_major: bool) {
        debug!("link change detected: major? {}", is_major);

        if is_major {
            self.msock.dns_resolver.clear_cache();
            self.msock.re_stun("link-change-major");
            self.close_stale_relay_connections().await;
            self.reset_endpoint_states();
        } else {
            self.msock.re_stun("link-change-minor");
        }
    }

    async fn handle_ping_actions(&mut self, mut msgs: Vec<PingAction>) {
        if msgs.is_empty() {
            return;
        }
        if let Err(err) =
            futures::future::poll_fn(|cx| self.msock.poll_handle_ping_actions(cx, &mut msgs)).await
        {
            debug!("failed to send pings: {err:?}");
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
                if let Some(path) = self.nodes_path.as_ref() {
                    match self.msock.node_map.save_to_file(path).await {
                        Ok(count) => {
                            debug!(count, "known nodes persisted")
                        }
                        Err(e) => debug!(%e, "failed to persist known nodes"),
                    }
                }
                self.port_mapper.deactivate();
                self.relay_actor_cancel_token.cancel();

                // Ignore errors from pconnN
                // They will frequently have been closed already by a call to connBind.Close.
                debug!("stopping connections");
                if let Some(ref conn) = self.pconn6 {
                    conn.close().await.ok();
                }
                self.pconn4.close().await.ok();

                debug!("shutdown complete");
                return true;
            }
            ActorMessage::ReceiveRelay(read_result) => {
                let passthroughs = self.process_relay_read_result(read_result);
                for passthrough in passthroughs {
                    self.relay_recv_sender
                        .send_async(passthrough)
                        .await
                        .expect("missing recv sender");
                    let mut wakers = self.msock.network_recv_wakers.lock();
                    if let Some(waker) = wakers.take() {
                        waker.wake();
                    }
                }
            }
            ActorMessage::EndpointPingExpired(id, txid) => {
                self.msock.node_map.notify_ping_timeout(id, txid);
            }
            ActorMessage::NetcheckReport(report, why) => {
                match report {
                    Ok(report) => {
                        self.handle_netcheck_report(report).await;
                    }
                    Err(err) => {
                        warn!("failed to generate netcheck report for: {}: {:?}", why, err);
                    }
                }
                self.finalize_endpoints_update(why);
            }
            ActorMessage::NetworkChange => {
                self.network_monitor.network_change().await.ok();
            }
            #[cfg(test)]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major).await;
            }
        }

        false
    }

    fn normalized_local_addr(&self) -> io::Result<SocketAddr> {
        let (v4, v6) = self.local_addr();
        if let Some(v6) = v6 {
            return v6;
        }
        v4
    }

    fn local_addr(&self) -> (io::Result<SocketAddr>, Option<io::Result<SocketAddr>>) {
        // TODO: think more about this
        // needs to pretend ipv6 always as the fake addrs are ipv6
        let mut ipv6_addr = None;
        if let Some(ref conn) = self.pconn6 {
            ipv6_addr = Some(conn.local_addr());
        }
        let ipv4_addr = self.pconn4.local_addr();

        (ipv4_addr, ipv6_addr)
    }

    fn process_relay_read_result(&mut self, dm: RelayReadResult) -> Vec<RelayRecvResult> {
        trace!("process_relay_read {} bytes", dm.buf.len());
        if dm.buf.is_empty() {
            warn!("received empty relay packet");
            return Vec::new();
        }
        let url = &dm.url;

        let quic_mapped_addr = self.msock.node_map.receive_relay(url, dm.src);

        // the relay packet is made up of multiple udp packets, prefixed by a u16 be length prefix
        //
        // split the packet into these parts
        let parts = PacketSplitIter::new(dm.buf);
        // Normalize local_ip
        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());

        let mut out = Vec::new();
        for part in parts {
            match part {
                Ok(part) => {
                    if self.handle_relay_disco_message(&part, url, dm.src) {
                        // Message was internal, do not bubble up.
                        continue;
                    }

                    let meta = quinn_udp::RecvMeta {
                        len: part.len(),
                        stride: part.len(),
                        addr: quic_mapped_addr.0,
                        dst_ip,
                        ecn: None,
                    };
                    out.push(Ok((dm.src, meta, part)));
                }
                Err(e) => {
                    out.push(Err(e));
                }
            }
        }

        out
    }

    /// Refreshes knowledge about our local endpoints.
    ///
    /// In other words, this triggers a netcheck run.
    ///
    /// Note that invoking this is managed by the [`EndpointUpdateState`] and this should
    /// never be invoked directly.  Some day this will be refactored to not allow this easy
    /// mistake to be made.
    #[instrument(level = "debug", skip_all)]
    async fn update_endpoints(&mut self, why: &'static str) {
        inc!(MagicsockMetrics, update_endpoints);

        debug!("starting endpoint update ({})", why);
        self.port_mapper.procure_mapping();
        self.update_net_info(why).await;
    }

    /// Stores the results of a successful endpoint update.
    async fn store_endpoints_update(&mut self, nr: Option<Arc<netcheck::Report>>) {
        let portmap_watcher = self.port_mapper.watch_external_address();

        // endpoint -> how it was found
        let mut already = HashMap::new();
        // unique endpoints
        let mut eps = Vec::new();

        macro_rules! add_addr {
            ($already:expr, $eps:expr, $ipp:expr, $et:expr) => {
                #[allow(clippy::map_entry)]
                if !$already.contains_key(&$ipp) {
                    $already.insert($ipp, $et);
                    $eps.push(config::Endpoint {
                        addr: $ipp,
                        typ: $et,
                    });
                }
            };
        }

        let maybe_port_mapped = *portmap_watcher.borrow();

        if let Some(portmap_ext) = maybe_port_mapped.map(SocketAddr::V4) {
            add_addr!(already, eps, portmap_ext, config::EndpointType::Portmapped);
            self.set_net_info_have_port_map().await;
        }

        if let Some(nr) = nr {
            if let Some(global_v4) = nr.global_v4 {
                add_addr!(already, eps, global_v4.into(), config::EndpointType::Stun);

                // If they're behind a hard NAT and are using a fixed
                // port locally, assume they might've added a static
                // port mapping on their router to the same explicit
                // port that we are running with. Worst case it's an invalid candidate mapping.
                let port = self.msock.port.load(Ordering::Relaxed);
                if nr.mapping_varies_by_dest_ip.unwrap_or_default() && port != 0 {
                    let mut addr = global_v4;
                    addr.set_port(port);
                    add_addr!(
                        already,
                        eps,
                        addr.into(),
                        config::EndpointType::Stun4LocalPort
                    );
                }
            }
            if let Some(global_v6) = nr.global_v6 {
                add_addr!(already, eps, global_v6.into(), config::EndpointType::Stun);
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

        let LocalAddresses {
            regular: mut ips,
            loopback,
        } = LocalAddresses::new();

        if is_unspecified_v4 || is_unspecified_v6 {
            if ips.is_empty() && eps.is_empty() {
                // Only include loopback addresses if we have no
                // interfaces at all to use as endpoints and don't
                // have a public IPv4 or IPv6 address. This allows
                // for localhost testing when you're on a plane and
                // offline, for example.
                ips = loopback;
            }
            let v4_port = local_addr_v4.and_then(|addr| {
                if addr.ip().is_unspecified() {
                    Some(addr.port())
                } else {
                    None
                }
            });

            let v6_port = local_addr_v6.and_then(|addr| {
                if addr.ip().is_unspecified() {
                    Some(addr.port())
                } else {
                    None
                }
            });

            for ip in ips {
                match ip {
                    IpAddr::V4(_) => {
                        if let Some(port) = v4_port {
                            add_addr!(
                                already,
                                eps,
                                SocketAddr::new(ip, port),
                                config::EndpointType::Local
                            );
                        }
                    }
                    IpAddr::V6(_) => {
                        if let Some(port) = v6_port {
                            add_addr!(
                                already,
                                eps,
                                SocketAddr::new(ip, port),
                                config::EndpointType::Local
                            );
                        }
                    }
                }
            }
        }

        if !is_unspecified_v4 {
            if let Some(addr) = local_addr_v4 {
                // Our local endpoint is bound to a particular address.
                // Do not offer addresses on other local interfaces.
                add_addr!(already, eps, addr, config::EndpointType::Local);
            }
        }

        if !is_unspecified_v6 {
            if let Some(addr) = local_addr_v6 {
                // Our local endpoint is bound to a particular address.
                // Do not offer addresses on other local interfaces.
                add_addr!(already, eps, addr, config::EndpointType::Local);
            }
        }

        // Note: the endpoints are intentionally returned in priority order,
        // from "farthest but most reliable" to "closest but least
        // reliable." Addresses returned from STUN should be globally
        // addressable, but might go farther on the network than necessary.
        // Local interface addresses might have lower latency, but not be
        // globally addressable.
        //
        // The STUN address(es) are always first.
        // Despite this sorting, clients are not relying on this sorting for decisions;

        let updated = self
            .msock
            .endpoints
            .update(DiscoveredEndpoints::new(eps))
            .is_ok();
        if updated {
            let eps = self.msock.endpoints.read();
            eps.log_endpoint_change();
            self.msock.publish_my_addr();
        }

        // Regardless of whether our local endpoints changed, we now want to send any queued
        // call-me-maybe messages.
        self.msock.send_queued_call_me_maybes();
    }

    /// Called when an endpoints update is done, no matter if it was successful or not.
    fn finalize_endpoints_update(&mut self, why: &'static str) {
        let new_why = self.msock.endpoints_update_state.next_update();
        if !self.msock.is_closed() {
            if let Some(new_why) = new_why {
                self.msock.endpoints_update_state.run(new_why);
                return;
            }
            self.periodic_re_stun_timer = new_re_stun_timer(true);
        }

        self.msock.endpoints_update_state.finish_run();
        debug!("endpoint update done ({})", why);
    }

    /// Updates `NetInfo.HavePortMap` to true.
    #[instrument(level = "debug", skip_all)]
    async fn set_net_info_have_port_map(&mut self) {
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
    async fn call_net_info_callback(&mut self, ni: config::NetInfo) {
        if let Some(ref net_info_last) = self.net_info_last {
            if ni.basically_equal(net_info_last) {
                return;
            }
        }

        self.net_info_last = Some(ni);
    }

    /// Calls netcheck.
    ///
    /// Note that invoking this is managed by [`EndpointUpdateState`] via `update_endpoints`
    /// and this should never be invoked directly.  Some day this will be refactored to not
    /// allow this easy mistake to be made.
    #[instrument(level = "debug", skip_all)]
    async fn update_net_info(&mut self, why: &'static str) {
        if self.msock.relay_map.is_empty() {
            debug!("skipping netcheck, empty RelayMap");
            self.msg_sender
                .send(ActorMessage::NetcheckReport(Ok(None), why))
                .await
                .ok();
            return;
        }

        let relay_map = self.msock.relay_map.clone();
        let pconn4 = Some(self.pconn4.as_socket());
        let pconn6 = self.pconn6.as_ref().map(|p| p.as_socket());

        debug!("requesting netcheck report");
        match self
            .net_checker
            .get_report_channel(relay_map, pconn4, pconn6)
            .await
        {
            Ok(rx) => {
                let msg_sender = self.msg_sender.clone();
                tokio::task::spawn(async move {
                    let report = time::timeout(NETCHECK_REPORT_TIMEOUT, rx).await;
                    let report: anyhow::Result<_> = match report {
                        Ok(Ok(Ok(report))) => Ok(Some(report)),
                        Ok(Ok(Err(err))) => Err(err),
                        Ok(Err(_)) => Err(anyhow!("netcheck report not received")),
                        Err(err) => Err(anyhow!("netcheck report timeout: {:?}", err)),
                    };
                    msg_sender
                        .send(ActorMessage::NetcheckReport(report, why))
                        .await
                        .ok();
                    // The receiver of the NetcheckReport message will call
                    // .finalize_endpoints_update().
                });
            }
            Err(err) => {
                warn!("unable to start netcheck generation: {:?}", err);
                self.finalize_endpoints_update(why);
            }
        }
    }

    async fn handle_netcheck_report(&mut self, report: Option<Arc<netcheck::Report>>) {
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

            let have_port_map = self.port_mapper.watch_external_address().borrow().is_some();
            let mut ni = config::NetInfo {
                relay_latency: Default::default(),
                mapping_varies_by_dest_ip: r.mapping_varies_by_dest_ip,
                hair_pinning: r.hair_pinning,
                portmap_probe: r.portmap_probe.clone(),
                have_port_map,
                working_ipv6: Some(r.ipv6),
                os_has_ipv6: Some(r.os_has_ipv6),
                working_udp: Some(r.udp),
                working_icmp_v4: r.icmpv4,
                working_icmp_v6: r.icmpv6,
                preferred_relay: r.preferred_relay.clone(),
                link_type: None,
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
        self.store_endpoints_update(report).await;
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

    /// Returns a deterministic relay node to connect to. This is only used if netcheck
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
        self.msock.node_map.reset_endpoint_states()
    }

    /// Tells the relay actor to close stale relay connections.
    ///
    /// The relay connections who's local endpoints no longer exist after a network change
    /// will error out soon enough.  Closing them eagerly speeds this up however and allows
    /// re-establishing a relay connection faster.
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

    fn handle_relay_disco_message(
        &mut self,
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
                self.msock.handle_disco_message(
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
fn bind(port: u16) -> Result<(UdpConn, Option<UdpConn>)> {
    let pconn4 = UdpConn::bind(port, IpFamily::V4).context("bind IPv4 failed")?;
    let ip4_port = pconn4.local_addr()?.port();
    let ip6_port = ip4_port.checked_add(1).unwrap_or(ip4_port - 1);

    let pconn6 = match UdpConn::bind(ip6_port, IpFamily::V6) {
        Ok(conn) => Some(conn),
        Err(err) => {
            info!("bind ignoring IPv6 bind failure: {:?}", err);
            None
        }
    };

    Ok((pconn4, pconn6))
}

#[derive(derive_more::Debug, Default, Clone)]
struct DiscoveredEndpoints {
    /// Records the endpoints found during the previous
    /// endpoint discovery. It's used to avoid duplicate endpoint change notifications.
    last_endpoints: Vec<config::Endpoint>,

    /// The last time the endpoints were updated, even if there was no change.
    last_endpoints_time: Option<Instant>,
}

impl PartialEq for DiscoveredEndpoints {
    fn eq(&self, other: &Self) -> bool {
        endpoint_sets_equal(&self.last_endpoints, &other.last_endpoints)
    }
}

impl DiscoveredEndpoints {
    fn new(endpoints: Vec<config::Endpoint>) -> Self {
        Self {
            last_endpoints: endpoints,
            last_endpoints_time: Some(Instant::now()),
        }
    }

    fn into_iter(self) -> impl Iterator<Item = config::Endpoint> {
        self.last_endpoints.into_iter()
    }

    fn iter(&self) -> impl Iterator<Item = &config::Endpoint> + '_ {
        self.last_endpoints.iter()
    }

    fn is_empty(&self) -> bool {
        self.last_endpoints.is_empty()
    }

    fn fresh_enough(&self) -> bool {
        match self.last_endpoints_time.as_ref() {
            None => false,
            Some(time) => time.elapsed() <= ENDPOINTS_FRESH_ENOUGH_DURATION,
        }
    }

    fn to_call_me_maybe_message(&self) -> disco::CallMeMaybe {
        let my_numbers = self.last_endpoints.iter().map(|ep| ep.addr).collect();
        disco::CallMeMaybe { my_numbers }
    }

    fn log_endpoint_change(&self) {
        debug!("endpoints changed: {}", {
            let mut s = String::new();
            for (i, ep) in self.last_endpoints.iter().enumerate() {
                if i > 0 {
                    s += ", ";
                }
                s += &format!("{} ({})", ep.addr, ep.typ);
            }
            s
        });
    }
}

/// Split a number of transmits into individual packets.
///
/// For each transmit, if it has a segment size, it will be split into
/// multiple packets according to that segment size. If it does not have a
/// segment size, the contents will be sent as a single packet.
fn split_packets(transmits: &[quinn_udp::Transmit]) -> RelayContents {
    let mut res = SmallVec::with_capacity(transmits.len());
    for transmit in transmits {
        let contents = &transmit.contents;
        if let Some(segment_size) = transmit.segment_size {
            for chunk in contents.chunks(segment_size) {
                res.push(contents.slice_ref(chunk));
            }
        } else {
            res.push(contents.clone());
        }
    }
    res
}

/// Splits a packet into its component items.
#[derive(Debug)]
pub struct PacketSplitIter {
    bytes: Bytes,
}

impl PacketSplitIter {
    /// Create a new PacketSplitIter from a packet.
    ///
    /// Returns an error if the packet is too big.
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    fn fail(&mut self) -> Option<std::io::Result<Bytes>> {
        self.bytes.clear();
        Some(Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "",
        )))
    }
}

impl Iterator for PacketSplitIter {
    type Item = std::io::Result<Bytes>;

    fn next(&mut self) -> Option<Self::Item> {
        use bytes::Buf;
        if self.bytes.has_remaining() {
            if self.bytes.remaining() < 2 {
                return self.fail();
            }
            let len = self.bytes.get_u16_le() as usize;
            if self.bytes.remaining() < len {
                return self.fail();
            }
            let item = self.bytes.split_to(len);
            Some(Ok(item))
        } else {
            None
        }
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
/// comes in as the inner [`SocketAddr`], in those interfaces we have to be careful to do
/// the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QuicMappedAddr(SocketAddr);

/// Counter to always generate unique addresses for [`QuicMappedAddr`].
static ADDR_COUNTER: AtomicU64 = AtomicU64::new(1);

impl QuicMappedAddr {
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

        let counter = ADDR_COUNTER.fetch_add(1, Ordering::Relaxed);
        addr[8..16].copy_from_slice(&counter.to_be_bytes());

        Self(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), 12345))
    }
}

impl std::fmt::Display for QuicMappedAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "QuicMappedAddr({})", self.0)
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

#[cfg(test)]
pub(crate) mod tests {
    use anyhow::Context;
    use futures::StreamExt;
    use iroh_test::CallOnDrop;
    use rand::RngCore;

    use crate::{relay::RelayMode, test_utils::run_relay_server, tls, MagicEndpoint};

    use super::*;

    /// Magicsock plus wrappers for sending packets
    #[derive(Clone)]
    struct MagicStack {
        secret_key: SecretKey,
        endpoint: MagicEndpoint,
    }

    const ALPN: &[u8] = b"n0/test/1";

    impl MagicStack {
        async fn new(relay_map: RelayMap) -> Result<Self> {
            let secret_key = SecretKey::generate();

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let endpoint = MagicEndpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .relay_mode(RelayMode::Custom(relay_map))
                .alpns(vec![ALPN.to_vec()])
                .bind(0)
                .await?;

            Ok(Self {
                secret_key,
                endpoint,
            })
        }

        fn tracked_endpoints(&self) -> Vec<PublicKey> {
            self.endpoint
                .connection_infos()
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
    /// Whenever the local endpoints of a magic endpoint change this address is added to the
    /// other magic sockets.  This function will await until the endpoints are connected the
    /// first time before returning.
    ///
    /// When the returned drop guard is dropped, the tasks doing this updating are stopped.
    async fn mesh_stacks(stacks: Vec<MagicStack>, relay_url: RelayUrl) -> Result<CallOnDrop> {
        /// Registers endpoint addresses of a node to all other nodes.
        fn update_eps(
            stacks: &[MagicStack],
            my_idx: usize,
            new_eps: Vec<config::Endpoint>,
            relay_url: RelayUrl,
        ) {
            let me = &stacks[my_idx];

            for (i, m) in stacks.iter().enumerate() {
                if i == my_idx {
                    continue;
                }

                let addr = NodeAddr {
                    node_id: me.public(),
                    info: crate::AddrInfo {
                        relay_url: Some(relay_url.clone()),
                        direct_addresses: new_eps.iter().map(|ep| ep.addr).collect(),
                    },
                };
                let _ = m.endpoint.add_node_addr(addr);
            }
        }

        // For each node, start a task which monitors its local endpoints and registers them
        // with the other nodes as local endpoints become known.
        let mut tasks = JoinSet::new();
        for (my_idx, m) in stacks.iter().enumerate() {
            let m = m.clone();
            let stacks = stacks.clone();
            let relay_url = relay_url.clone();
            tasks.spawn(async move {
                let me = m.endpoint.node_id().fmt_short();
                let mut stream = m.endpoint.local_endpoints();
                while let Some(new_eps) = stream.next().await {
                    info!(%me, "conn{} endpoints update: {:?}", my_idx + 1, new_eps);
                    update_eps(&stacks, my_idx, new_eps, relay_url.clone());
                }
            });
        }
        let guard = CallOnDrop::new(move || {
            tasks.abort_all();
        });

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
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("failed to connect nodes")?;

        Ok(guard)
    }

    #[instrument(skip_all, fields(me = %ep.endpoint.node_id().fmt_short()))]
    async fn echo_receiver(ep: MagicStack) -> Result<()> {
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
        send_bi.finish().await.context("[receiver] finishing")?;

        let stats = conn.stats();
        info!("stats: {:#?}", stats);
        // TODO: ensure panics in this function are reported ok
        assert!(
            stats.path.lost_packets < 10,
            "[reciever] should not loose many packets",
        );

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
        relay_url: RelayUrl,
        msg: &[u8],
    ) -> Result<()> {
        info!("connecting to {}", dest_id.fmt_short());
        let dest = NodeAddr::new(dest_id).with_relay_url(relay_url);
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
        send_bi.finish().await.context("[sender] finish")?;

        info!("reading_to_end");
        let val = recv_bi.read_to_end(usize::MAX).await.context("[sender]")?;
        assert_eq!(
            val,
            msg,
            "[sender] expected {}, got {}",
            hex::encode(msg),
            hex::encode(&val)
        );

        let stats = conn.stats();
        info!("stats: {:#?}", stats);
        assert!(
            stats.path.lost_packets < 10,
            "[sender] should not loose many packets",
        );

        info!("close");
        conn.close(0u32.into(), b"done");
        info!("wait idle");
        ep.endpoint.endpoint().wait_idle().await;
        Ok(())
    }

    /// Runs a roundtrip between the [`echo_sender`] and [`echo_receiver`].
    async fn run_roundtrip(
        sender: MagicStack,
        receiver: MagicStack,
        relay_url: RelayUrl,
        payload: &[u8],
    ) {
        let send_node_id = sender.endpoint.node_id();
        let recv_node_id = receiver.endpoint.node_id();
        info!("\nroundtrip: {send_node_id:#} -> {recv_node_id:#}");

        let receiver_task = tokio::spawn(echo_receiver(receiver));
        let sender_res = echo_sender(sender, recv_node_id, relay_url, payload).await;
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
    async fn test_two_devices_roundtrip_quinn_magic() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (relay_map, relay_url, _cleanup_guard) = run_relay_server().await?;

        let m1 = MagicStack::new(relay_map.clone()).await?;
        let m2 = MagicStack::new(relay_map.clone()).await?;

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()], relay_url.clone()).await?;

        for i in 0..5 {
            info!("\n-- round {i}");
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), b"hello m1").await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), b"hello m2").await;

            info!("\n-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), &data).await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), &data).await;
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "flaky"]
    async fn test_two_devices_roundtrip_network_change() -> Result<()> {
        time::timeout(
            Duration::from_secs(50),
            test_two_devices_roundtrip_network_change_impl(),
        )
        .await?
    }

    /// Same structure as `test_two_devices_roundtrip_quinn_magic`, but interrupts regularly
    /// with (simulated) network changes.
    async fn test_two_devices_roundtrip_network_change_impl() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        let (relay_map, relay_url, _cleanup) = run_relay_server().await?;

        let m1 = MagicStack::new(relay_map.clone()).await?;
        let m2 = MagicStack::new(relay_map.clone()).await?;

        let _guard = mesh_stacks(vec![m1.clone(), m2.clone()], relay_url.clone()).await?;

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
            CallOnDrop::new(move || {
                task.abort();
            })
        };

        for i in 0..rounds {
            println!("-- [m1 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), b"hello m1").await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), b"hello m2").await;

            println!("-- [m1 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), &data).await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), &data).await;
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
            CallOnDrop::new(move || {
                task.abort();
            })
        };

        for i in 0..rounds {
            println!("-- [m2 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), b"hello m1").await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), b"hello m2").await;

            println!("-- [m2 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), &data).await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), &data).await;
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
            CallOnDrop::new(move || {
                task.abort();
            })
        };

        for i in 0..rounds {
            println!("-- [m1 & m2 changes] round {}", i + 1);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), b"hello m1").await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), b"hello m2").await;

            println!("-- [m1 & m2 changes] larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            run_roundtrip(m1.clone(), m2.clone(), relay_url.clone(), &data).await;
            run_roundtrip(m2.clone(), m1.clone(), relay_url.clone(), &data).await;
        }

        std::mem::drop(m1_m2_network_change_guard);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_setup_teardown() -> Result<()> {
        iroh_test::logging::setup_multithreaded();
        for i in 0..10 {
            println!("-- round {i}");
            let (relay_map, url, _cleanup) = run_relay_server().await?;
            println!("setting up magic stack");
            let m1 = MagicStack::new(relay_map.clone()).await?;
            let m2 = MagicStack::new(relay_map.clone()).await?;

            let _guard = mesh_stacks(vec![m1.clone(), m2.clone()], url.clone()).await?;

            println!("closing endpoints");
            m1.endpoint.close(0u32.into(), b"done")?;
            m2.endpoint.close(0u32.into(), b"done")?;

            // TODO(@divma): this is no longer possible
            assert!(m1.endpoint.magic_sock().is_closed());
            assert!(m2.endpoint.magic_sock().is_closed());
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_two_devices_roundtrip_quinn_raw() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let make_conn = |addr: SocketAddr| -> anyhow::Result<quinn::Endpoint> {
            let key = SecretKey::generate();
            let conn = std::net::UdpSocket::bind(addr)?;

            let tls_server_config = tls::make_server_config(&key, vec![ALPN.to_vec()], false)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
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

            let tls_client_config =
                tls::make_client_config(&key, None, vec![ALPN.to_vec()], false)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
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
                        .await
                        .with_context(|| format!("[{}] finishing", b_name))?;

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
                    .await
                    .with_context(|| format!("[{}] finish", a_name))?;

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
                    hex::encode($msg),
                    hex::encode(val)
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
    async fn test_two_devices_roundtrip_quinn_rebinding_conn() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        fn make_conn(addr: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
            let key = SecretKey::generate();
            let conn = UdpConn::bind(addr.port(), addr.ip().into())?;

            let tls_server_config = tls::make_server_config(&key, vec![ALPN.to_vec()], false)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            server_config.transport_config(Arc::new(transport_config));
            let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                conn,
                Arc::new(quinn::TokioRuntime),
            )?;

            let tls_client_config =
                tls::make_client_config(&key, None, vec![ALPN.to_vec()], false)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
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
                        .await
                        .with_context(|| format!("[{}] finishing", b_name))?;

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
                    .await
                    .with_context(|| format!("[{}] finish", a_name))?;

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
                    hex::encode($msg),
                    hex::encode(val)
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
        fn mk_transmit(contents: &[u8], segment_size: Option<usize>) -> quinn_udp::Transmit {
            let destination = "127.0.0.1:0".parse().unwrap();
            quinn_udp::Transmit {
                destination,
                ecn: None,
                contents: contents.to_vec().into(),
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
        // no packets
        assert_eq!(split_packets(&[]), SmallVec::<[Bytes; 1]>::default());
        // no split
        assert_eq!(
            split_packets(&vec![
                mk_transmit(b"hello", None),
                mk_transmit(b"world", None)
            ]),
            mk_expected(["hello", "world"])
        );
        // split without rest
        assert_eq!(
            split_packets(&[mk_transmit(b"helloworld", Some(5))]),
            mk_expected(["hello", "world"])
        );
        // split with rest and second transmit
        assert_eq!(
            split_packets(&vec![
                mk_transmit(b"hello world", Some(5)),
                mk_transmit(b"!", None)
            ]),
            mk_expected(["hello", " worl", "d", "!"])
        );
        // split that results in 1 packet
        assert_eq!(
            split_packets(&vec![
                mk_transmit(b"hello world", Some(1000)),
                mk_transmit(b"!", None)
            ]),
            mk_expected(["hello world", "!"])
        );
    }

    #[tokio::test]
    async fn test_local_endpoints() {
        let _guard = iroh_test::logging::setup();
        let ms = MagicSock::new(Default::default()).await.unwrap();

        // See if we can get endpoints.
        let mut eps0 = ms.local_endpoints().next().await.unwrap();
        eps0.sort();
        println!("{eps0:?}");
        assert!(!eps0.is_empty());

        // Getting the endpoints again immediately should give the same results.
        let mut eps1 = ms.local_endpoints().next().await.unwrap();
        eps1.sort();
        println!("{eps1:?}");
        assert_eq!(eps0, eps1);
    }
}
