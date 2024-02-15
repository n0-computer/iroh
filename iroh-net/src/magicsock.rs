//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock
//!
//! ### `DEV_DERP_ONLY` env var:
//! When present at *compile time*, this env var will force all packets
//! to be sent over the DERP relay connection, regardless of whether or
//! not we have a direct UDP address for the given node.
//!
//! The intended use is for testing the DERP protocol inside the MagicSock
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
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc,
    },
    task::{ready, Context, Poll, Waker},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt};
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
    derp::{DerpMap, DerpUrl},
    disco::{self, SendAddr},
    dns::DNS_RESOLVER,
    key::{PublicKey, SecretKey, SharedSecret},
    magic_endpoint::NodeAddr,
    magicsock::peer_map::PingRole,
    net::{ip::LocalAddresses, netmon, IpFamily},
    netcheck, portmapper, stun, AddrInfo,
};

use self::{
    derp_actor::{DerpActor, DerpActorMessage, DerpReadResult},
    metrics::Metrics as MagicsockMetrics,
    peer_map::{NodeMap, PingAction, SendPing},
    rebinding_conn::RebindingUdpConn,
};

mod derp_actor;
mod metrics;
mod peer_map;
mod rebinding_conn;
mod timer;

pub use crate::net::UdpSocket;

pub use self::metrics::Metrics;
pub use self::peer_map::{ConnectionType, ControlMsg, DirectAddrInfo, EndpointInfo};
pub use self::timer::Timer;

/// How long we consider a STUN-derived endpoint valid for. UDP NAT mappings typically
/// expire at 30 seconds, so this is a few seconds shy of that.
const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How often to save node data.
const SAVE_NODES_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum duration to wait for a netcheck report.
const NETCHECK_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CurrentPortFate {
    Keep,
    Drop,
}

/// Contains options for `MagicSock::listen`.
#[derive(derive_more::Debug)]
pub struct Options {
    /// The port to listen on.
    /// Zero means to pick one automatically.
    pub port: u16,

    /// Secret key for this node.
    pub secret_key: SecretKey,

    /// The [`DerpMap`] to use, leave empty to not use a DERP server.
    pub derp_map: DerpMap,

    /// Path to store known nodes.
    pub nodes_path: Option<std::path::PathBuf>,

    /// Optional node discovery mechanism.
    pub discovery: Option<Box<dyn Discovery>>,
}

/// Node discovery for [`super::MagicEndpoint`].
///
/// The purpose of this trait is to hoop up a node discovery mechanism that
/// allows finding information such as the derp url and current addresses
/// of a node given the id.
///
/// To allow for discovery, the [`super::MagicEndpoint`] will call `publish` whenever
/// discovery information changes. If a discovery mechanism requires a periodic
/// refresh, it should start it's own task.
pub trait Discovery: std::fmt::Debug + Send + Sync {
    /// Publish the given [`AddrInfo`] to the discovery mechanisms.
    ///
    /// This is fire and forget, since the magicsock can not wait for successful
    /// publishing. If publishing is async, the implementation should start it's
    /// own task.
    ///
    /// This will be called from a tokio task, so it is safe to spawn new tasks.
    /// These tasks will be run on the runtime of the [`super::MagicEndpoint`].
    fn publish(&self, info: &AddrInfo);

    /// Resolve the [`AddrInfo`] for the given [`PublicKey`].
    ///
    /// This is only called from [`super::MagicEndpoint::connect_by_node_id`], and only if
    /// the [`AddrInfo`] is not already known.
    ///
    /// This is async since the connect can not proceed without the [`AddrInfo`].
    fn resolve<'a>(&'a self, node_id: &'a PublicKey) -> BoxFuture<'a, Result<AddrInfo>>;
}

impl Default for Options {
    fn default() -> Self {
        Options {
            port: 0,
            secret_key: SecretKey::generate(),
            derp_map: DerpMap::empty(),
            nodes_path: None,
            discovery: None,
        }
    }
}

/// Contents of a DERP message. Use a SmallVec to avoid allocations for the very
/// common case of a single packet.
pub(crate) type DerpContents = SmallVec<[Bytes; 1]>;

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to nodes based on node IDs, it will initially
/// route packets via a derper relay and transparently try and establish a node-to-node
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both endpoints change.
///
/// It is usually only necessary to use a single [`MagicSock`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about nodes as
/// possible.
#[derive(Clone, Debug)]
pub struct MagicSock {
    inner: Arc<Inner>,
    // Empty when closed
    actor_tasks: Arc<Mutex<JoinSet<()>>>,
}

/// The actual implementation of `MagicSock`.
#[derive(derive_more::Debug)]
struct Inner {
    actor_sender: mpsc::Sender<ActorMessage>,
    derp_actor_sender: mpsc::Sender<DerpActorMessage>,
    /// String representation of the node_id of this node.
    me: String,
    /// Used for receiving DERP messages.
    derp_recv_receiver: flume::Receiver<DerpRecvResult>,
    /// Stores wakers, to be called when derp_recv_ch receives new data.
    network_recv_wakers: parking_lot::Mutex<Option<Waker>>,
    network_send_wakers: parking_lot::Mutex<Option<Waker>>,

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

    /// None (or zero nodes) means DERP is disabled.
    derp_map: DerpMap,
    /// Nearest DERP node ID; 0 means none/unknown.
    my_derp: std::sync::RwLock<Option<DerpUrl>>,
    /// Tracks the networkmap node entity for each node discovery key.
    node_map: NodeMap,
    /// UDP IPv4 socket
    pconn4: RebindingUdpConn,
    /// UDP IPv6 socket
    pconn6: Option<RebindingUdpConn>,
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
    pending_call_me_maybes: parking_lot::Mutex<HashMap<PublicKey, DerpUrl>>,

    /// Indicates the update endpoint state.
    endpoints_update_state: EndpointUpdateState,
}

impl Inner {
    /// Returns the derp node we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any derp region.
    fn my_derp(&self) -> Option<DerpUrl> {
        self.my_derp.read().unwrap().clone()
    }

    /// Sets the derp node with the best latency.
    ///
    /// If we are not connected to any derp nodes, set this to `None`.
    fn set_my_derp(&self, my_derp: Option<DerpUrl>) {
        *self.my_derp.write().unwrap() = my_derp;
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

    /// Get the cached version of the Ipv4 and Ipv6 addrs of the current connection.
    fn local_addr(&self) -> (SocketAddr, Option<SocketAddr>) {
        *self.local_addrs.read().unwrap()
    }
    fn normalized_local_addr(&self) -> io::Result<SocketAddr> {
        let (v4, v6) = self.local_addr();
        let addr = if let Some(v6) = v6 { v6 } else { v4 };
        Ok(addr)
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

        match self
            .node_map
            .get_send_addrs_for_quic_mapped_addr(&dest, self.ipv6_reported.load(Ordering::Relaxed))
        {
            Some((public_key, udp_addr, derp_url, mut msgs)) => {
                let mut pings_sent = false;
                // If we have pings to send, we *have* to send them out first.
                if !msgs.is_empty() {
                    if let Err(err) = ready!(self.poll_handle_ping_actions(cx, &mut msgs)) {
                        warn!(node = %public_key.fmt_short(), "failed to handle ping actions: {err:?}");
                    }
                    pings_sent = true;
                }

                let mut udp_sent = false;
                let mut derp_sent = false;
                let mut udp_error = None;

                // send udp
                if let Some(addr) = udp_addr {
                    // rewrite target addresses.
                    for t in transmits.iter_mut() {
                        t.destination = addr;
                    }
                    match ready!(self.poll_send_udp(addr, &transmits, cx)) {
                        Ok(n) => {
                            trace!(node = %public_key.fmt_short(), dst = %addr, transmit_count=n, "sent transmits over UDP");
                            // truncate the transmits vec to `n`. these transmits will be sent to
                            // Derp further below. We only want to send those transmits to Derp that were
                            // sent to UDP, because the next transmits will be sent on the next
                            // call to poll_send, which will happen immediately after, because we
                            // are always returning Poll::Ready if poll_send_udp returned
                            // Poll::Ready.
                            transmits.truncate(n);
                            udp_sent = true;
                            // record metrics.
                        }
                        Err(err) => {
                            error!(node = %public_key.fmt_short(), ?addr, "failed to send udp: {err:?}");
                            udp_error = Some(err);
                        }
                    }
                }

                let n = transmits.len();

                // send derp
                if let Some(ref derp_url) = derp_url {
                    self.try_send_derp(derp_url, public_key, split_packets(&transmits));
                    derp_sent = true;
                }

                if !derp_sent && !udp_sent && !pings_sent {
                    warn!(node = %public_key.fmt_short(), "failed to send: no UDP or DERP addr");
                    let err = udp_error.unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::NotConnected,
                            "no UDP or Derp address available for node",
                        )
                    });
                    Poll::Ready(Err(err))
                } else {
                    trace!(
                        node = %public_key.fmt_short(),
                        transmit_count = %transmits.len(),
                        packet_count = &transmits.iter().map(|t| t.segment_size.map(|ss| t.contents.len() / ss).unwrap_or(1)).sum::<usize>(),
                        len = &transmits.iter().map(|t| t.contents.len()).sum::<usize>(),
                        send_udp = ?udp_addr,
                        send_derp = ?derp_url,
                        "sent transmits"
                    );
                    Poll::Ready(Ok(n))
                }
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

    fn conn_for_addr(&self, addr: SocketAddr) -> io::Result<&RebindingUdpConn> {
        if addr.is_ipv6() && self.pconn6.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "no IPv6 connection"));
        }
        Ok(if addr.is_ipv6() {
            self.pconn6.as_ref().unwrap()
        } else {
            &self.pconn4
        })
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

        // order of polling is: UDPv4, UDPv6, Derp
        let msgs = match self.pconn4.poll_recv(cx, bufs, metas)? {
            Poll::Pending | Poll::Ready(0) => match &self.pconn6 {
                Some(conn) => match conn.poll_recv(cx, bufs, metas)? {
                    Poll::Pending | Poll::Ready(0) => {
                        return self.poll_recv_derp(cx, bufs, metas);
                    }
                    Poll::Ready(n) => n,
                },
                None => {
                    return self.poll_recv_derp(cx, bufs, metas);
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
                    // [`quinn::EndpointConfig::grease_quic_bit`] is set to `true`.
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
    fn poll_recv_derp(
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
            match self.derp_recv_receiver.try_recv() {
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
                    inc_by!(MagicsockMetrics, recv_data_derp, bytes.len() as _);
                    trace!(src = %meta.addr, node = %node_id.fmt_short(), count = meta.len / meta.stride, len = meta.len, "recv quic packets from derp");
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

        if src.is_derp() {
            inc!(MagicsockMetrics, recv_disco_derp);
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
                if !matches!(src, DiscoMessageSource::Derp { .. }) {
                    warn!("call-me-maybe packets should only come via DERP");
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
            dst_key,
            tx_id,
            purpose,
        } = ping;
        let msg = disco::Message::Ping(disco::Ping {
            tx_id,
            node_key: self.public_key(),
        });
        let sent = match dst {
            SendAddr::Udp(addr) => self.udp_disco_sender.try_send((addr, dst_key, msg)).is_ok(),
            SendAddr::Derp(ref url) => self.send_disco_message_derp(url, dst_key, msg),
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
            dst_key,
            tx_id,
            purpose,
        } = ping;
        let msg = disco::Message::Ping(disco::Ping {
            tx_id: *tx_id,
            node_key: self.public_key(),
        });
        ready!(self.poll_send_disco_message(dst.clone(), *dst_key, msg, cx))?;
        let msg_sender = self.actor_sender.clone();
        debug!(%dst, tx = %hex::encode(tx_id), ?purpose, "ping sent (polled)");
        self.node_map
            .notify_ping_sent(*id, dst.clone(), *tx_id, *purpose, msg_sender);
        Poll::Ready(Ok(()))
    }

    /// Send a disco message. UDP messages will be queued.
    ///
    /// If `dst` is [`SendAddr::Derp`], the message will be pushed into the derp client channel.
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
            SendAddr::Derp(ref url) => self.send_disco_message_derp(url, dst_key, msg),
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
            SendAddr::Derp(ref url) => {
                self.send_disco_message_derp(url, dst_key, msg);
            }
        }
        Poll::Ready(Ok(()))
    }

    fn send_disco_message_derp(
        &self,
        url: &DerpUrl,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> bool {
        debug!(node = %dst_key.fmt_short(), %url, %msg, "send disco message (derp)");
        let pkt = self.encode_disco_message(dst_key, &msg);
        inc!(MagicsockMetrics, send_disco_derp);
        if self.try_send_derp(url, dst_key, smallvec![pkt]) {
            inc!(MagicsockMetrics, sent_disco_derp);
            disco_message_sent(&msg);
            true
        } else {
            false
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
                ref derp_url,
                dst_key,
            } => {
                self.send_or_queue_call_me_maybe(derp_url, dst_key);
            }
            PingAction::SendPing(ref ping) => {
                ready!(self.poll_send_ping(ping, cx))?;
            }
        }
        Poll::Ready(Ok(()))
    }

    fn try_send_derp(&self, url: &DerpUrl, node: PublicKey, contents: DerpContents) -> bool {
        trace!(node = %node.fmt_short(), derp_url = %url, count = contents.len(), len = contents.iter().map(|c| c.len()).sum::<usize>(), "send derp");
        let msg = DerpActorMessage::Send {
            url: url.clone(),
            contents,
            peer: node,
        };
        match self.derp_actor_sender.try_send(msg) {
            Ok(_) => {
                trace!(node = %node.fmt_short(), derp_url = %url, "send derp: message queued");
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!(node = %node.fmt_short(), derp_url = %url, "send derp: message dropped, channel to actor is closed");
                false
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %node.fmt_short(), derp_url = %url, "send derp: message dropped, channel to actor is full");
                false
            }
        }
    }

    fn send_queued_call_me_maybes(&self) {
        let msg = self.endpoints.read().to_call_me_maybe_message();
        let msg = disco::Message::CallMeMaybe(msg);
        for (public_key, url) in self.pending_call_me_maybes.lock().drain() {
            if !self.send_disco_message_derp(&url, public_key, msg.clone()) {
                warn!(node = %public_key.fmt_short(), "derp channel full, dropping call-me-maybe");
            }
        }
    }

    fn send_or_queue_call_me_maybe(&self, url: &DerpUrl, dst_key: PublicKey) {
        let endpoints = self.endpoints.read();
        if endpoints.fresh_enough() {
            let msg = endpoints.to_call_me_maybe_message();
            let msg = disco::Message::CallMeMaybe(msg);
            if !self.send_disco_message_derp(url, dst_key, msg) {
                warn!(dstkey = %dst_key.fmt_short(), derpurl = ?url,
                      "derp channel full, dropping call-me-maybe");
            } else {
                debug!(dstkey = %dst_key.fmt_short(), derpurl = ?url, "call-me-maybe sent");
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
}

#[derive(Clone, Debug)]
enum DiscoMessageSource {
    Udp(SocketAddr),
    Derp { url: DerpUrl, key: PublicKey },
}

impl Display for DiscoMessageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Udp(addr) => write!(f, "Udp({addr})"),
            Self::Derp { ref url, key } => write!(f, "Derp({url}, {})", key.fmt_short()),
        }
    }
}

impl From<DiscoMessageSource> for SendAddr {
    fn from(value: DiscoMessageSource) -> Self {
        match value {
            DiscoMessageSource::Udp(addr) => SendAddr::Udp(addr),
            DiscoMessageSource::Derp { url, .. } => SendAddr::Derp(url),
        }
    }
}

impl From<&DiscoMessageSource> for SendAddr {
    fn from(value: &DiscoMessageSource) -> Self {
        match value {
            DiscoMessageSource::Udp(addr) => SendAddr::Udp(*addr),
            DiscoMessageSource::Derp { url, .. } => SendAddr::Derp(url.clone()),
        }
    }
}

impl DiscoMessageSource {
    fn is_derp(&self) -> bool {
        matches!(self, DiscoMessageSource::Derp { .. })
    }
}

/// Manages currently running endpoint updates.
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
        if crate::util::derp_only_mode() {
            warn!("creating a MagicSock that will only send packets over a DERP relay connection.");
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
            derp_map,
            discovery,
            nodes_path,
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

        let (derp_recv_sender, derp_recv_receiver) = flume::bounded(128);

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

        let net_checker = netcheck::Client::new(Some(port_mapper.clone()))?;

        let (actor_sender, actor_receiver) = mpsc::channel(256);
        let (derp_actor_sender, derp_actor_receiver) = mpsc::channel(256);
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
        let inner = Arc::new(Inner {
            me,
            port: AtomicU16::new(port),
            secret_key,
            local_addrs: std::sync::RwLock::new((ipv4_addr, ipv6_addr)),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            derp_recv_receiver,
            network_recv_wakers: parking_lot::Mutex::new(None),
            network_send_wakers: parking_lot::Mutex::new(None),
            actor_sender: actor_sender.clone(),
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            derp_map,
            my_derp: Default::default(),
            pconn4: pconn4.clone(),
            pconn6: pconn6.clone(),
            net_checker: net_checker.clone(),
            disco_secrets: DiscoSecrets::default(),
            node_map,
            derp_actor_sender: derp_actor_sender.clone(),
            udp_state,
            send_buffer: Default::default(),
            udp_disco_sender,
            discovery,
            endpoints: Watchable::new(Default::default()),
            pending_call_me_maybes: Default::default(),
            endpoints_update_state: EndpointUpdateState::new(),
        });

        let mut actor_tasks = JoinSet::default();

        let derp_actor = DerpActor::new(inner.clone(), actor_sender.clone());
        let derp_actor_cancel_token = derp_actor.cancel_token();
        actor_tasks.spawn(
            async move {
                derp_actor.run(derp_actor_receiver).await;
            }
            .instrument(info_span!("derp-actor")),
        );

        let inner2 = inner.clone();
        actor_tasks.spawn(async move {
            while let Some((dst, dst_key, msg)) = udp_disco_receiver.recv().await {
                if let Err(err) = inner2.send_disco_message_udp(dst, dst_key, &msg).await {
                    warn!(%dst, node = %dst_key.fmt_short(), ?err, "failed to send disco message (UDP)");
                }
            }
        });

        let inner2 = inner.clone();
        let network_monitor = netmon::Monitor::new().await?;
        actor_tasks.spawn(
            async move {
                let actor = Actor {
                    msg_receiver: actor_receiver,
                    msg_sender: actor_sender,
                    derp_actor_sender,
                    derp_actor_cancel_token,
                    inner: inner2,
                    derp_recv_sender,
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
                    warn!("derp handler errored: {:?}", err);
                }
            }
            .instrument(info_span!("actor")),
        );

        let c = MagicSock {
            inner,
            actor_tasks: Arc::new(Mutex::new(actor_tasks)),
        };

        Ok(c)
    }

    /// Retrieve connection information about nodes in the network.
    pub async fn tracked_endpoints(&self) -> Result<Vec<EndpointInfo>> {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::TrackedEndpoints(s))
            .await?;
        let res = r.await?;
        Ok(res)
    }

    /// Retrieve connection information about a node in the network.
    pub async fn tracked_endpoint(&self, node_key: PublicKey) -> Result<Option<EndpointInfo>> {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::TrackedEndpoint(node_key, s))
            .await?;
        let res = r.await?;
        Ok(res)
    }
    /// Query for the local endpoints discovered during the last endpoint discovery.
    ///
    /// Will wait until some endpoints are discovered.
    pub async fn local_endpoints(&self) -> Result<Vec<config::Endpoint>> {
        {
            // check if we have some value already
            let current_value = self.inner.endpoints.read();
            if !current_value.is_empty() {
                return Ok(current_value.clone().into_iter().collect());
            }
        }

        self.local_endpoints_change().await
    }

    /// Waits for local endpoints to change and returns the new ones.
    pub async fn local_endpoints_change(&self) -> Result<Vec<config::Endpoint>> {
        let watcher = self.inner.endpoints.watch();
        let eps = watcher.next_value_async().await?;
        Ok(eps.into_iter().collect())
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
    pub async fn get_mapping_addr(&self, node_key: &PublicKey) -> Option<SocketAddr> {
        let (s, r) = tokio::sync::oneshot::channel();
        if self
            .inner
            .actor_sender
            .send(ActorMessage::GetMappingAddr(*node_key, s))
            .await
            .is_ok()
        {
            return r.await.ok().flatten().map(|m| m.0);
        }
        None
    }

    /// Sets the connection's preferred local port.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub async fn set_preferred_port(&self, port: u16) {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::SetPreferredPort(port, s))
            .await
            .unwrap();
        r.await.unwrap();
    }

    /// Returns the DERP node with the best latency.
    ///
    /// If `None`, then we currently have no verified connection to a DERP node.
    pub fn my_derp(&self) -> Option<DerpUrl> {
        self.inner.my_derp()
    }

    #[instrument(skip_all, fields(me = %self.inner.me))]
    /// Add addresses for a node to the magic socket's addresbook.
    pub fn add_node_addr(&self, addr: NodeAddr) {
        self.inner.node_map.add_node_addr(addr);
    }

    /// Closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.
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

    /// Closes and re-binds the UDP sockets and resets the DERP connection.
    /// It should be followed by a call to ReSTUN.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub async fn rebind_all(&self) {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::RebindAll(s))
            .await
            .unwrap();
        r.await.unwrap();
    }

    /// Reference to optional discovery service
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.inner.discovery.as_ref().map(Box::as_ref)
    }

    /// Call to notify the system of potential network changes.
    pub async fn network_change(&self) {
        self.inner
            .actor_sender
            .send(ActorMessage::NetworkChange)
            .await
            .ok();
    }

    #[cfg(test)]
    async fn force_network_change(&self, is_major: bool) {
        self.inner
            .actor_sender
            .send(ActorMessage::ForceNetworkChange(is_major))
            .await
            .ok();
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

type DerpRecvResult = Result<(PublicKey, quinn_udp::RecvMeta, Bytes), io::Error>;

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
        match &*self.inner.local_addrs.read().unwrap() {
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
    TrackedEndpoints(sync::oneshot::Sender<Vec<EndpointInfo>>),
    TrackedEndpoint(PublicKey, sync::oneshot::Sender<Option<EndpointInfo>>),
    GetMappingAddr(PublicKey, sync::oneshot::Sender<Option<QuicMappedAddr>>),
    SetPreferredPort(u16, sync::oneshot::Sender<()>),
    RebindAll(sync::oneshot::Sender<()>),
    Shutdown,
    ReceiveDerp(DerpReadResult),
    EndpointPingExpired(usize, stun::TransactionId),
    NetcheckReport(Result<Option<Arc<netcheck::Report>>>, &'static str),
    NetworkChange,
    #[cfg(test)]
    ForceNetworkChange(bool),
}

struct Actor {
    inner: Arc<Inner>,
    msg_receiver: mpsc::Receiver<ActorMessage>,
    msg_sender: mpsc::Sender<ActorMessage>,
    derp_actor_sender: mpsc::Sender<DerpActorMessage>,
    derp_actor_cancel_token: CancellationToken,
    /// Channel to send received derp messages on, for processing.
    derp_recv_sender: flume::Sender<DerpRecvResult>,
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<config::NetInfo>,
    /// Path where connection info from [`Inner::node_map`] is persisted.
    nodes_path: Option<PathBuf>,

    // The underlying UDP sockets used to send/rcv packets.
    pconn4: RebindingUdpConn,
    pconn6: Option<RebindingUdpConn>,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    port_mapper: portmapper::Client,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: bool,

    /// The prober that discovers local network conditions, including the closest DERP relay and NAT mappings.
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
        let mut endpoints_update_receiver = self.inner.endpoints_update_state.running.subscribe();
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
                    self.inner.re_stun("periodic");
                }
                Ok(()) = portmap_watcher.changed() => {
                    trace!("tick: portmap changed");
                    let new_external_address = *portmap_watcher.borrow();
                    debug!("external address updated: {new_external_address:?}");
                    self.inner.re_stun("portmap_updated");
                },
                _ = endpoint_heartbeat_timer.tick() => {
                    trace!("tick: endpoint heartbeat {} endpoints", self.inner.node_map.node_count());
                    // TODO: this might trigger too many packets at once, pace this

                    self.inner.node_map.prune_inactive();
                    let msgs = self.inner.node_map.endpoints_stayin_alive();
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

                    self.inner.node_map.prune_inactive();
                    match self.inner.node_map.save_to_file(path).await {
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
            // Clear DNS cache
            DNS_RESOLVER.clear_cache();
            self.inner.re_stun("link-change-major");
            self.rebind_all().await;
        } else {
            self.inner.re_stun("link-change-minor");
        }
    }

    async fn handle_ping_actions(&mut self, mut msgs: Vec<PingAction>) {
        if msgs.is_empty() {
            return;
        }
        if let Err(err) =
            futures::future::poll_fn(|cx| self.inner.poll_handle_ping_actions(cx, &mut msgs)).await
        {
            debug!("failed to send pings: {err:?}");
        }
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage) -> bool {
        match msg {
            ActorMessage::TrackedEndpoints(s) => {
                let eps: Vec<_> = self.inner.node_map.endpoint_infos(Instant::now());
                let _ = s.send(eps);
            }
            ActorMessage::TrackedEndpoint(node_key, s) => {
                let _ = s.send(self.inner.node_map.endpoint_info(&node_key));
            }
            ActorMessage::GetMappingAddr(node_key, s) => {
                let res = self
                    .inner
                    .node_map
                    .get_quic_mapped_addr_for_node_key(&node_key);
                let _ = s.send(res);
            }
            ActorMessage::Shutdown => {
                debug!("shutting down");

                self.inner.node_map.notify_shutdown();
                if let Some(path) = self.nodes_path.as_ref() {
                    match self.inner.node_map.save_to_file(path).await {
                        Ok(count) => {
                            debug!(count, "known nodes persisted")
                        }
                        Err(e) => debug!(%e, "failed to persist known nodes"),
                    }
                }
                self.port_mapper.deactivate();
                self.derp_actor_cancel_token.cancel();

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
            ActorMessage::RebindAll(s) => {
                self.rebind_all().await;
                let _ = s.send(());
            }
            ActorMessage::SetPreferredPort(port, s) => {
                self.set_preferred_port(port).await;
                let _ = s.send(());
            }
            ActorMessage::ReceiveDerp(read_result) => {
                let passthroughs = self.process_derp_read_result(read_result);
                for passthrough in passthroughs {
                    self.derp_recv_sender
                        .send_async(passthrough)
                        .await
                        .expect("missing recv sender");
                    let mut wakers = self.inner.network_recv_wakers.lock();
                    if let Some(waker) = wakers.take() {
                        waker.wake();
                    }
                }
            }
            ActorMessage::EndpointPingExpired(id, txid) => {
                self.inner.node_map.notify_ping_timeout(id, txid);
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

    fn process_derp_read_result(&mut self, dm: DerpReadResult) -> Vec<DerpRecvResult> {
        trace!("process_derp_read {} bytes", dm.buf.len());
        if dm.buf.is_empty() {
            warn!("received empty derp packet");
            return Vec::new();
        }
        let url = &dm.url;

        let quic_mapped_addr = self.inner.node_map.receive_derp(url, dm.src);

        // the derp packet is made up of multiple udp packets, prefixed by a u16 be length prefix
        //
        // split the packet into these parts
        let parts = PacketSplitIter::new(dm.buf);
        // Normalize local_ip
        let dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());

        let mut out = Vec::new();
        for part in parts {
            match part {
                Ok(part) => {
                    if self.handle_derp_disco_message(&part, url, dm.src) {
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

    #[instrument(level = "debug", skip_all)]
    async fn update_endpoints(&mut self, why: &'static str) {
        inc!(MagicsockMetrics, update_endpoints);

        debug!("starting endpoint update ({})", why);
        if self.no_v4_send && !self.inner.is_closed() {
            warn!(
                "last netcheck reported send error. Rebinding. (no_v4_send: {} conn closed: {})",
                self.no_v4_send,
                self.inner.is_closed()
            );
            self.rebind_all().await;
        }

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
                add_addr!(already, eps, global_v4, config::EndpointType::Stun);

                // If they're behind a hard NAT and are using a fixed
                // port locally, assume they might've added a static
                // port mapping on their router to the same explicit
                // port that we are running with. Worst case it's an invalid candidate mapping.
                let port = self.inner.port.load(Ordering::Relaxed);
                if nr.mapping_varies_by_dest_ip.unwrap_or_default() && port != 0 {
                    let mut addr = global_v4;
                    addr.set_port(port);
                    add_addr!(already, eps, addr, config::EndpointType::Stun4LocalPort);
                }
            }
            if let Some(global_v6) = nr.global_v6 {
                add_addr!(already, eps, global_v6, config::EndpointType::Stun);
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
            .inner
            .endpoints
            .update(DiscoveredEndpoints::new(eps))
            .is_ok();
        if updated {
            let eps = self.inner.endpoints.read();
            eps.log_endpoint_change();

            if let Some(ref discovery) = self.inner.discovery {
                let direct_addresses = eps.iter().map(|ep| ep.addr).collect();
                let info = AddrInfo {
                    derp_url: self.inner.my_derp(),
                    direct_addresses,
                };
                discovery.publish(&info);
            }
        }

        // Regardless of whether our local endpoints changed, we now want to send any queued
        // call-me-maybe messages.
        self.inner.send_queued_call_me_maybes();
    }

    /// Called when an endpoints update is done, no matter if it was successful or not.
    fn finalize_endpoints_update(&mut self, why: &'static str) {
        let new_why = self.inner.endpoints_update_state.next_update();
        if !self.inner.is_closed() {
            if let Some(new_why) = new_why {
                self.inner.endpoints_update_state.run(new_why);
                return;
            }
            self.periodic_re_stun_timer = new_re_stun_timer(true);
        }

        self.inner.endpoints_update_state.finish_run();
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

    #[instrument(level = "debug", skip_all)]
    async fn update_net_info(&mut self, why: &'static str) {
        if self.inner.derp_map.is_empty() {
            debug!("skipping netcheck, empty DerpMap");
            self.msg_sender
                .send(ActorMessage::NetcheckReport(Ok(None), why))
                .await
                .ok();
            return;
        }

        let derp_map = self.inner.derp_map.clone();
        let pconn4 = Some(self.pconn4.as_socket());
        let pconn6 = self.pconn6.as_ref().map(|p| p.as_socket());

        debug!("requesting netcheck report");
        match self
            .net_checker
            .get_report_channel(derp_map, pconn4, pconn6)
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
            self.inner
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
                derp_latency: Default::default(),
                mapping_varies_by_dest_ip: r.mapping_varies_by_dest_ip,
                hair_pinning: r.hair_pinning,
                portmap_probe: r.portmap_probe.clone(),
                have_port_map,
                working_ipv6: Some(r.ipv6),
                os_has_ipv6: Some(r.os_has_ipv6),
                working_udp: Some(r.udp),
                working_icm_pv4: Some(r.icmpv4),
                preferred_derp: r.preferred_derp.clone(),
                link_type: None,
            };
            for (rid, d) in r.derp_v4_latency.iter() {
                ni.derp_latency.insert(format!("{rid}-v4"), d.as_secs_f64());
            }
            for (rid, d) in r.derp_v6_latency.iter() {
                ni.derp_latency.insert(format!("{rid}-v6"), d.as_secs_f64());
            }

            if ni.preferred_derp.is_none() {
                // Perhaps UDP is blocked. Pick a deterministic but arbitrary one.
                ni.preferred_derp = self.pick_derp_fallback();
            }

            if !self.set_nearest_derp(ni.preferred_derp.clone()) {
                ni.preferred_derp = None;
            }

            // TODO: set link type
            self.call_net_info_callback(ni).await;
        }
        self.store_endpoints_update(report).await;
    }

    fn set_nearest_derp(&mut self, derp_url: Option<DerpUrl>) -> bool {
        let my_derp = self.inner.my_derp();
        if derp_url == my_derp {
            // No change.
            return true;
        }
        self.inner.set_my_derp(derp_url.clone());

        if let Some(ref derp_url) = derp_url {
            inc!(MagicsockMetrics, derp_home_change);

            // On change, notify all currently connected DERP servers and
            // start connecting to our home DERP if we are not already.
            info!("home is now derp {}", derp_url);

            self.send_derp_actor(DerpActorMessage::NotePreferred(derp_url.clone()));
            self.send_derp_actor(DerpActorMessage::Connect {
                url: derp_url.clone(),
                peer: None,
            });
        }

        true
    }

    /// Returns a deterministic DERP node to connect to. This is only used if netcheck
    /// couldn't find the nearest one, for instance, if UDP is blocked and thus STUN
    /// latency checks aren't working.
    ///
    /// If no the [`DerpMap`] is empty, returns `0`.
    fn pick_derp_fallback(&self) -> Option<DerpUrl> {
        // TODO: figure out which DERP node most of our nodes are using,
        // and use that region as our fallback.
        //
        // If we already had selected something in the past and it has any
        // nodes, we want to stay on it. If there are no nodes at all,
        // stay on whatever DERP we previously picked. If we need to pick
        // one and have no node info, pick a node randomly.
        //
        // We used to do the above for legacy clients, but never updated it for disco.

        let my_derp = self.inner.my_derp();
        if my_derp.is_some() {
            return my_derp;
        }

        let ids = self.inner.derp_map.urls().collect::<Vec<_>>();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        ids.choose(&mut rng).map(|c| (*c).clone())
    }

    async fn rebind_all(&mut self) {
        trace!("rebind_all");
        inc!(MagicsockMetrics, rebind_calls);
        if let Err(err) = self.rebind(CurrentPortFate::Keep).await {
            warn!("unable to rebind: {:?}", err);
            return;
        }

        let ifs = Default::default(); // TODO: load actual interfaces from the monitor
        self.send_derp_actor(DerpActorMessage::MaybeCloseDerpsOnRebind(ifs));
        self.reset_endpoint_states();
    }

    /// Resets the preferred address for all nodes.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    fn reset_endpoint_states(&mut self) {
        self.inner.node_map.reset_endpoint_states()
    }

    /// Closes and re-binds the UDP sockets.
    /// We consider it successful if we manage to bind the IPv4 socket.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    async fn rebind(&mut self, cur_port_fate: CurrentPortFate) -> Result<()> {
        let mut ipv6_addr = None;

        // TODO: rebind does not update the cloned connections in IpStream (and other places)
        // Need to send a message to do so, after successful changes.

        if let Some(ref mut conn) = self.pconn6 {
            let port = conn.port();
            trace!("IPv6 rebind {} {:?}", port, cur_port_fate);
            // If we were not able to bind ipv6 at program start, dont retry
            if let Err(err) = conn.rebind(port, IpFamily::V6, cur_port_fate) {
                info!("rebind ignoring IPv6 bind failure: {:?}", err);
            } else {
                ipv6_addr = conn.local_addr().ok();
            }
        }

        let port = self.local_port_v4();
        self.pconn4
            .rebind(port, IpFamily::V4, cur_port_fate)
            .context("rebind IPv4 failed")?;

        // reread, as it might have changed
        // we can end up with a zero port if std::net::UdpSocket::socket_addr fails
        match self.local_port_v4().try_into() {
            Ok(non_zero_port) => self.port_mapper.update_local_port(non_zero_port),
            Err(_zero_port) => {
                // since the local port might still be the same, don't deactivate port mapping
                debug!("Skipping port mapping on rebind with zero local port");
            }
        }
        let ipv4_addr = self.pconn4.local_addr()?;

        *self.inner.local_addrs.write().unwrap() = (ipv4_addr, ipv6_addr);

        Ok(())
    }

    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub async fn set_preferred_port(&mut self, port: u16) {
        let existing_port = self.inner.port.swap(port, Ordering::Relaxed);
        if existing_port == port {
            return;
        }

        if let Err(err) = self.rebind(CurrentPortFate::Drop).await {
            warn!("failed to rebind: {:?}", err);
            return;
        }
        self.reset_endpoint_states();
    }

    fn send_derp_actor(&self, msg: DerpActorMessage) {
        match self.derp_actor_sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to derp actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for derp actor, channel is full");
            }
        }
    }

    fn handle_derp_disco_message(
        &mut self,
        msg: &[u8],
        url: &DerpUrl,
        derp_node_src: PublicKey,
    ) -> bool {
        match disco::source_and_box(msg) {
            Some((source, sealed_box)) => {
                if derp_node_src != source {
                    // TODO: return here?
                    warn!("Received Derp disco message from connection for {}, but with message from {}", derp_node_src.fmt_short(), source.fmt_short());
                }
                self.inner.handle_disco_message(
                    source,
                    sealed_box,
                    DiscoMessageSource::Derp {
                        url: url.clone(),
                        key: derp_node_src,
                    },
                );
                true
            }
            None => false,
        }
    }

    /// Returns the current IPv4 listener's port number.
    fn local_port_v4(&self) -> u16 {
        self.pconn4.port()
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
fn bind(port: u16) -> Result<(RebindingUdpConn, Option<RebindingUdpConn>)> {
    let pconn4 = RebindingUdpConn::bind(port, IpFamily::V4).context("bind IPv4 failed")?;
    let ip4_port = pconn4.local_addr()?.port();
    let ip6_port = ip4_port.checked_add(1).unwrap_or(ip4_port - 1);

    let pconn6 = match RebindingUdpConn::bind(ip6_port, IpFamily::V6) {
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
fn split_packets(transmits: &[quinn_udp::Transmit]) -> DerpContents {
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
/// [`MagicSock`] can reach a node by several real socket addresses, or maybe even via the derper
/// relay.  The QUIC layer however needs to address a node by a stable [`SocketAddr`] so
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
    use rand::RngCore;
    use tokio::{net, sync, task::JoinSet};
    use tracing::{debug_span, Instrument};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::*;
    use crate::{derp::DerpMode, test_utils::run_derper, tls, MagicEndpoint};

    async fn pick_port() -> u16 {
        let conn = net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        conn.local_addr().unwrap().port()
    }

    /// Returns a new MagicSock.
    async fn new_test_conn() -> MagicSock {
        let port = pick_port().await;
        MagicSock::new(Options {
            port,
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_rebind_stress_single_thread() {
        rebind_stress().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_rebind_stress_multi_thread() {
        rebind_stress().await;
    }

    async fn rebind_stress() {
        let c = new_test_conn().await;

        let (cancel, mut cancel_r) = sync::oneshot::channel();

        let conn = c.clone();
        let t = tokio::task::spawn(async move {
            let mut buff = vec![0u8; 1500];
            let mut buffs = [io::IoSliceMut::new(&mut buff)];
            let mut meta = [quinn_udp::RecvMeta::default()];
            loop {
                tokio::select! {
                    _ = &mut cancel_r => {
                        println!("cancel");
                        return anyhow::Ok(());
                    }
                    res = futures::future::poll_fn(|cx| conn.poll_recv(cx, &mut buffs, &mut meta)) => {
                        println!("poll_recv");
                        if res.is_err() {
                            println!("failed to poll_recv: {:?}", res);
                        }
                        res?;
                    }
                }
            }
        });

        let conn = c.clone();
        let t1 = tokio::task::spawn(async move {
            for i in 0..2000 {
                println!("[t1] rebind {}", i);
                conn.rebind_all().await;
            }
        });

        let conn = c.clone();
        let t2 = tokio::task::spawn(async move {
            for i in 0..2000 {
                println!("[t2] rebind {}", i);
                conn.rebind_all().await;
            }
        });

        t1.await.unwrap();
        t2.await.unwrap();

        cancel.send(()).unwrap();
        t.await.unwrap().unwrap();

        c.close().await.unwrap();
    }

    /// Magicsock plus wrappers for sending packets
    #[derive(Clone)]
    struct MagicStack {
        secret_key: SecretKey,
        endpoint: MagicEndpoint,
    }

    const ALPN: &[u8] = b"n0/test/1";

    impl MagicStack {
        async fn new(derp_map: DerpMap) -> Result<Self> {
            let secret_key = SecretKey::generate();

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let endpoint = MagicEndpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .derp_mode(DerpMode::Custom(derp_map))
                .alpns(vec![ALPN.to_vec()])
                .bind(0)
                .await?;

            Ok(Self {
                secret_key,
                endpoint,
            })
        }

        async fn tracked_endpoints(&self) -> Vec<PublicKey> {
            self.endpoint
                .magic_sock()
                .tracked_endpoints()
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|ep| ep.public_key)
                .collect()
        }

        fn public(&self) -> PublicKey {
            self.secret_key.public()
        }
    }

    /// Monitors endpoint changes and plumbs things together.
    fn mesh_stacks(stacks: Vec<MagicStack>, derp_url: DerpUrl) -> Result<impl FnOnce()> {
        fn update_eps(
            ms: &[MagicStack],
            my_idx: usize,
            new_eps: Vec<config::Endpoint>,
            derp_url: DerpUrl,
        ) {
            let me = &ms[my_idx];

            for (i, m) in ms.iter().enumerate() {
                if i == my_idx {
                    continue;
                }

                let addr = NodeAddr {
                    node_id: me.public(),
                    info: crate::AddrInfo {
                        derp_url: Some(derp_url.clone()),
                        direct_addresses: new_eps.iter().map(|ep| ep.addr).collect(),
                    },
                };
                m.endpoint.magic_sock().add_node_addr(addr);
            }
        }

        let mut tasks = JoinSet::new();

        for (my_idx, m) in stacks.iter().enumerate() {
            let m = m.clone();
            let stacks = stacks.clone();
            let derp_url = derp_url.clone();
            tasks.spawn(async move {
                while let Ok(new_eps) = m.endpoint.magic_sock().local_endpoints_change().await {
                    debug!("conn{} endpoints update: {:?}", my_idx + 1, new_eps);
                    update_eps(&stacks, my_idx, new_eps, derp_url.clone());
                }
            });
        }

        Ok(move || {
            tasks.abort_all();
        })
    }

    pub fn setup_multithreaded_logging() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();
    }

    #[ignore = "flaky"]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_roundtrip_quinn_magic() -> Result<()> {
        setup_multithreaded_logging();
        let (derp_map, url, _cleanup) = run_derper().await?;

        let m1 = MagicStack::new(derp_map.clone()).await?;
        let m2 = MagicStack::new(derp_map.clone()).await?;

        let cleanup_mesh = mesh_stacks(vec![m1.clone(), m2.clone()], url.clone())?;

        // Wait for magicsock to be told about nodes from mesh_stacks.
        let m1t = m1.clone();
        let m2t = m2.clone();
        time::timeout(Duration::from_secs(10), async move {
            loop {
                let ab = m1t.tracked_endpoints().await.contains(&m2t.public());
                let ba = m2t.tracked_endpoints().await.contains(&m1t.public());
                if ab && ba {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("failed to connect nodes")?;

        // msg from  m2 -> m1
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());
                println!("[{}] {:?}", a_name, a.endpoint.local_addr());
                println!("[{}] {:?}", b_name, b.endpoint.local_addr());

                let a_addr = b.endpoint.magic_sock().get_mapping_addr(&a.public()).await.unwrap();
                let b_addr = a.endpoint.magic_sock().get_mapping_addr(&b.public()).await.unwrap();
                let b_node_id = b.endpoint.node_id();

                println!("{}: {}, {}: {}", a_name, a_addr, b_name, b_addr);

                let b_span = debug_span!("receiver", b_name, %b_addr);
                let b_task = tokio::task::spawn(
                    async move {
                        println!("[{}] accepting conn", b_name);
                        let conn = b.endpoint.accept().await.expect("no conn");

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

                        println!("[{}] replying", b_name);
                        for chunk in val.chunks(12) {
                            send_bi
                                .write_all(chunk)
                                .await
                                .with_context(|| format!("[{}] sending chunk", b_name))?;
                        }

                        println!("[{}] finishing", b_name);
                        send_bi
                            .finish()
                            .await
                            .with_context(|| format!("[{}] finishing", b_name))?;

                        let stats = conn.stats();
                        println!("[{}] stats: {:#?}", a_name, stats);
                        assert!(stats.path.lost_packets < 10, "[{}] should not loose many packets", b_name);

                        println!("[{}] close", b_name);
                        conn.close(0u32.into(), b"done");
                        println!("[{}] closed", b_name);

                        Ok::<_, anyhow::Error>(())
                    }
                    .instrument(b_span),
                );

                let a_span = debug_span!("sender", a_name, %a_addr);
                let url2 = url.clone();
                async move {
                    println!("[{}] connecting to {}", a_name, b_addr);
                    let node_b_data = NodeAddr::new(b_node_id).with_derp_url(url2).with_direct_addresses([b_addr]);
                    let conn = a
                        .endpoint
                        .connect(node_b_data, &ALPN)
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
                    let val = recv_bi
                        .read_to_end(usize::MAX)
                        .await
                        .with_context(|| format!("[{}]", a_name))?;
                    anyhow::ensure!(
                        val == $msg,
                        "expected {}, got {}",
                        hex::encode($msg),
                        hex::encode(val)
                    );

                    let stats = conn.stats();
                    println!("[{}] stats: {:#?}", a_name, stats);
                    assert!(stats.path.lost_packets < 10, "[{}] should not loose many packets", a_name);

                    println!("[{}] close", a_name);
                    conn.close(0u32.into(), b"done");
                    println!("[{}] wait idle", a_name);
                    a.endpoint.endpoint().wait_idle().await;
                    println!("[{}] waiting for channel", a_name);
                    b_task.await??;
                    Ok(())
                }
                .instrument(a_span)
                .await?;
            };
        }

        for i in 0..5 {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m2, m1, data);
        }

        println!("cleaning up");
        cleanup_mesh();
        Ok(())
    }

    /// Same structure as `test_two_devices_roundtrip_quinn_magic`, but interrupts regularly
    /// with (simulated) network changes.
    #[ignore = "flaky"]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_roundtrip_network_change() -> Result<()> {
        setup_multithreaded_logging();
        let (derp_map, url, _cleanup) = run_derper().await?;

        let m1 = MagicStack::new(derp_map.clone()).await?;
        let m2 = MagicStack::new(derp_map.clone()).await?;

        let cleanup_mesh = mesh_stacks(vec![m1.clone(), m2.clone()], url.clone())?;

        // Wait for magicsock to be told about nodes from mesh_stacks.
        let m1t = m1.clone();
        let m2t = m2.clone();
        time::timeout(Duration::from_secs(10), async move {
            loop {
                let ab = m1t.tracked_endpoints().await.contains(&m2t.public());
                let ba = m2t.tracked_endpoints().await.contains(&m1t.public());
                if ab && ba {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("failed to connect nodes")?;

        // msg from  m2 -> m1
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());
                println!("[{}] {:?}", a_name, a.endpoint.local_addr());
                println!("[{}] {:?}", b_name, b.endpoint.local_addr());

                let a_addr = b.endpoint.magic_sock().get_mapping_addr(&a.public()).await.unwrap();
                let b_addr = a.endpoint.magic_sock().get_mapping_addr(&b.public()).await.unwrap();
                let b_node_id = b.endpoint.node_id();

                println!("{}: {}, {}: {}", a_name, a_addr, b_name, b_addr);

                let b_span = debug_span!("receiver", b_name, %b_addr);
                let b_task = tokio::task::spawn(
                    async move {
                        println!("[{}] accepting conn", b_name);
                        let conn = b.endpoint.accept().await.expect("no conn");

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

                        println!("[{}] replying", b_name);
                        for chunk in val.chunks(12) {
                            send_bi
                                .write_all(chunk)
                                .await
                                .with_context(|| format!("[{}] sending chunk", b_name))?;
                        }

                        println!("[{}] finishing", b_name);
                        send_bi
                            .finish()
                            .await
                            .with_context(|| format!("[{}] finishing", b_name))?;

                        let stats = conn.stats();
                        assert!(stats.path.lost_packets < 10, "[{}] should not loose many packets", b_name);

                        println!("[{}] close", b_name);
                        conn.close(0u32.into(), b"done");
                        println!("[{}] closed", b_name);

                        Ok::<_, anyhow::Error>(())
                    }
                    .instrument(b_span),
                );

                let a_span = debug_span!("sender", a_name, %a_addr);
                let url2 = url.clone();
                async move {
                    println!("[{}] connecting to {}", a_name, b_addr);
                    let node_b_data = NodeAddr::new(b_node_id).with_derp_url(url2).with_direct_addresses([b_addr]);
                    let conn = a
                        .endpoint
                        .connect(node_b_data, &ALPN)
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
                    let val = recv_bi
                        .read_to_end(usize::MAX)
                        .await
                        .with_context(|| format!("[{}]", a_name))?;
                    anyhow::ensure!(
                        val == $msg,
                        "expected {}, got {}",
                        hex::encode($msg),
                        hex::encode(val)
                    );

                    let stats = conn.stats();
                    assert!(stats.path.lost_packets < 10, "[{}] should not loose many packets", a_name);

                    println!("[{}] close", a_name);
                    conn.close(0u32.into(), b"done");
                    println!("[{}] wait idle", a_name);
                    a.endpoint.endpoint().wait_idle().await;
                    println!("[{}] waiting for channel", a_name);
                    b_task.await??;
                    Ok(())
                }
                .instrument(a_span)
                .await?;
            };
        }

        let offset = || {
            let delay = rand::thread_rng().gen_range(10..=500);
            Duration::from_millis(delay)
        };
        let rounds = 5;

        let m1_t = m1.clone();

        // only m1
        let t = tokio::task::spawn(async move {
            loop {
                println!("[m1] network change");
                m1_t.endpoint.magic_sock().force_network_change(true).await;
                time::sleep(offset()).await;
            }
        });

        for i in 0..rounds {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m2, m1, data);
        }

        t.abort();

        let m2_t = m2.clone();

        // only m2
        let t = tokio::task::spawn(async move {
            loop {
                println!("[m2] network change");
                m2_t.endpoint.magic_sock().force_network_change(true).await;
                time::sleep(offset()).await;
            }
        });

        for i in 0..rounds {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m2, m1, data);
        }

        t.abort();

        let m1_t = m1.clone();
        let m2_t = m2.clone();

        // both
        let t = tokio::task::spawn(async move {
            loop {
                println!("[m1] network change");
                m1_t.endpoint.magic_sock().force_network_change(true).await;
                println!("[m2] network change");
                m2_t.endpoint.magic_sock().force_network_change(true).await;
                time::sleep(offset()).await;
            }
        });

        for i in 0..rounds {
            println!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello m1");
            roundtrip!(m2, m1, b"hello m2");

            println!("-- larger data");
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);

            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m2, m1, data);
        }

        t.abort();

        println!("cleaning up");
        cleanup_mesh();
        Ok(())
    }

    #[ignore = "flaky"]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_setup_teardown() -> Result<()> {
        setup_multithreaded_logging();
        for _ in 0..10 {
            let (derp_map, url, _cleanup) = run_derper().await?;
            println!("setting up magic stack");
            let m1 = MagicStack::new(derp_map.clone()).await?;
            let m2 = MagicStack::new(derp_map.clone()).await?;

            let cleanup_mesh = mesh_stacks(vec![m1.clone(), m2.clone()], url.clone())?;

            // Wait for magicsock to be told about nodes from mesh_stacks.
            println!("waiting for connection");
            let m1t = m1.clone();
            let m2t = m2.clone();
            time::timeout(Duration::from_secs(10), async move {
                loop {
                    let ab = m1t.tracked_endpoints().await.contains(&m2t.public());
                    let ba = m2t.tracked_endpoints().await.contains(&m1t.public());
                    if ab && ba {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
            .context("failed to connect nodes")?;

            println!("closing endpoints");
            m1.endpoint.close(0u32.into(), b"done").await?;
            m2.endpoint.close(0u32.into(), b"done").await?;

            assert!(m1.endpoint.magic_sock().inner.is_closed());
            assert!(m2.endpoint.magic_sock().inner.is_closed());

            println!("cleaning up");
            cleanup_mesh();
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
            let conn = RebindingUdpConn::bind(addr.port(), addr.ip().into())?;

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
        fn mk_expected(parts: impl IntoIterator<Item = &'static str>) -> DerpContents {
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
}
