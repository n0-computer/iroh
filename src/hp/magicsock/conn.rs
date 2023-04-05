use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use backoff::backoff::Backoff;
use futures::{future::BoxFuture, Future, StreamExt};
use quinn::{AsyncUdpSocket, Transmit};
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tokio::{
    sync::{self, Mutex, RwLock},
    task::JoinHandle,
    time,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, instrument, warn};

use crate::{
    hp::{
        cfg::{self, DERP_MAGIC_IP},
        derp::{self, DerpMap},
        disco, key,
        magicsock::SESSION_ACTIVE_TIMEOUT,
        netcheck, netmap, portmapper, stun,
    },
    net::ip::LocalAddresses,
};

use super::{
    endpoint::PeerMap, rebinding_conn::RebindingUdpConn, Endpoint, DERP_CLEAN_STALE_INTERVAL,
    DERP_INACTIVE_CLEANUP_TIME, ENDPOINTS_FRESH_ENOUGH_DURATION,
};

/// How many packets writes can be queued up the DERP client to write on the wire before we start
/// dropping.
///
/// TODO: this is currently arbitrary. Figure out something better?
const BUFFERED_DERP_WRITES_BEFORE_DROP: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum CurrentPortFate {
    Keep,
    Drop,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum Network {
    Ip4,
    Ip6,
}

impl Network {
    pub(super) fn default_addr(&self) -> IpAddr {
        match self {
            Self::Ip4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::Ip6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }
}

impl From<Network> for socket2::Domain {
    fn from(value: Network) -> Self {
        match value {
            Network::Ip4 => socket2::Domain::IPV4,
            Network::Ip6 => socket2::Domain::IPV6,
        }
    }
}

/// Contains options for `Conn::listen`.
pub struct Options {
    /// The port to listen on.
    /// Zero means to pick one automatically.
    pub port: u16,

    /// Optionally provides a func to be called when endpoints change.
    pub on_endpoints: Option<Box<dyn Fn(&[cfg::Endpoint]) + Send + Sync + 'static>>,

    /// Optionally provides a func to be called when a connection is made to a DERP server.
    pub on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,

    /// Optionally provides a func to return how long it's been since a TUN packet was sent or received.
    pub idle_for: Option<Box<dyn Fn() -> Duration + Send + Sync + 'static>>,

    /// A callback that provides a `cfg::NetInfo` when discovered network conditions change.
    pub on_net_info: Option<Box<dyn Fn(cfg::NetInfo) + Send + Sync + 'static>>,

    /// Private key for this node.
    pub private_key: key::node::SecretKey,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            port: 0,
            on_endpoints: None,
            on_derp_active: None,
            idle_for: None,
            on_net_info: None,
            private_key: key::node::SecretKey::generate(),
        }
    }
}

/// Routes UDP packets and actively manages a list of its endpoints.
#[derive(Clone, Debug)]
pub struct Conn {
    inner: Arc<Inner>,
    state: Arc<Mutex<ConnState>>,
}

impl Deref for Conn {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO:
        f.debug_struct("Inner").finish()
    }
}

impl Debug for ConnState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO:
        f.debug_struct("ConnState").finish()
    }
}

pub struct Inner {
    derp_sender: flume::Sender<DerpMessage>,
    pub(super) name: String,
    on_endpoints: Option<Box<dyn Fn(&[cfg::Endpoint]) + Send + Sync + 'static>>,
    on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,
    idle_for: Option<Box<dyn Fn() -> Duration + Send + Sync + 'static>>,
    /// A callback that provides a `cfg::NetInfo` when discovered network conditions change.
    on_net_info: Option<Box<dyn Fn(cfg::NetInfo) + Send + Sync + 'static>>,

    // TODO
    // connCtx:       context.Context, // closed on Conn.Close
    // connCtxCancel: func(),          // closes connCtx

    // The underlying UDP sockets used to send/rcv packets.
    pconn4: RebindingUdpConn,
    pconn6: Option<RebindingUdpConn>,

    /// The prober that discovers local network conditions, including the closest DERP relay and NAT mappings.
    net_checker: netcheck::Client,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    port_mapper: portmapper::Client,

    /// Holds the current STUN packet processing func.
    on_stun_receive: RwLock<
        Option<Box<dyn Fn(&[u8], SocketAddr) -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    >, // syncs.AtomicValue[func(p []byte, fromAddr netip.AddrPort)]

    /// Used for receiving DERP messages.
    derp_recv_ch: flume::Receiver<DerpReadResult>,

    // Used by receiveIPv4 and receiveIPv6, respectively, to cache an SocketAddr -> Endpoint for hot flows.
    socket_endpoint4: SocketEndpointCache,
    socket_endpoint6: SocketEndpointCache,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: AtomicBool,

    pub(super) public_key: key::node::PublicKey,
    last_net_check_report: RwLock<Option<Arc<netcheck::Report>>>,

    /// Preferred port from `Options::port`; 0 means auto.
    port: AtomicU16,

    /// Close is in progress (or done)
    closing: AtomicBool,
    /// Close was called.
    closed: AtomicBool,

    /// None (or zero regions/nodes) means DERP is disabled.
    /// Tracked outside to avoid deadlock issues (replaces atomic acess from go)
    derp_map: RwLock<Option<DerpMap>>,

    /// Tracks the networkmap node entity for each peer discovery key.
    pub(super) peer_map: RwLock<PeerMap>,
    /// The private naclbox key used for active discovery traffic. It's created once near
    /// (but not during) construction.
    disco_private: key::disco::SecretKey,
    /// Private key for this node
    private_key: key::node::SecretKey,

    /// Nearest DERP region ID; 0 means none/unknown.
    my_derp: AtomicU16,
}

impl Inner {
    pub(super) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    fn my_derp(&self) -> u16 {
        self.my_derp.load(Ordering::Relaxed)
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Returns the current IPv4 listener's port number.
    async fn local_port(&self) -> u16 {
        self.pconn4.port().await
    }
}

#[derive(Debug)]
struct EndpointUpdateState {
    /// If running, set to the task handle of the update.
    running: sync::watch::Sender<Option<&'static str>>,
    want_update: Option<&'static str>,
}

impl EndpointUpdateState {
    fn new() -> Self {
        let (running, _) = sync::watch::channel(None);
        EndpointUpdateState {
            running,
            want_update: None,
        }
    }

    /// Returns `true` if an update is currently in progress.
    fn is_running(&self) -> bool {
        self.running.borrow().is_some()
    }
}

pub(super) struct ConnState {
    /// `None` when closed.
    derp_task: Option<JoinHandle<()>>,

    /// The state for an active DiscoKey.
    disco_info: HashMap<key::disco::PublicKey, DiscoInfo>,

    net_map: Option<netmap::NetworkMap>,
}

impl ConnState {
    fn new(derp_task: JoinHandle<()>) -> Self {
        ConnState {
            derp_task: Some(derp_task),
            disco_info: HashMap::new(),
            net_map: None,
        }
    }
}

impl Conn {
    /// Creates a magic `Conn` listening on `opts.port`.
    /// As the set of possible endpoints for a Conn changes, the callback opts.EndpointsFunc is called.
    pub async fn new(name: String, opts: Options) -> Result<Self> {
        let port_mapper = portmapper::Client::new(); // TODO: pass self.on_port_map_changed
        let mut net_checker = netcheck::Client::default();
        net_checker.port_mapper = Some(port_mapper.clone());

        let Options {
            port,
            on_endpoints,
            on_derp_active,
            idle_for,
            on_net_info,
            private_key,
        } = opts;

        let (derp_recv_ch_sender, derp_recv_ch_receiver) = flume::bounded(64);

        let (pconn4, pconn6) = Self::bind(port).await?;
        let port = pconn4.port().await;
        port_mapper.set_local_port(port).await;

        let conn4 = pconn4.clone();
        net_checker.get_stun_conn4 = Some(Arc::new(Box::new(move || conn4.as_socket())));
        if let Some(conn6) = pconn6.clone() {
            net_checker.get_stun_conn6 = Some(Arc::new(Box::new(move || conn6.as_socket())));
        }
        let disco_private = key::disco::SecretKey::generate();

        let (derp_sender, derp_receiver) = flume::bounded(64);

        let inner = Arc::new(Inner {
            name,
            on_endpoints,
            on_derp_active,
            idle_for,
            on_net_info,
            port: AtomicU16::new(port),
            port_mapper,
            net_checker,
            public_key: private_key.public_key().into(),
            last_net_check_report: Default::default(),
            no_v4_send: AtomicBool::new(false),
            pconn4,
            pconn6,
            socket_endpoint4: SocketEndpointCache::default(),
            socket_endpoint6: SocketEndpointCache::default(),
            on_stun_receive: Default::default(),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            derp_recv_ch: derp_recv_ch_receiver,
            derp_map: Default::default(),
            peer_map: Default::default(),
            disco_private,
            private_key,
            derp_sender: derp_sender.clone(),
            my_derp: AtomicU16::new(0),
        });

        let derp_handler = DerpHandler::new(
            derp_receiver,
            derp_sender,
            derp_recv_ch_sender,
            inner.clone(),
        );

        let derp_task = tokio::task::spawn(async move {
            if let Err(err) = derp_handler.run().await {
                warn!("derp handler errored: {:?}", err);
            }
        });

        let c = Conn {
            inner,
            state: Arc::new(Mutex::new(ConnState::new(derp_task))),
        };

        Ok(c)
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    pub async fn re_stun(&self, why: &'static str) {
        self.derp_sender.send_async(DerpMessage::ReStun(why)).await;
    }

    pub async fn get_mapping_addr(&self, node_key: &key::node::PublicKey) -> Option<SocketAddr> {
        let peer_map = self.peer_map.read().await;
        peer_map
            .endpoint_for_node_key(node_key)
            .map(|ep| ep.fake_wg_addr)
    }

    /// Handles a "ping" CLI query.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn ping<F>(&self, peer: cfg::Node, mut res: cfg::PingResult, cb: F)
    where
        F: Fn(cfg::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    {
        res.node_ip = peer.addresses.get(0).copied();
        res.node_name = match peer.name.as_ref().and_then(|n| n.split('.').next()) {
            Some(name) => {
                // prefer DNS name
                Some(name.to_string())
            }
            None => {
                // else hostname
                Some(peer.hostinfo.hostname.clone())
            }
        };
        let ep = self
            .peer_map
            .read()
            .await
            .endpoint_for_node_key(&peer.key)
            .cloned();
        match ep {
            Some(ep) => {
                ep.cli_ping(res, cb).await;
            }
            None => {
                res.err = Some("unknown peer".to_string());
                cb(res);
            }
        }
    }

    pub(super) fn populate_cli_ping_response(
        &self,
        res: &mut cfg::PingResult,
        latency: Duration,
        ep: SocketAddr,
    ) {
        res.latency_seconds = Some(latency.as_secs_f64());
        if ep.ip() != DERP_MAGIC_IP {
            res.endpoint = Some(ep);
            return;
        }
        let region_id = usize::from(ep.port());
        res.derp_region_id = Some(region_id);
        res.derp_region_code = self.derp_region_code(region_id);
    }

    fn derp_region_code(&self, region_id: usize) -> String {
        match &*tokio::task::block_in_place(|| self.derp_map.blocking_read()) {
            Some(ref dm) => match dm.regions.get(&region_id) {
                Some(dr) => dr.region_code.clone(),
                None => "".to_string(),
            },
            None => "".to_string(),
        }
    }

    /// Returns the discovery public key.
    fn disco_public(&self) -> key::disco::PublicKey {
        self.disco_private.public()
    }

    /// Starts connecting to our DERP home, if any.
    async fn start_derp_home_connect(&self) {
        self.derp_sender
            .send_async(DerpMessage::Connect {
                port: self.my_derp(),
            })
            .await;
    }

    /// Returns the current IPv4 listener's port number.
    pub async fn local_port(&self) -> u16 {
        self.inner.local_port().await
    }

    /// Sends packet b to addr, which is either a real UDP address
    /// or a fake UDP address representing a DERP server (see derpmap).
    /// The provided public key identifies the recipient.
    ///
    /// The returned error is whether there was an error writing when it should've worked.
    /// The returned sent is whether a packet went out at all. An example of when they might
    /// be different: sending to an IPv6 address when the local machine doesn't have IPv6 support
    /// returns Ok(false); it's not an error, but nothing was sent.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) fn poll_send_addr(
        &self,
        udp_state: &quinn_udp::UdpState,
        cx: &mut Context,
        addr: SocketAddr,
        pub_key: Option<&key::node::PublicKey>,
        transmit: TransmitCow<'_>,
    ) -> Poll<io::Result<usize>> {
        if addr.ip() != DERP_MAGIC_IP {
            return self.poll_send_udp(udp_state, cx, addr, transmit);
        }

        match pub_key {
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "missing pub key for derp route",
                )));
            }
            Some(pub_key) => {
                let content = match transmit {
                    TransmitCow::Borrowed(t) => t[0].contents.clone(),
                    TransmitCow::Owned([t]) => t.contents,
                };
                let res = self.derp_sender.try_send(DerpMessage::WriteRequest {
                    port: addr.port(),
                    pub_key: pub_key.clone(),
                    content,
                });

                match res {
                    Ok(_) => {
                        // metricSendDERPQueued.Add(1)
                        return Poll::Ready(Ok(1));
                    }
                    Err(_) => {
                        // metricSendDERPErrorQueue.Add(1)
                        // Too many writes queued. Drop packet.
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "packet dropped",
                        )));
                    }
                }
            }
        }
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn poll_send_udp(
        &self,
        udp_state: &quinn_udp::UdpState,
        cx: &mut Context,
        addr: SocketAddr,
        transmit: TransmitCow<'_>,
    ) -> Poll<io::Result<usize>> {
        let mut transmit = transmit.to_owned();
        transmit[0].destination = addr;
        match addr {
            SocketAddr::V4(_) => self.pconn4.poll_send(udp_state, cx, &transmit),
            SocketAddr::V6(_) => {
                if let Some(ref conn) = self.pconn6 {
                    conn.poll_send(udp_state, cx, &transmit)
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "no IPv6 connection",
                    )))
                }
            }
        }
    }

    /// Handles deciding if a received UDP packet should be reported to the above layer or not.
    /// Returns `false` if this is an internal packet and it should not be reported.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn receive_ip(
        &self,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
        cache: &SocketEndpointCache,
    ) -> bool {
        debug!("received data {} from {}", meta.len, meta.addr);
        // Trunacte the slice, to the actual message length.
        let b = &b[..meta.len];
        if stun::is(b) {
            debug!("received STUN message {}", b.len());
            if let Some(ref f) =
                &*tokio::task::block_in_place(|| self.on_stun_receive.blocking_read())
            {
                f(b, meta.addr);
            }
            return false;
        }
        if self.handle_disco_message(b, meta.addr, None) {
            debug!("received DISCO message {}", b.len());
            return false;
        }
        if let Some(de) = cache.get(&meta.addr) {
            meta.addr = de.fake_wg_addr;
        } else {
            let peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_read());
            match peer_map.endpoint_for_ip_port(&meta.addr) {
                None => {
                    debug!("no peer_map state found for {}", meta.addr);
                    return false;
                }
                Some(de) => {
                    cache.update(meta.addr, de.clone());
                    meta.addr = de.fake_wg_addr;
                }
            }
        }

        // ep.noteRecvActivity();
        // if stats := c.stats.Load(); stats != nil {
        //     stats.UpdateRxPhysical(ep.nodeAddr, ipp, len(b));
        // }

        debug!("received passthrough message {}", b.len());

        true
    }

    /// Returns `true` if the message was internal, `false` otherwise.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn process_derp_read_result(
        &self,
        dm: DerpReadResult,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
    ) -> bool {
        debug!("process_derp_read {} bytes", dm.buf.len());
        if dm.buf.is_empty() {
            return true;
        }
        let region_id = dm.region_id;

        let ipp = SocketAddr::new(
            DERP_MAGIC_IP,
            u16::try_from(region_id).expect("invalid region id"),
        );

        if self.handle_disco_message(&dm.buf, ipp, Some(&dm.src)) {
            // Message was internal, do not bubble up.
            return true;
        }

        let ep_fake_wg_addr = {
            let peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_read());
            peer_map
                .endpoint_for_node_key(&dm.src)
                .map(|ep| ep.fake_wg_addr)
        };

        match ep_fake_wg_addr {
            Some(ep_fake_wg_addr) => {
                b[..dm.buf.len()].copy_from_slice(&dm.buf);

                // Update RecvMeta structure accordingly.
                meta.len = dm.buf.len();
                meta.stride = dm.buf.len();
                meta.addr = ep_fake_wg_addr;

                // if stats := c.stats.Load(); stats != nil {
                // 	stats.UpdateRxPhysical(ep.nodeAddr, ipp, dm.n)
                // }
                false
            }
            None => {
                // We don't know anything about this node key, nothing to record or process.
                true
            }
        }
    }

    /// Sends discovery message m to dst_disco at dst.
    ///
    /// If dst is a DERP IP:port, then dst_key must be Some.
    ///
    /// The dst_key should only be `Some` the dst_disco key unambiguously maps to exactly one peer.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) async fn send_disco_message(
        &self,
        dst: SocketAddr,
        dst_key: Option<&key::node::PublicKey>,
        dst_disco: &key::disco::PublicKey,
        msg: disco::Message,
    ) -> Result<bool> {
        debug!("sending disco message to {}: {:?}", dst, msg);
        let is_derp = dst.ip() == DERP_MAGIC_IP;
        let is_pong = matches!(msg, disco::Message::Pong(_));
        if is_pong && !is_derp && dst.ip().is_ipv4() {
            // TODO: figure oute the right value for this (debugIPv4DiscoPingPenalty())
            time::sleep(Duration::from_millis(10)).await;
        }

        if self.is_closed() {
            bail!("connection closed");
        }
        let mut state = self.state.lock().await;
        let ConnState { disco_info, .. } = &mut *state;
        let di = get_disco_info(disco_info, &self.disco_private, dst_disco);
        let seal = di.shared_key.seal(&msg.as_bytes());
        drop(state);

        // TODO
        // if is_derp {
        // 	metricSendDiscoDERP.Add(1)
        // } else {
        // 	metricSendDiscoUDP.Add(1)
        // }

        let pkt = disco::encode_message(&self.disco_public(), seal);
        let udp_state = quinn_udp::UdpState::default(); // TODO: store
        let sent = futures::future::poll_fn(move |cx| {
            self.poll_send_addr(
                &udp_state,
                cx,
                dst,
                dst_key,
                quinn_proto::Transmit {
                    destination: dst,
                    contents: pkt.clone(), // TODO: avoid
                    ecn: None,
                    segment_size: None, // TODO: make sure this is correct
                    src_ip: None,       // TODO
                }
                .into(),
            )
        })
        .await;
        match sent {
            Ok(0) => {
                // Can't send. (e.g. no IPv6 locally)
                Ok(false)
            }
            Ok(_n) => {
                // TODO:
                // if is_derp {
                //     metricSentDiscoDERP.Add(1);
                // } else {
                //     metricSentDiscoUDP.Add(1);
                // }
                // match msg {
                //     case *disco.Ping:
                //     	metricSentDiscoPing.Add(1)
                //     case *disco.Pong:
                //     	metricSentDiscoPong.Add(1)
                //     case *disco.CallMeMaybe:
                //     	metricSentDiscoCallMeMaybe.Add(1)
                //     }
                Ok(true)
            }
            Err(err) => {
                warn!("disco: failed to send {:?} to {}: {:?}", msg, dst, err);
                Err(err.into())
            }
        }
    }

    /// Handles a discovery message and reports whether `msg`f was a Tailscale inter-node discovery message.
    ///
    /// A discovery message has the form:
    ///
    ///   - magic             [6]byte
    ///   - senderDiscoPubKey [32]byte
    ///   - nonce             [24]byte
    ///   - naclbox of payload (see disco package for inner payload format)
    ///
    /// For messages received over DERP, the src.ip() will be DERP_MAGIC_IP (with src.port() being the region ID) and the
    /// derp_node_src will be the node key it was received from at the DERP layer. derp_node_src is None when received over UDP.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn handle_disco_message(
        &self,
        msg: &[u8],
        src: SocketAddr,
        derp_node_src: Option<&key::node::PublicKey>,
    ) -> bool {
        let source = disco::source_and_box(msg);
        if source.is_none() {
            return false;
        }

        let (source, sealed_box) = source.unwrap();

        if self.is_closed() {
            return true;
        }

        let sender = key::disco::PublicKey::from(source);
        let mut peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_write());
        if !peer_map.any_endpoint_for_disco_key(&sender) {
            // TODO:
            // metricRecvDiscoBadPeer.Add(1)
            debug!(
                "disco: ignoring disco-looking frame, don't know endpoint for {:?}",
                sender
            );
            return true;
        }

        // We're now reasonably sure we're expecting communication from
        // this peer, do the heavy crypto lifting to see what they want.

        let mut state = tokio::task::block_in_place(|| self.state.blocking_lock());
        let ConnState { disco_info, .. } = &mut *state;
        let di = get_disco_info(disco_info, &self.disco_private, &sender);
        let payload = di.shared_key.open(&sealed_box);
        if payload.is_err() {
            // This might be have been intended for a previous
            // disco key.  When we restart we get a new disco key
            // and old packets might've still been in flight (or
            // scheduled). This is particularly the case for LANs
            // or non-NATed endpoints.
            // Don't log in normal case. Pass on to wireguard, in case
            // it's actually a wireguard packet (super unlikely, but).
            debug!(
                "disco: [{:?}] failed to open box from {:?} (wrong rcpt?) {:?}",
                self.disco_public(),
                sender,
                payload,
            );
            // TODO:
            // metricRecvDiscoBadKey.Add(1)
            return true;
        }
        let payload = payload.unwrap();
        let dm = disco::Message::from_bytes(&payload);
        debug!("disco: disco.parse = {:?}", dm);

        if dm.is_err() {
            // Couldn't parse it, but it was inside a correctly
            // signed box, so just ignore it, assuming it's from a
            // newer version of Tailscale that we don't
            // understand. Not even worth logging about, lest it
            // be too spammy for old clients.

            // TODO:
            // metricRecvDiscoBadParse.Add(1)
            return true;
        }

        let dm = dm.unwrap();
        let is_derp = src.ip() == DERP_MAGIC_IP;
        // if isDERP {
        //     metricRecvDiscoDERP.Add(1);
        // } else {
        //     metricRecvDiscoUDP.Add(1)
        // };

        match dm {
            disco::Message::Ping(ping) => {
                // metricRecvDiscoPing.Add(1)
                self.handle_ping(&mut state, &mut peer_map, ping, &sender, src, derp_node_src);
                true
            }
            disco::Message::Pong(pong) => {
                // metricRecvDiscoPong.Add(1)

                // There might be multiple nodes for the sender's DiscoKey.
                // Ask each to handle it, stopping once one reports that
                // the Pong's TxID was theirs.
                let eps: Vec<_> = peer_map
                    .endpoints_with_disco_key(&sender)
                    .cloned()
                    .collect();
                for ep in eps {
                    if ep.handle_pong_conn(&mut *peer_map, &self.disco_public(), &pong, di, src) {
                        break;
                    }
                }
                true
            }
            disco::Message::CallMeMaybe(cm) => {
                // metricRecvDiscoCallMeMaybe.Add(1)

                if !is_derp || derp_node_src.is_none() {
                    // CallMeMaybe messages should only come via DERP.
                    debug!("[unexpected] CallMeMaybe packets should only come via DERP");
                    return true;
                }
                let node_key = derp_node_src.unwrap();
                let di_disco_key = di.disco_key.clone();
                drop(di);
                let ep = peer_map.endpoint_for_node_key(&node_key);
                if ep.is_none() {
                    // metricRecvDiscoCallMeMaybeBadNode.Add(1)
                    debug!(
                        "disco: ignoring CallMeMaybe from {:?}; {:?} is unknown",
                        sender, derp_node_src
                    );
                    return true;
                }
                let ep = ep.unwrap().clone();
                let ep_disco_key = ep.disco_key();
                if ep_disco_key != di_disco_key {
                    // metricRecvDiscoCallMeMaybeBadDisco.Add(1)
                    debug!("[unexpected] CallMeMaybe from peer via DERP whose netmap discokey != disco source");
                    return true;
                }

                {
                    let ConnState { disco_info, .. } = &mut *state;
                    let di = get_disco_info(disco_info, &self.disco_private, &sender);
                    di.set_node_key(node_key.clone());
                }
                info!(
                    "disco: {:?}<-{:?} ({:?}, {:?})  got call-me-maybe, {} endpoints",
                    self.disco_public(),
                    ep_disco_key,
                    ep.public_key,
                    src,
                    cm.my_number.len()
                );

                tokio::task::spawn(async move {
                    ep.handle_call_me_maybe(cm).await;
                });

                true
            }
        }
    }

    /// Attempts to look up an unambiguous mapping from a DiscoKey `dk` (which sent ping dm) to a NodeKey.
    /// `None` if not unamabigous.
    ///
    /// derp_node_src is `Some` if the disco ping arrived via DERP.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn unambiguous_node_key_of_ping(
        &self,
        peer_map: &PeerMap,
        dm: &disco::Ping,
        dk: &key::disco::PublicKey,
        derp_node_src: Option<&key::node::PublicKey>,
    ) -> Option<key::node::PublicKey> {
        if let Some(src) = derp_node_src {
            if let Some(ep) = peer_map.endpoint_for_node_key(src) {
                if &tokio::task::block_in_place(|| ep.state.blocking_lock()).disco_key == dk {
                    return Some(src.clone());
                }
            }
        }

        // Pings contains its node source. See if it maps back.
        if let Some(ep) = peer_map.endpoint_for_node_key(&dm.node_key) {
            if &tokio::task::block_in_place(|| ep.state.blocking_lock()).disco_key == dk {
                return Some(dm.node_key.clone());
            }
        }

        // If there's exactly 1 node in our netmap with DiscoKey dk,
        // then it's not ambiguous which node key dm was from.
        if let Some(set) = peer_map.nodes_of_disco.get(dk) {
            if set.len() == 1 {
                return Some(set.iter().next().unwrap().clone());
            }
        }

        None
    }

    /// di is the DiscoInfo of the source of the ping.
    /// derp_node_src is non-zero if the ping arrived via DERP.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn handle_ping(
        &self,
        state: &mut ConnState,
        peer_map: &mut PeerMap,
        dm: disco::Ping,
        sender: &key::disco::PublicKey,
        src: SocketAddr,
        derp_node_src: Option<&key::node::PublicKey>,
    ) {
        let ConnState { disco_info, .. } = &mut *state;
        let di = get_disco_info(disco_info, &self.disco_private, &sender);
        let likely_heart_beat = Some(src) == di.last_ping_from
            && di
                .last_ping_time
                .map(|s| s.elapsed() < Duration::from_secs(5))
                .unwrap_or_default();
        di.last_ping_from.replace(src);
        di.last_ping_time.replace(Instant::now());
        let is_derp = src.ip() == DERP_MAGIC_IP;

        // If we can figure out with certainty which node key this disco
        // message is for, eagerly update our IP<>node and disco<>node
        // mappings to make p2p path discovery faster in simple
        // cases. Without this, disco would still work, but would be
        // reliant on DERP call-me-maybe to establish the disco<>node
        // mapping, and on subsequent disco handlePongLocked to establish the IP<>disco mapping.
        if let Some(nk) =
            self.unambiguous_node_key_of_ping(&*peer_map, &dm, &di.disco_key, derp_node_src)
        {
            if !is_derp {
                peer_map.set_node_key_for_ip_port(&src, &nk);
            }
            di.set_node_key(nk);
        }

        // If we got a ping over DERP, then derp_node_src is non-zero and we reply
        // over DERP (in which case ip_dst is also a DERP address).
        // But if the ping was over UDP (ip_dst is not a DERP address), then dst_key
        // will be zero here, but that's fine: send_disco_message only requires
        // a dstKey if the dst ip:port is DERP.
        if is_derp {
            assert!(derp_node_src.is_some());
        } else {
            assert!(derp_node_src.is_none());
        }
        let mut dst_key = derp_node_src.cloned();

        // Remember this route if not present.
        let mut num_nodes = 0;
        let mut dup = false;
        if let Some(ref dst_key) = dst_key {
            if let Some(ep) = peer_map.endpoint_for_node_key(dst_key) {
                if ep.add_candidate_endpoint(src, dm.tx_id) {
                    return;
                }
                num_nodes = 1;
            }
        } else {
            for ep in peer_map.endpoints_with_disco_key(&di.disco_key) {
                if ep.add_candidate_endpoint(src, dm.tx_id) {
                    dup = true;
                    break;
                }
                num_nodes += 1;
                if num_nodes == 1 && dst_key.is_none() {
                    dst_key.replace(ep.public_key.clone());
                }
            }
            if dup {
                return;
            }
            if num_nodes > 1 {
                // Zero it out if it's ambiguous, so send_disco_message logging isn't confusing.
                dst_key = None;
            }
        }

        if num_nodes == 0 {
            warn!(
                "[unexpected] got disco ping from {:?}/{:?} for node not in peers",
                src, derp_node_src
            );
            return;
        }

        if !likely_heart_beat {
            let ping_node_src_str = if num_nodes > 1 {
                "[one-of-multi]".to_string()
            } else {
                format!("{:?}", dst_key)
            };
            info!(
                "disco: {:?}<-{:?} ({:?}, {:?})  got ping tx={:?}",
                self.disco_public(),
                di.disco_key,
                ping_node_src_str,
                src,
                dm.tx_id
            );
        }

        let ip_dst = src;
        let disco_dest = di.disco_key.clone();
        let pong = disco::Message::Pong(disco::Pong {
            tx_id: dm.tx_id,
            src,
        });

        let this = self.clone();
        tokio::task::spawn(async move {
            if let Err(err) = this
                .send_disco_message(ip_dst, dst_key.as_ref(), &disco_dest, pong)
                .await
            {
                warn!("failed to send disco message to {}: {:?}", ip_dst, err);
            }
        });
    }

    /// Schedules a send of disco.CallMeMaybe to de via derpAddr
    /// once we know that our STUN endpoint is fresh.
    ///
    /// derp_addr is Endpoint.derp_addr at the time of send. It's assumed the peer won't be
    /// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
    /// If they do, traffic will just go over DERP for a bit longer until the next discovery round.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) async fn enqueue_call_me_maybe(&self, derp_addr: SocketAddr, endpoint: Endpoint) {
        self.derp_sender
            .send_async(DerpMessage::EnqueueCallMeMaybe {
                derp_addr,
                endpoint,
            })
            .await;
    }

    /// Sets the connection's preferred local port.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_preferred_port(&self, port: u16) {
        // TODO: wait for response
        self.derp_sender
            .send_async(DerpMessage::SetPreferredPort(port))
            .await;
    }

    /// Controls which (if any) DERP servers are used. A `None` value means to disable DERP; it's disabled by default.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_derp_map(&self, dm: Option<derp::DerpMap>) {
        let derp_map_locked = &mut *self.derp_map.write().await;
        if *derp_map_locked == dm {
            return;
        }

        let old = std::mem::replace(derp_map_locked, dm);
        let derp_map = derp_map_locked.clone();
        drop(derp_map_locked); // clone and unlock
        if derp_map.is_none() {
            self.derp_sender
                .send_async(DerpMessage::CloseAll("derp-disabled"))
                .await;
            return;
        }

        // Reconnect any DERP region that changed definitions.
        if let Some(old) = old {
            let mut changes = false;
            for (rid, old_def) in old.regions {
                if let Some(new_def) = derp_map.as_ref().unwrap().regions.get(&rid) {
                    if &old_def == new_def {
                        continue;
                    }
                }
                changes = true;
                if u16::try_from(rid).expect("region too large") == self.my_derp() {
                    self.my_derp.store(0, Ordering::Relaxed);
                }
                self.derp_sender
                    .send_async(DerpMessage::Close(
                        rid.try_into().expect("region too large"),
                        "derp-region-redefined",
                    ))
                    .await;
            }
            // TODO:
            // if changes {
            //     self.log_active_derp(&mut state);
            // }
        }

        let this = self.clone();
        tokio::task::spawn(async move {
            this.re_stun("derp-map-update").await;
        });
    }

    /// Called when the control client gets a new network map from the control server.
    /// It should not use the DerpMap field of NetworkMap; that's
    /// conditionally sent to set_derp_map instead.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_network_map(&self, nm: netmap::NetworkMap) {
        if self.is_closed() {
            return;
        }

        let mut state = self.state.lock().await;

        // Update self.net_map regardless, before the following early return.
        let prior_netmap = state.net_map.replace(nm);

        // TODO:
        // metricNumPeers.Set(int64(len(nm.Peers)))

        if prior_netmap.is_some()
            && prior_netmap.as_ref().unwrap().peers == state.net_map.as_ref().unwrap().peers
        {
            // The rest of this function is all adjusting state for peers that have
            // changed. But if the set of peers is equal no need to do anything else.
            return;
        }

        info!(
            "got updated network map; {} peers",
            state.net_map.as_ref().unwrap().peers.len()
        );

        // Try a pass of just upserting nodes and creating missing
        // endpoints. If the set of nodes is the same, this is an
        // efficient alloc-free update. If the set of nodes is different,
        // we'll fall through to the next pass, which allocates but can
        // handle full set updates.
        let ConnState {
            disco_info,
            net_map,
            ..
        } = &mut *state;
        let mut peer_map = self.peer_map.write().await;
        for n in &net_map.as_ref().unwrap().peers {
            if let Some(ep) = peer_map.endpoint_for_node_key(&n.key).cloned() {
                let old_disco_key = ep.disco_key();
                ep.update_from_node(n).await;
                peer_map.upsert_endpoint(ep, Some(&old_disco_key)).await; // maybe update discokey mappings in peerMap
                continue;
            }
            let ep = Endpoint::new(self.clone(), n);
            ep.update_from_node(n).await;
            peer_map.upsert_endpoint(ep, None).await;
        }

        // If the set of nodes changed since the last set_network_map, the
        // upsert loop just above made self.peer_map contain the union of the
        // old and new peers - which will be larger than the set from the
        // current netmap. If that happens, go through the allocful
        // deletion path to clean up moribund nodes.
        if peer_map.node_count() != net_map.as_ref().unwrap().peers.len() {
            let keep: HashSet<_> = net_map
                .as_ref()
                .unwrap()
                .peers
                .iter()
                .map(|n| n.key.clone())
                .collect();

            let to_delete: Vec<_> = peer_map
                .endpoints()
                .filter_map(|ep| {
                    if keep.contains(&ep.public_key) {
                        None
                    } else {
                        Some(ep.clone())
                    }
                })
                .collect();

            for ep in to_delete {
                peer_map.delete_endpoint(&ep).await;
            }
        }

        // discokeys might have changed in the above. Discard unused info.
        disco_info.retain(|dk, _| peer_map.any_endpoint_for_disco_key(dk));
    }

    /// Reports the number of active DERP connections.
    pub async fn derps(&self) -> usize {
        todo!()
        // self.state.lock().await.active_derp.len()
    }

    async fn derp_region_code_of_addr(&self, ip_port: &str) -> String {
        let addr: std::result::Result<SocketAddr, _> = ip_port.parse();
        match addr {
            Ok(addr) => {
                let region_id = usize::from(addr.port());
                self.derp_region_code_of_id(region_id).await
            }
            Err(_) => String::new(),
        }
    }

    async fn derp_region_code_of_id(&self, region_id: usize) -> String {
        if let Some(ref dm) = &*self.derp_map.read().await {
            if let Some(r) = dm.regions.get(&region_id) {
                return r.region_code.clone();
            }
        }

        String::new()
    }

    /// Closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn close(&self) -> Result<()> {
        if self.is_closed() {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        self.closing.store(true, Ordering::Relaxed);
        self.port_mapper.close();

        {
            let peer_map = self.peer_map.read().await;
            for ep in peer_map.endpoints() {
                ep.stop_and_reset().await;
            }
        }

        self.closed.store(true, Ordering::SeqCst);
        // c.connCtxCancel()
        self.derp_sender.send_async(DerpMessage::Shutdown).await;
        // Ignore errors from c.pconnN.Close.
        // They will frequently have been closed already by a call to connBind.Close.
        if let Some(ref conn) = self.pconn6 {
            conn.close().await.ok();
        }
        self.pconn4.close().await.ok();

        if let Some(task) = state.derp_task.take() {
            task.await;
        }

        Ok(())
    }

    async fn on_port_map_changed(&self) {
        self.re_stun("portmap-changed").await;
    }

    /// Initial connection setup.
    async fn bind(port: u16) -> Result<(RebindingUdpConn, Option<RebindingUdpConn>)> {
        let pconn6 = match RebindingUdpConn::bind(port, Network::Ip6).await {
            Ok(conn) => Some(conn),
            Err(err) => {
                info!("rebind ignoring IPv6 bind failure: {:?}", err);
                None
            }
        };

        let pconn4 = RebindingUdpConn::bind(port, Network::Ip4)
            .await
            .context("rebind IPv4 failed")?;

        Ok((pconn4, pconn6))
    }

    /// Closes and re-binds the UDP sockets and resets the DERP connection.
    /// It should be followed by a call to ReSTUN.
    pub async fn rebind_all(&self) {
        // TODO: check all calls for responses.
        self.derp_sender.send_async(DerpMessage::RebindAll).await;
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) fn poll_send_raw(
        &self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        addr: SocketAddr,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        debug!("poll_send_raw: {} packets", transmits.len());

        let mut sum = 0;

        if addr.is_ipv6() && self.pconn6.is_none() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "no IPv6 connection",
            )));
        }

        let conn = if addr.is_ipv6() {
            self.pconn6.as_ref().unwrap()
        } else {
            &self.pconn4
        };

        let res = if transmits.iter().any(|t| t.destination != addr) {
            // :(
            let g: Vec<Transmit> = transmits
                .iter()
                .map(|t| Transmit {
                    destination: addr, // update destination
                    ecn: t.ecn,
                    contents: t.contents.clone(),
                    segment_size: t.segment_size,
                    src_ip: t.src_ip,
                })
                .collect();

            conn.poll_send(state, cx, &g[..])
        } else {
            conn.poll_send(state, cx, transmits)
        };
        let res = match res {
            Poll::Pending => None,
            Poll::Ready(Ok(r)) => {
                sum += r;
                None
            }
            Poll::Ready(Err(err)) => Some(Poll::Ready(Err(err))),
        };

        if let Some(err) = res {
            return err;
        }

        debug!("sent {} packets", sum);
        debug_assert!(
            sum <= transmits.len(),
            "too many msgs {} > {}",
            sum,
            transmits.len()
        );

        if sum > 0 {
            return Poll::Ready(Ok(sum));
        }

        Poll::Pending
    }
}

/// A route entry for a public key, saying that a certain peer should be available at DERP
/// node derpID, as long as the current connection for that derpID is dc. (but dc should not be
/// used to write directly; it's owned by the read/write loops)
#[derive(Debug)]
struct DerpRoute {
    derp_id: u16,
    dc: derp::http::Client, // don't use directly; see comment above
}

/// The info and state for the DiscoKey in the Conn.discoInfo map key.
///
/// Note that a DiscoKey does not necessarily map to exactly one
/// node. In the case of shared nodes and users switching accounts, two
/// nodes in the NetMap may legitimately have the same DiscoKey.  As
/// such, no fields in here should be considered node-specific.
pub(super) struct DiscoInfo {
    /// The same as the Conn.discoInfo map key, just so you can pass around a `DiscoInfo` alone.
    /// Not modified once initialized.
    disco_key: key::disco::PublicKey,

    /// The precomputed key for communication with the peer that has the `DiscoKey` used to
    /// look up this `DiscoInfo` in Conn.discoInfo.
    /// Not modified once initialized.
    shared_key: key::disco::SharedSecret,

    // Mutable fields follow, owned by Conn.mu:
    /// Tthe src of a ping for `DiscoKey`.
    last_ping_from: Option<SocketAddr>,

    /// The last time of a ping for discoKey.
    last_ping_time: Option<Instant>,

    /// The last NodeKey seen using `DiscoKey`.
    /// It's only updated if the NodeKey is unambiguous.
    last_node_key: Option<key::node::PublicKey>,

    /// The time a NodeKey was last seen using this `DiscoKey`. It's only updated if the
    /// NodeKey is unambiguous.
    last_node_key_time: Option<Instant>,
}

impl DiscoInfo {
    /// Sets the most recent mapping from di.discoKey to the NodeKey nk.
    pub fn set_node_key(&mut self, nk: key::node::PublicKey) {
        self.last_node_key.replace(nk);
        self.last_node_key_time.replace(Instant::now());
    }
}

/// Reports whether x and y represent the same set of endpoints. The order doesn't matter.
fn endpoint_sets_equal(xs: &[cfg::Endpoint], ys: &[cfg::Endpoint]) -> bool {
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
    let mut m: HashMap<&cfg::Endpoint, usize> = HashMap::new();
    for x in xs {
        *m.entry(x).or_default() |= 1;
    }
    for y in ys {
        *m.entry(y).or_default() |= 2;
    }

    m.values().all(|v| *v == 3)
}

impl AsyncUdpSocket for Conn {
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn poll_send(
        &mut self,
        udp_state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        debug!(
            "sending:\n{}",
            transmits
                .iter()
                .map(|t| format!(
                    "  dest: {}, src: {:?}, content_len: {}\n",
                    t.destination,
                    t.src_ip,
                    t.contents.len()
                ))
                .collect::<String>()
        );

        let mut num_msgs = 0;
        let res = group_by(
            transmits,
            |a, b| a.destination == b.destination,
            |group| {
                let dest = &group[0].destination;
                let peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_read());
                match peer_map.endpoint_for_ip_port(dest) {
                    Some(ep) => match ep.poll_send(udp_state, cx, &group) {
                        Poll::Pending => None,
                        Poll::Ready(Ok(n)) => {
                            num_msgs += n;
                            None
                        }
                        Poll::Ready(Err(e)) => Some(Poll::Ready(Err(e))),
                    },
                    None => {
                        // Should this error, do we need to create the EP?
                        debug!("trying to find endpoint for {}", dest);
                        None
                    }
                }
            },
        );
        if let Some(err) = res {
            return err;
        }

        debug_assert!(
            num_msgs <= transmits.len(),
            "too many msgs {} > {}",
            num_msgs,
            transmits.len()
        );
        if num_msgs > 0 {
            return Poll::Ready(Ok(num_msgs));
        }

        Poll::Pending
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // FIXME: currently ipv4 load results in ipv6 traffic being ignored
        debug_assert_eq!(bufs.len(), meta.len(), "non matching bufs & metas");
        debug!("trying to receive up to {} packets", bufs.len());

        let mut num_msgs_total = 0;

        // IPv4
        match self.pconn4.poll_recv(cx, bufs, meta) {
            Poll::Pending => {}
            Poll::Ready(Err(err)) => {
                return Poll::Ready(Err(err));
            }
            Poll::Ready(Ok(mut num_msgs)) => {
                debug!("received {} msgs on IPv4", num_msgs);
                debug_assert!(num_msgs <= bufs.len(), "{} > {}", num_msgs, bufs.len());
                let mut i = 0;
                while i < num_msgs {
                    if !self.receive_ip(&mut bufs[i], &mut meta[i], &self.socket_endpoint4) {
                        // move all following over
                        for k in i..num_msgs - 1 {
                            bufs.swap(k, k + 1);
                            meta.swap(k, k + 1);
                        }

                        // reduce num_msgs
                        num_msgs -= 1;
                    }

                    i += 1;
                }
                num_msgs_total += num_msgs;
            }
        }
        // IPv6
        if num_msgs_total < bufs.len() {
            if let Some(ref conn) = self.pconn6 {
                match conn.poll_recv(cx, &mut bufs[num_msgs_total..], &mut meta[num_msgs_total..]) {
                    Poll::Pending => {}
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(mut num_msgs)) => {
                        debug!("received {} msgs on IPv6", num_msgs);
                        debug_assert!(num_msgs + num_msgs_total <= bufs.len());
                        let mut i = num_msgs_total;
                        while i < num_msgs + num_msgs_total {
                            if !self.receive_ip(&mut bufs[i], &mut meta[i], &self.socket_endpoint6)
                            {
                                // move all following over
                                for k in i..num_msgs + num_msgs_total - 1 {
                                    bufs.swap(k, k + 1);
                                    meta.swap(k, k + 1);
                                }

                                // reduce num_msgs
                                num_msgs -= 1;
                            }

                            i += 1;
                        }
                        num_msgs_total += num_msgs;
                    }
                }
            }
        }
        // Derp
        let mut i = num_msgs_total;
        if num_msgs_total < bufs.len() {
            while i < bufs.len() {
                if let Ok(dm) = self.derp_recv_ch.try_recv() {
                    if self.is_closed() {
                        break;
                    }

                    let is_internal = self.process_derp_read_result(dm, &mut bufs[i], &mut meta[i]);
                    debug!("received derp message, is internal? {}", is_internal);
                    if is_internal {
                        // No read, continue
                        continue;
                    }

                    i += 1;
                } else {
                    break;
                }
            }
            num_msgs_total = i;
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs_total > 0 {
            info!(
                "received {:?} msgs {}",
                meta.iter().map(|m| m.addr).collect::<Vec<_>>(),
                num_msgs_total
            );

            return Poll::Ready(Ok(num_msgs_total));
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // TODO: think more about this
        // needs to pretend ipv6 always as the fake addrs are ipv6
        if let Some(ref conn) = self.pconn6 {
            return conn.local_addr_blocking();
        }
        let addr = self.pconn4.local_addr_blocking()?;
        Ok(addr)
    }
}

/// The type sent by run_derp_client to receive_ipv4 when a DERP packet is available.
struct DerpReadResult {
    region_id: u16,
    src: key::node::PublicKey,
    /// packet data
    buf: Vec<u8>,
}

struct DerpWriteRequest {
    pub_key: key::node::PublicKey,
    content: Vec<u8>,
}

#[derive(Default)]
struct SocketEndpointCache(std::sync::Mutex<Option<(SocketAddr, u64, Endpoint)>>);

impl SocketEndpointCache {
    pub fn get(&self, addr: &SocketAddr) -> Option<Endpoint> {
        if let Some(inner) = &*self.0.lock().unwrap() {
            if &inner.0 == addr && inner.1 == inner.2.num_stop_and_reset() {
                return Some(inner.2.clone());
            }
        }

        None
    }

    pub fn update(&self, addr: SocketAddr, ep: Endpoint) {
        let mut inner = self.0.lock().unwrap();
        inner.replace((addr, ep.num_stop_and_reset(), ep));
    }
}

/// Contains fields for an active DERP connection.
#[derive(Debug)]
struct ActiveDerp {
    c: derp::http::Client,
    cancel: CancellationToken,
    /// The time of the last request for its write
    /// channel (currently even if there was no write).
    last_write: Instant,
    create_time: Instant,
}

/// Returns the previous or new DiscoInfo for `k`.
fn get_disco_info<'a>(
    disco_info: &'a mut HashMap<key::disco::PublicKey, DiscoInfo>,
    disco_private: &key::disco::SecretKey,
    k: &key::disco::PublicKey,
) -> &'a mut DiscoInfo {
    if !disco_info.contains_key(k) {
        let shared_key = disco_private.shared(k);
        disco_info.insert(
            k.clone(),
            DiscoInfo {
                disco_key: k.clone(),
                shared_key,
                last_ping_from: None,
                last_ping_time: None,
                last_node_key: None,
                last_node_key_time: None,
            },
        );
    }

    disco_info.get_mut(k).unwrap()
}

/// Simple DropGuard for decrementing a Waitgroup.
struct WgGuard(wg::AsyncWaitGroup);
impl Drop for WgGuard {
    fn drop(&mut self) {
        self.0.done();
    }
}

fn group_by<F, G, T, U>(transmits: &[T], f: F, mut g: G) -> Option<U>
where
    F: Fn(&T, &T) -> bool,
    G: FnMut(&[T]) -> Option<U>,
{
    if transmits.is_empty() {
        return None;
    }

    let mut last = &transmits[0];
    let mut start = 0;
    let mut end = 1;

    for i in 1..transmits.len() {
        if f(last, &transmits[i]) {
            // Same group, continue.
            end += 1;
        } else {
            // New group.
            let res = g(&transmits[start..end]);
            if res.is_some() {
                return res;
            }
            start = i;
            end = i + 1;
        }
        last = &transmits[i];
    }

    // Last group.
    g(&transmits[start..end])
}

/// Hack around the usage of `&[Transmit]` in AsyncUdpSocket methods, to avoid copies.
#[derive(Debug)]
pub(super) enum TransmitCow<'a> {
    Borrowed(&'a [Transmit; 1]),
    Owned([Transmit; 1]),
}

impl TransmitCow<'_> {
    fn to_owned(self) -> [Transmit; 1] {
        match self {
            Self::Borrowed([t]) => [Transmit {
                destination: t.destination,
                ecn: t.ecn,
                contents: t.contents.clone(),
                segment_size: t.segment_size,
                src_ip: t.src_ip,
            }],
            Self::Owned(t) => t,
        }
    }
}

impl Deref for TransmitCow<'_> {
    type Target = [Transmit];

    fn deref(&self) -> &Self::Target {
        match self {
            TransmitCow::Borrowed(t) => &t[..],
            TransmitCow::Owned(t) => &t[..],
        }
    }
}

impl<'a> From<&'a [Transmit; 1]> for TransmitCow<'a> {
    fn from(value: &'a [Transmit; 1]) -> Self {
        TransmitCow::Borrowed(value)
    }
}

impl From<Transmit> for TransmitCow<'_> {
    fn from(value: Transmit) -> Self {
        TransmitCow::Owned([value])
    }
}

enum DerpMessage {
    SetPreferredPort(u16),
    RebindAll,
    Shutdown,
    MaybeCloseOnRebind(Vec<IpAddr>),
    CloseAll(&'static str),
    Close(u16, &'static str),
    ReStun(&'static str),
    Connect {
        port: u16,
    },
    WriteRequest {
        port: u16,
        pub_key: key::node::PublicKey,
        content: Vec<u8>,
    },
    EnqueueCallMeMaybe {
        derp_addr: SocketAddr,
        endpoint: Endpoint,
    },
}

struct DerpHandler {
    conn: Arc<Inner>,
    msg_receiver: flume::Receiver<DerpMessage>,
    msg_sender: flume::Sender<DerpMessage>,
    /// Channel to send received derp messages on, for processing.
    derp_recv_sender: flume::Sender<DerpReadResult>,
    /// DERP regionID -> connection to a node in that region
    active_derp: HashMap<u16, ActiveDerp>,
    prev_derp: HashMap<u16, wg::AsyncWaitGroup>,
    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home DERP connection.  If they sent us a message
    /// on a different DERP connection (which should really only be on our DERP
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new DERP connection back to their home.
    derp_route: HashMap<key::node::PublicKey, DerpRoute>,
    /// Indicates the update endpoint state.
    endpoints_update_state: EndpointUpdateState,
    /// Records the endpoints found during the previous
    /// endpoint discovery. It's used to avoid duplicate endpoint change notifications.
    last_endpoints: Vec<cfg::Endpoint>,

    /// The last time the endpoints were updated, even if there was no change.
    last_endpoints_time: Option<Instant>,

    /// Functions to run (in their own tasks) when endpoints are refreshed.
    on_endpoint_refreshed:
        HashMap<Endpoint, Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    /// When set, is an AfterFunc timer that will call Conn::do_periodic_stun.
    periodic_re_stun_timer: Option<time::Interval>,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<cfg::NetInfo>,
}

impl DerpHandler {
    fn new(
        msg_receiver: flume::Receiver<DerpMessage>,
        msg_sender: flume::Sender<DerpMessage>,
        derp_recv_sender: flume::Sender<DerpReadResult>,
        conn: Arc<Inner>,
    ) -> Self {
        DerpHandler {
            msg_receiver,
            msg_sender,
            conn,
            derp_recv_sender,
            active_derp: HashMap::default(),
            prev_derp: HashMap::default(),
            derp_route: HashMap::new(),
            endpoints_update_state: EndpointUpdateState::new(),
            last_endpoints: Vec::new(),
            last_endpoints_time: None,
            on_endpoint_refreshed: HashMap::new(),
            periodic_re_stun_timer: None,
            net_info_last: None,
        }
    }

    async fn run(mut self) -> Result<()> {
        let mut cleanup_timer = time::interval(DERP_CLEAN_STALE_INTERVAL);

        let mut recvs = futures::stream::FuturesUnordered::new();
        let mut endpoints_update_receiver = self.endpoints_update_state.running.subscribe();

        loop {
            tokio::select! {
                msg = self.msg_receiver.recv_async() => {
                    match msg? {
                        DerpMessage::MaybeCloseOnRebind(ifs) => {
                            self.maybe_close_derps_on_rebind(&ifs).await;
                        }
                        DerpMessage::Shutdown => {
                            self.close_all_derp("conn-close").await;
                            return Ok(());
                        }
                        DerpMessage::CloseAll(reason) => {
                            self.close_all_derp(reason).await;
                        }
                        DerpMessage::Close(rid, reason) => {
                            self.close_derp(rid, reason).await;
                        }
                        DerpMessage::ReStun(reason) => {
                            self.re_stun(reason).await;
                        }
                        DerpMessage::Connect { port } => {
                            let (derp_client, cancel) = self.connect(port, None);
                            if let Some(cancel) = cancel {
                                let rs = ReaderState::new(port, cancel, derp_client);
                                recvs.push(rs.recv());
                            }
                        }

                        DerpMessage::WriteRequest { port, pub_key, content} => {
                            if let Some((derp_client, Some(cancel))) = self.send(port, pub_key, content).await {
                                let rs = ReaderState::new(port, cancel, derp_client);
                                recvs.push(rs.recv());
                            }
                        }
                        DerpMessage::EnqueueCallMeMaybe {
                            derp_addr,
                            endpoint,
                        } => {
                            self.enqueue_call_me_maybe(derp_addr, endpoint).await;
                        }
                        DerpMessage::RebindAll => {
                            self.rebind_all().await;
                        }
                        DerpMessage::SetPreferredPort(port) => {
                            self.set_preferred_port(port).await;
                        }
                    }
                }
                Some((rs, result, action)) = recvs.next() => {
                    match action {
                        ReadAction::None => {},
                        ReadAction::AddPeerRoute { peers, region, derp_client } => {
                            for peer in peers {
                                self.add_derp_peer_route(peer, region, derp_client.clone());
                            }
                        },
                        ReadAction::RemovePeerRoute { peers, region, derp_client } => {
                            for peer in peers {
                                self.remove_derp_peer_route(peer, region, &derp_client);
                            }
                        }
                    }
                    match result {
                        ReadResult::Break => {
                            // drop client
                            continue;
                        }
                        ReadResult::Continue => {
                            recvs.push(rs.recv())
                        }
                        ReadResult::Yield(read_result) => {
                            self.derp_recv_sender.send_async(read_result).await;
                            recvs.push(rs.recv());
                        }
                    }
                }
                _ = self.periodic_re_stun_timer.as_mut().unwrap().tick(), if self.periodic_re_stun_timer.is_some()  => {
                    self.re_stun("periodic").await;
                }
                _ = endpoints_update_receiver.changed() => {
                    let reason = endpoints_update_receiver.borrow().clone();
                    if let Some(reason) = reason {
                        self.update_endpoints(reason).await;
                    }
                }
                _ = cleanup_timer.tick() => {
                    self.clean_stale_derp().await;
                }
                else => {}
            }
        }
    }

    async fn clean_stale_derp(&mut self) {
        let now = Instant::now();
        let mut dirty = false;

        let mut to_close = Vec::new();
        for (i, ad) in &self.active_derp {
            if *i == self.conn.my_derp.load(Ordering::Relaxed) {
                continue;
            }
            if ad.last_write.duration_since(now) > DERP_INACTIVE_CLEANUP_TIME {
                to_close.push(*i);
                dirty = true;
            }
        }
        for i in to_close {
            self.close_derp(i, "idle").await;
        }
        if dirty {
            self.log_active_derp();
        }
    }

    async fn close_all_derp(&mut self, why: &'static str) {
        if self.active_derp.is_empty() {
            return;
        }
        // Need to collect to avoid double borrow
        let regions: Vec<_> = self.active_derp.keys().copied().collect();
        for region in regions {
            self.close_derp(region, why).await;
        }
        self.log_active_derp();
    }

    async fn close_derp(&mut self, region_id: u16, why: &'static str) {
        if let Some(ad) = self.active_derp.remove(&region_id) {
            debug!(
                "closing connection to derp-{} ({:?}), age {}s",
                region_id,
                why,
                ad.create_time.elapsed().as_secs()
            );

            let ActiveDerp { c, cancel, .. } = ad;
            c.close().await;
            cancel.cancel();

            // TODO:
            // metricNumDERPConns.Set(int64(len(c.activeDerp)))
        }
    }

    fn connect(
        &mut self,
        region_id: u16,
        peer: Option<&key::node::PublicKey>,
    ) -> (derp::http::Client, Option<CancellationToken>) {
        // See if we have a connection open to that DERP node ID
        // first. If so, might as well use it. (It's a little
        // arbitrary whether we use this one vs. the reverse route
        // below when we have both.)

        if let Some(ad) = self.active_derp.get_mut(&region_id) {
            ad.last_write = Instant::now();
            return (ad.c.clone(), None);
        }

        // If we don't have an open connection to the peer's home DERP
        // node, see if we have an open connection to a DERP node
        // where we'd heard from that peer already. For instance,
        // perhaps peer's home is Frankfurt, but they dialed our home DERP
        // node in SF to reach us, so we can reply to them using our
        // SF connection rather than dialing Frankfurt.
        if let Some(peer) = peer {
            if let Some(r) = self.derp_route.get(peer) {
                if let Some(ad) = self.active_derp.get_mut(&r.derp_id) {
                    if ad.c == r.dc {
                        ad.last_write = Instant::now();
                        return (ad.c.clone(), None);
                    }
                }
            }
        }

        let why = if let Some(peer) = peer {
            format!("{:?}", peer)
        } else {
            "home-keep-alive".to_string()
        };
        info!("adding connection to derp-{} for {}", region_id, why);

        let my_derp = self.conn.my_derp.load(Ordering::Relaxed);

        // Note that derp::http.new_region_client does not dial the server
        // (it doesn't block) so it is safe to do under the state lock.

        let conn0 = self.conn.clone();
        let conn1 = self.conn.clone();
        let dc = derp::http::ClientBuilder::new()
            .address_family_selector(move || {
                let conn = conn0.clone();
                Box::pin(async move {
                    // TODO: use atomic read?
                    if let Some(r) = &*conn.last_net_check_report.read().await {
                        return r.ipv6;
                    }
                    false
                })
            })
            .can_ack_pings(true)
            .is_preferred(my_derp == region_id)
            .new_region(self.conn.private_key.clone(), move || {
                let conn = conn1.clone();
                Box::pin(async move {
                    // Warning: it is not legal to acquire
                    // magicsock.Conn.mu from this callback.
                    // It's run from derp::http::Client.connect (via Send, etc)
                    // and the lock ordering rules are that magicsock.Conn.mu
                    // must be acquired before derp::http.Client.mu

                    if conn.is_closing() {
                        // We're closing anyway; return to stop dialing.
                        return None;
                    }

                    // Need to load the derp map without aquiring the lock

                    let derp_map = &*conn.derp_map.read().await;
                    match derp_map {
                        None => None,
                        Some(derp_map) => derp_map.regions.get(&usize::from(region_id)).cloned(),
                    }
                })
            });

        // TODO: DNS Cache
        // dc.DNSCache = dnscache.Get();

        let cancel = CancellationToken::new();
        let ad = ActiveDerp {
            c: dc.clone(),
            cancel: cancel.clone(),
            last_write: Instant::now(),
            create_time: Instant::now(),
        };
        self.active_derp.insert(region_id, ad);

        // TODO:
        // metricNumDERPConns.Set(int64(len(c.activeDerp)))
        self.log_active_derp();

        if let Some(ref f) = self.conn.on_derp_active {
            // TODO: spawn
            f();
        }

        (dc, Some(cancel))
    }

    async fn send(
        &mut self,
        port: u16,
        peer: key::node::PublicKey,
        content: Vec<u8>,
    ) -> Option<(derp::http::Client, Option<CancellationToken>)> {
        let region_id = port;
        {
            let derp_map = self.conn.derp_map.read().await;
            if derp_map.is_none() {
                warn!("DERP is disabled");
                return None;
            }
            if !derp_map
                .as_ref()
                .unwrap()
                .regions
                .contains_key(&usize::from(region_id))
            {
                warn!("unknown region id {}", region_id);
                return None;
            }
        }

        let (derp_client, cancel) = self.connect(region_id, Some(&peer));
        match derp_client.send(peer, content).await {
            Ok(_) => {
                // TODO:
                // metricSendDERP.Add(1)
            }
            Err(err) => {
                warn!("derp.send: failed {:?}", err);
                // TODO:
                // metricSendDERPError.Add(1)
            }
        }
        Some((derp_client, cancel))
    }

    /// Removes a DERP route entry previously added by add_derp_peer_route.
    async fn remove_derp_peer_route(
        &mut self,
        peer: key::node::PublicKey,
        derp_id: u16,
        dc: &derp::http::Client,
    ) {
        match self.derp_route.entry(peer) {
            std::collections::hash_map::Entry::Occupied(r) => {
                if r.get().derp_id == derp_id && &r.get().dc == dc {
                    r.remove();
                }
            }
            _ => {}
        }
    }

    /// Adds a DERP route entry, noting that peer was seen on DERP node `derp_id`, at least on the
    /// connection identified by `dc`.
    async fn add_derp_peer_route(
        &mut self,
        peer: key::node::PublicKey,
        derp_id: u16,
        dc: derp::http::Client,
    ) {
        self.derp_route.insert(peer, DerpRoute { derp_id, dc });
    }

    /// Called in response to a rebind, closes all DERP connections that don't have a local address in okay_local_ips
    /// and pings all those that do.
    async fn maybe_close_derps_on_rebind(&mut self, okay_local_ips: &[IpAddr]) {
        let mut tasks = Vec::new();
        for (region_id, ad) in &self.active_derp {
            let la = match ad.c.local_addr().await {
                None => {
                    tasks.push((*region_id, "rebind-no-localaddr"));
                    continue;
                }
                Some(la) => la,
            };

            if !okay_local_ips.contains(&la.ip()) {
                tasks.push((*region_id, "rebind-default-route-change"));
                continue;
            }

            let dc = ad.c.clone();
            let region_id = *region_id;
            // TODO:
            // tokio::task::spawn(
            // time::timeout(Duration::from_secs(3), async move {
            //     if let Err(_err) = dc.ping().await {
            //         self.close_or_reconnect_derp(region_id, "rebind-ping-fail")
            //             .await;
            //         return;
            //     }
            //     debug!("post-rebind ping of DERP region {} okay", region_id);
            // });
        }
        for (region_id, why) in tasks {
            self.close_or_reconnect_derp(region_id, why).await;
        }

        self.log_active_derp();
    }

    /// Closes the DERP connection to the provided `region_id` and starts reconnecting it if it's
    /// our current home DERP.
    async fn close_or_reconnect_derp(&mut self, region_id: u16, why: &'static str) {
        self.close_derp(region_id.into(), why).await;
        if self.conn.my_derp.load(Ordering::Relaxed) == region_id {
            self.connect(region_id, None);
        }
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    async fn re_stun(&mut self, why: &'static str) {
        // TODO:
        // metricReSTUNCalls.Add(1)

        if self.endpoints_update_state.is_running() {
            if Some(why) != self.endpoints_update_state.want_update {
                debug!(
                    "re_stun({:?}): endpoint update active, need another later: {:?}",
                    self.endpoints_update_state.want_update, why
                );
                self.endpoints_update_state.want_update.replace(why);
            }
        } else {
            debug!("re_stun({}): started", why);
            self.endpoints_update_state
                .running
                .send(Some(why))
                .expect("update state not to go away");
        }
    }

    async fn update_endpoints(&mut self, why: &'static str) {
        // TODO:
        // metricUpdateEndpoints.Add(1)

        debug!("starting endpoint update ({})", why);
        if self.conn.no_v4_send.load(Ordering::Relaxed) {
            if !self.conn.is_closed() {
                debug!("last netcheck reported send error. Rebinding.");
                self.rebind_all().await;
            }
        }

        match self.determine_endpoints().await {
            Ok(endpoints) => {
                if self.set_endpoints(&endpoints).await {
                    log_endpoint_change(&endpoints);
                    if let Some(ref cb) = self.conn.on_endpoints {
                        cb(&endpoints[..]);
                    }
                }
            }
            Err(err) => {
                info!("endpoint update ({}) failed: {:#?}", why, err);
                // TODO(crawshaw): are there any conditions under which
                // we should trigger a retry based on the error here?
            }
        }

        let new_why = self.endpoints_update_state.want_update.take();
        if !self.conn.is_closed() {
            if let Some(new_why) = new_why {
                debug!("endpoint update: needed new ({})", new_why);
                self.endpoints_update_state
                    .running
                    .send(Some(new_why))
                    .expect("sender not go away");
                return;
            }
            if self.should_do_periodic_re_stun() {
                // Pick a random duration between 20 and 26 seconds (just under 30s,
                // a common UDP NAT timeout on Linux,etc)
                let d: Duration = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(Duration::from_secs(20)..=Duration::from_secs(26))
                };
                debug!("scheduling periodic_stun to run in {}s", d.as_secs());
                self.periodic_re_stun_timer.replace(time::interval(d));
            } else {
                debug!("periodic STUN idle");
                self.stop_periodic_re_stun_timer();
            }
        }

        debug!("endpoint update done ({})", why);
    }

    fn should_do_periodic_re_stun(&self) -> bool {
        if let Some(ref f) = self.conn.idle_for {
            let idle_for = f();
            debug!("periodic_re_stun: idle for {}s", idle_for.as_secs());

            if idle_for > SESSION_ACTIVE_TIMEOUT {
                return false;
            }
        }

        true
    }

    fn stop_periodic_re_stun_timer(&mut self) {
        self.periodic_re_stun_timer.take();
    }

    /// Returns the machine's endpoint addresses. It does a STUN lookup (via netcheck)
    /// to determine its public address.
    async fn determine_endpoints(&mut self) -> Result<Vec<cfg::Endpoint>> {
        let mut portmap_ext = self
            .conn
            .port_mapper
            .get_cached_mapping_or_start_creating_one()
            .await;
        let nr = self.update_net_info().await.context("update_net_info")?;

        // endpoint -> how it was found
        let mut already = HashMap::new();
        // unique endpoints
        let mut eps = Vec::new();

        macro_rules! add_addr {
            ($already:expr, $eps:expr, $ipp:expr, $et:expr) => {
                if !$already.contains_key(&$ipp) {
                    $already.insert($ipp, $et);
                    $eps.push(cfg::Endpoint {
                        addr: $ipp,
                        typ: $et,
                    });
                }
            };
        }

        // If we didn't have a portmap earlier, maybe it's done by now.
        if portmap_ext.is_none() {
            portmap_ext = self
                .conn
                .port_mapper
                .get_cached_mapping_or_start_creating_one()
                .await;
        }
        if let Some(portmap_ext) = portmap_ext {
            add_addr!(already, eps, portmap_ext, cfg::EndpointType::Portmapped);
            self.set_net_info_have_port_map().await;
        }

        if let Some(global_v4) = nr.global_v4 {
            add_addr!(already, eps, global_v4, cfg::EndpointType::Stun);

            // If they're behind a hard NAT and are using a fixed
            // port locally, assume they might've added a static
            // port mapping on their router to the same explicit
            // port that we are running with. Worst case it's an invalid candidate mapping.
            let port = self.conn.port.load(Ordering::Relaxed);
            if nr.mapping_varies_by_dest_ip.unwrap_or_default() && port != 0 {
                let mut addr = global_v4;
                addr.set_port(port);
                add_addr!(already, eps, addr, cfg::EndpointType::Stun4LocalPort);
            }
        }
        if let Some(global_v6) = nr.global_v6 {
            add_addr!(already, eps, global_v6, cfg::EndpointType::Stun);
        }

        self.ignore_stun_packets().await;

        if let Ok(local_addr) = self.conn.pconn4.local_addr().await {
            if local_addr.ip().is_unspecified() {
                let LocalAddresses {
                    regular: mut ips,
                    loopback,
                } = LocalAddresses::new();

                if ips.is_empty() && eps.is_empty() {
                    // Only include loopback addresses if we have no
                    // interfaces at all to use as endpoints and don't
                    // have a public IPv4 or IPv6 address. This allows
                    // for localhost testing when you're on a plane and
                    // offline, for example.
                    ips = loopback;
                }
                for ip in ips {
                    add_addr!(
                        already,
                        eps,
                        SocketAddr::new(ip, local_addr.port()),
                        cfg::EndpointType::Local
                    );
                }
            } else {
                // Our local endpoint is bound to a particular address.
                // Do not offer addresses on other local interfaces.
                add_addr!(already, eps, local_addr, cfg::EndpointType::Local);
            }
        }

        // Note: the endpoints are intentionally returned in priority order,
        // from "farthest but most reliable" to "closest but least
        // reliable." Addresses returned from STUN should be globally
        // addressable, but might go farther on the network than necessary.
        // Local interface addresses might have lower latency, but not be
        // globally addressable.
        //
        // The STUN address(es) are always first so that legacy wireguard
        // can use eps[0] as its only known endpoint address (although that's
        // obviously non-ideal).
        //
        // Despite this sorting, clients are not relying on this sorting for decisions;

        Ok(eps)
    }

    /// Updates `NetInfo.HavePortMap` to true.
    async fn set_net_info_have_port_map(&mut self) {
        if let Some(ref mut net_info_last) = self.net_info_last {
            if net_info_last.have_port_map {
                // No change.
                return;
            }
            net_info_last.have_port_map = true;
            let net_info = net_info_last.clone();
            self.call_net_info_callback_locked(net_info);
        }
    }

    /// Calls the NetInfo callback (if previously
    /// registered with SetNetInfoCallback) if ni has substantially changed
    /// since the last state.
    ///
    /// callNetInfoCallback takes ownership of ni.
    async fn call_net_info_callback(&mut self, ni: cfg::NetInfo) {
        if let Some(ref net_info_last) = self.net_info_last {
            if ni.basically_equal(net_info_last) {
                return;
            }
        }

        self.call_net_info_callback_locked(ni);
    }

    fn call_net_info_callback_locked(&mut self, ni: cfg::NetInfo) {
        self.net_info_last = Some(ni.clone());
        if let Some(ref on_net_info) = self.conn.on_net_info {
            debug!("net_info update: {:?}", ni);
            on_net_info(ni);
            // tokio::task::spawn(async move { cb(ni) });
        }
    }

    async fn update_net_info(&mut self) -> Result<Arc<netcheck::Report>> {
        let dm = self.conn.derp_map.read().await.clone();
        if dm.is_none() {
            return Ok(Default::default());
        }

        let conn = self.conn.clone();

        let report = time::timeout(Duration::from_secs(2), async move {
            let dm = dm.unwrap();
            let net_checker = conn.net_checker.clone();
            *conn.on_stun_receive.write().await = Some(Box::new(move |a, b| {
                let a = a.to_vec(); // :(
                let net_checker = net_checker.clone();
                Box::pin(async move {
                    net_checker.receive_stun_packet(&a, b).await;
                })
            }));
            let report = conn.net_checker.get_report(&dm).await?;
            *conn.last_net_check_report.write().await = Some(report.clone());
            let r = &report;
            conn.no_v4_send.store(!r.ipv4_can_send, Ordering::Relaxed);

            let mut ni = cfg::NetInfo {
                derp_latency: Default::default(),
                mapping_varies_by_dest_ip: r.mapping_varies_by_dest_ip,
                hair_pinning: r.hair_pinning,
                upnp: r.upnp,
                pmp: r.pmp,
                pcp: r.pcp,
                have_port_map: conn.port_mapper.have_mapping(),
                working_ipv6: Some(r.ipv6),
                os_has_ipv6: Some(r.os_has_ipv6),
                working_udp: Some(r.udp),
                working_icm_pv4: Some(r.icmpv4),
                preferred_derp: r.preferred_derp,
                link_type: None,
            };
            for (rid, d) in &r.region_v4_latency {
                ni.derp_latency
                    .insert(format!("{}-v4", rid), d.as_secs_f64());
            }
            for (rid, d) in &r.region_v6_latency {
                ni.derp_latency
                    .insert(format!("{}-v6", rid), d.as_secs_f64());
            }

            if ni.preferred_derp == 0 {
                // Perhaps UDP is blocked. Pick a deterministic but arbitrary one.
                ni.preferred_derp = self.pick_derp_fallback().await;
            }
            if !self.set_nearest_derp(ni.preferred_derp.try_into()?).await {
                ni.preferred_derp = 0;
            }

            // TODO: set link type
            drop(r);
            self.call_net_info_callback(ni).await;
            Ok::<_, anyhow::Error>(report)
        })
        .await;

        // TODO:
        // self.ignore_stun_packets().await;
        let report = report??;
        Ok(report)
    }

    /// Returns a non-zero but deterministic DERP node to
    /// connect to. This is only used if netcheck couldn't find the nearest one
    /// For instance, if UDP is blocked and thus STUN latency checks aren't working
    async fn pick_derp_fallback(&self) -> usize {
        let derp_map = self.conn.derp_map.read().await;
        if derp_map.is_none() {
            return 0;
        }
        let ids = derp_map
            .as_ref()
            .map(|d| d.region_ids())
            .unwrap_or_default();
        if ids.is_empty() {
            // No DERP regions in map.
            return 0;
        }

        // TODO: figure out which DERP region most of our peers are using,
        // and use that region as our fallback.
        //
        // If we already had selected something in the past and it has any
        // peers, we want to stay on it. If there are no peers at all,
        // stay on whatever DERP we previously picked. If we need to pick
        // one and have no peer info, pick a region randomly.
        //
        // We used to do the above for legacy clients, but never updated it for disco.

        let my_derp = self.conn.my_derp();
        if my_derp > 0 {
            return my_derp.into();
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        *ids.choose(&mut rng).unwrap()
    }

    /// Sets a STUN packet processing func that does nothing.
    async fn ignore_stun_packets(&self) {
        *self.conn.on_stun_receive.write().await = None;
    }

    /// Records the new endpoints, reporting whether they're changed.
    async fn set_endpoints(&mut self, endpoints: &[cfg::Endpoint]) -> bool {
        let any_stun = endpoints.iter().any(|ep| ep.typ == cfg::EndpointType::Stun);

        let derp_map = self.conn.derp_map.read().await;

        if !any_stun && derp_map.is_none() {
            // Don't bother storing or reporting this yet. We
            // don't have a DERP map or any STUN entries, so we're
            // just starting up. A DERP map should arrive shortly
            // and then we'll have more interesting endpoints to
            // report. This saves a map update.
            debug!(
                "ignoring pre-DERP map, STUN-less endpoint update: {:?}",
                endpoints
            );
            return false;
        }

        self.last_endpoints_time = Some(Instant::now());
        for (_de, f) in self.on_endpoint_refreshed.drain() {
            tokio::task::spawn(async move {
                f();
            });
        }

        if endpoint_sets_equal(endpoints, &self.last_endpoints) {
            return false;
        }
        self.last_endpoints.clear();
        self.last_endpoints.extend_from_slice(endpoints);

        true
    }

    fn enqueue_call_me_maybe(
        &mut self,
        derp_addr: SocketAddr,
        endpoint: Endpoint,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + '_>> {
        Box::pin(async move {
            if self.last_endpoints_time.is_none()
                || self.last_endpoints_time.as_ref().unwrap().elapsed()
                    > ENDPOINTS_FRESH_ENOUGH_DURATION
            {
                info!(
                    "want call-me-maybe but endpoints stale; restunning ({:?})",
                    self.last_endpoints_time
                );

                let msg_sender = self.msg_sender.clone();
                self.on_endpoint_refreshed.insert(
                    endpoint.clone(),
                    Box::new(move || {
                        let endpoint = endpoint.clone();
                        let msg_sender = msg_sender.clone();
                        Box::pin(async move {
                            info!(
                                "STUN done; sending call-me-maybe to {:?} {:?}",
                                endpoint.disco_key(),
                                endpoint.public_key
                            );
                            msg_sender
                                .send_async(DerpMessage::EnqueueCallMeMaybe {
                                    derp_addr,
                                    endpoint,
                                })
                                .await;
                        })
                    }),
                );

                self.msg_sender
                    .send_async(DerpMessage::ReStun("refresh-for-peering"))
                    .await;
            } else {
                let eps: Vec<_> = self.last_endpoints.iter().map(|ep| ep.addr).collect();
                let msg = disco::Message::CallMeMaybe(disco::CallMeMaybe { my_number: eps });

                tokio::task::spawn(async move {
                    if let Err(err) = endpoint
                        .c
                        .send_disco_message(
                            derp_addr,
                            Some(&endpoint.public_key),
                            &endpoint.disco_key(),
                            msg,
                        )
                        .await
                    {
                        warn!("failed to send disco message to {}: {:?}", derp_addr, err);
                    }
                });
            }
        })
    }

    async fn rebind_all(&mut self) {
        // TODO:
        // metricRebindCalls.Add(1)
        if let Err(err) = self.rebind(CurrentPortFate::Keep).await {
            debug!("{:?}", err);
            return;
        }

        let ifs = Default::default(); // TODO: load actual interfaces from the monitor
        self.maybe_close_derps_on_rebind(ifs).await;
        self.reset_endpoint_states().await;
    }

    /// Resets the preferred address for all peers.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    async fn reset_endpoint_states(&self) {
        let peer_map = self.conn.peer_map.read().await;
        for ep in peer_map.endpoints() {
            ep.note_connectivity_change().await;
        }
    }

    /// Closes and re-binds the UDP sockets.
    /// We consider it successful if we manage to bind the IPv4 socket.
    async fn rebind(&self, cur_port_fate: CurrentPortFate) -> Result<()> {
        let port = self.conn.local_port().await;
        if let Some(ref conn) = self.conn.pconn6 {
            // If we were not able to bind ipv6 at program start, dont retry
            if let Err(err) = conn.rebind(port, Network::Ip6, cur_port_fate).await {
                info!("rebind ignoring IPv6 bind failure: {:?}", err);
            }
        }
        self.conn
            .pconn4
            .rebind(port, Network::Ip4, cur_port_fate)
            .await
            .context("rebind IPv4 failed")?;

        // reread, as it might have changed
        let port = self.conn.local_port().await;
        self.conn.port_mapper.set_local_port(port).await;

        Ok(())
    }

    pub async fn set_preferred_port(&self, port: u16) {
        let existing_port = self.conn.port.swap(port, Ordering::Relaxed);
        if existing_port == port {
            return;
        }

        if let Err(err) = self.rebind(CurrentPortFate::Drop).await {
            warn!("failed to rebind: {:?}", err);
            return;
        }
        self.reset_endpoint_states().await;
    }

    async fn set_nearest_derp(&mut self, derp_num: u16) -> bool {
        if self.conn.derp_map.read().await.is_none() {
            self.conn.my_derp.store(0, Ordering::Relaxed);
            return false;
        }
        let my_derp = self.conn.my_derp();
        if derp_num == my_derp {
            // No change.
            return true;
        }
        if my_derp != 0 && derp_num != 0 {
            // TODO:
            // metricDERPHomeChange.Add(1)
        }
        self.conn.my_derp.store(derp_num, Ordering::Relaxed);

        // On change, notify all currently connected DERP servers and
        // start connecting to our home DERP if we are not already.
        match self
            .conn
            .derp_map
            .read()
            .await
            .as_ref()
            .expect("already checked")
            .regions
            .get(&usize::from(derp_num))
        {
            Some(dr) => {
                info!("home is now derp-{} ({})", derp_num, dr.region_code);
            }
            None => {
                warn!("derp_map.regions[{}] is empty", derp_num);
            }
        }

        let my_derp = self.conn.my_derp.load(Ordering::Relaxed);
        futures::future::join_all(self.active_derp.iter().map(|(i, ad)| async move {
            let b = *i == my_derp;
            ad.c.note_preferred(b).await;
        }))
        .await;

        self.connect(derp_num, None);
        true
    }

    fn log_active_derp(&self) {
        let now = Instant::now();
        debug!("{} active derp conns{}", self.active_derp.len(), {
            let mut s = String::new();
            if !self.active_derp.is_empty() {
                s += ":";
                for (node, ad) in self.active_derp_sorted() {
                    s += &format!(
                        " derp-{}=cr{},wr{}",
                        node,
                        now.duration_since(ad.create_time).as_secs(),
                        now.duration_since(ad.last_write).as_secs()
                    );
                }
            }
            s
        });
    }

    fn active_derp_sorted(&self) -> impl Iterator<Item = (u16, &'_ ActiveDerp)> + '_ {
        let mut ids: Vec<_> = self.active_derp.keys().copied().collect();
        ids.sort();

        ids.into_iter()
            .map(|id| (id, self.active_derp.get(&id).unwrap()))
    }
}

fn log_endpoint_change(endpoints: &[cfg::Endpoint]) {
    info!("endpoints changed: {}", {
        let mut s = String::new();
        for (i, ep) in endpoints.iter().enumerate() {
            if i > 0 {
                s += ", ";
            }
            s += &format!("{} ({})", ep.addr, ep.typ);
        }
        s
    });
}

/// Manages reading state for a single derp connection.
struct ReaderState {
    region: u16,
    derp_client: derp::http::Client,
    /// The set of senders we know are present on this connection, based on
    /// messages we've received from the server.
    peer_present: HashSet<key::node::PublicKey>,
    backoff: backoff::exponential::ExponentialBackoff<backoff::SystemClock>,
    last_packet_time: Option<Instant>,
    last_packet_src: Option<key::node::PublicKey>,
    cancel: CancellationToken,
}

enum ReadResult {
    Yield(DerpReadResult),
    Break,
    Continue,
}

enum ReadAction {
    None,
    RemovePeerRoute {
        peers: Vec<key::node::PublicKey>,
        region: u16,
        derp_client: derp::http::Client,
    },
    AddPeerRoute {
        peers: Vec<key::node::PublicKey>,
        region: u16,
        derp_client: derp::http::Client,
    },
}

impl ReaderState {
    fn new(region: u16, cancel: CancellationToken, derp_client: derp::http::Client) -> Self {
        ReaderState {
            region,
            derp_client,
            cancel,
            peer_present: HashSet::new(),
            backoff: backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build(),
            last_packet_time: None,
            last_packet_src: None,
        }
    }

    async fn recv(mut self) -> (Self, ReadResult, ReadAction) {
        let msg = tokio::select! {
            msg = self.derp_client.recv_detail() => {
                msg
            }
            _ = self.cancel.cancelled() => {
                return (self, ReadResult::Break, ReadAction::None);
            }
        };
        debug!("derp.recv(derp-{}) received: {:?}", self.region, msg);

        match msg {
            Err(err) => {
                debug!(
                    "[{:?}] derp.recv(derp-{}): {:?}",
                    self.derp_client, self.region, err
                );

                // Forget that all these peers have routes.
                let peers = self.peer_present.drain().collect();
                let action = ReadAction::RemovePeerRoute {
                    peers,
                    region: self.region,
                    derp_client: self.derp_client.clone(),
                };

                if matches!(err, derp::http::ClientError::Closed) {
                    // drop client
                    return (self, ReadResult::Break, action);
                }

                // If our DERP connection broke, it might be because our network
                // conditions changed. Start that check.
                // TODO:
                // self.re_stun("derp-recv-error").await;

                // Back off a bit before reconnecting.
                match self.backoff.next_backoff() {
                    Some(t) => {
                        debug!("backoff sleep: {}ms", t.as_millis());
                        time::sleep(t).await;
                        (self, ReadResult::Continue, action)
                    }
                    None => (self, ReadResult::Break, action),
                }
            }
            Ok((msg, conn_gen)) => {
                // reset
                self.backoff.reset();
                let now = Instant::now();
                if self.last_packet_time.is_none()
                    || self.last_packet_time.as_ref().unwrap().elapsed() > Duration::from_secs(5)
                {
                    self.last_packet_time = Some(now);
                }

                match msg {
                    derp::ReceivedMessage::ServerInfo { .. } => {
                        info!("derp-{} connected; connGen={}", self.region, conn_gen);
                        (self, ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::ReceivedPacket { source, data } => {
                        debug!("got derp-{} packet: {} bytes", self.region, data.len());
                        // If this is a new sender we hadn't seen before, remember it and
                        // register a route for this peer.
                        let action = if self.last_packet_src.is_none()
                            || &source != self.last_packet_src.as_ref().unwrap()
                        {
                            // avoid map lookup w/ high throughput single peer
                            self.last_packet_src = Some(source.clone());
                            let mut peers = Vec::new();
                            if !self.peer_present.contains(&source) {
                                self.peer_present.insert(source.clone());
                                peers.push(source.clone());
                            }
                            ReadAction::AddPeerRoute {
                                peers,
                                region: self.region,
                                derp_client: self.derp_client.clone(),
                            }
                        } else {
                            ReadAction::None
                        };

                        let res = DerpReadResult {
                            region_id: self.region,
                            src: source,
                            buf: data,
                        };
                        (self, ReadResult::Yield(res), action)
                    }
                    derp::ReceivedMessage::Ping(data) => {
                        // Best effort reply to the ping.
                        let dc = self.derp_client.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = dc.send_pong(data).await {
                                info!("derp-{} send_pong error: {:?}", self.region, err);
                            }
                        });
                        (self, ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::Health { .. } => {
                        // health.SetDERPRegionHealth(regionID, m.Problem);
                        (self, ReadResult::Continue, ReadAction::None)
                    }
                    derp::ReceivedMessage::PeerGone(key) => {
                        // self.remove_derp_peer_route(key, region_id, &dc).await;
                        (self, ReadResult::Continue, ReadAction::None)
                    }
                    _ => {
                        // Ignore.
                        (self, ReadResult::Continue, ReadAction::None)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use hyper::server::conn::Http;
    use rand::RngCore;
    use tokio::{net, sync, task::JoinSet};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::*;
    use crate::{
        hp::derp::{DerpNode, DerpRegion, UseIpv4, UseIpv6},
        tls,
    };

    #[test]
    fn test_group_by_continue() {
        let cases = [
            (vec![1, 1], vec![vec![1, 1]]),
            (vec![1, 2, 3], vec![vec![1], vec![2], vec![3]]),
            (
                vec![1, 1, 2, 3, 4, 4, 4, 5, 1],
                vec![
                    vec![1, 1],
                    vec![2],
                    vec![3],
                    vec![4, 4, 4],
                    vec![5],
                    vec![1],
                ],
            ),
        ];
        for (input, expected) in cases {
            let mut out = Vec::new();
            let res: Option<()> = group_by(
                &input,
                |a, b| a == b,
                |els| {
                    out.push(els.to_vec());
                    None
                },
            );
            assert!(res.is_none());
            assert_eq!(out, expected,);
        }
    }

    #[test]
    fn test_group_by_early_return() {
        let cases = [
            (vec![(1, true), (1, false)], vec![vec![1, 1]]),
            (
                vec![(1, true), (2, false), (3, false)],
                vec![vec![1], vec![2]],
            ),
            (
                vec![
                    (1, true),
                    (1, true),
                    (2, true),
                    (3, true),
                    (4, true),
                    (4, false),
                    (4, false),
                    (5, false),
                ],
                vec![vec![1, 1], vec![2], vec![3], vec![4, 4, 4]],
            ),
        ];
        for (i, (input, expected)) in cases.into_iter().enumerate() {
            println!("case {}", i);
            let mut out: Vec<Vec<usize>> = Vec::new();
            let res: Option<()> = group_by(
                &input,
                |a, b| a.0 == b.0,
                |els| {
                    out.push(els.iter().map(|(e, _)| *e).collect());
                    if els.last().unwrap().1 {
                        None
                    } else {
                        Some(())
                    }
                },
            );
            assert!(res.is_some()); // all abort early
            assert_eq!(out, expected);
        }
    }

    async fn pick_port() -> u16 {
        let conn = net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        conn.local_addr().unwrap().port()
    }

    /// Returns a new Conn.
    async fn new_test_conn() -> Conn {
        let port = pick_port().await;
        Conn::new(
            format!("test-{port}"),
            Options {
                port,
                ..Default::default()
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_rebind_stress() {
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
                        return Ok(());
                    }
                    res = futures::future::poll_fn(|cx| conn.poll_recv(cx, &mut buffs, &mut meta)) => {
                        if let Err(err) = res {
                            return Err(err);
                        }
                    }
                }
            }
        });

        let conn = c.clone();
        let t1 = tokio::task::spawn(async move {
            for _i in 0..2000 {
                conn.rebind_all().await;
            }
        });

        let conn = c.clone();
        let t2 = tokio::task::spawn(async move {
            for _i in 0..2000 {
                conn.rebind_all().await;
            }
        });

        t1.await.unwrap();
        t2.await.unwrap();

        cancel.send(()).unwrap();

        c.close().await.unwrap();
        t.await.unwrap().unwrap();
    }

    struct Devices {
        stun_ip: IpAddr,
    }

    async fn run_derp_and_stun(stun_ip: IpAddr) -> Result<(DerpMap, impl FnOnce())> {
        // TODO: pass a mesh_key?
        let derp_server: derp::Server<
            net::tcp::OwnedReadHalf,
            net::tcp::OwnedWriteHalf,
            derp::http::Client,
        > = derp::Server::new(key::node::SecretKey::generate(), None);

        let http_listener = net::TcpListener::bind("127.0.0.1:0").await?;
        let http_addr = http_listener.local_addr()?;

        let (derp_shutdown, mut rx) = sync::oneshot::channel::<()>();

        // TODO: TLS
        // httpsrv.StartTLS()

        // Spawn server on the default executor,
        // which is usually a thread-pool from tokio default runtime.
        tokio::task::spawn(async move {
            let derp_client_handler = derp_server.client_conn_handler(Default::default());
            loop {
                tokio::select! {
                    biased;
                    _ = &mut rx => {
                        derp_server.close().await;
                        return Ok::<_, anyhow::Error>(());
                    }

                    conn = http_listener.accept() => {
                        let (stream, _) = conn?;
                        let derp_client_handler = derp_client_handler.clone();
                        tokio::task::spawn(async move {
                            if let Err(err) = Http::new()
                                .serve_connection(stream, derp_client_handler)
                                .with_upgrades()
                                .await
                            {
                                eprintln!("Failed to serve connection: {:?}", err);
                            }
                        });
                    }
                }
            }
        });

        let (stun_addr, _, stun_cleanup) = stun::test::serve(stun_ip).await?;
        let m = DerpMap {
            regions: [(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "test".into(),
                    nodes: vec![DerpNode {
                        name: "t1".into(),
                        region_id: 1,
                        host_name: "test-node.invalid".into(),
                        stun_only: false,
                        stun_port: stun_addr.port(),
                        ipv4: UseIpv4::Some("127.0.0.1".parse().unwrap()),
                        ipv6: UseIpv6::None,

                        derp_port: http_addr.port(),
                        stun_test_ip: Some(stun_addr.ip()),
                    }],
                    avoid: false,
                },
            )]
            .into_iter()
            .collect(),
        };

        let cleanup = || {
            println!("CLEANUP");
            stun_cleanup.send(()).unwrap();
            derp_shutdown.send(()).unwrap();
        };

        Ok((m, cleanup))
    }

    /// Magicsock plus wrappers for sending packets
    #[derive(Clone)]
    struct MagicStack {
        ep_ch: flume::Receiver<Vec<cfg::Endpoint>>,
        key: key::node::SecretKey,
        conn: Conn,
        quic_ep: quinn::Endpoint,
    }

    impl MagicStack {
        async fn new(derp_map: DerpMap) -> Result<Self> {
            let (ep_s, ep_r) = flume::bounded(16);
            let opts = Options {
                on_endpoints: Some(Box::new(move |eps: &[cfg::Endpoint]| {
                    let _ = ep_s.send(eps.to_vec());
                })),
                ..Default::default()
            };
            let key = opts.private_key.clone();
            let conn = Conn::new(
                format!("magic-{}", hex::encode(&key.public_key().as_ref()[..8])),
                opts,
            )
            .await?;
            conn.set_derp_map(Some(derp_map)).await;

            // TODO: alternative check?
            // let c = conn.clone();
            // tokio::time::timeout(Duration::from_secs(10), async move {
            //     while !c.0.state.lock().await.derp_started {
            //         tokio::time::sleep(Duration::from_millis(100)).await;
            //     }
            // })
            // .await?;

            let tls_server_config =
                tls::make_server_config(&key.clone().into(), vec![tls::P2P_ALPN.to_vec()], false)?;
            let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            server_config.transport_config(Arc::new(transport_config));
            let mut quic_ep = quinn::Endpoint::new_with_abstract_socket(
                quinn::EndpointConfig::default(),
                Some(server_config),
                conn.clone(),
                quinn::TokioRuntime,
            )?;

            let tls_client_config = tls::make_client_config(
                &key.clone().into(),
                None,
                vec![tls::P2P_ALPN.to_vec()],
                false,
            )?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));
            client_config.transport_config(Arc::new(transport_config));
            quic_ep.set_default_client_config(client_config);

            Ok(Self {
                ep_ch: ep_r,
                key,
                conn,
                quic_ep,
            })
        }

        async fn tracked_endpoints(&self) -> Vec<key::node::PublicKey> {
            let peer_map = &*self.conn.peer_map.read().await;
            let mut out = Vec::new();
            for ep in peer_map.endpoints() {
                out.push(ep.public_key.clone());
            }
            out
        }

        fn public(&self) -> key::node::PublicKey {
            self.key.public_key().into()
        }
    }

    /// Monitors endpoint changes and plumbs things together.
    async fn mesh_stacks(stacks: Vec<MagicStack>) -> Result<impl FnOnce()> {
        // Serialize all reconfigurations globally, just to keep things simpler.
        let eps = Arc::new(Mutex::new(vec![Vec::new(); stacks.len()]));

        async fn build_netmap(
            eps: &[Vec<cfg::Endpoint>],
            ms: &[MagicStack],
            my_idx: usize,
        ) -> netmap::NetworkMap {
            let mut peers = Vec::new();

            for (i, peer) in ms.iter().enumerate() {
                if i == my_idx {
                    continue;
                }

                let addresses = vec![Ipv4Addr::new(1, 0, 0, (i + 1) as u8).into()];
                peers.push(cfg::Node {
                    addresses: addresses.clone(),
                    id: (i + 1) as u64,
                    stable_id: String::new(),
                    name: Some(format!("node{}", i + 1)),
                    key: peer.key.public_key().into(),
                    disco_key: peer.conn.disco_public(),
                    allowed_ips: addresses,
                    endpoints: eps[i].iter().map(|ep| ep.addr).collect(),
                    derp: Some(SocketAddr::new(DERP_MAGIC_IP, 1)),
                    created: Instant::now(),
                    hostinfo: crate::hp::hostinfo::Hostinfo::new(),
                    keep_alive: false,
                    expired: false,
                    online: None,
                    last_seen: None,
                });
            }

            netmap::NetworkMap { peers }
        }

        async fn update_eps(
            eps: Arc<Mutex<Vec<Vec<cfg::Endpoint>>>>,
            ms: &[MagicStack],
            idx: usize,
            new_eps: Vec<cfg::Endpoint>,
        ) {
            let eps = &mut *eps.lock().await;
            eps[idx] = new_eps;

            for (i, m) in ms.iter().enumerate() {
                let nm = build_netmap(&eps[..], ms, i).await;
                m.conn.set_network_map(nm).await;
            }
        }

        let mut tasks = JoinSet::new();

        for (my_idx, m) in stacks.iter().enumerate() {
            let m = m.clone();
            let eps = eps.clone();
            let stacks = stacks.clone();
            tasks.spawn(async move {
                loop {
                    tokio::select! {
                        res = m.ep_ch.recv_async() => match res {
                            Ok(new_eps) => {
                                debug!("conn{} endpoints update", my_idx + 1);
                                update_eps(eps.clone(), &stacks, my_idx, new_eps).await;
                            }
                            Err(err) => {
                                warn!("err: {:?}", err);
                                break;
                            }
                        }
                    }
                }
            });
        }

        Ok(move || {
            tasks.abort_all();
        })
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_roundtrip() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        let devices = Devices {
            stun_ip: "127.0.0.1".parse()?,
        };

        let (derp_map, cleanup) = run_derp_and_stun(devices.stun_ip).await?;

        let m1 = MagicStack::new(derp_map.clone()).await?;
        let m2 = MagicStack::new(derp_map.clone()).await?;

        let cleanup_mesh = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

        // Wait for magicsock to be told about peers from mesh_stacks.
        let m1t = m1.clone();
        let m2t = m2.clone();
        time::timeout(Duration::from_secs(10), async move {
            loop {
                let ab = m1t.tracked_endpoints().await.contains(&m2t.public());
                let ba = m2t.tracked_endpoints().await.contains(&m1t.public());
                if ab && ba {
                    break;
                }
            }
        })
        .await
        .context("failed to connect peers")?;

        // msg from  m2 -> m1
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                println!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());

                let a_addr = b.conn.get_mapping_addr(&a.public()).await.unwrap();
                let b_addr = a.conn.get_mapping_addr(&b.public()).await.unwrap();

                println!("{}: {}, {}: {}", a_name, a_addr, b_name, b_addr);

                let b_task = tokio::task::spawn(async move {
                    println!("[{}] accepting conn", b_name);
                    while let Some(conn) = b.quic_ep.accept().await {
                        println!("[{}] connecting", b_name);
                        let conn = conn
                            .await
                            .with_context(|| format!("[{}] connecting", b_name))?;
                        println!("[{}] accepting bi", b_name);
                        let (mut send_bi, recv_bi) = conn
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
                        println!("[{}] finished", b_name);

                        return Ok::<_, anyhow::Error>(val);
                    }
                    bail!("no connections available anymore");
                });

                println!("[{}] connecting to {}", a_name, b_addr);
                let conn = a
                    .quic_ep
                    .connect(b_addr, "localhost")?
                    .await
                    .with_context(|| format!("[{}] connect", a_name))?;

                println!("[{}] opening bi", a_name);
                let (mut send_bi, recv_bi) = conn
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
                a.quic_ep.wait_idle().await;

                drop(send_bi);

                // make sure the right values arrived
                println!("waiting for channel");
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
        }

        println!("-- larger data");
        {
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);
            roundtrip!(m2, m1, data);
        }

        println!("cleaning up");
        cleanup();
        cleanup_mesh();
        Ok(())
    }
}
