use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    io,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use backoff::backoff::Backoff;
use futures::{future::BoxFuture, Future};
use quinn::AsyncUdpSocket;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{self, Mutex, RwLock},
    time::{self, Instant},
};
use tracing::{debug, info, warn};

use crate::hp::{
    cfg::{self, DERP_MAGIC_IP},
    derp::{self, DerpMap},
    disco, interfaces, key,
    magicsock::SESSION_ACTIVE_TIMEOUT,
    monitor, netcheck, netmap, portmapper, stun,
};

use super::{
    endpoint::PeerMap,
    rebinding_conn::{RebindingUdpConn, UdpSocket},
    Endpoint, Timer, DERP_CLEAN_STALE_INTERVAL, DERP_INACTIVE_CLEANUP_TIME, SOCKET_BUFFER_SIZE,
};

/// How many packets writes can be queued up the DERP client to write on the wire before we start
/// dropping.
///
/// TODO: this is currently arbitrary. Figure out something better?
const BUFFERED_DERP_WRITES_BEFORE_DROP: usize = 32;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CurrentPortFate {
    Keep,
    Drop,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(super) enum Network {
    Ip4,
    Ip6,
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
    // Zero means to pick one automatically.
    pub port: u16,

    /// Optionally provides a func to be called when endpoints change.
    pub on_endpoints: Option<Box<dyn Fn(&[cfg::Endpoint]) + Send + Sync + 'static>>,

    // Optionally provides a func to be called when a connection is made to a DERP server.
    pub on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,

    // Optionally provides a func to return how long it's been since a TUN packet was sent or received.
    pub idle_for: Option<Box<dyn Fn() -> Duration + Send + Sync + 'static>>,

    /// A callback that provides a `cfg::NetInfo` when discovered network conditions change.
    pub on_net_info: Option<Box<dyn Fn(cfg::NetInfo) + Send + Sync + 'static>>,

    /// If provided, is a function for magicsock to call
    /// whenever it receives a packet from a a peer if it's been more
    /// than ~10 seconds since the last one. (10 seconds is somewhat
    /// arbitrary; the sole user just doesn't need or want it called on
    /// every packet, just every minute or two for WireGuard timeouts,
    /// and 10 seconds seems like a good trade-off between often enough
    /// and not too often.)
    /// The provided func is likely to call back into
    /// Conn.ParseEndpoint, which acquires Conn.mu. As such, you should
    /// not hold Conn.mu while calling it.
    pub on_note_recv_activity: Option<Box<dyn Fn(&key::node::PublicKey) + Send + Sync + 'static>>,

    /// The link monitor to use. With one, the portmapper won't be used.
    pub link_monitor: Option<monitor::Monitor>,
}

/// Routes UDP packets and actively manages a list of its endpoints.
#[derive(Clone, Debug)]
pub struct Conn(Arc<Inner>);

impl Deref for Conn {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TODO:
        f.debug_struct("Inner").finish()
    }
}

pub struct Inner {
    on_endpoints: Option<Box<dyn Fn(&[cfg::Endpoint]) + Send + Sync + 'static>>,
    on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,
    idle_for: Option<Box<dyn Fn() -> Duration + Send + Sync + 'static>>,
    on_note_recv_activity: Option<Box<dyn Fn(&key::node::PublicKey) + Send + Sync + 'static>>,
    link_monitor: Option<monitor::Monitor>,
    /// A callback that provides a `cfg::NetInfo` when discovered network conditions change.
    on_net_info: Option<Box<dyn Fn(cfg::NetInfo) + Send + Sync + 'static>>,

    // ================================================================
    // No locking required to access these fields, either because
    // they're static after construction, or are wholly owned by a single goroutine.

    // TODO
    // connCtx:       context.Context, // closed on Conn.Close
    // connCtxCancel: func(),          // closes connCtx

    // The underlying UDP sockets used to send/rcv packets for wireguard and other magicsock protocols.
    pconn4: RebindingUdpConn,
    pconn6: RebindingUdpConn,

    // TODO:
    // closeDisco4 and closeDisco6 are io.Closers to shut down the raw
    // disco packet receivers. If nil, no raw disco receiver is running for the given family.
    close_disco4: Option<()>, // io.Closer
    close_disco6: Option<()>, // io.Closer
    /// The prober that discovers local network conditions, including the closest DERP relay and NAT mappings.
    net_checker: netcheck::Client,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    port_mapper: portmapper::Client,

    /// Holds the current STUN packet processing func.
    on_stun_receive: RwLock<
        Option<Box<dyn Fn(&[u8], SocketAddr) -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    >, // syncs.AtomicValue[func(p []byte, fromAddr netip.AddrPort)]

    /// Used for receiving DERP messages.
    derp_recv_ch: (
        flume::Sender<DerpReadResult>,
        flume::Receiver<DerpReadResult>,
    ),

    // TODO: check if this is needed
    /// The wireguard-go conn.Bind for Conn.
    // bind: UdpSocket, // ConnBind,

    // owned by receiveIPv4 and receiveIPv6, respectively, to cache an SocketAddr -> Endpoint for hot flows.
    socket_endpoint4: SocketEndpointCache,
    socket_endpoint6: SocketEndpointCache,

    // ============================================================
    // Fields that must be accessed via atomic load/stores.
    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: AtomicBool,

    /// Whether the network is up (some interface is up
    /// with IPv4 or IPv6). It's used to suppress log spam and prevent new connection that'll fail.
    network_up: AtomicBool,

    /// Whether privateKey is non-zero.
    have_private_key: AtomicBool,
    // TODO:
    // public_key_atomic: syncs.AtomicValue[key.NodePublic] // or NodeKey zero value if !havePrivateKey

    // TODO: add if needed
    // derpMapAtomic is the same as derpMap, but without requiring
    // sync.Mutex. For use with NewRegionClient's callback, to avoid
    // lock ordering deadlocks. See issue 3726 and mu field docs.
    // derpMapAtomic atomic.Pointer[tailcfg.DERPMap]
    last_net_check_report: RwLock<Option<netcheck::Report>>,

    /// Preferred port from opts.Port; 0 means auto.
    port: AtomicU16,

    // TODO
    // Maintains per-connection counters. (atomic pointer originally)
    // stats: RwLock<connstats.Statistics>

    //     // ============================================================
    //     // mu guards all following fields; see userspaceEngine lock
    //     // ordering rules against the engine. For derphttp, mu must
    //     // be held before derphttp.Client.mu.
    state: Mutex<ConnState>,
    state_notifier: sync::Notify,
    /// Close is in progress (or done)
    closing: AtomicBool,
}

pub(super) struct ConnState {
    /// Close was called
    closed: bool,

    /// A timer that fires to occasionally clean up idle DERP connections.
    /// It's only used when there is a non-home DERP connection in use.
    derp_cleanup_timer: Option<Timer>,

    /// Whether derp_cleanup_timer is scheduled to fire within derp_clean_stale_interval.
    derp_cleanup_timer_armed: bool,
    // When set, is an AfterFunc timer that will call Conn::do_periodic_stun.
    periodic_re_stun_timer: Option<Timer>,

    /// Indicates that update_endpoints is currently running. It's used to deduplicate
    /// concurrent endpoint update requests.
    endpoints_update_active: bool,
    /// If set, means that a new endpoints update should begin immediately after the currently-running one
    /// completes. It can only be non-empty if `endpoints_update_active == true`.
    want_endpoints_update: Option<&'static str>,
    /// Records the endpoints found during the previous
    /// endpoint discovery. It's used to avoid duplicate endpoint change notifications.
    last_endpoints: Vec<cfg::Endpoint>,

    /// The last time the endpoints were updated, even if there was no change.
    last_endpoints_time: Option<Instant>,

    /// Functions to run (in their own tasks) when endpoints are refreshed.
    on_endpoint_refreshed: HashMap<Endpoint, Box<dyn Fn() + Send + Sync + 'static>>,
    /// The set of peers that are currently configured in
    /// WireGuard. These are not used to filter inbound or outbound
    /// traffic at all, but only to track what state can be cleaned up
    /// in other maps below that are keyed by peer public key.
    peer_set: HashSet<key::node::PublicKey>,

    /// The private naclbox key used for active discovery traffic. It's created once near
    /// (but not during) construction.
    disco_private: key::disco::SecretKey,
    /// Public key of disco_private.
    disco_public: key::disco::PublicKey,

    /// Tracks the networkmap Node entity for each peer discovery key.
    peer_map: PeerMap,

    // The state for an active DiscoKey.
    disco_info: HashMap<key::disco::PublicKey, DiscoInfo>,

    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<cfg::NetInfo>,

    /// None (or zero regions/nodes) means DERP is disabled.
    derp_map: Option<DerpMap>,
    net_map: Option<netmap::NetworkMap>,
    /// WireGuard private key for this node
    private_key: Option<key::node::SecretKey>,
    /// Whether we ever had a non-zero private key
    ever_had_key: bool,
    /// Nearest DERP region ID; 0 means none/unknown.
    my_derp: usize,
    // derp_started chan struct{}      // closed on first connection to DERP; for tests & cleaner Close
    /// DERP regionID -> connection to a node in that region
    active_derp: HashMap<usize, ActiveDerp>,
    prev_derp: HashMap<usize, ()>, //    map[int]*syncs.WaitGroupChan

    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home DERP connection.  If they sent us a message
    /// on a different DERP connection (which should really only be on our DERP
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new DERP connection back to their home.
    derp_route: HashMap<key::node::PublicKey, DerpRoute>,
}

impl Default for ConnState {
    fn default() -> Self {
        let disco_private = key::disco::SecretKey::generate();
        let disco_public = disco_private.public();
        ConnState {
            closed: false,
            derp_cleanup_timer: None,
            derp_cleanup_timer_armed: false,
            periodic_re_stun_timer: None,
            endpoints_update_active: false,
            want_endpoints_update: None,
            last_endpoints: Vec::new(),
            last_endpoints_time: None,
            on_endpoint_refreshed: HashMap::new(),
            peer_set: HashSet::new(),
            disco_private,
            disco_public,
            peer_map: PeerMap::default(),
            disco_info: HashMap::new(),
            net_info_last: None,
            derp_map: None,
            net_map: None,
            private_key: None,
            ever_had_key: false,
            my_derp: 0,
            active_derp: HashMap::new(),
            prev_derp: HashMap::new(),
            derp_route: HashMap::new(),
        }
    }
}

impl Conn {
    /// Removes a DERP route entry previously added by addDerpPeerRoute.
    async fn remove_derp_peer_route(
        &self,
        peer: key::node::PublicKey,
        derp_id: usize,
        dc: &derp::http::Client,
    ) {
        let mut state = self.state.lock().await;
        match state.derp_route.entry(peer) {
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
        &self,
        peer: key::node::PublicKey,
        derp_id: usize,
        dc: derp::http::Client,
    ) {
        let mut state = self.state.lock().await;
        state.derp_route.insert(peer, DerpRoute { derp_id, dc });
    }

    /// Creates a magic `Conn` listening on `opts.port`.
    /// As the set of possible endpoints for a Conn changes, the callback opts.EndpointsFunc is called.
    pub async fn new(opts: Options) -> Result<Self> {
        let port_mapper = portmapper::Client::new(); // TODO: pass self.on_port_map_changed
        let mut net_checker = netcheck::Client::default();
        // TODO:
        // GetSTUNConn4:        func() netcheck.STUNConn { return &c.pconn4 },
        // GetSTUNConn6:        func() netcheck.STUNConn { return &c.pconn6 },
        // SkipExternalNetwork: inTest(),
        net_checker.port_mapper = Some(port_mapper.clone());

        let Options {
            port,
            on_endpoints,
            on_derp_active,
            idle_for,
            on_net_info,
            on_note_recv_activity,
            link_monitor,
        } = opts;

        if let Some(ref link_monitor) = link_monitor {
            // TODO:
            // c.portMapper.SetGatewayLookupFunc(opts.LinkMonitor.GatewayAndSelfIP)
        }

        let derp_recv_ch = flume::bounded(64);

        let mut c = Conn(Arc::new(Inner {
            on_endpoints,
            on_derp_active,
            idle_for,
            on_net_info,
            on_note_recv_activity,
            link_monitor,
            network_up: AtomicBool::new(true), // assume up until told otherwise
            port: AtomicU16::new(port),
            port_mapper,
            net_checker,
            have_private_key: AtomicBool::new(false),
            last_net_check_report: Default::default(),
            no_v4_send: AtomicBool::new(false),
            pconn4: RebindingUdpConn::default(),
            pconn6: RebindingUdpConn::default(),
            socket_endpoint4: SocketEndpointCache::default(),
            socket_endpoint6: SocketEndpointCache::default(),
            state_notifier: sync::Notify::new(),
            on_stun_receive: Default::default(),
            state: Default::default(),
            close_disco4: None,
            close_disco6: None,
            closing: AtomicBool::new(false),
            derp_recv_ch,
        }));

        c.rebind(CurrentPortFate::Keep).await?;

        // TODO:
        // c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())

        match c.listen_raw_disco("ip4") {
            Ok(d4) => {
                info!("using BPF disco receiver for IPv4");
                Arc::get_mut(&mut c.0).unwrap().close_disco4 = Some(d4);
            }
            Err(err) => {
                info!(
                    "couldn't create raw v4 disco listener, using regular listener instead: {:?}",
                    err
                );
            }
        }
        match c.listen_raw_disco("ip6") {
            Ok(d6) => {
                info!("[v1] using BPF disco receiver for IPv6");
                Arc::get_mut(&mut c.0).unwrap().close_disco6 = Some(d6);
            }
            Err(err) => {
                info!(
                    "couldn't create raw v6 disco listener, using regular listener instead: {:?}",
                    err
                );
            }
        }

        Ok(c)
    }

    /// Sets a STUN packet processing func that does nothing.
    async fn ignore_stun_packets(&self) {
        *self.on_stun_receive.write().await = None;
    }

    fn listen_raw_disco(&self, family: &str) -> Result<()> {
        // TODO: figure out support & if it needed for different OSes
        bail!("not supported on this OS");
    }

    pub(super) fn is_closing(&self) -> bool {
        self.closing.load(Ordering::Relaxed)
    }

    /// Called (in a new task) by `periodic_re_stun_timer` when periodic STUNs are active.
    async fn do_periodic_stun(&self) {
        self.re_stun("periodic").await;
    }

    async fn stop_periodic_re_stun_timer(&self, state: &mut ConnState) {
        if let Some(timer) = state.periodic_re_stun_timer.take() {
            timer.stop().await;
        }
    }

    async fn update_endpoints_after(&self) {
        let mut state = self.state.lock().await;
        let why = state.want_endpoints_update.take();
        if !state.closed {
            if let Some(why) = why {
                let this = self.clone();
                tokio::task::spawn(async move { this.update_endpoints(why).await });
                return;
            }
            if self.should_do_periodic_re_stun(&mut state) {
                // Pick a random duration between 20 and 26 seconds (just under 30s,
                // a common UDP NAT timeout on Linux,etc)
                let mut rng = rand::thread_rng();
                let d: Duration = rng.gen_range(Duration::from_secs(20)..=Duration::from_secs(26));
                if let Some(ref mut t) = state.periodic_re_stun_timer {
                    t.reset(d).await;
                } else {
                    debug!("scheduling periodic_stun to run in {}s", d.as_secs());
                    let this = self.clone();
                    state.periodic_re_stun_timer =
                        Some(Timer::after(
                            d,
                            async move { this.do_periodic_stun().await },
                        ));
                }
            } else {
                debug!("periodic STUN idle");
                self.stop_periodic_re_stun_timer(&mut state).await;
            }
        }
        state.endpoints_update_active = false;
        self.state_notifier.notify_waiters();
    }

    // c.mu must NOT be held.
    async fn update_endpoints(&self, why: &'static str) {
        // TODO:
        // metricUpdateEndpoints.Add(1)

        debug!("starting endpoint update ({})", why);
        if self.no_v4_send.load(Ordering::Relaxed) {
            let closed = self.state.lock().await.closed;
            if !closed {
                debug!("last netcheck reported send error. Rebinding.");
                self.rebind_all().await;
            }
        }

        match self.determine_endpoints().await {
            Ok(endpoints) => {
                if self.set_endpoints(&endpoints).await {
                    self.log_endpoint_change(&endpoints);
                    if let Some(ref cb) = self.on_endpoints {
                        cb(&endpoints[..]);
                    }
                }
            }
            Err(err) => {
                info!("endpoint update ({}) failed: {:?}", why, err);
                // TODO(crawshaw): are there any conditions under which
                // we should trigger a retry based on the error here?
                return;
            }
        }
    }

    /// Records the new endpoints, reporting whether they're changed.
    async fn set_endpoints(&self, endpoints: &[cfg::Endpoint]) -> bool {
        let any_stun = endpoints.iter().any(|ep| ep.typ == cfg::EndpointType::Stun);

        let mut state = self.state.lock().await;

        if !any_stun && state.derp_map.is_none() {
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

        state.last_endpoints_time = Some(Instant::now());
        for (de, f) in state.on_endpoint_refreshed.drain() {
            tokio::task::spawn(async move {
                f();
            });
        }

        if endpoint_sets_equal(endpoints, &state.last_endpoints) {
            return false;
        }
        state.last_endpoints.clear();
        state.last_endpoints.extend_from_slice(endpoints);

        true
    }

    /// Updates `NetInfo.HavePortMap` to true.
    async fn set_net_info_have_port_map(&self) {
        let mut state = self.state.lock().await;
        if let Some(ref mut net_info_last) = state.net_info_last {
            if net_info_last.have_port_map {
                // No change.
                return;
            }
            net_info_last.have_port_map = true;
            self.call_net_info_callback_locked(net_info_last.clone(), &mut state);
        }
    }

    async fn update_net_info(&self) -> Result<netcheck::Report> {
        let dm = self.state.lock().await.derp_map.clone();
        if dm.is_none() || self.network_down() {
            return Ok(Default::default());
        }

        let report = time::timeout(Duration::from_secs(2), async move {
            let dm = dm.unwrap();
            let this = self.clone();
            *self.on_stun_receive.write().await = Some(Box::new(move |a, b| {
                let a = a.to_vec(); // :(
                let this = this.clone();
                Box::pin(async move {
                    this.net_checker.receive_stun_packet(&a, b).await;
                })
            }));
            let report = self.net_checker.get_report(&dm).await?;
            *self.last_net_check_report.write().await = Some(report.clone());
            let r = report.read().await;
            self.no_v4_send.store(r.ipv4_can_send, Ordering::Relaxed);

            let mut ni = cfg::NetInfo {
                derp_latency: Default::default(),
                mapping_varies_by_dest_ip: r.mapping_varies_by_dest_ip,
                hair_pinning: r.hair_pinning,
                upnp: r.upnp,
                pmp: r.pmp,
                pcp: r.pcp,
                have_port_map: self.port_mapper.have_mapping(),
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
            if !self.set_nearest_derp(ni.preferred_derp).await {
                ni.preferred_derp = 0;
            }

            // TODO: set link type

            drop(r);
            self.call_net_info_callback(ni).await;
            Ok::<_, anyhow::Error>(report)
        })
        .await;

        self.ignore_stun_packets().await;
        let report = report??;
        Ok(report)
    }

    /// Returns a non-zero but deterministic DERP node to
    /// connect to.  This is only used if netcheck couldn't find the
    /// nearest one (for instance, if UDP is blocked and thus STUN latency checks aren't working).
    async fn pick_derp_fallback(&self) -> usize {
        let mut state = self.state.lock().await;
        if !self.want_derp_locked(&mut state) {
            return 0;
        }
        let ids = state
            .derp_map
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

        if state.my_derp != 0 {
            return state.my_derp;
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        *ids.choose(&mut rng).unwrap()
    }

    /// Calls the NetInfo callback (if previously
    /// registered with SetNetInfoCallback) if ni has substantially changed
    /// since the last state.
    ///
    /// callNetInfoCallback takes ownership of ni.
    async fn call_net_info_callback(&self, ni: cfg::NetInfo) {
        let mut state = self.state.lock().await;

        if let Some(ref net_info_last) = state.net_info_last {
            if ni.basically_equal(net_info_last) {
                return;
            }
        }

        self.call_net_info_callback_locked(ni, &mut state);
    }

    fn call_net_info_callback_locked(&self, ni: cfg::NetInfo, state: &mut ConnState) {
        state.net_info_last = Some(ni.clone());
        if let Some(ref on_net_info) = self.on_net_info {
            debug!("net_info update: {:?}", ni);
            on_net_info(ni);
            // tokio::task::spawn(async move { cb(ni) });
        }
    }

    /// Makes addr a validated disco address for discoKey. It's used in tests to enable receiving of packets from
    /// addr without having to spin up the entire active discovery machinery.
    #[cfg(test)]
    async fn add_valid_disco_path_for_test(
        &self,
        node_key: &key::node::PublicKey,
        addr: &SocketAddr,
    ) {
        let mut state = self.state.lock().await;
        state.peer_map.set_node_key_for_ip_port(addr, node_key);
    }

    /// Describes the time we last got traffic from this endpoint (updated every ~10 seconds).
    async fn last_recv_activity_of_node_key(&self, nk: &key::node::PublicKey) -> String {
        let state = self.state.lock().await;
        match state.peer_map.endpoint_for_node_key(nk) {
            Some(de) => {
                let saw = &*de.last_recv.read().await;
                match saw {
                    Some(saw) => saw.elapsed().as_secs().to_string(),
                    None => "never".to_string(),
                }
            }
            None => "never".to_string(),
        }
    }

    /// Handles a "ping" CLI query.
    pub async fn ping<F>(&self, peer: cfg::Node, res: cfg::PingResult, cb: F)
    where
        F: Fn(cfg::PingResult),
    {
        let state = self.state.lock().await;

        let mut res = cfg::PingResult::default();

        if state.private_key.is_none() {
            res.err = Some("local node stopped".to_string());
            cb(res);
            return;
        }

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
        let ep = state.peer_map.endpoint_for_node_key(&peer.key);
        match ep {
            Some(ep) => {
                ep.cli_ping(res, cb);
            }
            None => {
                res.err = Some("unknown peer".to_string());
                cb(res);
            }
        }
    }

    fn populate_cli_ping_response_locked(
        &self,
        state: &mut ConnState,
        mut res: cfg::PingResult,
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
        res.derp_region_code = self.derp_region_code_locked(state, region_id);
    }

    fn derp_region_code_locked(&self, state: &mut ConnState, region_id: usize) -> String {
        match state.derp_map {
            Some(ref dm) => match dm.regions.get(&region_id) {
                Some(dr) => dr.region_code.clone(),
                None => "".to_string(),
            },
            None => "".to_string(),
        }
    }

    /// Returns the discovery public key.
    async fn disco_public_key(&self) -> key::disco::PublicKey {
        // TODO: move this out of ConnState?
        let state = self.state.lock().await;
        state.disco_public.clone()
    }

    async fn set_nearest_derp(&self, derp_num: usize) -> bool {
        let mut state = self.state.lock().await;

        if !self.want_derp_locked(&mut state) {
            state.my_derp = 0;
            return false;
        }
        if derp_num == state.my_derp {
            // No change.
            return true;
        }
        if state.my_derp != 0 && derp_num != 0 {
            // TODO
            // metricDERPHomeChange.Add(1)
        }
        state.my_derp = derp_num;

        if state.private_key.is_none() {
            // No private key yet, so DERP connections won't come up anyway.
            // Return early rather than ultimately log a couple lines of noise.
            return true;
        }

        // On change, notify all currently connected DERP servers and
        // start connecting to our home DERP if we are not already.
        match state
            .derp_map
            .as_ref()
            .expect("already checked")
            .regions
            .get(&derp_num)
        {
            Some(dr) => {
                info!("home is now derp-{} ({})", derp_num, dr.region_code);
            }
            None => {
                info!("[unexpected]: derpMap.Regions[{}] is empty", derp_num);
            }
        }
        for (i, ad) in &state.active_derp {
            // TODO: spawn
            let b = *i == state.my_derp;
            // TODO:
            // tokio::task::spawn(async move { ad.c.note_preferred(b).await });
        }
        self.go_derp_connect(derp_num);
        true
    }

    /// Starts connecting to our DERP home, if any.
    fn start_derp_home_connect_locked(&self, state: &mut ConnState) {
        self.go_derp_connect(state.my_derp);
    }

    /// Starts a goroutine to start connecting to the given DERP node.
    fn go_derp_connect(&self, node: usize) {
        if node == 0 {
            return;
        }
        let this = self.clone();
        tokio::task::spawn(async move {
            this.derp_write_chan_of_addr(
                SocketAddr::new(DERP_MAGIC_IP, u16::try_from(node).expect("node too large")),
                None,
            )
            .await;
        });
    }

    /// Returns the machine's endpoint addresses. It does a STUN lookup (via netcheck)
    /// to determine its public address.
    async fn determine_endpoints(&self) -> Result<Vec<cfg::Endpoint>> {
        let (mut portmap_ext, mut have_portmap) = self
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
        if !have_portmap {
            (portmap_ext, have_portmap) = self
                .port_mapper
                .get_cached_mapping_or_start_creating_one()
                .await;
        }
        if have_portmap {
            add_addr!(already, eps, portmap_ext, cfg::EndpointType::Portmapped);
            self.set_net_info_have_port_map().await;
        }

        let nr = nr.read().await;
        if let Some(global_v4) = nr.global_v4 {
            add_addr!(already, eps, global_v4, cfg::EndpointType::Stun);

            // If they're behind a hard NAT and are using a fixed
            // port locally, assume they might've added a static
            // port mapping on their router to the same explicit
            // port that we are running with. Worst case it's an invalid candidate mapping.
            let port = self.port.load(Ordering::Relaxed);
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

        if let Ok(local_addr) = self.pconn4.local_addr().await {
            if local_addr.ip().is_unspecified() {
                let (mut ips, loopback) = interfaces::local_addresses();

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

    /// Returns the current IPv4 listener's port number.
    pub async fn local_port(&self) -> u16 {
        let laddr = self.pconn4.local_addr().await;
        laddr.map(|l| l.port()).unwrap_or_default()
    }

    fn network_down(&self) -> bool {
        !self.network_up.load(Ordering::Relaxed)
    }

    pub async fn send(&self, buffs: &[&[u8]], ep: &Endpoint) -> Result<()> {
        let n = buffs.len();

        // TODO:
        // metricSendData.Add(n)
        if self.network_down() {
            // TODO:
            // metricSendDataNetworkDown.Add(n)
            bail!("network down");
        }

        ep.send(buffs).await
    }

    /// Sends packet b to addr, which is either a real UDP address
    /// or a fake UDP address representing a DERP server (see derpmap).
    /// The provided public key identifies the recipient.
    ///
    /// The returned error is whether there was an error writing when it should've worked.
    /// The returned sent is whether a packet went out at all. An example of when they might
    /// be different: sending to an IPv6 address when the local machine doesn't have IPv6 support
    /// returns Ok(false); it's not an error, but nothing was sent.
    async fn send_addr(
        &self,
        addr: SocketAddr,
        pub_key: Option<&key::node::PublicKey>,
        b: &[u8],
    ) -> Result<bool> {
        if addr.ip() != DERP_MAGIC_IP {
            return self.send_udp(addr, b).await;
        }

        match self.derp_write_chan_of_addr(addr, pub_key).await {
            None => {
                // TODO:
                // metricSendDERPErrorChan.Add(1)
                return Ok(false);
            }
            Some(ch) => {
                if self.closing.load(Ordering::Relaxed) {
                    bail!("connection closed");
                }

                match ch.try_send(DerpWriteRequest {
                    addr,
                    pub_key: pub_key.cloned(),
                    b: b.to_vec(),
                }) {
                    Ok(_) => {
                        //   metricSendDERPQueued.Add(1)
                        return Ok(true);
                    }
                    Err(_) => {
                        //   metricSendDERPErrorQueue.Add(1)
                        // Too many writes queued. Drop packet.
                        bail!("packet dropped");
                    }
                }
            }
        }
    }

    async fn send_udp(&self, addr: SocketAddr, b: &[u8]) -> Result<bool> {
        let ok = match addr {
            SocketAddr::V4(_) => self.pconn4.send_to(addr, b).await?,
            SocketAddr::V6(_) => self.pconn6.send_to(addr, b).await?,
        };

        Ok(ok)
    }

    /// Returns a DERP client for fake UDP addresses that represent DERP servers, creating them as necessary.
    /// For real UDP addresses, it returns `None`.
    ///
    /// If peer is `Some`, it can be used to find an active reverse path, without using addr.
    async fn derp_write_chan_of_addr(
        &self,
        addr: SocketAddr,
        peer: Option<&key::node::PublicKey>,
    ) -> Option<flume::Sender<DerpWriteRequest>> {
        if addr.ip() != DERP_MAGIC_IP {
            return None;
        }
        if self.network_down() {
            return None;
        }
        let region_id = usize::from(addr.port());

        let mut state = self.state.lock().await;
        if !self.want_derp_locked(&mut state) || state.closed {
            return None;
        }
        if state.derp_map.is_none()
            || !state
                .derp_map
                .as_ref()
                .unwrap()
                .regions
                .contains_key(&region_id)
        {
            return None;
        }
        if state.private_key.is_none() {
            debug!("DERP lookup of {} with no private key; ignoring", addr);
            return None;
        }

        // See if we have a connection open to that DERP node ID
        // first. If so, might as well use it. (It's a little
        // arbitrary whether we use this one vs. the reverse route
        // below when we have both.)
        let ad = state.active_derp.get_mut(&region_id);
        if let Some(ad) = ad {
            ad.last_write = Instant::now();
            return Some(ad.write_ch.clone());
        }

        // If we don't have an open connection to the peer's home DERP
        // node, see if we have an open connection to a DERP node
        // where we'd heard from that peer already. For instance,
        // perhaps peer's home is Frankfurt, but they dialed our home DERP
        // node in SF to reach us, so we can reply to them using our
        // SF connection rather than dialing Frankfurt.
        if let Some(peer) = peer {
            let ConnState {
                derp_route,
                active_derp,
                ..
            } = &mut *state;
            if let Some(r) = derp_route.get(peer) {
                if let Some(ad) = active_derp.get_mut(&r.derp_id) {
                    if ad.c == r.dc {
                        ad.last_write = Instant::now();
                        return Some(ad.write_ch.clone());
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

        // Note that derp::http.new_region_client does not dial the server
        // (it doesn't block) so it is safe to do under the state lock.
        let this = self.clone();
        let dc = derp::http::Client::new_region(
            state.private_key.clone().expect("checked for key earlier"),
            move || {
                // Warning: it is not legal to acquire
                // magicsock.Conn.mu from this callback.
                // It's run from derp::http::Client.connect (via Send, etc)
                // and the lock ordering rules are that magicsock.Conn.mu
                // must be acquired before derp::http.Client.mu

                if this.is_closing() {
                    // We're closing anyway; return to stop dialing.
                    return None;
                }

                todo!();
                // Need to load the derp map without aquiring the lock

                // let derp_map = c.derpMapAtomic.Load();
                // if derp_map == nil {
                //     return None
                // }
                // derp_map.regions.get(region_id)
            },
        );

        dc.set_can_ack_pings(true);
        dc.note_preferred(state.my_derp == region_id);
        let this = self.clone();
        dc.set_address_family_selector(move || {
            // TODO: use atomic read?
            if let Some(r) = &*this.last_net_check_report.blocking_read() {
                // TODO: avoid locking on the report
                return r.blocking_read().ipv6;
            }
            false
        });

        // TODO: DNS Cache
        // dc.DNSCache = dnscache.Get();

        let (write_ch, write_ch_receiver) = flume::bounded(BUFFERED_DERP_WRITES_BEFORE_DROP);
        let (cancel_sender, cancel_receiver) = sync::watch::channel(false);
        let ad = ActiveDerp {
            c: dc.clone(),
            write_ch: write_ch.clone(),
            cancel: cancel_sender,
            last_write: Instant::now(),
            create_time: Instant::now(),
        };
        state.active_derp.insert(region_id, ad);

        // TODO:
        // metricNumDERPConns.Set(int64(len(c.activeDerp)))
        self.log_active_derp_locked(&mut state);

        self.schedule_clean_stale_derp_locked(&mut state).await;

        // TODO:

        // Build a start_gate for the derp reader+writer
        // tasks, so they don't start running until any
        // previous generation is closed.
        // let start_gate = if let Some(prev) = state.prev_derp.get(&region_id) {
        //     prev.done_chan()
        // } else {
        //     sync::Notify::new()
        // };
        // // And register a WaitGroup(Chan) for this generation.
        // wg := syncs.NewWaitGroupChan();
        // wg.Add(2);
        // c.prevDerp[regionID] = wg;

        // if firstDerp {
        //     startGate = c.derpStarted;
        //     go func() {
        // 	dc.Connect(ctx)
        // 	  close(c.derpStarted)
        // 	    c.muCond.Broadcast()
        //     }()
        // }

        let this = self.clone();
        let cancel = cancel_receiver.clone();
        let dc1 = dc.clone();
        tokio::task::spawn(async move {
            this.run_derp_reader(addr, dc1, cancel).await;
        });

        let this = self.clone();
        let cancel = cancel_receiver.clone();
        tokio::task::spawn(async move {
            this.run_derp_writer(dc, write_ch_receiver, cancel).await;
        });

        if let Some(ref f) = self.on_derp_active {
            // TODO: spawn
            f();
        }

        Some(write_ch)
    }

    /// Runs in a task for the life of a DERP connection, handling received packets.
    async fn run_derp_reader(
        &self,
        derp_fake_addr: SocketAddr,
        dc: derp::http::Client,
        cancel: sync::watch::Receiver<bool>,
        /*wg *syncs.WaitGroupChan, startGate <-chan struct{}*/
    ) {
        // TODO:
        // defer wg.Decr()
        // defer dc.Close()

        // TODO:
        // select {
        // case <-startGate:
        // case <-ctx.Done():
        // 	return
        // }

        let region_id = usize::from(derp_fake_addr.port());

        // The set of senders we know are present on this connection, based on messages we've received from the server.

        let mut peer_present = HashSet::new();
        let mut bo: backoff::exponential::ExponentialBackoff<backoff::SystemClock> =
            backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build();
        // NewBackoff(fmt.Sprintf("derp-%d", regionID), c.logf, 5 * time.Second);

        let mut last_packet_time: Option<Instant> = None;
        let mut last_packet_src: Option<key::node::PublicKey> = None;

        loop {
            match dc.recv_detail().await {
                Err(err) => {
                    // Forget that all these peers have routes.
                    for peer in peer_present.drain() {
                        self.remove_derp_peer_route(peer, region_id, &dc).await;
                    }
                    if err == derp::http::ClientError::Closed {
                        return;
                    }
                    if self.network_down() {
                        info!("derp.recv(derp-{}): network down, closing", region_id);
                        return;
                    }

                    if *cancel.borrow() {
                        return;
                    }

                    info!("[{:?}] derp.recv(derp-{}): {:?}", dc, region_id, err);

                    // If our DERP connection broke, it might be because our network
                    // conditions changed. Start that check.
                    self.re_stun("derp-recv-error").await;

                    // Back off a bit before reconnecting.
                    match bo.next_backoff() {
                        Some(t) => {
                            info!("backoff sleep: {}ms", t.as_millis());
                            time::sleep(t).await
                        }
                        None => return,
                    }

                    if *cancel.borrow() {
                        return;
                    }
                }
                Ok((msg, conn_gen)) => {
                    // reset
                    bo.reset();

                    let now = Instant::now();
                    if last_packet_time.is_none()
                        || last_packet_time.as_ref().unwrap().elapsed() > Duration::from_secs(5)
                    {
                        last_packet_time = Some(now);
                    }
                    match msg {
                        derp::ReceivedMessage::ServerInfo { .. } => {
                            info!("derp-{} connected; connGen={}", region_id, conn_gen);
                            continue;
                        }
                        derp::ReceivedMessage::ReceivedPacket { source, data } => {
                            debug!("magicsock: got derp-{} packet: {:?}", region_id, data);
                            // If this is a new sender we hadn't seen before, remember it and
                            // register a route for this peer.
                            if last_packet_src.is_none()
                                || &source != last_packet_src.as_ref().unwrap()
                            {
                                // avoid map lookup w/ high throughput single peer
                                last_packet_src = Some(source.clone());
                                if !peer_present.contains(&source) {
                                    peer_present.insert(source.clone());
                                    self.add_derp_peer_route(source.clone(), region_id, dc.clone())
                                        .await;
                                }
                            }

                            let res = DerpReadResult {
                                region_id,
                                src: source,
                                buf: data,
                            };
                            self.derp_recv_ch.0.send_async(res).await;
                        }
                        derp::ReceivedMessage::Ping(data) => {
                            // Best effort reply to the ping.
                            let dc = dc.clone();
                            tokio::task::spawn(async move {
                                if let Err(err) = dc.send_pong(data).await {
                                    info!("derp-{} send_pong error: {:?}", region_id, err);
                                }
                            });
                            continue;
                        }
                        derp::ReceivedMessage::Health { .. } => {
                            // health.SetDERPRegionHealth(regionID, m.Problem);
                        }
                        derp::ReceivedMessage::PeerGone(key) => {
                            self.remove_derp_peer_route(key, region_id, &dc).await;
                        }
                        _ => {
                            // Ignore.
                            continue;
                        }
                    }

                    if *cancel.borrow() {
                        return;
                    }
                }
            }
        }
    }

    // runDerpWriter runs in a goroutine for the life of a DERP
    // connection, handling received packets.
    async fn run_derp_writer(
        &self,
        dc: derp::http::Client,
        ch: flume::Receiver<DerpWriteRequest>,
        mut cancel: sync::watch::Receiver<bool>, /*wg *syncs.WaitGroupChan, startGate <-chan struct{}*/
    ) {
        // TODO:
        // defer wg.Decr()

        // TODO:
        // select {
        // case <-startGate:
        // case <-ctx.Done():
        // 	return
        // }

        // TODO: in the loop
        /*_ = done => {
            // <-ctx.Done():
            return;
        }*/
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        break;
                    }
                }
                wr = ch.recv_async() => match wr {
                    Ok(wr) => match dc.send(wr.pub_key, wr.b).await {
                        Ok(_) => {
                            // TODO
                            // metricSendDERP.Add(1)
                        }
                        Err(err) => {
                            info!("derp.send({:?}): {:?}", wr.addr, err);
                            // TODO
                            // metricSendDERPError.Add(1)
                        }
                    }
                    Err(_) => {
                        return;
                    }
                }
            }
        }
    }

    /// Handles deciding if a received UDP packet should be reported to the above layer or not.
    /// Returns `false` if this is an internal packet and it should not be reported.
    fn receive_ip(
        &self,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
        cache: &SocketEndpointCache,
    ) -> bool {
        if stun::is(b) {
            if let Some(ref f) = &*self.on_stun_receive.blocking_read() {
                f(b, meta.addr);
            }
            return false;
        }
        if self.handle_disco_message(b, meta.addr, None) {
            return false;
        }
        if !self.have_private_key.load(Ordering::Relaxed) {
            // If we have no private key, we're logged out or
            // stopped. Don't try to pass these packets along
            return false;
        }

        if let Some(de) = cache.get(&meta.addr) {
            meta.dst_ip = Some(de.fake_wg_addr.ip());
        } else {
            let state = self.state.blocking_lock();
            match state.peer_map.endpoint_for_ip_port(&meta.addr) {
                None => {
                    return false;
                }
                Some(de) => {
                    cache.update(meta.addr, de.clone());
                    meta.dst_ip = Some(de.fake_wg_addr.ip());
                }
            }
        }

        // ep.noteRecvActivity();
        // if stats := c.stats.Load(); stats != nil {
        //     stats.UpdateRxPhysical(ep.nodeAddr, ipp, len(b));
        // }
        true
    }

    fn process_derp_read_result(
        &self,
        dm: DerpReadResult,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
    ) -> usize {
        if dm.buf.is_empty() {
            return 0;
        }
        let buf = &dm.buf;
        let n = buf.len();
        let region_id = dm.region_id;

        let ipp = SocketAddr::new(
            DERP_MAGIC_IP,
            u16::try_from(region_id).expect("invalid region id"),
        );

        if self.handle_disco_message(&b[..n], ipp, Some(&dm.src)) {
            // Message was internal, do not bubble up.
            return 0;
        }

        let ep = {
            let state = self.state.blocking_lock();
            let ep = state.peer_map.endpoint_for_node_key(&dm.src);
            ep.cloned()
        };
        if ep.is_none() {
            // We don't know anything about this node key, nothing to record or process.
            return 0;
        }

        let ep = ep.unwrap();
        ep.note_recv_activity();
        meta.dst_ip = Some(ep.fake_wg_addr.ip());

        // if stats := c.stats.Load(); stats != nil {
        // 	stats.UpdateRxPhysical(ep.nodeAddr, ipp, dm.n)
        // }
        n
    }

    /// Sends discovery message m to dst_disco at dst.
    ///
    /// If dst is a DERP IP:port, then dst_key must be Some.
    ///
    /// The dst_key should only be `Some` the dst_disco key unambiguously maps to exactly one peer.
    async fn send_disco_message(
        &self,
        dst: SocketAddr,
        dst_key: Option<&key::node::PublicKey>,
        dst_disco: &key::disco::PublicKey,
        msg: disco::Message,
    ) -> Result<bool> {
        let is_derp = dst.ip() == DERP_MAGIC_IP;
        let is_pong = matches!(msg, disco::Message::Pong(_));
        if is_pong && !is_derp && dst.ip().is_ipv4() {
            // TODO: figure oute the right value for this (debugIPv4DiscoPingPenalty())
            time::sleep(Duration::from_millis(10)).await;
        }

        let mut state = self.state.lock().await;
        if state.closed {
            bail!("connection closed");
        }

        let disco_public = state.disco_public.clone();
        let di = self.disco_info_locked(&mut state, dst_disco);
        let seal = di.shared_key.seal(&msg.as_bytes());
        drop(state);

        // TODO
        // if is_derp {
        // 	metricSendDiscoDERP.Add(1)
        // } else {
        // 	metricSendDiscoUDP.Add(1)
        // }

        let pkt = disco::encode_message(&disco_public, seal);
        let sent = self.send_addr(dst, dst_key, &pkt).await;
        match sent {
            Ok(true) => {
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
            }
            Ok(false) => {
                // Can't send. (e.g. no IPv6 locally)
            }
            Err(ref err) => {
                if !self.network_down() {
                    warn!("disco: failed to send {:?} to {}: {:?}", msg, dst, err);
                }
            }
        }

        sent
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

        let mut state = self.state.blocking_lock();
        if state.closed || state.private_key.is_none() {
            return true;
        }

        let sender = key::disco::PublicKey::from(source);

        if !state.peer_map.any_endpoint_for_disco_key(&sender) {
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

        let di = self.disco_info_locked(&mut state, &sender);
        let payload = di.shared_key.open(&sealed_box);
        if payload.is_err() {
            // This might be have been intended for a previous
            // disco key.  When we restart we get a new disco key
            // and old packets might've still been in flight (or
            // scheduled). This is particularly the case for LANs
            // or non-NATed endpoints.
            // Don't log in normal case. Pass on to wireguard, in case
            // it's actually a wireguard packet (super unlikely, but).
            debug!("disco: failed to open box from {:?} (wrong rcpt?)", sender);
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
                self.handle_ping_locked(&mut state, ping, &sender, src, derp_node_src);
                true
            }
            disco::Message::Pong(pong) => {
                // metricRecvDiscoPong.Add(1)

                // There might be multiple nodes for the sender's DiscoKey.
                // Ask each to handle it, stopping once one reports that
                // the Pong's TxID was theirs.
                for ep in state.peer_map.endpoints_with_disco_key(&sender) {
                    todo!();
                    // if ep.handle_pong_conn_locked(&mut state, &pong, &di, src) {
                    //     break;
                    // }
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
                let ep = state.peer_map.endpoint_for_node_key(&node_key);
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
                let di = self.disco_info_locked(&mut state, &sender);
                di.set_node_key(node_key.clone());
                info!(
                    "disco: {:?}<-{:?} ({:?}, {:?})  got call-me-maybe, {} endpoints",
                    state.disco_public,
                    ep_disco_key,
                    ep.public_key,
                    src,
                    cm.my_number.len()
                );

                tokio::task::spawn(async move {
                    ep.handle_call_me_maybe(cm);
                });

                true
            }
        }
    }

    /// Attempts to look up an unambiguous mapping from a DiscoKey `dk` (which sent ping dm) to a NodeKey.
    /// `None` if not unamabigous.
    ///
    /// derp_node_src is `Some` if the disco ping arrived via DERP.
    async fn unambiguous_node_key_of_ping_locked(
        &self,
        state: &mut ConnState,
        dm: &disco::Ping,
        dk: &key::disco::PublicKey,
        derp_node_src: Option<&key::node::PublicKey>,
    ) -> Option<key::node::PublicKey> {
        if let Some(src) = derp_node_src {
            if let Some(ep) = state.peer_map.endpoint_for_node_key(src) {
                if &ep.state.lock().await.disco_key == dk {
                    return Some(src.clone());
                }
            }
        }

        // Pings contains its node source. See if it maps back.
        if let Some(ep) = state.peer_map.endpoint_for_node_key(&dm.node_key) {
            if &ep.state.lock().await.disco_key == dk {
                return Some(dm.node_key.clone());
            }
        }

        // If there's exactly 1 node in our netmap with DiscoKey dk,
        // then it's not ambiguous which node key dm was from.
        if let Some(set) = state.peer_map.nodes_of_disco.get(dk) {
            if set.len() == 1 {
                return Some(set.iter().next().unwrap().clone());
            }
        }

        None
    }

    /// di is the DiscoInfo of the source of the ping.
    /// derp_node_src is non-zero if the ping arrived via DERP.
    fn handle_ping_locked(
        &self,
        state: &mut ConnState,
        dm: disco::Ping,
        sender: &key::disco::PublicKey,
        src: SocketAddr,
        derp_node_src: Option<&key::node::PublicKey>,
    ) {
        let di = self.disco_info_locked(state, &sender);
        todo!();
        // 	likelyHeartBeat := src == di.lastPingFrom && time.Since(di.lastPingTime) < 5*time.Second
        // 	di.lastPingFrom = src
        // 	di.lastPingTime = time.Now()
        // 	isDerp := src.Addr() == derpMagicIPAddr

        // 	// If we can figure out with certainty which node key this disco
        // 	// message is for, eagerly update our IP<>node and disco<>node
        // 	// mappings to make p2p path discovery faster in simple
        // 	// cases. Without this, disco would still work, but would be
        // 	// reliant on DERP call-me-maybe to establish the disco<>node
        // 	// mapping, and on subsequent disco handlePongLocked to establish
        // 	// the IP<>disco mapping.
        // 	if nk, ok := c.unambiguousNodeKeyOfPingLocked(dm, di.discoKey, derpNodeSrc); ok {
        // 		di.setNodeKey(nk)
        // 		if !isDerp {
        // 			c.peerMap.setNodeKeyForIPPort(src, nk)
        // 		}
        // 	}

        // 	// If we got a ping over DERP, then derpNodeSrc is non-zero and we reply
        // 	// over DERP (in which case ipDst is also a DERP address).
        // 	// But if the ping was over UDP (ipDst is not a DERP address), then dstKey
        // 	// will be zero here, but that's fine: sendDiscoMessage only requires
        // 	// a dstKey if the dst ip:port is DERP.
        // 	dstKey := derpNodeSrc

        // 	// Remember this route if not present.
        // 	var numNodes int
        // 	var dup bool
        // 	if isDerp {
        // 		if ep, ok := c.peerMap.endpointForNodeKey(derpNodeSrc); ok {
        // 			if ep.addCandidateEndpoint(src, dm.TxID) {
        // 				return
        // 			}
        // 			numNodes = 1
        // 		}
        // 	} else {
        // 		c.peerMap.forEachEndpointWithDiscoKey(di.discoKey, func(ep *endpoint) (keepGoing bool) {
        // 			if ep.addCandidateEndpoint(src, dm.TxID) {
        // 				dup = true
        // 				return false
        // 			}
        // 			numNodes++
        // 			if numNodes == 1 && dstKey.IsZero() {
        // 				dstKey = ep.publicKey
        // 			}
        // 			return true
        // 		})
        // 		if dup {
        // 			return
        // 		}
        // 		if numNodes > 1 {
        // 			// Zero it out if it's ambiguous, so sendDiscoMessage logging
        // 			// isn't confusing.
        // 			dstKey = key.node::PublicKey{}
        // 		}
        // 	}

        // 	if numNodes == 0 {
        // 		c.logf("[unexpected] got disco ping from %v/%v for node not in peers", src, derpNodeSrc)
        // 		return
        // 	}

        // 	if !likelyHeartBeat || debugDisco() {
        // 		pingNodeSrcStr := dstKey.ShortString()
        // 		if numNodes > 1 {
        // 			pingNodeSrcStr = "[one-of-multi]"
        // 		}
        // 		c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got ping tx=%x", c.discoShort, di.discoShort, pingNodeSrcStr, src, dm.TxID[:6])
        // 	}

        // 	ipDst := src
        // 	discoDest := di.discoKey
        // 	go c.sendDiscoMessage(ipDst, dstKey, discoDest, &disco.Pong{
        // 		TxID: dm.TxID,
        // 		Src:  src,
        // 	}, discoVerboseLog)
    }

    /// Schedules a send of disco.CallMeMaybe to de via derpAddr
    /// once we know that our STUN endpoint is fresh.
    ///
    /// derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
    /// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
    /// If they do, traffic will just go over DERP for a bit longer until the next discovery round.
    fn enqueue_call_me_maybe(&self, derp_addr: SocketAddr, de: &Endpoint) {
        todo!()
        // 	c.mu.Lock()
        // 	defer c.mu.Unlock()

        // 	if !c.lastEndpointsTime.After(time.Now().Add(-endpointsFreshEnoughDuration)) {
        // 		c.dlogf("[v1] magicsock: want call-me-maybe but endpoints stale; restunning")

        // 		mak.Set(&c.onEndpointRefreshed, de, func() {
        // 			c.dlogf("[v1] magicsock: STUN done; sending call-me-maybe to %v %v", de.discoShort, de.publicKey.ShortString())
        // 			c.enqueueCallMeMaybe(derpAddr, de)
        // 		})
        // 		// TODO(bradfitz): make a new 'reSTUNQuickly' method
        // 		// that passes down a do-a-lite-netcheck flag down to
        // 		// netcheck that does 1 (or 2 max) STUN queries
        // 		// (UDP-only, not HTTPs) to find our port mapping to
        // 		// our home DERP and maybe one other. For now we do a
        // 		// "full" ReSTUN which may or may not be a full one
        // 		// (depending on age) and may do HTTPS timing queries
        // 		// (if UDP is blocked). Good enough for now.
        // 		go c.ReSTUN("refresh-for-peering")
        // 		return
        // 	}

        // 	eps := make([]netip.AddrPort, 0, len(c.lastEndpoints))
        // 	for _, ep := range c.lastEndpoints {
        // 		eps = append(eps, ep.Addr)
        // 	}
        // 	go de.c.sendDiscoMessage(derpAddr, de.publicKey, de.discoKey, &disco.CallMeMaybe{MyNumber: eps}, discoLog)
    }

    /// Returns the previous or new DiscoInfo for `k`.
    fn disco_info_locked<'a>(
        &self,
        state: &'a mut ConnState,
        k: &key::disco::PublicKey,
    ) -> &'a mut DiscoInfo {
        if !state.disco_info.contains_key(k) {
            let shared_key = state.disco_private.shared(k);
            state.disco_info.insert(
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

        state.disco_info.get_mut(k).unwrap()
    }

    pub async fn set_network_up(&self, up: bool) {
        let mut state = self.state.lock().await;
        if self.network_up.load(Ordering::Relaxed) == up {
            return;
        }

        info!("magicsock: set_network_up({})", up);
        self.network_up.store(up, Ordering::Relaxed);

        if up {
            self.start_derp_home_connect_locked(&mut state);
        } else {
            self.port_mapper.note_network_down();
            self.close_all_derp_locked(&mut state, "network-down");
        }
    }

    /// Sets the connection's preferred local port.
    pub async fn set_preferred_port(&self, port: u16) {
        let existing_port = self.port.swap(port, Ordering::Relaxed);
        if existing_port == port {
            return;
        }

        if let Err(err) = self.rebind(CurrentPortFate::Drop).await {
            warn!("failed to rebind: {:?}", err);
            return;
        }
        self.reset_endpoint_states().await;
    }

    /// Sets the connection's secret key.
    ///
    /// This is only used to be able prove our identity when connecting to DERP servers.
    ///
    /// If the secret key changes, any DERP connections are torn down & recreated when needed.
    pub async fn set_private_key(&self, new_key: key::node::SecretKey) -> Result<()> {
        let mut state = self.state.lock().await;

        let old_key = &state.private_key;
        if old_key.is_some()
            && old_key
                .as_ref()
                .unwrap()
                .to_bytes()
                .ct_eq(&new_key.to_bytes())
                .into()
        {
            return Ok(());
        }
        let old_key = state.private_key.replace(new_key);
        self.have_private_key.store(true, Ordering::Relaxed);

        if old_key.is_none() {
            state.ever_had_key = true;
            info!("set_private_key called (init)");

            let this = self.clone();
            tokio::task::spawn(async move {
                this.re_stun("set-private-key").await;
            });
        } else {
            info!("set_private_key called (changed)");
            self.close_all_derp_locked(&mut state, "new-private-key");
        }

        // Key changed. Close existing DERP connections and reconnect to home.
        if state.my_derp != 0 {
            info!(
                "private key changed, reconnecting to home derp-{}",
                state.my_derp
            );
            self.start_derp_home_connect_locked(&mut state);
        }

        Ok(())
    }

    /// Called when the set of WireGuard peers changes. It then removes any state for old peers.
    pub async fn update_peers(&self, new_peers: HashSet<key::node::PublicKey>) {
        let mut state = self.state.lock().await;

        let old_peers = std::mem::replace(&mut state.peer_set, new_peers);

        // Clean up any maps for peers that no longer exist.
        for peer in &old_peers {
            if !state.peer_set.contains(peer) {
                state.derp_route.remove(peer);
            }
        }

        if old_peers.is_empty() && !state.peer_set.is_empty() {
            let this = self.clone();
            tokio::task::spawn(async move {
                this.re_stun("non-zero-peers").await;
            });
        }
    }

    /// Controls which (if any) DERP servers are used. A `None` value means to disable DERP; it's disabled by default.
    pub async fn set_derp_map(&self, dm: Option<derp::DerpMap>) {
        let mut state = self.state.lock().await;

        if state.derp_map == dm {
            return;
        }

        let old = std::mem::replace(&mut state.derp_map, dm);
        if state.derp_map.is_none() {
            self.close_all_derp_locked(&mut state, "derp-disabled");
            return;
        }

        // Reconnect any DERP region that changed definitions.
        if let Some(old) = old {
            let mut changes = false;
            for (rid, old_def) in old.regions {
                if let Some(new_def) = state.derp_map.as_ref().unwrap().regions.get(&rid) {
                    if &old_def == new_def {
                        continue;
                    }
                }
                changes = true;
                if rid == state.my_derp {
                    state.my_derp = 0;
                }
                self.close_derp_locked(rid, "derp-region-redefined", &mut state.active_derp);
            }
            if changes {
                self.log_active_derp_locked(&mut state);
            }
        }

        let this = self.clone();
        tokio::task::spawn(async move {
            this.re_stun("derp-map-update").await;
        });
    }

    /// Called when the control client gets a new network map from the control server.
    /// It should not use the DerpMap field of NetworkMap; that's
    /// conditionally sent to set_derp_map instead.
    pub async fn set_network_map(&self, nm: netmap::NetworkMap) {
        let mut state = self.state.lock().await;

        if state.closed {
            return;
        }

        // Update selt.net_map regardless, before the following early return.
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
            peer_map,
            ..
        } = &mut *state;
        for n in &net_map.as_ref().unwrap().peers {
            if let Some(ep) = peer_map.endpoint_for_node_key(&n.key).cloned() {
                let old_disco_key = ep.disco_key();
                ep.update_from_node(n);
                peer_map.upsert_endpoint(ep, Some(&old_disco_key)).await; // maybe update discokey mappings in peerMap
                continue;
            }
            let ep = Endpoint::new(self.clone(), n);
            ep.update_from_node(n);
            peer_map.upsert_endpoint(ep, None).await;
        }

        // If the set of nodes changed since the last SetNetworkMap, the
        // upsert loop just above made c.peerMap contain the union of the
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

    fn want_derp_locked(&self, state: &mut ConnState) -> bool {
        state.derp_map.is_some()
    }

    fn close_all_derp_locked(&self, state: &mut ConnState, why: &'static str) {
        if state.active_derp.is_empty() {
            return; // without the useless log statement
        }
        // Need to collect to avoid double borrow
        let regions: Vec<_> = state.active_derp.keys().copied().collect();
        for region in regions {
            self.close_derp_locked(region, why, &mut state.active_derp);
        }
        self.log_active_derp_locked(state);
    }

    /// Called in response to a rebind, closes all DERP connections that don't have a local address in okay_local_ips
    /// and pings all those that do.
    async fn maybe_close_derps_on_rebind(&self, okay_local_ips: &[IpAddr]) {
        let mut state = self.state.lock().await;

        let mut tasks: Vec<(usize, &'static str)> = Vec::new();
        {
            for (region_id, ad) in &state.active_derp {
                let la = match ad.c.local_addr() {
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
                let this = self.clone();
                let region_id = *region_id;
                tokio::task::spawn(time::timeout(Duration::from_secs(3), async move {
                    if let Err(_err) = dc.ping().await {
                        let mut state = this.state.lock().await;
                        this.close_or_reconnect_derp_locked(
                            region_id,
                            "rebind-ping-fail",
                            &mut state,
                        )
                        .await;
                        return;
                    }
                    debug!("post-rebind ping of DERP region {} okay", region_id);
                }));
            }
        }

        for (region_id, why) in tasks {
            self.close_or_reconnect_derp_locked(region_id, why, &mut state)
                .await;
        }

        self.log_active_derp_locked(&mut state);
    }

    /// Closes the DERP connection to the provided `region_id` and starts reconnecting it if it's
    /// our current home DERP.
    async fn close_or_reconnect_derp_locked(
        &self,
        region_id: usize,
        why: &'static str,
        state: &mut ConnState,
    ) {
        self.close_derp_locked(region_id, why, &mut state.active_derp);
        if state.private_key.is_some() && state.my_derp == region_id {
            self.start_derp_home_connect_locked(state);
        }
    }

    /// It is the responsibility of the caller to call `log_active_derp_locked` after any set of closes.
    fn close_derp_locked(
        &self,
        region_id: usize,
        why: &'static str,
        active_derp: &mut HashMap<usize, ActiveDerp>,
    ) {
        if let Some(mut ad) = active_derp.remove(&region_id) {
            debug!(
                "closing connection to derp-{} ({:?}), age {}s",
                region_id,
                why,
                ad.create_time.elapsed().as_secs()
            );

            todo!();
            // TODO:
            // tokio::task::spawn(ad.c.close());
            ad.cancel.send(true);

            // TODO:
            // metricNumDERPConns.Set(int64(len(c.activeDerp)))
        }
    }

    fn log_active_derp_locked(&self, state: &mut ConnState) {
        let now = Instant::now();
        debug!("{} active derp conns{}", state.active_derp.len(), {
            let mut s = String::new();
            if !state.active_derp.is_empty() {
                s += ":";
                for (node, ad) in self.active_derp_sorted(state) {
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

    fn log_endpoint_change(&self, endpoints: &[cfg::Endpoint]) {
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

    fn active_derp_sorted<'a, 'b: 'a>(
        &'a self,
        state: &'b mut ConnState,
    ) -> impl Iterator<Item = (usize, &'b ActiveDerp)> + '_ {
        let mut ids: Vec<_> = state.active_derp.keys().copied().collect();
        ids.sort();

        ids.into_iter()
            .map(|id| (id, state.active_derp.get(&id).unwrap()))
    }

    async fn clean_stale_derp(&self) {
        let mut state = self.state.lock().await;
        if state.closed {
            return;
        }
        state.derp_cleanup_timer_armed = false;
        let too_old = DERP_INACTIVE_CLEANUP_TIME;
        let now = Instant::now();
        let mut dirty = false;
        let mut some_non_home_open = false;

        let mut to_close = Vec::new();
        for (i, ad) in &state.active_derp {
            if *i == state.my_derp {
                continue;
            }
            if ad.last_write.duration_since(now) > DERP_INACTIVE_CLEANUP_TIME {
                to_close.push(*i);
                dirty = true;
            } else {
                some_non_home_open = true;
            }
        }
        for i in to_close {
            self.close_derp_locked(i, "idle", &mut state.active_derp);
        }
        if dirty {
            self.log_active_derp_locked(&mut state);
        }
        if some_non_home_open {
            self.schedule_clean_stale_derp_locked(&mut state).await;
        }
    }

    // uses Pin<Box>> to avoid cycles in type inf
    fn schedule_clean_stale_derp_locked<'a, 'b: 'a>(
        &'a self,
        state: &'b mut ConnState,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> {
        Box::pin(async {
            if state.derp_cleanup_timer_armed {
                // Already going to fire soon. Let the existing one
                // fire lest it get infinitely delayed by repeated
                // calls to scheduleCleanStaleDerpLocked.
                return;
            }
            state.derp_cleanup_timer_armed = true;
            if let Some(ref t) = state.derp_cleanup_timer {
                t.reset(DERP_CLEAN_STALE_INTERVAL).await;
            } else {
                let this = self.clone();
                state.derp_cleanup_timer =
                    Some(Timer::after(DERP_CLEAN_STALE_INTERVAL, async move {
                        this.clean_stale_derp().await;
                    }));
            }
        })
    }

    /// Reports the number of active DERP connections.
    pub async fn derps(&self) -> usize {
        self.state.lock().await.active_derp.len()
    }

    fn derp_region_code_of_addr_locked(&self, state: &mut ConnState, ip_port: &str) -> String {
        let addr: std::result::Result<SocketAddr, _> = ip_port.parse();
        match addr {
            Ok(addr) => {
                let region_id = usize::from(addr.port());
                self.derp_region_code_of_id_locked(state, region_id)
            }
            Err(_) => String::new(),
        }
    }

    fn derp_region_code_of_id_locked(&self, state: &mut ConnState, region_id: usize) -> String {
        if let Some(ref dm) = state.derp_map {
            if let Some(r) = dm.regions.get(&region_id) {
                return r.region_code.clone();
            }
        }

        String::new()
    }

    /// Close closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.
    pub async fn close(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if state.closed {
            return Ok(());
        }
        self.closing.store(true, Ordering::Relaxed);
        if state.derp_cleanup_timer_armed {
            if let Some(t) = state.derp_cleanup_timer.take() {
                t.stop().await;
            }
        }
        self.stop_periodic_re_stun_timer(&mut state).await;
        self.port_mapper.close();

        for ep in state.peer_map.endpoints() {
            ep.stop_and_reset().await;
        }

        state.closed = true;
        // c.connCtxCancel()
        self.close_all_derp_locked(&mut state, "conn-close");
        // Ignore errors from c.pconnN.Close.
        // They will frequently have been closed already by a call to connBind.Close.
        self.pconn6.close().await.ok();
        self.pconn4.close().await.ok();

        // Wait on tasks updating right at the end, once everything is
        // already closed. We want everything else in the Conn to be
        // consistently in the closed state before we release mu to wait
        // on the endpoint updater & derphttp.Connect.
        while self.tasks_running_locked(&mut state).await {
            self.state_notifier.notified().await;
        }

        Ok(())
    }

    async fn tasks_running_locked(&self, state: &mut ConnState) -> bool {
        if state.endpoints_update_active {
            return true;
        }
        // TODO: track spawned tasks and join them
        false
    }

    fn should_do_periodic_re_stun(&self, state: &mut ConnState) -> bool {
        if self.network_down() {
            return false;
        }
        if state.peer_set.is_empty() || state.private_key.is_none() {
            // If no peers, not worth doing.
            // Also don't if there's no key (not running).
            return false;
        }
        if let Some(ref f) = self.idle_for {
            let idle_for = f();
            debug!("periodic_re_stun: idle for {}s", idle_for.as_secs());

            if idle_for > SESSION_ACTIVE_TIMEOUT {
                return false;
            }
        }

        true
    }

    async fn on_port_map_changed(&self) {
        self.re_stun("portmap-changed").await;
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    async fn re_stun(&self, why: &'static str) {
        let mut state = self.state.lock().await;
        if state.closed {
            // raced with a shutdown.
            return;
        }
        // TODO:
        // metricReSTUNCalls.Add(1)

        // If the user stopped the app, stop doing work. (When the
        // user stops we get reconfigures the engine with a no private key.)
        //
        // This used to just check c.privateKey.IsZero, but that broke
        // some end-to-end tests that didn't ever set a private
        // key somehow. So for now, only stop doing work if we ever
        // had a key, which helps real users, but appeases tests for
        // now. TODO: rewrite those tests to be less brittle or more realistic.
        if state.private_key.is_some() && state.ever_had_key {
            debug!("re_stun({}) ignored; stopped, no private key", why);
            return;
        }

        if state.endpoints_update_active {
            if state.want_endpoints_update.is_none() || state.want_endpoints_update.unwrap() != why
            {
                debug!(
                    "re_stun: endpoint update active, need another later ({})",
                    why
                );
                state.want_endpoints_update = Some(why);
            }
        } else {
            state.endpoints_update_active = true;
            let this = self.clone();
            tokio::task::spawn(async move {
                this.update_endpoints(why).await;
            });
        }
    }

    /// Opens a packet listener.
    async fn listen_packet(&self, network: Network, port: u16) -> Result<UdpSocket> {
        let addr: SocketAddr = format!(":{}", port).parse().expect("invalid bind address");
        let socket = socket2::Socket::new(
            network.into(),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        if let Err(err) = socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE) {
            info!(
                "failed to set recv_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        if let Err(err) = socket.set_send_buffer_size(SOCKET_BUFFER_SIZE) {
            info!(
                "failed to set send_buffer_size to {}: {:?}",
                SOCKET_BUFFER_SIZE, err
            );
        }
        socket.set_nonblocking(true)?;
        socket.bind(&addr.into())?;
        let socket = UdpSocket::from_std(socket.into())?;

        Ok(socket)
    }

    // bindSocket initializes rucPtr if necessary and binds a UDP socket to it.
    // Network indicates the UDP socket type; it must be "udp4" or "udp6".
    // If rucPtr had an existing UDP socket bound, it closes that socket.
    // The caller is responsible for informing the portMapper of any changes.
    // If curPortFate is set to dropCurrentPort, no attempt is made to reuse
    // the current port.
    async fn bind_socket(
        &self,
        ruc: &RebindingUdpConn,
        network: Network,
        cur_port_fate: CurrentPortFate,
    ) -> Result<()> {
        debug!(
            "bind_socket: network={:?} cur_port_fate={:?}",
            network, cur_port_fate
        );

        // Hold the ruc lock the entire time, so that the close+bind is atomic from the perspective of ruc receive functions.
        let mut ruc = ruc.inner.write().await;

        // Build a list of preferred ports.
        // - Best is the port that the user requested.
        // - Second best is the port that is currently in use.
        // - If those fail, fall back to 0.

        let mut ports = Vec::new();
        let port = self.port.load(Ordering::Relaxed);
        if port != 0 {
            ports.push(port);
        }
        if cur_port_fate == CurrentPortFate::Keep {
            if let Ok(cur_addr) = ruc.local_addr() {
                ports.push(cur_addr.port());
            }
        }
        ports.push(0);
        // Remove duplicates. (All duplicates are consecutive.)
        ports.dedup();
        debug!("bind_socket: candidate ports: {:?}", ports);

        for port in &ports {
            // Close the existing conn, in case it is sitting on the port we want.
            if let Err(err) = ruc.close() {
                // !errors.Is(err, net.ErrClosed) && !errors.Is(err, errNilPConn) {
                info!("bind_socket {:?} close failed: {:?}", network, err);
            }
            // Open a new one with the desired port.
            match self.listen_packet(network, *port).await {
                Ok(pconn) => {
                    debug!(
                        "bind_socket: successfully listened {:?} port {}",
                        network, port
                    );
                    ruc.set_conn(pconn, network);
                    break;
                }
                Err(err) => {
                    info!(
                        "bind_socket: unable to bind {:?} port {}: {:?}",
                        network, port, err
                    );
                    continue;
                }
            }
        }

        // Failed to bind, including on port 0 (!).
        // Set pconn to a dummy conn whose reads block until closed.
        // This keeps the receive funcs alive for a future in which
        // we get a link change and we can try binding again.

        // TODO:
        // ruc.set_conn(newBlockForeverConn(), "");

        bail!("failed to bind any ports (tried {:?})", ports);
    }

    /// Closes and re-binds the UDP sockets.
    /// We consider it successful if we manage to bind the IPv4 socket.
    async fn rebind(&self, cur_port_fate: CurrentPortFate) -> Result<()> {
        if let Err(err) = self
            .bind_socket(&self.pconn6, Network::Ip6, cur_port_fate)
            .await
        {
            info!("rebind ignoring IPv6 bind failure: {:?}", err);
        }
        self.bind_socket(&self.pconn4, Network::Ip4, cur_port_fate)
            .await
            .context("rebind IPv4 failed")?;

        self.port_mapper
            .set_local_port(self.local_port().await)
            .await;

        Ok(())
    }

    /// Closes and re-binds the UDP sockets and resets the DERP connection.
    /// It should be followed by a call to ReSTUN.
    async fn rebind_all(&self) {
        // TODO:
        // metricRebindCalls.Add(1)
        if let Err(err) = self.rebind(CurrentPortFate::Keep).await {
            debug!("{:?}", err);
            return;
        }

        let mut if_ips = Vec::new();
        if let Some(ref link_mon) = self.link_monitor {
            let st = link_mon.interface_state();
            if let Some(ref def_if) = st.default_route_interface {
                if let Some(ifs) = st.interface_ips.get(def_if) {
                    for i in ifs {
                        if_ips.push(i.addr());
                    }
                    info!("rebind_all; def_if={:?}, ips={:?}", def_if, if_ips);
                }
            }
        }

        self.maybe_close_derps_on_rebind(&if_ips).await;
        self.reset_endpoint_states().await;
    }

    /// Resets the preferred address for all peers.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    async fn reset_endpoint_states(&self) {
        let state = self.state.lock().await;
        for ep in state.peer_map.endpoints() {
            ep.note_connectivity_change().await;
        }
    }
}

/// A route entry for a public key, saying that a certain peer should be available at DERP
/// node derpID, as long as the current connection for that derpID is dc. (but dc should not be
/// used to write directly; it's owned by the read/write loops)
#[derive(Debug)]
struct DerpRoute {
    derp_id: usize,
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
    fn set_node_key(&mut self, nk: key::node::PublicKey) {
        self.last_node_key.replace(nk);
        self.last_node_key_time.replace(Instant::now());
    }
}

// TODO:
// // ippEndpointCache is a mutex-free single-element cache, mapping from
// // a single netip.AddrPort to a single endpoint.
// type ippEndpointCache struct {
// 	ipp netip.AddrPort
// 	gen int64
// 	de  *endpoint
// }

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
    fn poll_send(
        &mut self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        // TODO: find a way around the copies
        let mut transmits_ipv4: Vec<quinn::Transmit> = Vec::new();
        let mut transmits_ipv6: Vec<quinn::Transmit> = Vec::new();

        for t in transmits {
            if t.destination.is_ipv6() {
                transmits_ipv6.push(quinn::Transmit {
                    destination: t.destination,
                    ecn: t.ecn,
                    contents: t.contents.clone(),
                    segment_size: t.segment_size,
                    src_ip: t.src_ip,
                });
            } else {
                transmits_ipv4.push(quinn::Transmit {
                    destination: t.destination,
                    ecn: t.ecn,
                    contents: t.contents.clone(),
                    segment_size: t.segment_size,
                    src_ip: t.src_ip,
                });
            }
        }
        let mut sum = 0;
        if !transmits_ipv4.is_empty() {
            match self.pconn4.poll_send(state, cx, &transmits_ipv4[..]) {
                Poll::Pending => {}
                Poll::Ready(Ok(r)) => {
                    sum += r;
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(err));
                }
            }
        }
        if !transmits_ipv6.is_empty() {
            match self.pconn6.poll_send(state, cx, &transmits_ipv6) {
                Poll::Pending => {}
                Poll::Ready(Ok(r)) => {
                    sum += r;
                }
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(err));
                }
            }
        }

        if sum > 0 {
            return Poll::Ready(Ok(sum));
        }

        Poll::Pending
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // FIXME: currently ipv4 load results in ipv6 traffic being ignored
        debug_assert_eq!(bufs.len(), meta.len());

        let mut num_msgs_total = 0;

        // IPv4
        match self.pconn4.poll_recv(cx, bufs, meta) {
            Poll::Pending => {}
            Poll::Ready(Err(err)) => {
                return Poll::Ready(Err(err));
            }
            Poll::Ready(Ok(mut num_msgs)) => {
                debug_assert!(num_msgs < bufs.len());
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
            match self.pconn6.poll_recv(
                cx,
                &mut bufs[num_msgs_total..],
                &mut meta[num_msgs_total..],
            ) {
                Poll::Pending => {}
                Poll::Ready(Err(err)) => {
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(mut num_msgs)) => {
                    debug_assert!(num_msgs + num_msgs_total < bufs.len());
                    let mut i = num_msgs_total;
                    while i < num_msgs + num_msgs_total {
                        if !self.receive_ip(&mut bufs[i], &mut meta[i], &self.socket_endpoint6) {
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
        // Derp
        let mut i = num_msgs_total;
        if num_msgs_total < bufs.len() {
            while i < bufs.len() {
                if let Ok(dm) = self.derp_recv_ch.1.try_recv() {
                    if self.state.blocking_lock().closed {
                        break;
                    }

                    let n = self.process_derp_read_result(dm, &mut bufs[i], &mut meta[i]);
                    if n == 0 {
                        // No read, continue
                        continue;
                    }

                    i += 1;
                } else {
                    break;
                }
            }
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs_total > 0 {
            return Poll::Ready(Ok(num_msgs_total));
        }

        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        // TODO: Just uses ip4 for now, is this enough?
        let addr = self.pconn4.local_addr_blocking()?;
        Ok(addr)
    }
}

/// The type sent by run_derp_client to receive_ipv4 when a DERP packet is available.
struct DerpReadResult {
    region_id: usize,
    src: key::node::PublicKey,
    /// packet data
    buf: Vec<u8>,
}

struct DerpWriteRequest {
    addr: SocketAddr,
    pub_key: Option<key::node::PublicKey>,
    b: Vec<u8>,
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
    cancel: sync::watch::Sender<bool>,
    write_ch: flume::Sender<DerpWriteRequest>,
    /// The time of the last request for its write
    // channel (currently even if there was no write).
    // It is always non-nil and initialized to a non-zero Time.
    last_write: Instant,
    create_time: Instant,
}
