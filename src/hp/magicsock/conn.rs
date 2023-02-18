use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::{
        atomic::{AtomicBool, AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use futures::future::BoxFuture;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tokio::{
    net::UdpSocket,
    sync::{self, oneshot, Mutex, RwLock},
    time::{self, Instant},
};
use tracing::{debug, info};

use crate::hp::{
    cfg::{self, DERP_MAGIC_IP},
    derp::{self, DerpMap},
    disco, interfaces, key,
    magicsock::SESSION_ACTIVE_TIMEOUT,
    monitor, netcheck, netmap, portmapper,
};

use super::{
    endpoint::PeerMap, rebinding_conn::RebindingUdpConn, ActiveDerp, Endpoint, Timer,
    SOCKET_BUFFER_SIZE,
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
#[derive(Clone)]
pub struct Conn(Arc<Inner>);

impl Deref for Conn {
    type Target = Inner;

    fn deref(&self) -> &Self::Target {
        &self.0
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
    // donec:         <-chan struct{}, // connCtx.Done()'s to avoid context.cancelCtx.Done()'s mutex per call

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

    // TODO:
    // Used by receiveDERP to read DERP messages.
    // It must have buffer size > 0; see issue 3736.
    // derpRecvCh chan derpReadResult

    // TODO: check if this is needed
    /// The wireguard-go conn.Bind for Conn.
    // bind: UdpSocket, // ConnBind,

    // TODO:
    // owned by receiveIPv4 and receiveIPv6, respectively, to cache an IPPort->endpoint for hot flows.
    // ippEndpoint4, ippEndpoint6 ippEndpointCache

    // ============================================================
    // Fields that must be accessed via atomic load/stores.
    /// Whether IPv4 and IPv6 are known to be missing.
    /// They're only used to suppress log spam. The name
    /// is named negatively because in early start-up, we don't yet
    /// necessarily have a netcheck.Report and don't want to skip logging.
    no_v4: AtomicBool,
    no_v6: AtomicBool,

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

struct ConnState {
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
            no_v4: AtomicBool::new(false),
            no_v6: AtomicBool::new(false),
            no_v4_send: AtomicBool::new(false),
            pconn4: RebindingUdpConn::default(),
            pconn6: RebindingUdpConn::default(),
            state_notifier: sync::Notify::new(),
            on_stun_receive: Default::default(),
            state: Default::default(),
            close_disco4: None,
            close_disco6: None,
            closing: AtomicBool::new(false),
        }));

        c.rebind(CurrentPortFate::Keep).await?;

        // TODO:
        // c.connCtx, c.connCtxCancel = context.WithCancel(context.Background())
        // c.donec = c.connCtx.Done()

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
            self.no_v4.store(r.ipv4, Ordering::Relaxed);
            self.no_v6.store(r.ipv6, Ordering::Relaxed);
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
            );
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

        if let Some(local_addr) = self.pconn4.local_addr().await {
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

    // Sends UDP packet `b` to `ipp`.
    async fn send_udp(&self, ipp: SocketAddr, b: &[u8]) -> Result<bool> {
        let res = self.send_udp_std(ipp, b).await;

        match res {
            Ok(true) => {
                // TODO
                // metricSendUDP.Add(1)
            }
            _ => {}
            Err(_) => {
                // TODO:
                // metricSendUDPError.Add(1)
            }
        }

        res
    }

    /// Sends UDP packet b to addr.
    async fn send_udp_std(&self, addr: SocketAddr, b: &[u8]) -> Result<bool> {
        let res = match addr {
            SocketAddr::V4(_) => {
                let res = self.pconn4.write_to(addr, b).await;
                if res.is_err()
                    && (self.no_v4.load(Ordering::Relaxed)
                        || res.as_ref().unwrap_err().treat_as_lost_udp())
                {
                    return Ok(false);
                }
                res
            }
            SocketAddr::V6(_) => {
                let res = self.pconn6.write_to(addr, b).await;
                if res.is_err()
                    && (self.no_v6.load(Ordering::Relaxed)
                        || res.as_ref().unwrap_err().treat_as_lost_udp())
                {
                    return Ok(false);
                }
                res
            }
        };

        res.map(|_| true).map_err(Into::into)
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

        match self.derp_write_chan_of_addr(addr, pub_key) {
            None => {
                // TODO:
                // metricSendDERPErrorChan.Add(1)
                return Ok(false);
            }
            Some(ch) => {
                let pkt = b.to_vec();

                // tokio::select! {
                // case <-c.donec:
                //   metricSendDERPErrorClosed.Add(1)
                //   return false, errConnClosed
                // case ch <- derpWriteRequest{addr, pubKey, pkt}:
                //   metricSendDERPQueued.Add(1)
                //   return true, nil
                // default:
                //   metricSendDERPErrorQueue.Add(1)
                //   // Too many writes queued. Drop packet.
                //   return false, errDropDerpPacket
                // }
                todo!()
            }
        }
    }

    /// Returns a DERP client for fake UDP addresses that represent DERP servers, creating them as necessary.
    /// For real UDP addresses, it returns `None`.
    ///
    /// If peer is `Some`, it can be used to find an active reverse path, without using addr.
    fn derp_write_chan_of_addr(
        &self,
        addr: SocketAddr,
        peer: Option<&key::node::PublicKey>,
    ) -> Option<()> {
        todo!()
        // chan<- derpWriteRequest {
        // if addr.Addr() != derpMagicIPAddr {
        // 	return nil
        // }
        // regionID := int(addr.Port())

        // if c.networkDown() {
        // 	return nil
        // }

        // c.mu.Lock()
        // defer c.mu.Unlock()
        // if !c.wantDerpLocked() || c.closed {
        // 	return nil
        // }
        // if c.derpMap == nil || c.derpMap.Regions[regionID] == nil {
        // 	return nil
        // }
        // if c.privateKey.IsZero() {
        // 	c.logf("magicsock: DERP lookup of %v with no private key; ignoring", addr)
        // 	return nil
        // }

        // 	// See if we have a connection open to that DERP node ID
        // 	// first. If so, might as well use it. (It's a little
        // 	// arbitrary whether we use this one vs. the reverse route
        // 	// below when we have both.)
        // 	ad, ok := c.activeDerp[regionID]
        // 	if ok {
        // 		*ad.lastWrite = time.Now()
        // 		c.setPeerLastDerpLocked(peer, regionID, regionID)
        // 		return ad.writeCh
        // 	}

        // 	// If we don't have an open connection to the peer's home DERP
        // 	// node, see if we have an open connection to a DERP node
        // 	// where we'd heard from that peer already. For instance,
        // 	// perhaps peer's home is Frankfurt, but they dialed our home DERP
        // 	// node in SF to reach us, so we can reply to them using our
        // 	// SF connection rather than dialing Frankfurt. (Issue 150)
        // 	if !peer.IsZero() && useDerpRoute() {
        // 		if r, ok := c.derpRoute[peer]; ok {
        // 			if ad, ok := c.activeDerp[r.derpID]; ok && ad.c == r.dc {
        // 				c.setPeerLastDerpLocked(peer, r.derpID, regionID)
        // 				*ad.lastWrite = time.Now()
        // 				return ad.writeCh
        // 			}
        // 		}
        // 	}

        // 	why := "home-keep-alive"
        // 	if !peer.IsZero() {
        // 		why = peer.ShortString()
        // 	}
        // 	c.logf("magicsock: adding connection to derp-%v for %v", regionID, why)

        // 	firstDerp := false
        // 	if c.activeDerp == nil {
        // 		firstDerp = true
        // 		c.activeDerp = make(map[int]activeDerp)
        // 		c.prevDerp = make(map[int]*syncs.WaitGroupChan)
        // 	}

        // 	// Note that derphttp.NewRegionClient does not dial the server
        // 	// (it doesn't block) so it is safe to do under the c.mu lock.
        // 	dc := derphttp.NewRegionClient(c.privateKey, c.logf, func() *tailcfg.DERPRegion {
        // 		// Warning: it is not legal to acquire
        // 		// magicsock.Conn.mu from this callback.
        // 		// It's run from derphttp.Client.connect (via Send, etc)
        // 		// and the lock ordering rules are that magicsock.Conn.mu
        // 		// must be acquired before derphttp.Client.mu.
        // 		// See https://github.com/tailscale/tailscale/issues/3726
        // 		if c.connCtx.Err() != nil {
        // 			// We're closing anyway; return nil to stop dialing.
        // 			return nil
        // 		}
        // 		derpMap := c.derpMapAtomic.Load()
        // 		if derpMap == nil {
        // 			return nil
        // 		}
        // 		return derpMap.Regions[regionID]
        // 	})

        // 	dc.SetCanAckPings(true)
        // 	dc.NotePreferred(c.myDerp == regionID)
        // 	dc.SetAddressFamilySelector(derpAddrFamSelector{c})
        // 	dc.DNSCache = dnscache.Get()

        // 	ctx, cancel := context.WithCancel(c.connCtx)
        // 	ch := make(chan derpWriteRequest, bufferedDerpWritesBeforeDrop)

        // 	ad.c = dc
        // 	ad.writeCh = ch
        // 	ad.cancel = cancel
        // 	ad.lastWrite = new(time.Time)
        // 	*ad.lastWrite = time.Now()
        // 	ad.createTime = time.Now()
        // 	c.activeDerp[regionID] = ad
        // 	metricNumDERPConns.Set(int64(len(c.activeDerp)))
        // 	c.logActiveDerpLocked()
        // 	c.setPeerLastDerpLocked(peer, regionID, regionID)
        // 	c.scheduleCleanStaleDerpLocked()

        // 	// Build a startGate for the derp reader+writer
        // 	// goroutines, so they don't start running until any
        // 	// previous generation is closed.
        // 	startGate := syncs.ClosedChan()
        // 	if prev := c.prevDerp[regionID]; prev != nil {
        // 		startGate = prev.DoneChan()
        // 	}
        // 	// And register a WaitGroup(Chan) for this generation.
        // 	wg := syncs.NewWaitGroupChan()
        // 	wg.Add(2)
        // 	c.prevDerp[regionID] = wg

        // 	if firstDerp {
        // 		startGate = c.derpStarted
        // 		go func() {
        // 			dc.Connect(ctx)
        // 			close(c.derpStarted)
        // 			c.muCond.Broadcast()
        // 		}()
        // 	}

        // 	go c.runDerpReader(ctx, addr, dc, wg, startGate)
        // 	go c.runDerpWriter(ctx, dc, ch, wg, startGate)
        // 	go c.derpActiveFunc()

        // 	return ad.writeCh
    }

    // /// Runs in a task for the life of a DERP connection, handling received packets.
    // fn run_derp_reader(&self, derp_fake_addr: SocketAddr, dc: derp::http::Client, /*wg *syncs.WaitGroupChan, startGate <-chan struct{}*/) {
    //     // TODO:
    //     // defer wg.Decr()
    //     // defer dc.Close()

    //     // TODO:
    //     // select {
    //     // case <-startGate:
    //     // case <-ctx.Done():
    //     // 	return
    //     // }

    //     let (did_copy_s, did_copy_r) = oneshot::channel();
    //     let region_id = usize::from(derp_fake_addr.port());
    //     let mut pkt = derp::ReceivedPacket;
    //     let mut res = DerpReadResult {
    //         region_id,
    //         n: 0,
    //         copy_buf: Box::new(|| |dst: &[u8]| -> usize {
    //             let n = pkt.data[..dst.len()].copy_from_slice(dst);
    //     	did_copy_s.send(());
    //     	return n
    //         })
    //     };

    //     // The set of senders we know are present on this connection, based on messages we've received from the server.

    //     let mut peer_present = map[key.node::PublicKey]bool{};
    //     // let bo = backoff.NewBackoff(fmt.Sprintf("derp-%d", regionID), c.logf, 5*time.Second);
    //     let mut  last_packet_time: Option<Instant> = None;
    //     let mut last_packet_src: Option<key:node::PublicKey> = None;

    //     loop {
    //         match dc.recv_detail().await {
    //             Err(err)=> {
    //     	    // Forget that all these peers have routes.
    //     	    for peer := range peerPresent {
    //     		delete(peerPresent, peer);
    //     		c.removeDerpPeerRoute(peer, regionID, dc);
    //     	    }
    //     	    if err == derphttp.ErrClientClosed {
    //     		return;
    //     	    }
    //     	    if c.networkDown() {
    //     		c.logf("[v1] magicsock: derp.Recv(derp-%d): network down, closing", regionID);
    //     		return;
    //     	    }
    //                 if ctx.done() {
    //                     return
    //                 }

    //     	    c.logf("magicsock: [%p] derp.Recv(derp-%d): %v", dc, regionID, err);

    //     	    // If our DERP connection broke, it might be because our network
    //     	    // conditions changed. Start that check.
    //     	    c.ReSTUN("derp-recv-error");

    //     	    // Back off a bit before reconnecting.
    //     	    bo.BackOff(ctx, err);

    //                 if ctx.Done() {
    //                     return;
    //                 }
    //     	}
    //             Ok(msg, conn_gen) => {
    //                 // reset
    //     	    bo.BackOff(ctx, nil);

    //     	    let now = time.Now();
    //     	    if lastPacketTime.IsZero() || now.Sub(lastPacketTime) > 5*time.Second {
    //     		health.NoteDERPRegionReceivedFrame(regionID);
    //     		lastPacketTime = now;
    //     	    }
    //                 match msg.typ {
    //     	        derp.ServerInfoMessage => {
    //     		    health.SetDERPRegionConnectedState(regionID, true);
    //     		    health.SetDERPRegionHealth(regionID, ""); // until declared otherwise
    //     		    c.logf("magicsock: derp-%d connected; connGen=%v", regionID, connGen);
    //     		    continue;
    //                     }
    //     	        derp.ReceivedPacket => {
    //     		    pkt = m;
    //     		    res.n = len(m.Data);
    //     		    res.src = m.Source;
    //     		    debug!("magicsock: got derp-%v packet: %q", regionID, m.Data);
    //     		    // If this is a new sender we hadn't seen before, remember it and
    //     		    // register a route for this peer.
    //     		    if res.src != lastPacketSrc { // avoid map lookup w/ high throughput single peer
    //     			lastPacketSrc = res.src;
    //     			if _, ok := peerPresent[res.src]; !ok {
    //     				peerPresent[res.src] = true;
    //     			    c.addDerpPeerRoute(res.src, regionID, dc);
    //     			}
    //     		    }
    //                     }
    //     	        derp.PingMessage => {
    //     		    // Best effort reply to the ping.
    //     		    pingData := [8]byte(m);
    //     		    go func() {
    //     			if err := dc.SendPong(pingData); err != nil {
    //     			    c.logf("magicsock: derp-%d SendPong error: %v", regionID, err);
    //     			}
    //     		    }();
    //     		    continue;
    //                     }
    //     	        derp.HealthMessage => {
    //     		    health.SetDERPRegionHealth(regionID, m.Problem);
    //                     }
    //     	        derp.PeerGoneMessage => {
    //     		    c.removeDerpPeerRoute(key.node::PublicKey(m), regionID, dc)
    //                     }
    //     	        _ => {
    //     		    // Ignore.
    //     		    continue;
    //     	        }
    //                 }

    //     	    tokio::select! {
    //     	        _ = ctx.Done() => {
    //     		    return;
    //                     }
    //     	        _ = c.derpRecvCh.send(res) => {
    //                     }
    //     	    }

    //     	    tokio::select! {
    //     	        _ = ctx.Done() => {
    //     		    return;
    //     	        }
    //                     case = did_copy => {
    //     		    continue
    //                     }
    //                 }
    //     	}
    //         }
    //     }
    // }

    // type derpWriteRequest struct {
    // 	addr   netip.AddrPort
    // 	pubKey key.node::PublicKey
    // 	b      []byte // copied; ownership passed to receiver
    // }

    // // runDerpWriter runs in a goroutine for the life of a DERP
    // // connection, handling received packets.
    // func (c *Conn) runDerpWriter(ctx context.Context, dc *derphttp.Client, ch <-chan derpWriteRequest, wg *syncs.WaitGroupChan, startGate <-chan struct{}) {
    // 	defer wg.Decr()
    // 	select {
    // 	case <-startGate:
    // 	case <-ctx.Done():
    // 		return
    // 	}

    // 	for {
    // 		select {
    // 		case <-ctx.Done():
    // 			return
    // 		case wr := <-ch:
    // 			err := dc.Send(wr.pubKey, wr.b)
    // 			if err != nil {
    // 				c.logf("magicsock: derp.Send(%v): %v", wr.addr, err)
    // 				metricSendDERPError.Add(1)
    // 			} else {
    // 				metricSendDERP.Add(1)
    // 			}
    // 		}
    // 	}
    // }

    // type receiveBatch struct {
    // 	msgs []ipv6.Message
    // }

    // func (c *Conn) getReceiveBatch() *receiveBatch {
    // 	batch := c.receiveBatchPool.Get().(*receiveBatch)
    // 	return batch
    // }

    // func (c *Conn) putReceiveBatch(batch *receiveBatch) {
    // 	for i := range batch.msgs {
    // 		batch.msgs[i] = ipv6.Message{Buffers: batch.msgs[i].Buffers}
    // 	}
    // 	c.receiveBatchPool.Put(batch)
    // }

    // func (c *Conn) receiveIPv6(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
    // 	health.ReceiveIPv6.Enter()
    // 	defer health.ReceiveIPv6.Exit()

    // 	batch := c.getReceiveBatch()
    // 	defer c.putReceiveBatch(batch)
    // 	for {
    // 		for i := range buffs {
    // 			batch.msgs[i].Buffers[0] = buffs[i]
    // 		}
    // 		numMsgs, err := c.pconn6.ReadBatch(batch.msgs, 0)
    // 		if err != nil {
    // 			if neterror.PacketWasTruncated(err) {
    // 				// TODO(raggi): discuss whether to log?
    // 				continue
    // 			}
    // 			return 0, err
    // 		}

    // 		reportToCaller := false
    // 		for i, msg := range batch.msgs[:numMsgs] {
    // 			ipp := msg.Addr.(*net.UDPAddr).AddrPort()
    // 			if ep, ok := c.receiveIP(msg.Buffers[0][:msg.N], ipp, &c.ippEndpoint6); ok {
    // 				metricRecvDataIPv6.Add(1)
    // 				eps[i] = ep
    // 				sizes[i] = msg.N
    // 				reportToCaller = true
    // 			} else {
    // 				sizes[i] = 0
    // 			}
    // 		}

    // 		if reportToCaller {
    // 			return numMsgs, nil
    // 		}
    // 	}
    // }

    // func (c *Conn) receiveIPv4(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
    // 	health.ReceiveIPv4.Enter()
    // 	defer health.ReceiveIPv4.Exit()

    // 	batch := c.getReceiveBatch()
    // 	defer c.putReceiveBatch(batch)
    // 	for {
    // 		for i := range buffs {
    // 			batch.msgs[i].Buffers[0] = buffs[i]
    // 		}
    // 		numMsgs, err := c.pconn4.ReadBatch(batch.msgs, 0)
    // 		if err != nil {
    // 			if neterror.PacketWasTruncated(err) {
    // 				// TODO(raggi): discuss whether to log?
    // 				continue
    // 			}
    // 			return 0, err
    // 		}

    // 		reportToCaller := false
    // 		for i, msg := range batch.msgs[:numMsgs] {
    // 			ipp := msg.Addr.(*net.UDPAddr).AddrPort()
    // 			if ep, ok := c.receiveIP(msg.Buffers[0][:msg.N], ipp, &c.ippEndpoint4); ok {
    // 				metricRecvDataIPv4.Add(1)
    // 				eps[i] = ep
    // 				sizes[i] = msg.N
    // 				reportToCaller = true
    // 			} else {
    // 				sizes[i] = 0
    // 			}
    // 		}
    // 		if reportToCaller {
    // 			return numMsgs, nil
    // 		}
    // 	}
    // }

    // // receiveIP is the shared bits of ReceiveIPv4 and ReceiveIPv6.
    // //
    // // ok is whether this read should be reported up to wireguard-go (our
    // // caller).
    // func (c *Conn) receiveIP(b []byte, ipp netip.AddrPort, cache *ippEndpointCache) (ep *endpoint, ok bool) {
    // 	if stun.Is(b) {
    // 		c.stunReceiveFunc.Load()(b, ipp)
    // 		return nil, false
    // 	}
    // 	if c.handleDiscoMessage(b, ipp, key.node::PublicKey{}) {
    // 		return nil, false
    // 	}
    // 	if !c.havePrivateKey.Load() {
    // 		// If we have no private key, we're logged out or
    // 		// stopped. Don't try to pass these wireguard packets
    // 		// up to wireguard-go; it'll just complain (issue 1167).
    // 		return nil, false
    // 	}
    // 	if cache.ipp == ipp && cache.de != nil && cache.gen == cache.de.numStopAndReset() {
    // 		ep = cache.de
    // 	} else {
    // 		c.mu.Lock()
    // 		de, ok := c.peerMap.endpointForIPPort(ipp)
    // 		c.mu.Unlock()
    // 		if !ok {
    // 			return nil, false
    // 		}
    // 		cache.ipp = ipp
    // 		cache.de = de
    // 		cache.gen = de.numStopAndReset()
    // 		ep = de
    // 	}
    // 	ep.noteRecvActivity()
    // 	if stats := c.stats.Load(); stats != nil {
    // 		stats.UpdateRxPhysical(ep.nodeAddr, ipp, len(b))
    // 	}
    // 	return ep, true
    // }

    // func (c *connBind) receiveDERP(buffs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
    // 	health.ReceiveDERP.Enter()
    // 	defer health.ReceiveDERP.Exit()

    // 	for dm := range c.derpRecvCh {
    // 		if c.Closed() {
    // 			break
    // 		}
    // 		n, ep := c.processDERPReadResult(dm, buffs[0])
    // 		if n == 0 {
    // 			// No data read occurred. Wait for another packet.
    // 			continue
    // 		}
    // 		metricRecvDataDERP.Add(1)
    // 		sizes[0] = n
    // 		eps[0] = ep
    // 		return 1, nil
    // 	}
    // 	return 0, net.ErrClosed
    // }

    // func (c *Conn) processDERPReadResult(dm derpReadResult, b []byte) (n int, ep *endpoint) {
    // 	if dm.copyBuf == nil {
    // 		return 0, nil
    // 	}
    // 	var regionID int
    // 	n, regionID = dm.n, dm.regionID
    // 	ncopy := dm.copyBuf(b)
    // 	if ncopy != n {
    // 		err := fmt.Errorf("received DERP packet of length %d that's too big for WireGuard buf size %d", n, ncopy)
    // 		c.logf("magicsock: %v", err)
    // 		return 0, nil
    // 	}

    // 	ipp := netip.AddrPortFrom(derpMagicIPAddr, uint16(regionID))
    // 	if c.handleDiscoMessage(b[:n], ipp, dm.src) {
    // 		return 0, nil
    // 	}

    // 	var ok bool
    // 	c.mu.Lock()
    // 	ep, ok = c.peerMap.endpointForNodeKey(dm.src)
    // 	c.mu.Unlock()
    // 	if !ok {
    // 		// We don't know anything about this node key, nothing to
    // 		// record or process.
    // 		return 0, nil
    // 	}

    // 	ep.noteRecvActivity()
    // 	if stats := c.stats.Load(); stats != nil {
    // 		stats.UpdateRxPhysical(ep.nodeAddr, ipp, dm.n)
    // 	}
    // 	return n, ep
    // }

    // // discoLogLevel controls the verbosity of discovery log messages.
    // type discoLogLevel int

    // const (
    // 	// discoLog means that a message should be logged.
    // 	discoLog discoLogLevel = iota

    // 	// discoVerboseLog means that a message should only be logged
    // 	// in TS_DEBUG_DISCO mode.
    // 	discoVerboseLog
    // )

    // // TS_DISCO_PONG_IPV4_DELAY, if set, is a time.Duration string that is how much
    // // fake latency to add before replying to disco pings. This can be used to bias
    // // peers towards using IPv6 when both IPv4 and IPv6 are available at similar
    // // speeds.
    // var debugIPv4DiscoPingPenalty = envknob.RegisterDuration("TS_DISCO_PONG_IPV4_DELAY")

    // // sendDiscoMessage sends discovery message m to dstDisco at dst.
    // //
    // // If dst is a DERP IP:port, then dstKey must be non-zero.
    // //
    // // The dstKey should only be non-zero if the dstDisco key
    // // unambiguously maps to exactly one peer.
    // func (c *Conn) sendDiscoMessage(dst netip.AddrPort, dstKey key.node::PublicKey, dstDisco key.DiscoPublic, m disco.Message, logLevel discoLogLevel) (sent bool, err error) {
    // 	isDERP := dst.Addr() == derpMagicIPAddr
    // 	if _, isPong := m.(*disco.Pong); isPong && !isDERP && dst.Addr().Is4() {
    // 		time.Sleep(debugIPv4DiscoPingPenalty())
    // 	}

    // 	c.mu.Lock()
    // 	if c.closed {
    // 		c.mu.Unlock()
    // 		return false, errConnClosed
    // 	}
    // 	var nonce [disco.NonceLen]byte
    // 	if _, err := crand.Read(nonce[:]); err != nil {
    // 		panic(err) // worth dying for
    // 	}
    // 	pkt := make([]byte, 0, 512) // TODO: size it correctly? pool? if it matters.
    // 	pkt = append(pkt, disco.Magic...)
    // 	pkt = c.discoPublic.AppendTo(pkt)
    // 	di := c.discoInfoLocked(dstDisco)
    // 	c.mu.Unlock()

    // 	if isDERP {
    // 		metricSendDiscoDERP.Add(1)
    // 	} else {
    // 		metricSendDiscoUDP.Add(1)
    // 	}

    // 	box := di.sharedKey.Seal(m.AppendMarshal(nil))
    // 	pkt = append(pkt, box...)
    // 	sent, err = c.sendAddr(dst, dstKey, pkt)
    // 	if sent {
    // 		if logLevel == discoLog || (logLevel == discoVerboseLog && debugDisco()) {
    // 			node := "?"
    // 			if !dstKey.IsZero() {
    // 				node = dstKey.ShortString()
    // 			}
    // 			c.dlogf("[v1] magicsock: disco: %v->%v (%v, %v) sent %v", c.discoShort, dstDisco.ShortString(), node, derpStr(dst.String()), disco.MessageSummary(m))
    // 		}
    // 		if isDERP {
    // 			metricSentDiscoDERP.Add(1)
    // 		} else {
    // 			metricSentDiscoUDP.Add(1)
    // 		}
    // 		switch m.(type) {
    // 		case *disco.Ping:
    // 			metricSentDiscoPing.Add(1)
    // 		case *disco.Pong:
    // 			metricSentDiscoPong.Add(1)
    // 		case *disco.CallMeMaybe:
    // 			metricSentDiscoCallMeMaybe.Add(1)
    // 		}
    // 	} else if err == nil {
    // 		// Can't send. (e.g. no IPv6 locally)
    // 	} else {
    // 		if !c.networkDown() {
    // 			c.logf("magicsock: disco: failed to send %T to %v: %v", m, dst, err)
    // 		}
    // 	}
    // 	return sent, err
    // }

    // // handleDiscoMessage handles a discovery message and reports whether
    // // msg was a Tailscale inter-node discovery message.
    // //
    // // A discovery message has the form:
    // //
    // //   - magic             [6]byte
    // //   - senderDiscoPubKey [32]byte
    // //   - nonce             [24]byte
    // //   - naclbox of payload (see tailscale.com/disco package for inner payload format)
    // //
    // // For messages received over DERP, the src.Addr() will be derpMagicIP (with
    // // src.Port() being the region ID) and the derpNodeSrc will be the node key
    // // it was received from at the DERP layer. derpNodeSrc is zero when received
    // // over UDP.
    // func (c *Conn) handleDiscoMessage(msg []byte, src netip.AddrPort, derpNodeSrc key.node::PublicKey) (isDiscoMsg bool) {
    // 	const headerLen = len(disco.Magic) + key.DiscoPublicRawLen
    // 	if len(msg) < headerLen || string(msg[:len(disco.Magic)]) != disco.Magic {
    // 		return false
    // 	}

    // 	// If the first four parts are the prefix of disco.Magic
    // 	// (0x5453f09f) then it's definitely not a valid WireGuard
    // 	// packet (which starts with little-endian uint32 1, 2, 3, 4).
    // 	// Use naked returns for all following paths.
    // 	isDiscoMsg = true

    // 	sender := key.DiscoPublicFromRaw32(mem.B(msg[len(disco.Magic):headerLen]))

    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	if c.closed {
    // 		return
    // 	}
    // 	if debugDisco() {
    // 		c.logf("magicsock: disco: got disco-looking frame from %v", sender.ShortString())
    // 	}
    // 	if c.privateKey.IsZero() {
    // 		// Ignore disco messages when we're stopped.
    // 		// Still return true, to not pass it down to wireguard.
    // 		return
    // 	}
    // 	if c.discoPrivate.IsZero() {
    // 		if debugDisco() {
    // 			c.logf("magicsock: disco: ignoring disco-looking frame, no local key")
    // 		}
    // 		return
    // 	}

    // 	if !c.peerMap.anyEndpointForDiscoKey(sender) {
    // 		metricRecvDiscoBadPeer.Add(1)
    // 		if debugDisco() {
    // 			c.logf("magicsock: disco: ignoring disco-looking frame, don't know endpoint for %v", sender.ShortString())
    // 		}
    // 		return
    // 	}

    // 	// We're now reasonably sure we're expecting communication from
    // 	// this peer, do the heavy crypto lifting to see what they want.
    // 	//
    // 	// From here on, peerNode and de are non-nil.

    // 	di := c.discoInfoLocked(sender)

    // 	sealedBox := msg[headerLen:]
    // 	payload, ok := di.sharedKey.Open(sealedBox)
    // 	if !ok {
    // 		// This might be have been intended for a previous
    // 		// disco key.  When we restart we get a new disco key
    // 		// and old packets might've still been in flight (or
    // 		// scheduled). This is particularly the case for LANs
    // 		// or non-NATed endpoints.
    // 		// Don't log in normal case. Pass on to wireguard, in case
    // 		// it's actually a wireguard packet (super unlikely,
    // 		// but).
    // 		if debugDisco() {
    // 			c.logf("magicsock: disco: failed to open naclbox from %v (wrong rcpt?)", sender)
    // 		}
    // 		metricRecvDiscoBadKey.Add(1)
    // 		return
    // 	}

    // 	dm, err := disco.Parse(payload)
    // 	if debugDisco() {
    // 		c.logf("magicsock: disco: disco.Parse = %T, %v", dm, err)
    // 	}
    // 	if err != nil {
    // 		// Couldn't parse it, but it was inside a correctly
    // 		// signed box, so just ignore it, assuming it's from a
    // 		// newer version of Tailscale that we don't
    // 		// understand. Not even worth logging about, lest it
    // 		// be too spammy for old clients.
    // 		metricRecvDiscoBadParse.Add(1)
    // 		return
    // 	}

    // 	isDERP := src.Addr() == derpMagicIPAddr
    // 	if isDERP {
    // 		metricRecvDiscoDERP.Add(1)
    // 	} else {
    // 		metricRecvDiscoUDP.Add(1)
    // 	}

    // 	switch dm := dm.(type) {
    // 	case *disco.Ping:
    // 		metricRecvDiscoPing.Add(1)
    // 		c.handlePingLocked(dm, src, di, derpNodeSrc)
    // 	case *disco.Pong:
    // 		metricRecvDiscoPong.Add(1)
    // 		// There might be multiple nodes for the sender's DiscoKey.
    // 		// Ask each to handle it, stopping once one reports that
    // 		// the Pong's TxID was theirs.
    // 		c.peerMap.forEachEndpointWithDiscoKey(sender, func(ep *endpoint) (keepGoing bool) {
    // 			if ep.handlePongConnLocked(dm, di, src) {
    // 				return false
    // 			}
    // 			return true
    // 		})
    // 	case *disco.CallMeMaybe:
    // 		metricRecvDiscoCallMeMaybe.Add(1)
    // 		if !isDERP || derpNodeSrc.IsZero() {
    // 			// CallMeMaybe messages should only come via DERP.
    // 			c.logf("[unexpected] CallMeMaybe packets should only come via DERP")
    // 			return
    // 		}
    // 		nodeKey := derpNodeSrc
    // 		ep, ok := c.peerMap.endpointForNodeKey(nodeKey)
    // 		if !ok {
    // 			metricRecvDiscoCallMeMaybeBadNode.Add(1)
    // 			c.logf("magicsock: disco: ignoring CallMeMaybe from %v; %v is unknown", sender.ShortString(), derpNodeSrc.ShortString())
    // 			return
    // 		}
    // 		if ep.discoKey != di.discoKey {
    // 			metricRecvDiscoCallMeMaybeBadDisco.Add(1)
    // 			c.logf("[unexpected] CallMeMaybe from peer via DERP whose netmap discokey != disco source")
    // 			return
    // 		}
    // 		di.setNodeKey(nodeKey)
    // 		c.dlogf("[v1] magicsock: disco: %v<-%v (%v, %v)  got call-me-maybe, %d endpoints",
    // 			c.discoShort, ep.discoShort,
    // 			ep.publicKey.ShortString(), derpStr(src.String()),
    // 			len(dm.MyNumber))
    // 		go ep.handleCallMeMaybe(dm)
    // 	}
    // 	return
    // }

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

    // // di is the discoInfo of the source of the ping.
    // // derpNodeSrc is non-zero if the ping arrived via DERP.
    // func (c *Conn) handlePingLocked(dm *disco.Ping, src netip.AddrPort, di *discoInfo, derpNodeSrc key.node::PublicKey) {
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
    // }

    // // enqueueCallMeMaybe schedules a send of disco.CallMeMaybe to de via derpAddr
    // // once we know that our STUN endpoint is fresh.
    // //
    // // derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
    // // flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
    // // If they do, traffic will just go over DERP for a bit longer until the next
    // // discovery round.
    // func (c *Conn) enqueueCallMeMaybe(derpAddr netip.AddrPort, de *endpoint) {
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
    // }

    // // discoInfoLocked returns the previous or new discoInfo for k.
    // //
    // // c.mu must be held.
    // func (c *Conn) discoInfoLocked(k key.DiscoPublic) *discoInfo {
    // 	di, ok := c.discoInfo[k]
    // 	if !ok {
    // 		di = &discoInfo{
    // 			discoKey:   k,
    // 			discoShort: k.ShortString(),
    // 			sharedKey:  c.discoPrivate.Shared(k),
    // 		}
    // 		c.discoInfo[k] = di
    // 	}
    // 	return di
    // }

    // func (c *Conn) SetNetworkUp(up bool) {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()
    // 	if c.networkUp.Load() == up {
    // 		return
    // 	}

    // 	c.logf("magicsock: SetNetworkUp(%v)", up)
    // 	c.networkUp.Store(up)

    // 	if up {
    // 		c.startDerpHomeConnectLocked()
    // 	} else {
    // 		c.portMapper.NoteNetworkDown()
    // 		c.closeAllDerpLocked("network-down")
    // 	}
    // }

    // // SetPreferredPort sets the connection's preferred local port.
    // func (c *Conn) SetPreferredPort(port uint16) {
    // 	if uint16(c.port.Load()) == port {
    // 		return
    // 	}
    // 	c.port.Store(uint32(port))

    // 	if err := c.rebind(dropCurrentPort); err != nil {
    // 		c.logf("%w", err)
    // 		return
    // 	}
    // 	c.resetEndpointStates()
    // }

    // // SetPrivateKey sets the connection's private key.
    // //
    // // This is only used to be able prove our identity when connecting to
    // // DERP servers.
    // //
    // // If the private key changes, any DERP connections are torn down &
    // // recreated when needed.
    // func (c *Conn) SetPrivateKey(privateKey key.NodePrivate) error {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	oldKey, newKey := c.privateKey, privateKey
    // 	if newKey.Equal(oldKey) {
    // 		return nil
    // 	}
    // 	c.privateKey = newKey
    // 	c.havePrivateKey.Store(!newKey.IsZero())

    // 	if newKey.IsZero() {
    // 		c.publicKeyAtomic.Store(key.node::PublicKey{})
    // 	} else {
    // 		c.publicKeyAtomic.Store(newKey.Public())
    // 	}

    // 	if oldKey.IsZero() {
    // 		c.everHadKey = true
    // 		c.logf("magicsock: SetPrivateKey called (init)")
    // 		go c.ReSTUN("set-private-key")
    // 	} else if newKey.IsZero() {
    // 		c.logf("magicsock: SetPrivateKey called (zeroed)")
    // 		c.closeAllDerpLocked("zero-private-key")
    // 		c.stopPeriodicReSTUNTimerLocked()
    // 		c.onEndpointRefreshed = nil
    // 	} else {
    // 		c.logf("magicsock: SetPrivateKey called (changed)")
    // 		c.closeAllDerpLocked("new-private-key")
    // 	}

    // 	// Key changed. Close existing DERP connections and reconnect to home.
    // 	if c.myDerp != 0 && !newKey.IsZero() {
    // 		c.logf("magicsock: private key changed, reconnecting to home derp-%d", c.myDerp)
    // 		c.startDerpHomeConnectLocked()
    // 	}

    // 	if newKey.IsZero() {
    // 		c.peerMap.forEachEndpoint(func(ep *endpoint) {
    // 			ep.stopAndReset()
    // 		})
    // 	}

    // 	return nil
    // }

    // // UpdatePeers is called when the set of WireGuard peers changes. It
    // // then removes any state for old peers.
    // //
    // // The caller passes ownership of newPeers map to UpdatePeers.
    // func (c *Conn) UpdatePeers(newPeers map[key.node::PublicKey]struct{}) {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	oldPeers := c.peerSet
    // 	c.peerSet = newPeers

    // 	// Clean up any key.node::PublicKey-keyed maps for peers that no longer
    // 	// exist.
    // 	for peer := range oldPeers {
    // 		if _, ok := newPeers[peer]; !ok {
    // 			delete(c.derpRoute, peer)
    // 			delete(c.peerLastDerp, peer)
    // 		}
    // 	}

    // 	if len(oldPeers) == 0 && len(newPeers) > 0 {
    // 		go c.ReSTUN("non-zero-peers")
    // 	}
    // }

    // // SetDERPMap controls which (if any) DERP servers are used.
    // // A nil value means to disable DERP; it's disabled by default.
    // func (c *Conn) SetDERPMap(dm *tailcfg.DERPMap) {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	if reflect.DeepEqual(dm, c.derpMap) {
    // 		return
    // 	}

    // 	c.derpMapAtomic.Store(dm)
    // 	old := c.derpMap
    // 	c.derpMap = dm
    // 	if dm == nil {
    // 		c.closeAllDerpLocked("derp-disabled")
    // 		return
    // 	}

    // 	// Reconnect any DERP region that changed definitions.
    // 	if old != nil {
    // 		changes := false
    // 		for rid, oldDef := range old.Regions {
    // 			if reflect.DeepEqual(oldDef, dm.Regions[rid]) {
    // 				continue
    // 			}
    // 			changes = true
    // 			if rid == c.myDerp {
    // 				c.myDerp = 0
    // 			}
    // 			c.closeDerpLocked(rid, "derp-region-redefined")
    // 		}
    // 		if changes {
    // 			c.logActiveDerpLocked()
    // 		}
    // 	}

    // 	go c.ReSTUN("derp-map-update")
    // }

    // func nodesEqual(x, y []*tailcfg.Node) bool {
    // 	if len(x) != len(y) {
    // 		return false
    // 	}
    // 	for i := range x {
    // 		if !x[i].Equal(y[i]) {
    // 			return false
    // 		}
    // 	}
    // 	return true
    // }

    // // SetNetworkMap is called when the control client gets a new network
    // // map from the control server. It must always be non-nil.
    // //
    // // It should not use the DERPMap field of NetworkMap; that's
    // // conditionally sent to SetDERPMap instead.
    // func (c *Conn) SetNetworkMap(nm *netmap.NetworkMap) {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	if c.closed {
    // 		return
    // 	}

    // 	priorNetmap := c.netMap
    // 	var priorDebug *tailcfg.Debug
    // 	if priorNetmap != nil {
    // 		priorDebug = priorNetmap.Debug
    // 	}
    // 	debugChanged := !reflect.DeepEqual(priorDebug, nm.Debug)
    // 	metricNumPeers.Set(int64(len(nm.Peers)))

    // 	// Update c.netMap regardless, before the following early return.
    // 	c.netMap = nm

    // 	if priorNetmap != nil && nodesEqual(priorNetmap.Peers, nm.Peers) && !debugChanged {
    // 		// The rest of this function is all adjusting state for peers that have
    // 		// changed. But if the set of peers is equal and the debug flags (for
    // 		// silent disco) haven't changed, no need to do anything else.
    // 		return
    // 	}

    // 	c.logf("[v1] magicsock: got updated network map; %d peers", len(nm.Peers))
    // 	heartbeatDisabled := debugEnableSilentDisco() || (c.netMap != nil && c.netMap.Debug != nil && c.netMap.Debug.EnableSilentDisco)

    // 	// Try a pass of just upserting nodes and creating missing
    // 	// endpoints. If the set of nodes is the same, this is an
    // 	// efficient alloc-free update. If the set of nodes is different,
    // 	// we'll fall through to the next pass, which allocates but can
    // 	// handle full set updates.
    // 	for _, n := range nm.Peers {
    // 		if ep, ok := c.peerMap.endpointForNodeKey(n.Key); ok {
    // 			if n.DiscoKey.IsZero() {
    // 				// Discokey transitioned from non-zero to zero? Ignore. Server's confused.
    // 				c.peerMap.deleteEndpoint(ep)
    // 				continue
    // 			}
    // 			oldDiscoKey := ep.discoKey
    // 			ep.updateFromNode(n, heartbeatDisabled)
    // 			c.peerMap.upsertEndpoint(ep, oldDiscoKey) // maybe update discokey mappings in peerMap
    // 			continue
    // 		}
    // 		if n.DiscoKey.IsZero() {
    // 			// Ancient pre-0.100 node. Ignore, so we can assume elsewhere in magicsock
    // 			// that all nodes have a DiscoKey.
    // 			continue
    // 		}

    // 		ep := &endpoint{
    // 			c:                 c,
    // 			publicKey:         n.Key,
    // 			publicKeyHex:      n.Key.UntypedHexString(),
    // 			sentPing:          map[stun.TxID]sentPing{},
    // 			endpointState:     map[netip.AddrPort]*endpointState{},
    // 			heartbeatDisabled: heartbeatDisabled,
    // 		}
    // 		if len(n.Addresses) > 0 {
    // 			ep.nodeAddr = n.Addresses[0].Addr()
    // 		}
    // 		ep.discoKey = n.DiscoKey
    // 		ep.discoShort = n.DiscoKey.ShortString()
    // 		ep.initFakeUDPAddr()
    // 		if debugDisco() { // rather than making a new knob
    // 			c.logf("magicsock: created endpoint key=%s: disco=%s; %v", n.Key.ShortString(), n.DiscoKey.ShortString(), logger.ArgWriter(func(w *bufio.Writer) {
    // 				const derpPrefix = "127.3.3.40:"
    // 				if strings.HasPrefix(n.DERP, derpPrefix) {
    // 					ipp, _ := netip.ParseAddrPort(n.DERP)
    // 					regionID := int(ipp.Port())
    // 					code := c.derpRegionCodeLocked(regionID)
    // 					if code != "" {
    // 						code = "(" + code + ")"
    // 					}
    // 					fmt.Fprintf(w, "derp=%v%s ", regionID, code)
    // 				}

    // 				for _, a := range n.AllowedIPs {
    // 					if a.IsSingleIP() {
    // 						fmt.Fprintf(w, "aip=%v ", a.Addr())
    // 					} else {
    // 						fmt.Fprintf(w, "aip=%v ", a)
    // 					}
    // 				}
    // 				for _, ep := range n.Endpoints {
    // 					fmt.Fprintf(w, "ep=%v ", ep)
    // 				}
    // 			}))
    // 		}
    // 		ep.updateFromNode(n, heartbeatDisabled)
    // 		c.peerMap.upsertEndpoint(ep, key.DiscoPublic{})
    // 	}

    // 	// If the set of nodes changed since the last SetNetworkMap, the
    // 	// upsert loop just above made c.peerMap contain the union of the
    // 	// old and new peers - which will be larger than the set from the
    // 	// current netmap. If that happens, go through the allocful
    // 	// deletion path to clean up moribund nodes.
    // 	if c.peerMap.nodeCount() != len(nm.Peers) {
    // 		keep := make(map[key.node::PublicKey]bool, len(nm.Peers))
    // 		for _, n := range nm.Peers {
    // 			keep[n.Key] = true
    // 		}
    // 		c.peerMap.forEachEndpoint(func(ep *endpoint) {
    // 			if !keep[ep.publicKey] {
    // 				c.peerMap.deleteEndpoint(ep)
    // 			}
    // 		})
    // 	}

    // 	// discokeys might have changed in the above. Discard unused info.
    // 	for dk := range c.discoInfo {
    // 		if !c.peerMap.anyEndpointForDiscoKey(dk) {
    // 			delete(c.discoInfo, dk)
    // 		}
    // 	}
    // }

    fn want_derp_locked(&self, state: &mut ConnState) -> bool {
        state.derp_map.is_some()
    }

    // // c.mu must be held.
    // func (c *Conn) closeAllDerpLocked(why string) {
    // 	if len(c.activeDerp) == 0 {
    // 		return // without the useless log statement
    // 	}
    // 	for i := range c.activeDerp {
    // 		c.closeDerpLocked(i, why)
    // 	}
    // 	c.logActiveDerpLocked()
    // }

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
        self.close_derp_locked(region_id, why, state);
        if state.private_key.is_some() && state.my_derp == region_id {
            self.start_derp_home_connect_locked(state);
        }
    }

    /// It is the responsibility of the caller to call `log_active_derp_locked` after any set of closes.
    fn close_derp_locked(&self, region_id: usize, why: &'static str, state: &mut ConnState) {
        if let Some(ad) = state.active_derp.remove(&region_id) {
            debug!(
                "closing connection to derp-{} ({:?}), age {}s",
                region_id,
                why,
                ad.create_time.elapsed().as_secs()
            );
            // TODO:
            // tokio::task::spawn(ad.c.close());
            // ad.cancel();

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

    // func (c *Conn) cleanStaleDerp() {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()
    // 	if c.closed {
    // 		return
    // 	}
    // 	c.derpCleanupTimerArmed = false

    // 	tooOld := time.Now().Add(-derpInactiveCleanupTime)
    // 	dirty := false
    // 	someNonHomeOpen := false
    // 	for i, ad := range c.activeDerp {
    // 		if i == c.myDerp {
    // 			continue
    // 		}
    // 		if ad.lastWrite.Before(tooOld) {
    // 			c.closeDerpLocked(i, "idle")
    // 			dirty = true
    // 		} else {
    // 			someNonHomeOpen = true
    // 		}
    // 	}
    // 	if dirty {
    // 		c.logActiveDerpLocked()
    // 	}
    // 	if someNonHomeOpen {
    // 		c.scheduleCleanStaleDerpLocked()
    // 	}
    // }

    // func (c *Conn) scheduleCleanStaleDerpLocked() {
    // 	if c.derpCleanupTimerArmed {
    // 		// Already going to fire soon. Let the existing one
    // 		// fire lest it get infinitely delayed by repeated
    // 		// calls to scheduleCleanStaleDerpLocked.
    // 		return
    // 	}
    // 	c.derpCleanupTimerArmed = true
    // 	if c.derpCleanupTimer != nil {
    // 		c.derpCleanupTimer.Reset(derpCleanStaleInterval)
    // 	} else {
    // 		c.derpCleanupTimer = time.AfterFunc(derpCleanStaleInterval, c.cleanStaleDerp)
    // 	}
    // }

    // // DERPs reports the number of active DERP connections.
    // func (c *Conn) DERPs() int {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	return len(c.activeDerp)
    // }

    // func (c *Conn) derpRegionCodeOfAddrLocked(ipPort string) string {
    // 	_, portStr, err := net.SplitHostPort(ipPort)
    // 	if err != nil {
    // 		return ""
    // 	}
    // 	regionID, err := strconv.Atoi(portStr)
    // 	if err != nil {
    // 		return ""
    // 	}
    // 	return c.derpRegionCodeOfIDLocked(regionID)
    // }

    // func (c *Conn) derpRegionCodeOfIDLocked(regionID int) string {
    // 	if c.derpMap == nil {
    // 		return ""
    // 	}
    // 	if r, ok := c.derpMap.Regions[regionID]; ok {
    // 		return r.RegionCode
    // 	}
    // 	return ""
    // }

    // func (c *Conn) UpdateStatus(sb *ipnstate.StatusBuilder) {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()

    // 	var tailscaleIPs []netip.Addr
    // 	if c.netMap != nil {
    // 		tailscaleIPs = make([]netip.Addr, 0, len(c.netMap.Addresses))
    // 		for _, addr := range c.netMap.Addresses {
    // 			if !addr.IsSingleIP() {
    // 				continue
    // 			}
    // 			sb.AddTailscaleIP(addr.Addr())
    // 			tailscaleIPs = append(tailscaleIPs, addr.Addr())
    // 		}
    // 	}

    // 	sb.MutateSelfStatus(func(ss *ipnstate.PeerStatus) {
    // 		if !c.privateKey.IsZero() {
    // 			ss.PublicKey = c.privateKey.Public()
    // 		} else {
    // 			ss.PublicKey = key.node::PublicKey{}
    // 		}
    // 		ss.Addrs = make([]string, 0, len(c.lastEndpoints))
    // 		for _, ep := range c.lastEndpoints {
    // 			ss.Addrs = append(ss.Addrs, ep.Addr.String())
    // 		}
    // 		ss.OS = version.OS()
    // 		if c.derpMap != nil {
    // 			derpRegion, ok := c.derpMap.Regions[c.myDerp]
    // 			if ok {
    // 				ss.Relay = derpRegion.RegionCode
    // 			}
    // 		}
    // 		ss.TailscaleIPs = tailscaleIPs
    // 	})

    // 	if sb.WantPeers {
    // 		c.peerMap.forEachEndpoint(func(ep *endpoint) {
    // 			ps := &ipnstate.PeerStatus{InMagicSock: true}
    // 			//ps.Addrs = append(ps.Addrs, n.Endpoints...)
    // 			ep.populatePeerStatus(ps)
    // 			sb.AddPeer(ep.publicKey, ps)
    // 		})
    // 	}

    // 	c.foreachActiveDerpSortedLocked(func(node int, ad activeDerp) {
    // 		// TODO(bradfitz): add to ipnstate.StatusBuilder
    // 		//f("<li><b>derp-%v</b>: cr%v,wr%v</li>", node, simpleDur(now.Sub(ad.createTime)), simpleDur(now.Sub(*ad.lastWrite)))
    // 	})
    // }

    // // SetStatistics specifies a per-connection statistics aggregator.
    // // Nil may be specified to disable statistics gathering.
    // func (c *Conn) SetStatistics(stats *connstats.Statistics) {
    // 	c.stats.Store(stats)
    // }

    // // Close closes the connection.
    // //
    // // Only the first close does anything. Any later closes return nil.
    // func (c *Conn) Close() error {
    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()
    // 	if c.closed {
    // 		return nil
    // 	}
    // 	c.closing.Store(true)
    // 	if c.derpCleanupTimerArmed {
    // 		c.derpCleanupTimer.Stop()
    // 	}
    // 	c.stopPeriodicReSTUNTimerLocked()
    // 	c.portMapper.Close()

    // 	c.peerMap.forEachEndpoint(func(ep *endpoint) {
    // 		ep.stopAndReset()
    // 	})

    // 	c.closed = true
    // 	c.connCtxCancel()
    // 	c.closeAllDerpLocked("conn-close")
    // 	// Ignore errors from c.pconnN.Close.
    // 	// They will frequently have been closed already by a call to connBind.Close.
    // 	c.pconn6.Close()
    // 	c.pconn4.Close()

    // 	// Wait on goroutines updating right at the end, once everything is
    // 	// already closed. We want everything else in the Conn to be
    // 	// consistently in the closed state before we release mu to wait
    // 	// on the endpoint updater & derphttp.Connect.
    // 	for c.goroutinesRunningLocked() {
    // 		c.muCond.Wait()
    // 	}
    // 	return nil
    // }

    // func (c *Conn) goroutinesRunningLocked() bool {
    // 	if c.endpointsUpdateActive {
    // 		return true
    // 	}
    // 	// The goroutine running dc.Connect in derpWriteChanOfAddr may linger
    // 	// and appear to leak, as observed in https://github.com/tailscale/tailscale/issues/554.
    // 	// This is despite the underlying context being cancelled by connCtxCancel above.
    // 	// To avoid this condition, we must wait on derpStarted here
    // 	// to ensure that this goroutine has exited by the time Close returns.
    // 	// We only do this if derpWriteChanOfAddr has executed at least once:
    // 	// on the first run, it sets firstDerp := true and spawns the aforementioned goroutine.
    // 	// To detect this, we check activeDerp, which is initialized to non-nil on the first run.
    // 	if c.activeDerp != nil {
    // 		select {
    // 		case <-c.derpStarted:
    // 			break
    // 		default:
    // 			return true
    // 		}
    // 	}
    // 	return false
    // }

    // func maxIdleBeforeSTUNShutdown() time.Duration {
    // 	if debugReSTUNStopOnIdle() {
    // 		return 45 * time.Second
    // 	}
    // 	return sessionActiveTimeout
    // }

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
        let mut ruc = ruc.0.write().await;

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
            if let Some(cur_addr) = ruc.local_addr() {
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

    // // packIPPort packs an IPPort into the form wanted by WireGuard.
    // func packIPPort(ua netip.AddrPort) []byte {
    // 	ip := ua.Addr().Unmap()
    // 	a := ip.As16()
    // 	ipb := a[:]
    // 	if ip.Is4() {
    // 		ipb = ipb[12:]
    // 	}
    // 	b := make([]byte, 0, len(ipb)+2)
    // 	b = append(b, ipb...)
    // 	b = append(b, byte(ua.Port()))
    // 	b = append(b, byte(ua.Port()>>8))
    // 	return b
    // }

    // // ParseEndpoint is called by WireGuard to connect to an endpoint.
    // func (c *Conn) ParseEndpoint(nodeKeyStr string) (conn.Endpoint, error) {
    // 	k, err := key.Parsenode::PublicKeyUntyped(mem.S(nodeKeyStr))
    // 	if err != nil {
    // 		return nil, fmt.Errorf("magicsock: ParseEndpoint: parse failed on %q: %w", nodeKeyStr, err)
    // 	}

    // 	c.mu.Lock()
    // 	defer c.mu.Unlock()
    // 	if c.closed {
    // 		return nil, errConnClosed
    // 	}
    // 	ep, ok := c.peerMap.endpointForNodeKey(k)
    // 	if !ok {
    // 		// We should never be telling WireGuard about a new peer
    // 		// before magicsock knows about it.
    // 		c.logf("[unexpected] magicsock: ParseEndpoint: unknown node key=%s", k.ShortString())
    // 		return nil, fmt.Errorf("magicsock: ParseEndpoint: unknown peer %q", k.ShortString())
    // 	}

    // 	return ep, nil
    // }
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
struct DiscoInfo {
    /// The same as the Conn.discoInfo map key, just so you can pass around a `DiscoInfo` alone.
    /// Not modified once initialized.
    disco_key: key::disco::PublicKey,

    /// The precomputed key for communication with the peer that has the `DiscoKey` used to
    /// look up this `DiscoInfo` in Conn.discoInfo.
    /// Not modified once initialized.
    shared_key: key::disco::SharedSecret,

    // Mutable fields follow, owned by Conn.mu:
    /// Tthe src of a ping for `DiscoKey`.
    last_ping_from: SocketAddr,

    /// The last time of a ping for discoKey.
    last_ping_time: Instant,

    /// The last NodeKey seen using `DiscoKey`.
    /// It's only updated if the NodeKey is unambiguous.
    last_node_key: key::node::PublicKey,

    /// The time a NodeKey was last seen using this `DiscoKey`. It's only updated if the
    /// NodeKey is unambiguous.
    last_node_key_time: Instant,
}

// // setNodeKey sets the most recent mapping from di.discoKey to the
// // NodeKey nk.
// func (di *discoInfo) setNodeKey(nk key.node::PublicKey) {
// 	di.lastNodeKey = nk
// 	di.lastNodeKeyTime = time.Now()
// }

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

/// The type sent by runDerpClient to ReceiveIPv4when a DERP packet is available.
///
/// Notably, it doesn't include the derp.ReceivedPacket because we
/// don't want to give the receiver access to the aliased []byte.  To
/// get at the packet contents they need to call copyBuf to copy it
/// out, which also releases the buffer.
struct DerpReadResult {
    region_id: usize,
    /// length of data received
    n: usize,
    src: key::node::PublicKey,
    /// Called to copy the data to dst. It returns how much data was copied,
    /// which will be `n` if `dst` is large enough.
    /// If copy_buf is `None`, that's a signal from the sender to ignore this message.
    copy_buf: Option<Box<dyn FnOnce(&[u8]) -> usize>>,
}
