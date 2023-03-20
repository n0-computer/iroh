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
use futures::{future::BoxFuture, Future};
use quinn::AsyncUdpSocket;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tokio::{
    sync::{self, Mutex, RwLock},
    task::JoinHandle,
    time,
};
use tracing::{debug, info, instrument, warn};

use crate::{
    hp::{
        cfg::{self, DERP_MAGIC_IP},
        derp::{self, DerpMap},
        disco, key,
        magicsock::SESSION_ACTIVE_TIMEOUT,
        monitor, netcheck, netmap, portmapper, stun,
    },
    net::LocalAddresses,
};

use super::{
    endpoint::PeerMap, rebinding_conn::RebindingUdpConn, Endpoint, Timer,
    DERP_CLEAN_STALE_INTERVAL, DERP_INACTIVE_CLEANUP_TIME, ENDPOINTS_FRESH_ENOUGH_DURATION,
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
            on_note_recv_activity: None,
            link_monitor: None,
            private_key: key::node::SecretKey::generate(),
        }
    }
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
    name: String,
    on_endpoints: Option<Box<dyn Fn(&[cfg::Endpoint]) + Send + Sync + 'static>>,
    on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,
    idle_for: Option<Box<dyn Fn() -> Duration + Send + Sync + 'static>>,
    pub(super) on_note_recv_activity:
        Option<Box<dyn Fn(&key::node::PublicKey) + Send + Sync + 'static>>,
    link_monitor: Option<monitor::Monitor>,
    /// A callback that provides a `cfg::NetInfo` when discovered network conditions change.
    on_net_info: Option<Box<dyn Fn(cfg::NetInfo) + Send + Sync + 'static>>,

    // TODO
    // connCtx:       context.Context, // closed on Conn.Close
    // connCtxCancel: func(),          // closes connCtx

    // The underlying UDP sockets used to send/rcv packets for wireguard and other magicsock protocols.
    pconn4: RebindingUdpConn,
    pconn6: Option<RebindingUdpConn>,

    // TODO:
    // closeDisco4 and closeDisco6 are io.Closers to shut down the raw
    // disco packet receivers. If None, no raw disco receiver is running for the given family.
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

    pub(super) public_key: key::node::PublicKey,
    last_net_check_report: RwLock<Option<Arc<netcheck::Report>>>,

    /// Preferred port from opts.Port; 0 means auto.
    port: AtomicU16,

    state: Mutex<ConnState>,
    /// Close is in progress (or done)
    closing: AtomicBool,

    /// None (or zero regions/nodes) means DERP is disabled.
    /// Tracked outside to avoid deadlock issues (replaces atomic acess from go)
    derp_map: RwLock<Option<DerpMap>>,

    /// Tracks the networkmap Node entity for each peer discovery key.
    pub(super) peer_map: RwLock<PeerMap>,
}

#[derive(Debug, Default)]
struct EndpointUpdateState {
    /// If running, set to the task handle of the update.
    running: Option<JoinHandle<()>>,
    want_update: Option<&'static str>,
}

impl EndpointUpdateState {
    /// Returns `true` if an update is currently in progress.
    fn is_running(&self) -> bool {
        match self.running {
            Some(ref handle) => !handle.is_finished(),
            None => false,
        }
    }
}

pub(super) struct ConnState {
    /// Close was called.
    closed: bool,

    /// A timer that fires to occasionally clean up idle DERP connections.
    /// It's only used when there is a non-home DERP connection in use.
    derp_cleanup_timer: Option<Timer>,

    /// Whether derp_cleanup_timer is scheduled to fire within derp_clean_stale_interval.
    derp_cleanup_timer_armed: bool,
    // When set, is an AfterFunc timer that will call Conn::do_periodic_stun.
    periodic_re_stun_timer: Option<Timer>,

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
    /// The set of peers that are currently configured in
    /// WireGuard. These are not used to filter inbound or outbound
    /// traffic at all, but only to track what state can be cleaned up
    /// in other maps below that are keyed by peer public key.
    peer_set: HashSet<key::node::PublicKey>,

    /// The private naclbox key used for active discovery traffic. It's created once near
    /// (but not during) construction.
    disco_private: key::disco::SecretKey,
    /// Public key of disco_private.
    pub(super) disco_public: key::disco::PublicKey,

    // The state for an active DiscoKey.
    disco_info: HashMap<key::disco::PublicKey, DiscoInfo>,

    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<cfg::NetInfo>,

    net_map: Option<netmap::NetworkMap>,
    /// WireGuard private key for this node
    private_key: key::node::SecretKey,
    /// Nearest DERP region ID; 0 means none/unknown.
    my_derp: usize,
    // derp_started chan struct{}      // closed on first connection to DERP; for tests & cleaner Close
    /// DERP regionID -> connection to a node in that region
    active_derp: HashMap<usize, ActiveDerp>,
    prev_derp: HashMap<usize, wg::AsyncWaitGroup>,

    /// Contains optional alternate routes to use as an optimization instead of
    /// contacting a peer via their home DERP connection.  If they sent us a message
    /// on a different DERP connection (which should really only be on our DERP
    /// home connection, or what was once our home), then we remember that route here to optimistically
    /// use instead of creating a new DERP connection back to their home.
    derp_route: HashMap<key::node::PublicKey, DerpRoute>,
}

impl ConnState {
    fn new(private_key: key::node::SecretKey) -> Self {
        let disco_private = key::disco::SecretKey::generate();
        let disco_public = disco_private.public();

        ConnState {
            closed: false,
            derp_cleanup_timer: None,
            derp_cleanup_timer_armed: false,
            periodic_re_stun_timer: None,
            endpoints_update_state: Default::default(),
            last_endpoints: Vec::new(),
            last_endpoints_time: None,
            on_endpoint_refreshed: HashMap::new(),
            peer_set: HashSet::new(),
            disco_private,
            disco_public,
            disco_info: HashMap::new(),
            net_info_last: None,
            net_map: None,
            private_key,
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
    pub async fn new(name: String, opts: Options) -> Result<Self> {
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
            private_key,
        } = opts;

        if let Some(ref _link_monitor) = link_monitor {
            // TODO:
            // self.port_mapper.set_gateway_lookup_func(opts.LinkMonitor.GatewayAndSelfIP);
        }

        let derp_recv_ch = flume::bounded(64);

        let (pconn4, pconn6) = Self::bind(port).await?;
        let port = pconn4.port().await;
        port_mapper.set_local_port(port).await;

        let c = Conn(Arc::new(Inner {
            name,
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
            public_key: private_key.verifying_key().into(),
            last_net_check_report: Default::default(),
            no_v4_send: AtomicBool::new(false),
            pconn4,
            pconn6,
            socket_endpoint4: SocketEndpointCache::default(),
            socket_endpoint6: SocketEndpointCache::default(),
            on_stun_receive: Default::default(),
            state: ConnState::new(private_key).into(),
            close_disco4: None,
            close_disco6: None,
            closing: AtomicBool::new(false),
            derp_recv_ch,
            derp_map: Default::default(),
            peer_map: Default::default(),
        }));

        Ok(c)
    }

    /// Sets a STUN packet processing func that does nothing.
    async fn ignore_stun_packets(&self) {
        *self.on_stun_receive.write().await = None;
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

    // c.mu must NOT be held.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn update_endpoints(&self, why: &'static str) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
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
                    info!("endpoint update ({}) failed: {:#?}", why, err);
                    // TODO(crawshaw): are there any conditions under which
                    // we should trigger a retry based on the error here?
                }
            }

            let mut state = self.state.lock().await;
            let new_why = state.endpoints_update_state.want_update.take();
            if !state.closed {
                if let Some(new_why) = new_why {
                    debug!("endpoint update: needed new ({})", new_why);
                    let this = self.clone();
                    state
                        .endpoints_update_state
                        .running
                        .replace(tokio::task::spawn(async move {
                            this.update_endpoints(new_why).await
                        }));
                    return;
                }
                if self.should_do_periodic_re_stun(&mut state) {
                    // Pick a random duration between 20 and 26 seconds (just under 30s,
                    // a common UDP NAT timeout on Linux,etc)
                    let d: Duration = {
                        let mut rng = rand::thread_rng();
                        rng.gen_range(Duration::from_secs(20)..=Duration::from_secs(26))
                    };
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

            debug!("endpoint update done ({})", why);
        })
    }

    /// Records the new endpoints, reporting whether they're changed.
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn set_endpoints(&self, endpoints: &[cfg::Endpoint]) -> bool {
        let any_stun = endpoints.iter().any(|ep| ep.typ == cfg::EndpointType::Stun);

        let mut state = self.state.lock().await;
        let derp_map = self.derp_map.read().await;

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

        state.last_endpoints_time = Some(Instant::now());
        for (_de, f) in state.on_endpoint_refreshed.drain() {
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

    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn update_net_info(&self) -> Result<Arc<netcheck::Report>> {
        let dm = self.derp_map.read().await.clone();
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
            let r = &report;
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
        let state = self.state.lock().await;
        let derp_map = self.derp_map.read().await;
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

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn call_net_info_callback_locked(&self, ni: cfg::NetInfo, state: &mut ConnState) {
        state.net_info_last = Some(ni.clone());
        if let Some(ref on_net_info) = self.on_net_info {
            debug!("net_info update: {:?}", ni);
            on_net_info(ni);
            // tokio::task::spawn(async move { cb(ni) });
        }
    }

    /// Makes addr a validated disco address for discoKey.
    /// Used to provide user/externally discovered addresses.
    #[cfg(test)]
    async fn add_valid_disco_path_for_test(
        &self,
        node_key: &key::node::PublicKey,
        addr: &SocketAddr,
    ) {
        let mut peer_map = self.peer_map.write().await;
        peer_map.set_node_key_for_ip_port(addr, node_key);
        if let Some(ep) = peer_map.endpoint_for_node_key(node_key) {
            ep.maybe_add_best_addr(*addr).await;
        }
    }

    /// Describes the time we last got traffic from this endpoint (updated every ~10 seconds).
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn last_recv_activity_of_node_key(&self, nk: &key::node::PublicKey) -> String {
        let peer_map = self.peer_map.read().await;
        match peer_map.endpoint_for_node_key(nk) {
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
    async fn disco_public_key(&self) -> key::disco::PublicKey {
        // TODO: move this out of ConnState?
        let state = self.state.lock().await;
        state.disco_public.clone()
    }

    async fn set_nearest_derp(&self, derp_num: usize) -> bool {
        let mut state = self.state.lock().await;

        if self.derp_map.read().await.is_none() {
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

        // On change, notify all currently connected DERP servers and
        // start connecting to our home DERP if we are not already.
        let derp_map = self.derp_map.read().await;
        match derp_map
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
            let b = *i == state.my_derp;
            let c = ad.c.clone();
            tokio::task::spawn(async move {
                c.note_preferred(b);
            });
        }
        self.go_derp_connect(derp_num);
        true
    }

    /// Starts connecting to our DERP home, if any.
    fn start_derp_home_connect(&self, state: &mut ConnState) {
        self.go_derp_connect(state.my_derp);
    }

    /// Starts a task to start connecting to the given DERP node.
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn determine_endpoints(&self) -> Result<Vec<cfg::Endpoint>> {
        let mut portmap_ext = self
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

    /// Returns the current IPv4 listener's port number.
    pub async fn local_port(&self) -> u16 {
        self.pconn4.port().await
    }

    fn network_down(&self) -> bool {
        !self.network_up.load(Ordering::Relaxed)
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
        pub_key: Option<&key::node::PublicKey>,
        transmit: quinn_proto::Transmit,
    ) -> Poll<io::Result<usize>> {
        if transmit.destination.ip() != DERP_MAGIC_IP {
            return self.poll_send_udp(udp_state, cx, transmit);
        }

        match self.derp_write_chan_of_addr(transmit.destination, pub_key) {
            None => {
                // TODO:
                // metricSendDERPErrorChan.Add(1)
                return Poll::Ready(Ok(0));
            }
            Some(ch) => {
                if self.closing.load(Ordering::Relaxed) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "connection closed",
                    )));
                }

                match ch.try_send(DerpWriteRequest {
                    pub_key: pub_key.cloned(),
                    addr: transmit.destination,
                    content: transmit.contents,
                }) {
                    Ok(_) => {
                        //   metricSendDERPQueued.Add(1)
                        return Poll::Ready(Ok(1));
                    }
                    Err(_) => {
                        //   metricSendDERPErrorQueue.Add(1)
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
        transmit: quinn_proto::Transmit,
    ) -> Poll<io::Result<usize>> {
        let transmits = [transmit];
        match transmits[0].destination {
            SocketAddr::V4(_) => self.pconn4.poll_send(udp_state, cx, &transmits),
            SocketAddr::V6(_) => {
                if let Some(ref conn) = self.pconn6 {
                    conn.poll_send(udp_state, cx, &transmits)
                } else {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "no IPv6 connection",
                    )))
                }
            }
        }
    }

    /// Returns a DERP client for fake UDP addresses that represent DERP servers, creating them as necessary.
    /// For real UDP addresses, it returns `None`.
    ///
    /// If peer is `Some`, it can be used to find an active reverse path, without using addr.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn derp_write_chan_of_addr(
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

        let mut state = tokio::task::block_in_place(|| self.state.blocking_lock());
        let derp_map = tokio::task::block_in_place(|| self.derp_map.blocking_read());
        if derp_map.is_none() || state.closed {
            return None;
        }
        if !derp_map.as_ref().unwrap().regions.contains_key(&region_id) {
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
        let dc = derp::http::Client::new_region(state.private_key.clone(), move || {
            let this = this.clone();
            Box::pin(async move {
                // Warning: it is not legal to acquire
                // magicsock.Conn.mu from this callback.
                // It's run from derp::http::Client.connect (via Send, etc)
                // and the lock ordering rules are that magicsock.Conn.mu
                // must be acquired before derp::http.Client.mu

                if this.is_closing() {
                    // We're closing anyway; return to stop dialing.
                    return None;
                }

                // Need to load the derp map without aquiring the lock

                let derp_map = &*this.derp_map.read().await;
                match derp_map {
                    None => None,
                    Some(derp_map) => derp_map.regions.get(&region_id).cloned(),
                }
            })
        });

        dc.set_can_ack_pings(true);
        dc.note_preferred(state.my_derp == region_id);
        let this = self.clone();
        dc.set_address_family_selector(move || {
            let this = this.clone();
            Box::pin(async move {
                // TODO: use atomic read?
                if let Some(r) = &*this.last_net_check_report.read().await {
                    return r.ipv6;
                }
                false
            })
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
        self.log_active_derp(&mut state);

        let this = self.clone();
        tokio::task::spawn(async move {
            let mut state = this.state.lock().await;
            this.schedule_clean_stale_derp(&mut state).await;
        });

        // Build a start_gate for the derp reader+writer tasks, so they don't start running
        // until any previous generation is closed.
        // And register a WaitGroup(Chan) for this generation.
        let wg = wg::AsyncWaitGroup::new();
        wg.add(2);
        let start_gate = state
            .prev_derp
            .insert(region_id, wg.clone())
            .unwrap_or_else(|| wg::AsyncWaitGroup::new());

        // if firstDerp {
        //     startGate = c.derpStarted;
        //     go func() {
        // 	dc.Connect(ctx)
        // 	  close(c.derpStarted)
        // 	    c.muCond.Broadcast()
        //     }()
        // }

        {
            let this = self.clone();
            let cancel = cancel_receiver.clone();
            let dc = dc.clone();
            let sg = start_gate.clone();
            let wg = wg.clone();
            tokio::task::spawn(async move {
                this.run_derp_reader(addr, dc, cancel, wg, sg).await;
            });
        }

        let this = self.clone();
        let cancel = cancel_receiver;
        let sg = start_gate;
        tokio::task::spawn(async move {
            this.run_derp_writer(dc, write_ch_receiver, cancel, wg, sg)
                .await;
        });

        if let Some(ref f) = self.on_derp_active {
            // TODO: spawn
            f();
        }

        Some(write_ch)
    }

    /// Runs in a task for the life of a DERP connection, handling received packets.
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn run_derp_reader(
        &self,
        derp_fake_addr: SocketAddr,
        dc: derp::http::Client,
        mut cancel: sync::watch::Receiver<bool>,
        wg: wg::AsyncWaitGroup,
        start_gate: wg::AsyncWaitGroup,
    ) {
        let _guard = WgGuard(wg);
        tokio::select! {
            _ = start_gate.wait() => {}
            _ = cancel.changed() => {
                return;
            }
        }

        let region_id = usize::from(derp_fake_addr.port());

        // The set of senders we know are present on this connection, based on messages we've received from the server.

        let mut peer_present = HashSet::new();
        let mut bo: backoff::exponential::ExponentialBackoff<backoff::SystemClock> =
            backoff::exponential::ExponentialBackoffBuilder::new()
                .with_initial_interval(Duration::from_millis(10))
                .with_max_interval(Duration::from_secs(5))
                .build();

        let mut last_packet_time: Option<Instant> = None;
        let mut last_packet_src: Option<key::node::PublicKey> = None;

        loop {
            match dc.recv_detail().await {
                Err(err) => {
                    // Forget that all these peers have routes.
                    for peer in peer_present.drain() {
                        self.remove_derp_peer_route(peer, region_id, &dc).await;
                    }
                    if err == derp::http::ClientError::Closed
                        || err == derp::http::ClientError::Todo
                    {
                        return;
                    }
                    if self.network_down() {
                        info!("derp.recv(derp-{}): network down, closing", region_id);
                        return;
                    }

                    if *cancel.borrow() {
                        return;
                    }

                    debug!("[{:?}] derp.recv(derp-{}): {:?}", dc, region_id, err);

                    // If our DERP connection broke, it might be because our network
                    // conditions changed. Start that check.
                    self.re_stun("derp-recv-error").await;

                    // Back off a bit before reconnecting.
                    match bo.next_backoff() {
                        Some(t) => {
                            debug!("backoff sleep: {}ms", t.as_millis());
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
                            self.derp_recv_ch
                                .0
                                .send_async(res)
                                .await
                                .expect("derp_recv_ch gone");
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn run_derp_writer(
        &self,
        dc: derp::http::Client,
        ch: flume::Receiver<DerpWriteRequest>,
        mut cancel: sync::watch::Receiver<bool>,
        wg: wg::AsyncWaitGroup,
        start_gate: wg::AsyncWaitGroup,
    ) {
        let _guard = WgGuard(wg);
        tokio::select! {
            _ = start_gate.wait() => {}
            _ = cancel.changed() => {
                return;
            }
        }

        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        break;
                    }
                }
                wr = ch.recv_async() => match wr {
                    Ok(wr) => match dc.send(wr.pub_key, wr.content).await {
                        Ok(_) => {
                            // TODO:
                            // metricSendDERP.Add(1)
                        }
                        Err(err) => {
                            info!("derp.send({:?}): {:?}", wr.addr, err);
                            // TODO:
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn receive_ip(
        &self,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
        cache: &SocketEndpointCache,
    ) -> bool {
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
            meta.dst_ip = Some(de.fake_wg_addr.ip());
        } else {
            let peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_read());
            match peer_map.endpoint_for_ip_port(&meta.addr) {
                None => {
                    debug!("no peer_map state found for {}", meta.addr);
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

        debug!("received passthrough message {}", b.len());

        true
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn process_derp_read_result(
        &self,
        dm: DerpReadResult,
        b: &mut io::IoSliceMut<'_>,
        meta: &mut quinn_udp::RecvMeta,
    ) -> usize {
        let b = &b[..meta.len];
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
            let peer_map = tokio::task::block_in_place(|| self.peer_map.blocking_read());
            peer_map.endpoint_for_node_key(&dm.src).cloned()
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

        let mut state = self.state.lock().await;
        if state.closed {
            bail!("connection closed");
        }

        let disco_public = state.disco_public.clone();
        let ConnState {
            disco_info,
            disco_private,
            ..
        } = &mut *state;
        let di = get_disco_info(disco_info, &*disco_private, dst_disco);
        let seal = di.shared_key.seal(&msg.as_bytes());
        drop(state);

        // TODO
        // if is_derp {
        // 	metricSendDiscoDERP.Add(1)
        // } else {
        // 	metricSendDiscoUDP.Add(1)
        // }

        let pkt = disco::encode_message(&disco_public, seal);
        let udp_state = quinn_udp::UdpState::default(); // TODO: store
        let sent = futures::future::poll_fn(move |cx| {
            self.poll_send_addr(
                &udp_state,
                cx,
                dst_key,
                quinn_proto::Transmit {
                    destination: dst,
                    contents: pkt.clone(), // TODO: avoid
                    ecn: None,
                    segment_size: None, // TODO: make sure this is correct
                    src_ip: None,       // TODO
                },
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
                if !self.network_down() {
                    warn!("disco: failed to send {:?} to {}: {:?}", msg, dst, err);
                }
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

        let mut state = tokio::task::block_in_place(|| self.state.blocking_lock());
        if state.closed {
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

        let ConnState {
            disco_info,
            disco_private,
            disco_public,
            ..
        } = &mut *state;
        let di = get_disco_info(disco_info, &*disco_private, &sender);
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
                disco_private.public(),
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
                    if ep.handle_pong_conn(&mut *peer_map, &disco_public, &pong, di, src) {
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
                    let ConnState {
                        disco_info,
                        disco_private,
                        ..
                    } = &mut *state;
                    let di = get_disco_info(disco_info, &*disco_private, &sender);
                    di.set_node_key(node_key.clone());
                }
                info!(
                    "disco: {:?}<-{:?} ({:?}, {:?})  got call-me-maybe, {} endpoints",
                    state.disco_public,
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
        let ConnState {
            disco_info,
            disco_private,
            disco_public,
            ..
        } = &mut *state;
        let di = get_disco_info(disco_info, &*disco_private, &sender);
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
                disco_public, di.disco_key, ping_node_src_str, src, dm.tx_id
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
    /// derpAddr is de.derpAddr at the time of send. It's assumed the peer won't be
    /// flipping primary DERPs in the 0-30ms it takes to confirm our STUN endpoint.
    /// If they do, traffic will just go over DERP for a bit longer until the next discovery round.
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) fn enqueue_call_me_maybe(
        &self,
        derp_addr: SocketAddr,
        de: Endpoint,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + Sync + '_>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;

            if state.last_endpoints_time.is_none()
                || state.last_endpoints_time.as_ref().unwrap().elapsed()
                    > ENDPOINTS_FRESH_ENOUGH_DURATION
            {
                info!(
                    "want call-me-maybe but endpoints stale; restunning ({:?})",
                    state.last_endpoints_time
                );

                let this = self.clone();
                state.on_endpoint_refreshed.insert(
                    de.clone(),
                    Box::new(move || {
                        let this = this.clone();
                        let de = de.clone();
                        Box::pin(async move {
                            info!(
                                "STUN done; sending call-me-maybe to {:?} {:?}",
                                de.disco_key(),
                                de.public_key
                            );
                            this.enqueue_call_me_maybe(derp_addr, de).await;
                        })
                    }),
                );

                // TODO(bradfitz): make a new 'reSTUNQuickly' method
                // that passes down a do-a-lite-netcheck flag down to
                // netcheck that does 1 (or 2 max) STUN queries
                // (UDP-only, not HTTPs) to find our port mapping to
                // our home DERP and maybe one other. For now we do a
                // "full" ReSTUN which may or may not be a full one
                // (depending on age) and may do HTTPS timing queries
                // (if UDP is blocked). Good enough for now.
                let this = self.clone();
                tokio::task::spawn(async move {
                    this.re_stun("refresh-for-peering").await;
                });
                return;
            }

            let eps: Vec<_> = state.last_endpoints.iter().map(|ep| ep.addr).collect();
            tokio::task::spawn(async move {
                if let Err(err) =
                    de.c.send_disco_message(
                        derp_addr,
                        Some(&de.public_key),
                        &de.disco_key(),
                        disco::Message::CallMeMaybe(disco::CallMeMaybe { my_number: eps }),
                    )
                    .await
                {
                    warn!("failed to send disco message to {}: {:?}", derp_addr, err);
                }
            });
        })
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_network_up(&self, up: bool) {
        let mut state = self.state.lock().await;
        if self.network_up.load(Ordering::Relaxed) == up {
            return;
        }

        info!("magicsock: set_network_up({})", up);
        self.network_up.store(up, Ordering::Relaxed);

        if up {
            self.start_derp_home_connect(&mut state);
        } else {
            self.port_mapper.note_network_down();
            self.close_all_derp(&mut state, "network-down");
        }
    }

    /// Sets the connection's preferred local port.
    #[instrument(skip_all, fields(self.name = %self.name))]
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

    /// Called when the set of peers changes. It then removes any state for old peers.
    #[instrument(skip_all, fields(self.name = %self.name))]
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_derp_map(&self, dm: Option<derp::DerpMap>) {
        let mut state = self.state.lock().await;
        let derp_map_locked = &mut *self.derp_map.write().await;
        if *derp_map_locked == dm {
            return;
        }

        let old = std::mem::replace(derp_map_locked, dm);
        let derp_map = derp_map_locked.clone();
        drop(derp_map_locked); // clone and unlock
        if derp_map.is_none() {
            self.close_all_derp(&mut state, "derp-disabled");
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
                if rid == state.my_derp {
                    state.my_derp = 0;
                }
                self.close_derp(rid, "derp-region-redefined", &mut state.active_derp);
            }
            if changes {
                self.log_active_derp(&mut state);
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    pub async fn set_network_map(&self, nm: netmap::NetworkMap) {
        let mut state = self.state.lock().await;

        if state.closed {
            return;
        }

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

    fn close_all_derp(&self, state: &mut ConnState, why: &'static str) {
        if state.active_derp.is_empty() {
            return; // without the useless log statement
        }
        // Need to collect to avoid double borrow
        let regions: Vec<_> = state.active_derp.keys().copied().collect();
        for region in regions {
            self.close_derp(region, why, &mut state.active_derp);
        }
        self.log_active_derp(state);
    }

    /// Called in response to a rebind, closes all DERP connections that don't have a local address in okay_local_ips
    /// and pings all those that do.
    #[instrument(skip_all, fields(self.name = %self.name))]
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
                        this.close_or_reconnect_derp(region_id, "rebind-ping-fail", &mut state)
                            .await;
                        return;
                    }
                    debug!("post-rebind ping of DERP region {} okay", region_id);
                }));
            }
        }

        for (region_id, why) in tasks {
            self.close_or_reconnect_derp(region_id, why, &mut state)
                .await;
        }

        self.log_active_derp(&mut state);
    }

    /// Closes the DERP connection to the provided `region_id` and starts reconnecting it if it's
    /// our current home DERP.
    async fn close_or_reconnect_derp(
        &self,
        region_id: usize,
        why: &'static str,
        state: &mut ConnState,
    ) {
        self.close_derp(region_id, why, &mut state.active_derp);
        if state.my_derp == region_id {
            self.start_derp_home_connect(state);
        }
    }

    /// It is the responsibility of the caller to call `log_active_derp` after any set of closes.
    #[instrument(skip_all, fields(self.name = %self.name))]
    fn close_derp(
        &self,
        region_id: usize,
        why: &'static str,
        active_derp: &mut HashMap<usize, ActiveDerp>,
    ) {
        if let Some(ad) = active_derp.remove(&region_id) {
            debug!(
                "closing connection to derp-{} ({:?}), age {}s",
                region_id,
                why,
                ad.create_time.elapsed().as_secs()
            );

            let ActiveDerp { c, cancel, .. } = ad;
            tokio::task::spawn(c.close());
            let _ = cancel.send(true);

            // TODO:
            // metricNumDERPConns.Set(int64(len(c.activeDerp)))
        }
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn log_active_derp(&self, state: &mut ConnState) {
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

    #[instrument(skip_all, fields(self.name = %self.name))]
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
            self.close_derp(i, "idle", &mut state.active_derp);
        }
        if dirty {
            self.log_active_derp(&mut state);
        }
        if some_non_home_open {
            self.schedule_clean_stale_derp(&mut state).await;
        }
    }

    // uses Pin<Box>> to avoid cycles in type inf
    fn schedule_clean_stale_derp<'a, 'b: 'a>(
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

    /// Close closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.
    #[instrument(skip_all, fields(self.name = %self.name))]
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

        {
            let peer_map = self.peer_map.read().await;
            for ep in peer_map.endpoints() {
                ep.stop_and_reset().await;
            }
        }

        state.closed = true;
        // c.connCtxCancel()
        self.close_all_derp(&mut state, "conn-close");
        // Ignore errors from c.pconnN.Close.
        // They will frequently have been closed already by a call to connBind.Close.
        if let Some(ref conn) = self.pconn6 {
            conn.close().await.ok();
        }
        self.pconn4.close().await.ok();

        // Wait on tasks updating right at the end, once everything is
        // already closed. We want everything else in the Conn to be
        // consistently in the closed state before we release mu to wait
        // on the endpoint updater & derphttp.Connect.
        self.tasks_running(&mut state).await;

        Ok(())
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn tasks_running(&self, state: &mut ConnState) {
        if let Some(handle) = state.endpoints_update_state.running.take() {
            if let Err(err) = handle.await {
                debug!("endpoint update error: {:?}", err);
            };
        }
        // TODO: track spawned tasks and join them
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    fn should_do_periodic_re_stun(&self, state: &mut ConnState) -> bool {
        if self.network_down() {
            return false;
        }
        if state.peer_set.is_empty() {
            // If no peers, not worth doing.
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
    #[instrument(skip_all, fields(self.name = %self.name))]
    async fn re_stun(&self, why: &'static str) {
        let mut state = self.state.lock().await;
        if state.closed {
            // raced with a shutdown.
            return;
        }
        // TODO:
        // metricReSTUNCalls.Add(1)

        if state.endpoints_update_state.is_running() {
            if Some(why) != state.endpoints_update_state.want_update {
                debug!(
                    "re_stun({:?}): endpoint update active, need another later: {:?}",
                    state.endpoints_update_state.want_update, why
                );
                state.endpoints_update_state.want_update.replace(why);
            }
        } else {
            debug!("re_stun({}): started", why);
            let this = self.clone();
            state
                .endpoints_update_state
                .running
                .replace(tokio::task::spawn(async move {
                    this.update_endpoints(why).await;
                }));
        }
    }

    /// Closes and re-binds the UDP sockets.
    /// We consider it successful if we manage to bind the IPv4 socket.
    async fn rebind(&self, cur_port_fate: CurrentPortFate) -> Result<()> {
        let port = self.local_port().await;
        if let Some(ref conn) = self.pconn6 {
            // If we were not able to bind ipv6 at program start, dont retry
            if let Err(err) = conn.rebind(port, Network::Ip6, cur_port_fate).await {
                info!("rebind ignoring IPv6 bind failure: {:?}", err);
            }
        }
        self.pconn4
            .rebind(port, Network::Ip4, cur_port_fate)
            .await
            .context("rebind IPv4 failed")?;

        // reread, as it might have changed
        let port = self.local_port().await;
        self.port_mapper.set_local_port(port).await;

        Ok(())
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
        let peer_map = self.peer_map.read().await;
        for ep in peer_map.endpoints() {
            ep.note_connectivity_change().await;
        }
    }

    #[instrument(skip_all, fields(self.name = %self.name))]
    pub(super) fn poll_send_raw(
        &self,
        state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_proto::Transmit],
    ) -> Poll<io::Result<usize>> {
        debug!("poll_send_raw: {} packets", transmits.len());

        let mut sum = 0;

        let res = group_by(
            transmits,
            |a, b| a.destination.is_ipv6() == b.destination.is_ipv6(),
            |group| {
                let res = if group[0].destination.is_ipv6() {
                    if let Some(ref conn) = self.pconn6 {
                        conn.poll_send(state, cx, &transmits)
                    } else {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "no IPv6 connection",
                        )))
                    }
                } else {
                    self.pconn4.poll_send(state, cx, group)
                };
                match res {
                    Poll::Pending => None,
                    Poll::Ready(Ok(r)) => {
                        sum += r;
                        None
                    }
                    Poll::Ready(Err(err)) => Some(Poll::Ready(Err(err))),
                }
            },
        );

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
                        todo!()
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
                if let Ok(dm) = self.derp_recv_ch.1.try_recv() {
                    if tokio::task::block_in_place(|| self.state.blocking_lock()).closed {
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
        debug!("received {} msgs", num_msgs_total);
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
    cancel: sync::watch::Sender<bool>,
    write_ch: flume::Sender<DerpWriteRequest>,
    /// The time of the last request for its write
    // channel (currently even if there was no write).
    // It is always non-nil and initialized to a non-zero Time.
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

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use rand::RngCore;
    use tokio::{net, task::JoinSet};
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
        let d = derp::Server::new(key::node::SecretKey::generate());

        // TODO: configure DERP server when actually implemented
        // httpsrv := httptest.NewUnstartedServer(derphttp.Handler(d))
        // httpsrv.Config.ErrorLog = logger.StdLogger(logf)
        // httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
        // httpsrv.StartTLS()

        let (stun_addr, _, stun_cleanup) = stun::test::serve().await?;
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
                        stun_only: true, // TODO: switch to false once derp is implemented,
                        stun_port: stun_addr.port(),
                        ipv4: UseIpv4::Some("127.0.0.1".parse().unwrap()),
                        ipv6: UseIpv6::None,

                        derp_port: 1234, // TODO: httpsrv.Listener.Addr().(*net.TCPAddr).Port,
                        stun_test_ip: Some(stun_addr.ip()),
                    }],
                    avoid: false,
                },
            )]
            .into_iter()
            .collect(),
        };

        let cleanup = || {
            // httpsrv.CloseClientConnections()
            // httpsrv.Close()
            // d.Close()

            stun_cleanup.send(()).unwrap();
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
                    ep_s.send(eps.to_vec()).unwrap();
                })),
                ..Default::default()
            };
            let key = opts.private_key.clone();
            let conn = Conn::new(
                format!("magic-{}", hex::encode(&key.verifying_key().as_ref()[..8])),
                opts,
            )
            .await?;
            conn.set_derp_map(Some(derp_map)).await;

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
            self.key.verifying_key().into()
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
            let me = &ms[my_idx];
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
                    key: peer.key.verifying_key().into(),
                    disco_key: peer.conn.disco_public_key().await,
                    allowed_ips: addresses,
                    endpoints: eps[i].iter().map(|ep| ep.addr).collect(),
                    derp: Some("127.3.3.40:1".parse().unwrap()),
                    created: Instant::now(),
                    hostinfo: crate::hp::hostinfo::Hostinfo::new(),
                    keep_alive: false,
                    expired: false,
                    online: None,
                    last_seen: None,
                });
            }

            let nm = netmap::NetworkMap {
                peers,
                // 	PrivateKey: me.privateKey,
                // 	NodeKey:    me.privateKey.Public(),
                // 	Addresses:  []netip.Prefix{netip.PrefixFrom(netaddr.IPv4(1, 0, 0, byte(myIdx+1)), 32)},
            };

            // if mutateNetmap != nil {
            // 	mutateNetmap(myIdx, nm)
            // }
            nm
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
                let peer_set: HashSet<_> = nm.peers.iter().map(|p| p.key.clone()).collect();
                m.conn.set_network_map(nm).await;
                m.conn.update_peers(peer_set).await;
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

        // Setup connection information for discovery
        {
            let m1_addr = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                m1.quic_ep.local_addr()?.port(),
            );
            let m2_addr = SocketAddr::new(
                "127.0.0.1".parse().unwrap(),
                m2.quic_ep.local_addr()?.port(),
            );
            m1.conn
                .add_valid_disco_path_for_test(&m2.public(), &m2_addr)
                .await;
            m2.conn
                .add_valid_disco_path_for_test(&m1.public(), &m1_addr)
                .await;
        }

        // msg from  m2 -> m1
        macro_rules! roundtrip {
            ($a:expr, $b:expr, $msg:expr) => {
                let a = $a.clone();
                let b = $b.clone();
                let a_name = stringify!($a);
                let b_name = stringify!($b);
                info!("{} -> {} ({} bytes)", a_name, b_name, $msg.len());
                let a_addr =
                    SocketAddr::new("127.0.0.1".parse().unwrap(), a.quic_ep.local_addr()?.port());
                let b_addr =
                    SocketAddr::new("127.0.0.1".parse().unwrap(), b.quic_ep.local_addr()?.port());
                info!(
                    "{}: {}, {}: {}",
                    a_name,
                    a_addr,
                    b_name,
                    b.quic_ep.local_addr()?
                );

                let b_task = tokio::task::spawn(async move {
                    info!("[{}] accepting conn", b_name);
                    while let Some(conn) = b.quic_ep.accept().await {
                        info!("[{}] connecting", b_name);
                        let conn = conn
                            .await
                            .with_context(|| format!("[{}] connecting", b_name))?;
                        info!("[{}] accepting bi", b_name);
                        let (mut send_bi, recv_bi) = conn
                            .accept_bi()
                            .await
                            .with_context(|| format!("[{}] accepting bi", b_name))?;

                        info!("[{}] reading", b_name);
                        let val = recv_bi
                            .read_to_end(usize::MAX)
                            .await
                            .with_context(|| format!("[{}] reading to end", b_name))?;
                        send_bi
                            .finish()
                            .await
                            .with_context(|| format!("[{}] finishing", b_name))?;
                        info!("[{}] finished", b_name);
                        return Ok::<_, anyhow::Error>(val);
                    }
                    bail!("no connections available anymore");
                });

                info!("[{}] connecting to {}", a_name, b_addr);
                let conn = a
                    .quic_ep
                    .connect(b_addr, "localhost")?
                    .await
                    .with_context(|| format!("[{}] connect", a_name))?;

                info!("[{}] opening bi", a_name);
                let (mut send_bi, recv_bi) = conn
                    .open_bi()
                    .await
                    .with_context(|| format!("[{}] open bi", a_name))?;
                info!("[{}] writing message", a_name);
                send_bi
                    .write_all(&$msg[..])
                    .await
                    .with_context(|| format!("[{}] write all", a_name))?;

                info!("[{}] finishing", a_name);
                send_bi
                    .finish()
                    .await
                    .with_context(|| format!("[{}] finish", a_name))?;

                info!("[{}] reading_to_end", a_name);
                let _ = recv_bi
                    .read_to_end(usize::MAX)
                    .await
                    .with_context(|| format!("[{}]", a_name))?;
                info!("[{}] close", a_name);
                conn.close(0u32.into(), b"done");
                info!("[{}] wait idle", a_name);
                a.quic_ep.wait_idle().await;

                drop(send_bi);

                // make sure the right values arrived
                info!("waiting for channel");
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
            info!("-- round {}", i + 1);
            roundtrip!(m1, m2, b"hello");
            roundtrip!(m2, m1, b"hello");
        }

        info!("-- larger data");
        {
            let mut data = vec![0u8; 10 * 1024];
            rand::thread_rng().fill_bytes(&mut data);
            roundtrip!(m1, m2, data);
            roundtrip!(m2, m1, data);
        }

        info!("cleaning up");
        cleanup();
        cleanup_mesh();
        Ok(())
    }
}
