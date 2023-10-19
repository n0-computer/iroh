//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//! Based on tailscale/wgengine/magicsock
//!
//! ### `DEV_DERP_ONLY` env var:
//! When present at *compile time*, this env var will force all packets
//! to be sent over the DERP relay connection, regardless of whether or
//! not we have a direct UDP address for the given peer.
//!
//! The intended use is for testing the DERP protocol inside the MagicSock
//! to ensure that we can rely on the relay to send packets when two peers
//! are unable to find direct UDP connections to each other.
//!
//! This also prevent this node from attempting to hole punch and prevents it
//! from responding to any hole punching attemtps. This node will still,
//! however, read any packets that come off the UDP sockets.

// #[cfg(test)]
// pub(crate) use conn::tests as conn_tests;

use std::{
    collections::HashMap,
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _, Result};
use bytes::Bytes;
use futures::{future::BoxFuture, FutureExt};
use iroh_metrics::{inc, inc_by};
use quinn::AsyncUdpSocket;
use rand::{seq::SliceRandom, Rng, SeedableRng};
use tokio::{
    sync::{self, mpsc, Mutex},
    time,
};
use tracing::{debug, error, error_span, info, info_span, instrument, trace, warn, Instrument};

use crate::{
    config::{self, DERP_MAGIC_IP},
    derp::{DerpMap, DerpRegion},
    disco,
    dns::DNS_RESOLVER,
    key::{PublicKey, SecretKey, SharedSecret},
    magic_endpoint::PeerAddr,
    net::{ip::LocalAddresses, netmon},
    netcheck, portmapper, stun,
    util::AbortingJoinHandle,
};

use self::{
    derp_actor::{DerpActor, DerpActorMessage, DerpReadResult},
    endpoint::{Options as EndpointOptions, PeerMap, PingAction},
    metrics::Metrics as MagicsockMetrics,
    rebinding_conn::RebindingUdpConn,
    udp_actor::{IpPacket, NetworkReadResult, NetworkSource, UdpActor, UdpActorMessage},
};

mod derp_actor;
mod endpoint;
mod metrics;
mod rebinding_conn;
mod timer;
mod udp_actor;

pub use self::endpoint::ConnectionType;
pub use self::endpoint::{DirectAddrInfo, EndpointInfo};
pub use self::metrics::Metrics;
pub use self::timer::Timer;

/// How long we consider a STUN-derived endpoint valid for. UDP NAT mappings typically
/// expire at 30 seconds, so this is a few seconds shy of that.
const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How often to save peer data.
const SAVE_PEERS_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CurrentPortFate {
    Keep,
    Drop,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Network {
    Ipv4,
    Ipv6,
}

impl From<IpAddr> for Network {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }
}

impl Network {
    fn default_addr(&self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::UNSPECIFIED.into(),
            Self::Ipv6 => Ipv6Addr::UNSPECIFIED.into(),
        }
    }

    #[cfg(test)]
    fn local_addr(&self) -> IpAddr {
        match self {
            Self::Ipv4 => Ipv4Addr::LOCALHOST.into(),
            Self::Ipv6 => Ipv6Addr::LOCALHOST.into(),
        }
    }
}

impl From<Network> for socket2::Domain {
    fn from(value: Network) -> Self {
        match value {
            Network::Ipv4 => socket2::Domain::IPV4,
            Network::Ipv6 => socket2::Domain::IPV6,
        }
    }
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

    /// Callbacks to emit on various socket events
    pub callbacks: Callbacks,

    /// Path to store known peers.
    pub peers_path: Option<std::path::PathBuf>,
}

/// Contains options for `MagicSock::listen`.
#[derive(derive_more::Debug, Default)]
pub struct Callbacks {
    /// Optionally provides a func to be called when endpoints change.
    #[allow(clippy::type_complexity)]
    #[debug("on_endpoints: Option<Box<..>>")]
    pub on_endpoints: Option<Box<dyn Fn(&[config::Endpoint]) + Send + Sync + 'static>>,

    /// Optionally provides a func to be called when a connection is made to a DERP server.
    #[debug("on_derp_active: Option<Box<..>>")]
    pub on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,

    /// A callback that provides a `config::NetInfo` when discovered network conditions change.
    #[debug("on_net_info: Option<Box<..>>")]
    pub on_net_info: Option<Box<dyn Fn(config::NetInfo) + Send + Sync + 'static>>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            port: 0,
            secret_key: SecretKey::generate(),
            derp_map: DerpMap::empty(),
            callbacks: Default::default(),
            peers_path: None,
        }
    }
}

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to peers based on peer IDs, it will initially
/// route packets via a derper relay and transparently try and establish a peer-to-peer
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both endpoints change.
///
/// It is usually only necessary to use a single [`MagicSock`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about peers as
/// possible.
#[derive(Clone, Debug)]
pub struct MagicSock {
    inner: Arc<Inner>,
    // Empty when closed
    actor_tasks: Arc<Mutex<Vec<AbortingJoinHandle<()>>>>,
}

/// The actual implementation of `MagicSock`.
#[derive(derive_more::Debug)]
struct Inner {
    actor_sender: mpsc::Sender<ActorMessage>,
    /// Sends network messages.
    network_sender: mpsc::Sender<Vec<quinn_udp::Transmit>>,
    /// String representation of the peer_id of this node.
    me: String,
    #[allow(clippy::type_complexity)]
    #[debug("on_endpoints: Option<Box<..>>")]
    on_endpoints: Option<Box<dyn Fn(&[config::Endpoint]) + Send + Sync + 'static>>,
    #[debug("on_derp_active: Option<Box<..>>")]
    on_derp_active: Option<Box<dyn Fn() + Send + Sync + 'static>>,
    /// A callback that provides a `config::NetInfo` when discovered network conditions change.
    #[debug("on_net_info: Option<Box<..>>")]
    on_net_info: Option<Box<dyn Fn(config::NetInfo) + Send + Sync + 'static>>,

    /// Used for receiving DERP messages.
    network_recv_ch: flume::Receiver<NetworkReadResult>,
    /// Stores wakers, to be called when derp_recv_ch receives new data.
    network_recv_wakers: std::sync::Mutex<Option<Waker>>,
    network_send_wakers: std::sync::Mutex<Option<Waker>>,

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

    /// None (or zero regions/nodes) means DERP is disabled.
    derp_map: DerpMap,
    /// Nearest DERP region ID; 0 means none/unknown.
    my_derp: AtomicU16,
}

impl Inner {
    /// Returns the derp region we are connected to, that has the best latency.
    ///
    /// If `0`, then we are not connected to any derp region.
    fn my_derp(&self) -> u16 {
        self.my_derp.load(Ordering::Relaxed)
    }

    /// Sets the derp region with the best latency.
    ///
    /// If we are not connected to any derp regions, set this to `0`.
    fn set_my_derp(&self, my_derp: u16) {
        self.my_derp.store(my_derp, Ordering::Relaxed);
    }

    /// Returns `true` if we have DERP configuration for the given DERP `region`.
    async fn has_derp_region(&self, region: u16) -> bool {
        self.derp_map.contains_region(region)
    }

    async fn get_derp_region(&self, region: u16) -> Option<DerpRegion> {
        self.derp_map.get_region(region).cloned()
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

impl MagicSock {
    /// Creates a magic `MagicSock` listening on `opts.port`.
    ///
    /// As the set of possible endpoints for a MagicSock changes, the [`Callbacks::on_endpoints`]
    /// callback of [`Options::callbacks`] is called.
    ///
    /// [`Callbacks::on_endpoint`]: crate::magicsock::conn::Callbacks::on_endpoints
    pub async fn new(opts: Options) -> Result<Self> {
        let me = opts.secret_key.public().fmt_short();
        if crate::util::derp_only_mode() {
            warn!("creating a MagicSock that will only send packets over a DERP relay connection.");
        }

        Self::with_name(me.clone(), opts)
            .instrument(error_span!("magicsock", %me))
            .await
    }

    /// Returns `true` if we have DERP configuration for the given DERP `region`.
    pub async fn has_derp_region(&self, region: u16) -> bool {
        self.inner.has_derp_region(region).await
    }

    async fn with_name(me: String, opts: Options) -> Result<Self> {
        let port_mapper = portmapper::Client::default().await;

        let Options {
            port,
            secret_key,
            derp_map,
            callbacks:
                Callbacks {
                    on_endpoints,
                    on_derp_active,
                    on_net_info,
                },
            peers_path,
        } = opts;

        let peers_path = match peers_path {
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

        let (network_recv_ch_sender, network_recv_ch_receiver) = flume::bounded(128);

        let (pconn4, pconn6) = bind(port).await?;
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

        let net_checker = netcheck::Client::new(Some(port_mapper.clone())).await?;
        let (actor_sender, actor_receiver) = mpsc::channel(128);
        let (network_sender, network_receiver) = mpsc::channel(128);

        let inner = Arc::new(Inner {
            me,
            on_endpoints,
            on_derp_active,
            on_net_info,
            port: AtomicU16::new(port),
            secret_key,
            local_addrs: std::sync::RwLock::new((ipv4_addr, ipv6_addr)),
            closing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            network_recv_ch: network_recv_ch_receiver,
            network_recv_wakers: std::sync::Mutex::new(None),
            network_send_wakers: std::sync::Mutex::new(None),
            actor_sender: actor_sender.clone(),
            network_sender,
            ipv6_reported: Arc::new(AtomicBool::new(false)),
            derp_map,
            my_derp: AtomicU16::new(0),
        });

        let udp_state = quinn_udp::UdpState::default();
        let (ip_sender, ip_receiver) = mpsc::channel(128);
        let (udp_actor_sender, udp_actor_receiver) = mpsc::channel(128);

        let udp_actor_task = {
            let udp_actor =
                UdpActor::new(&udp_state, inner.clone(), pconn4.clone(), pconn6.clone());
            let net_checker = net_checker.clone();
            tokio::task::spawn(
                async move {
                    udp_actor
                        .run(udp_actor_receiver, net_checker, ip_sender)
                        .await;
                }
                .instrument(info_span!("udp.actor")),
            )
        };

        let (derp_actor_sender, derp_actor_receiver) = mpsc::channel(256);
        let derp_actor = DerpActor::new(inner.clone(), actor_sender.clone());
        let derp_actor_task = tokio::task::spawn(
            async move {
                derp_actor.run(derp_actor_receiver).await;
            }
            .instrument(info_span!("derp.actor")),
        );

        // load the peer data
        let peer_map = match peers_path.as_ref() {
            Some(path) if path.exists() => match PeerMap::load_from_file(path) {
                Ok(peer_map) => {
                    let count = peer_map.node_count();
                    debug!(count, "loaded peer map");
                    peer_map
                }
                Err(e) => {
                    debug!(%e, "failed to load peer map: using default");
                    PeerMap::default()
                }
            },
            _ => PeerMap::default(),
        };

        let inner2 = inner.clone();
        let main_actor_task = tokio::task::spawn(
            async move {
                let actor = Actor {
                    msg_receiver: actor_receiver,
                    msg_sender: actor_sender,
                    derp_actor_sender,
                    udp_actor_sender,
                    network_receiver,
                    ip_receiver,
                    inner: inner2,
                    derp_recv_sender: network_recv_ch_sender,
                    endpoints_update_state: EndpointUpdateState::new(),
                    last_endpoints: Vec::new(),
                    last_endpoints_time: None,
                    on_endpoint_refreshed: HashMap::new(),
                    periodic_re_stun_timer: new_re_stun_timer(false),
                    net_info_last: None,
                    disco_info: HashMap::new(),
                    peer_map,
                    peers_path,
                    port_mapper,
                    pconn4,
                    pconn6,
                    udp_state,
                    no_v4_send: false,
                    net_checker,
                };

                if let Err(err) = actor.run().await {
                    warn!("derp handler errored: {:?}", err);
                }
            }
            .instrument(info_span!("actor")),
        );

        let c = MagicSock {
            inner,
            actor_tasks: Arc::new(Mutex::new(vec![
                main_actor_task.into(),
                derp_actor_task.into(),
                udp_actor_task.into(),
            ])),
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
    pub async fn local_endpoints(&self) -> Result<Vec<config::Endpoint>> {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::LocalEndpoints(s))
            .await?;
        let res = r.await?;
        Ok(res)
    }

    /// Get the cached version of the Ipv4 and Ipv6 addrs of the current connection.
    pub fn local_addr(&self) -> Result<(SocketAddr, Option<SocketAddr>)> {
        Ok(*self.inner.local_addrs.read().unwrap())
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    pub async fn re_stun(&self, why: &'static str) {
        self.inner
            .actor_sender
            .send(ActorMessage::ReStun(why))
            .await
            .unwrap();
    }

    /// Returns the [`SocketAddr`] which can be used by the QUIC layer to dial this peer.
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

    // TODO
    // /// Handles a "ping" CLI query.
    // #[instrument(skip_all, fields(me = %self.inner.me))]
    // pub async fn ping<F>(&self, peer: config::Node, mut res: config::PingResult, cb: F)
    // where
    //     F: Fn(config::PingResult) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    // {
    //     res.node_ip = peer.addresses.get(0).copied();
    //     res.node_name = match peer.name.as_ref().and_then(|n| n.split('.').next()) {
    //         Some(name) => {
    //             // prefer DNS name
    //             Some(name.to_string())
    //         }
    //         None => {
    //             // else hostname
    //             Some(peer.hostinfo.hostname.clone())
    //         }
    //     };
    //     let ep = self
    //         .peer_map
    //         .read()
    //         .await
    //         .endpoint_for_node_key(&peer.key)
    //         .cloned();
    //     match ep {
    //         Some(ep) => {
    //             ep.cli_ping(res, cb).await;
    //         }
    //         None => {
    //             res.err = Some("unknown peer".to_string());
    //             cb(res);
    //         }
    //     }
    // }

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

    /// Returns the DERP region with the best latency.
    ///
    /// If `None`, then we currently have no verified connection to a DERP node in any region.
    pub async fn my_derp(&self) -> Option<u16> {
        let my_derp = self.inner.my_derp();
        if my_derp == 0 {
            None
        } else {
            Some(my_derp)
        }
    }

    #[instrument(skip_all, fields(me = %self.inner.me))]
    /// Add addresses for a node to the magic socket's addresbook.
    pub async fn add_peer_addr(&self, addr: PeerAddr) -> Result<()> {
        let (s, r) = sync::oneshot::channel();
        self.inner
            .actor_sender
            .send(ActorMessage::AddKnownAddr(addr, s))
            .await?;
        r.await?;
        Ok(())
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

        let mut tasks = self.actor_tasks.lock().await;
        let task_count = tasks.len();
        let mut i = 0;
        while let Some(task) = tasks.pop() {
            debug!("waiting for task {i}/{task_count}");
            task.await?;
            i += 1;
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
}

/// The info and state for the DiscoKey in the MagicSock.discoInfo map key.
///
/// Note that a DiscoKey does not necessarily map to exactly one
/// node. In the case of shared nodes and users switching accounts, two
/// nodes in the NetMap may legitimately have the same DiscoKey.  As
/// such, no fields in here should be considered node-specific.
struct DiscoInfo {
    node_key: PublicKey,
    /// The precomputed key for communication with the peer that has the `node_key` used to
    /// look up this `DiscoInfo` in MagicSock.discoInfo.
    /// Not modified once initialized.
    shared_key: SharedSecret,

    /// The src of a ping for `node_key`.
    last_ping_from: Option<SendAddr>,

    /// The last time of a ping for `node_key`.
    last_ping_time: Option<Instant>,
}

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
    #[instrument(skip_all, fields(me = %self.inner.me))]
    fn poll_send(
        &self,
        _udp_state: &quinn_udp::UdpState,
        cx: &mut Context,
        transmits: &[quinn_udp::Transmit],
    ) -> Poll<io::Result<usize>> {
        let bytes_total: usize = transmits.iter().map(|t| t.contents.len()).sum();
        inc_by!(MagicsockMetrics, send_data, bytes_total as _);

        if self.inner.is_closed() {
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

        // Split up transmits by destination, as the rest of the code assumes single dest.
        let groups = TransmitIter::new(transmits);
        for group in groups {
            match self.inner.network_sender.try_reserve() {
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // TODO: add counter?
                    self.inner
                        .network_send_wakers
                        .lock()
                        .unwrap()
                        .replace(cx.waker().clone());
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Ok(permit) => {
                    n += group.len();
                    permit.send(group);
                }
            }
        }
        if n > 0 {
            return Poll::Ready(Ok(n));
        }

        Poll::Pending
    }

    #[instrument(skip_all, fields(me = %self.inner.me))]
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // FIXME: currently ipv4 load results in ipv6 traffic being ignored
        debug_assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        if self.inner.is_closed() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "connection closed",
            )));
        }

        let mut num_msgs = 0;
        for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
            match self.inner.network_recv_ch.try_recv() {
                Err(flume::TryRecvError::Empty) => {
                    self.inner
                        .network_recv_wakers
                        .lock()
                        .unwrap()
                        .replace(cx.waker().clone());
                    break;
                }
                Err(flume::TryRecvError::Disconnected) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Ok(dm) => {
                    if self.inner.is_closed() {
                        break;
                    }

                    match dm {
                        NetworkReadResult::Error(err) => {
                            return Poll::Ready(Err(err));
                        }
                        NetworkReadResult::Ok {
                            bytes,
                            meta,
                            source,
                        } => {
                            buf_out[..bytes.len()].copy_from_slice(&bytes);
                            *meta_out = meta;

                            match source {
                                NetworkSource::Derp => {
                                    inc_by!(MagicsockMetrics, recv_data_derp, bytes.len() as _);
                                }
                                NetworkSource::Ipv4 => {
                                    inc_by!(MagicsockMetrics, recv_data_ipv4, bytes.len() as _);
                                }
                                NetworkSource::Ipv6 => {
                                    inc_by!(MagicsockMetrics, recv_data_ipv6, bytes.len() as _);
                                }
                            }
                            trace!(
                                "[QUINN] <- {} ({}b) ({}) ({:?}, {:?})",
                                meta_out.addr,
                                meta_out.len,
                                self.inner.me,
                                meta_out.dst_ip,
                                source
                            );
                        }
                    }

                    num_msgs += 1;
                }
            }
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs > 0 {
            inc_by!(MagicsockMetrics, recv_datagrams, num_msgs as _);
            trace!("received {} datagrams", num_msgs);
            return Poll::Ready(Ok(num_msgs));
        }

        Poll::Pending
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
#[allow(clippy::large_enum_variant)]
enum ActorMessage {
    TrackedEndpoints(sync::oneshot::Sender<Vec<EndpointInfo>>),
    TrackedEndpoint(PublicKey, sync::oneshot::Sender<Option<EndpointInfo>>),
    LocalEndpoints(sync::oneshot::Sender<Vec<config::Endpoint>>),
    GetMappingAddr(PublicKey, sync::oneshot::Sender<Option<QuicMappedAddr>>),
    SetPreferredPort(u16, sync::oneshot::Sender<()>),
    RebindAll(sync::oneshot::Sender<()>),
    Shutdown,
    CloseOrReconnect(u16, &'static str),
    ReStun(&'static str),
    EnqueueCallMeMaybe {
        derp_region: u16,
        endpoint_id: usize,
    },
    SendCallMeMaybe {
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::CallMeMaybe,
    },
    AddKnownAddr(PeerAddr, sync::oneshot::Sender<()>),
    ReceiveDerp(DerpReadResult),
    EndpointPingExpired(usize, stun::TransactionId),
}

struct Actor {
    inner: Arc<Inner>,
    msg_receiver: mpsc::Receiver<ActorMessage>,
    msg_sender: mpsc::Sender<ActorMessage>,
    derp_actor_sender: mpsc::Sender<DerpActorMessage>,
    udp_actor_sender: mpsc::Sender<UdpActorMessage>,
    network_receiver: mpsc::Receiver<Vec<quinn_udp::Transmit>>,
    ip_receiver: mpsc::Receiver<IpPacket>,
    /// Channel to send received derp messages on, for processing.
    derp_recv_sender: flume::Sender<NetworkReadResult>,
    /// Indicates the update endpoint state.
    endpoints_update_state: EndpointUpdateState,
    /// Records the endpoints found during the previous
    /// endpoint discovery. It's used to avoid duplicate endpoint change notifications.
    last_endpoints: Vec<config::Endpoint>,

    /// The last time the endpoints were updated, even if there was no change.
    last_endpoints_time: Option<Instant>,

    /// Functions to run (in their own tasks) when endpoints are refreshed.
    on_endpoint_refreshed:
        HashMap<usize, Box<dyn Fn() -> BoxFuture<'static, ()> + Send + Sync + 'static>>,
    /// When set, is an AfterFunc timer that will call MagicSock::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,
    /// The `NetInfo` provided in the last call to `net_info_func`. It's used to deduplicate calls to netInfoFunc.
    net_info_last: Option<config::NetInfo>,
    /// The state for an active DiscoKey.
    disco_info: HashMap<PublicKey, DiscoInfo>,
    /// Tracks the networkmap node entity for each peer discovery key.
    peer_map: PeerMap,
    /// Path where connection info from [`Self::peer_map`] is persisted.
    peers_path: Option<PathBuf>,

    // The underlying UDP sockets used to send/rcv packets.
    pconn4: RebindingUdpConn,
    pconn6: Option<RebindingUdpConn>,
    udp_state: quinn_udp::UdpState,

    /// The NAT-PMP/PCP/UPnP prober/client, for requesting port mappings from NAT devices.
    port_mapper: portmapper::Client,

    /// Whether IPv4 UDP is known to be unable to transmit
    /// at all. This could happen if the socket is in an invalid state
    /// (as can happen on darwin after a network link status change).
    no_v4_send: bool,

    /// The prober that discovers local network conditions, including the closest DERP relay and NAT mappings.
    net_checker: netcheck::Client,
}

impl Actor {
    async fn run(mut self) -> Result<()> {
        // Setup network monitoring
        let monitor = netmon::Monitor::new().await?;
        let sender = self.msg_sender.clone();
        let _token = monitor
            .subscribe(move |is_major| {
                let sender = sender.clone();
                async move {
                    info!("link change detected: major? {}", is_major);

                    // Clear DNS cache
                    DNS_RESOLVER.clear_cache();

                    if is_major {
                        let (s, r) = sync::oneshot::channel();
                        sender.send(ActorMessage::RebindAll(s)).await.ok();
                        sender
                            .send(ActorMessage::ReStun("link-change-major"))
                            .await
                            .ok();
                        r.await.ok();
                    } else {
                        sender
                            .send(ActorMessage::ReStun("link-change-minor"))
                            .await
                            .ok();
                    }
                }
                .boxed()
            })
            .await?;

        // Let the the hearbeat only start a couple seconds later
        let mut endpoint_heartbeat_timer = time::interval_at(
            time::Instant::now() + Duration::from_secs(5),
            HEARTBEAT_INTERVAL,
        );
        let mut endpoints_update_receiver = self.endpoints_update_state.running.subscribe();
        let mut portmap_watcher = self.port_mapper.watch_external_address();
        let mut save_peers_timer = if self.peers_path.is_some() {
            tokio::time::interval_at(
                time::Instant::now() + SAVE_PEERS_INTERVAL,
                SAVE_PEERS_INTERVAL,
            )
        } else {
            tokio::time::interval(Duration::MAX)
        };

        loop {
            tokio::select! {
                Some(transmits) = self.network_receiver.recv() => {
                    trace!("tick: network send");
                    self.send_network(transmits).await;
                }
                Some(msg) = self.msg_receiver.recv() => {
                    trace!(?msg, "tick: msg");
                    if self.handle_actor_message(msg).await {
                        return Ok(());
                    }
                }
                Some(msg) = self.ip_receiver.recv() => {
                    trace!("tick: ip_receiver");
                    match msg {
                        IpPacket::Disco { sender, sealed_box, src } => {
                            self.handle_disco_message(sender, &sealed_box, src, None).await;
                        }
                        IpPacket::Forward(mut forward) => {
                            if let NetworkReadResult::Ok { meta, bytes, .. } = &mut forward {
                                if !self.receive_ip(bytes, meta) {
                                    continue;
                                }
                            }

                            let _ = self.derp_recv_sender.send_async(forward).await;
                            let mut wakers = self.inner.network_recv_wakers.lock().unwrap();
                            while let Some(waker) = wakers.take() {
                                waker.wake();
                            }
                        }
                    }
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    self.re_stun("periodic").await;
                }
                Ok(()) = portmap_watcher.changed() => {
                    trace!("tick: portmap changed");
                    let new_external_address = *portmap_watcher.borrow();
                    debug!("external address updated: {new_external_address:?}");
                    self.re_stun("portmap_updated").await;
                },
                _ = endpoint_heartbeat_timer.tick() => {
                    trace!("tick: endpoint heartbeat {} endpoints", self.peer_map.node_count());
                    // TODO: this might trigger too many packets at once, pace this
                    self.peer_map.prune_inactive();
                    let mut msgs = Vec::new();
                    for (_, ep) in self.peer_map.endpoints_mut() {
                        msgs.extend(ep.stayin_alive());
                    }
                    self.handle_ping_actions(msgs).await;
                }
                _ = endpoints_update_receiver.changed() => {
                    let reason = *endpoints_update_receiver.borrow();
                    trace!("tick: endpoints update receiver {:?}", reason);
                    if let Some(reason) = reason {
                        self.update_endpoints(reason).await;
                    }
                }
                _ = save_peers_timer.tick(), if self.peers_path.is_some() => {
                    let path = self.peers_path.as_ref().expect("precondition: `is_some()`");
                    self.peer_map.prune_inactive();
                    match self.peer_map.save_to_file(path).await {
                        Ok(count) => debug!(count, "peers persisted"),
                        Err(e) => debug!(%e, "failed to persist known peers"),
                    }
                }
                else => {
                    trace!("tick: other");
                }
            }
        }
    }

    async fn handle_ping_actions(&mut self, msgs: Vec<PingAction>) {
        if msgs.is_empty() {
            return;
        }

        info!("handle_ping_actions ({}): {:?}", msgs.len(), msgs);
        for msg in msgs {
            // Abort sending as soon as we know we are shutting down.
            if self.inner.is_closing() || self.inner.is_closed() {
                break;
            }
            match msg {
                PingAction::EnqueueCallMeMaybe {
                    derp_region,
                    endpoint_id,
                } => {
                    self.enqueue_call_me_maybe(derp_region, endpoint_id).await;
                }
                PingAction::SendPing {
                    id,
                    dst,
                    dst_key,
                    tx_id,
                    purpose,
                } => {
                    let msg = disco::Message::Ping(disco::Ping {
                        tx_id,
                        node_key: self.inner.public_key(),
                    });
                    match self.send_disco_message(dst, dst_key, msg).await {
                        Ok(true) => {
                            if let Some(ep) = self.peer_map.by_id_mut(&id) {
                                ep.ping_sent(dst, tx_id, purpose, self.msg_sender.clone());
                            }
                        }
                        _ => {
                            debug!("failed to send ping to {:?}", dst);
                        }
                    }
                }
            }
        }
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage) -> bool {
        match msg {
            ActorMessage::TrackedEndpoints(s) => {
                let eps: Vec<_> = self.peer_map.endpoint_infos(Instant::now());
                let _ = s.send(eps);
            }
            ActorMessage::TrackedEndpoint(node_key, s) => {
                let _ = s.send(self.peer_map.endpoint_info(&node_key));
            }
            ActorMessage::LocalEndpoints(s) => {
                let eps: Vec<_> = self.last_endpoints.clone();
                let _ = s.send(eps);
            }
            ActorMessage::GetMappingAddr(node_key, s) => {
                let res = self
                    .peer_map
                    .endpoint_for_node_key(&node_key)
                    .map(|ep| ep.quic_mapped_addr);
                let _ = s.send(res);
            }
            ActorMessage::Shutdown => {
                debug!("shutting down");
                for (_, ep) in self.peer_map.endpoints_mut() {
                    ep.stop_and_reset();
                }
                if let Some(path) = self.peers_path.as_ref() {
                    match self.peer_map.save_to_file(path).await {
                        Ok(count) => {
                            debug!(count, "known peers persisted")
                        }
                        Err(e) => debug!(%e, "failed to persist known peers"),
                    }
                }
                self.port_mapper.deactivate();
                self.derp_actor_sender
                    .send(DerpActorMessage::Shutdown)
                    .await
                    .ok();
                self.udp_actor_sender
                    .send(UdpActorMessage::Shutdown)
                    .await
                    .ok();

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
            ActorMessage::CloseOrReconnect(region_id, reason) => {
                self.send_derp_actor(DerpActorMessage::CloseOrReconnect { region_id, reason });
            }
            ActorMessage::ReStun(reason) => {
                self.re_stun(reason).await;
            }
            ActorMessage::EnqueueCallMeMaybe {
                derp_region,
                endpoint_id,
            } => {
                self.enqueue_call_me_maybe(derp_region, endpoint_id).await;
            }
            ActorMessage::RebindAll(s) => {
                self.rebind_all().await;
                let _ = s.send(());
            }
            ActorMessage::SetPreferredPort(port, s) => {
                self.set_preferred_port(port).await;
                let _ = s.send(());
            }
            ActorMessage::SendCallMeMaybe { dst, dst_key, msg } => {
                let msg = disco::Message::CallMeMaybe(msg);
                let _res = self.send_disco_message(dst, dst_key, msg).await;
            }
            ActorMessage::AddKnownAddr(addr, s) => {
                self.add_known_addr(addr);
                s.send(()).ok();
            }
            ActorMessage::ReceiveDerp(read_result) => {
                let passthroughs = self.process_derp_read_result(read_result).await;
                for passthrough in passthroughs {
                    self.derp_recv_sender
                        .send_async(passthrough)
                        .await
                        .expect("missing recv sender");
                    let mut wakers = self.inner.network_recv_wakers.lock().unwrap();
                    if let Some(waker) = wakers.take() {
                        waker.wake();
                    }
                }
            }
            ActorMessage::EndpointPingExpired(id, txid) => {
                if let Some(ep) = self.peer_map.by_id_mut(&id) {
                    ep.ping_timeout(txid);
                }
            }
        }

        false
    }

    /// This modifies the [`quinn_udp::RecvMeta`] for the packet to set the addresses
    /// to those that the QUIC layer should see.  E.g. the remote address will be set to the
    /// [`QuicMappedAddr`] instead of the actual remote. It also registers activity for this peer.
    ///
    /// Returns `true` if the message should be processed.
    fn receive_ip(&mut self, bytes: &Bytes, meta: &mut quinn_udp::RecvMeta) -> bool {
        debug!("received data {} from {}", meta.len, meta.addr);
        match self.peer_map.receive_ip(meta.addr) {
            None => {
                warn!(peer=?meta.addr, "no peer_map state found for peer, skipping");
                return false;
            }
            Some(ep) => {
                debug!("peer_map state found for {}", meta.addr);
                meta.addr = ep.quic_mapped_addr.0;
            }
        }

        // Normalize local_ip
        meta.dst_ip = self.normalized_local_addr().ok().map(|addr| addr.ip());

        debug!("received passthrough message {}", bytes.len());
        true
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

    async fn process_derp_read_result(&mut self, dm: DerpReadResult) -> Vec<NetworkReadResult> {
        debug!("process_derp_read {} bytes", dm.buf.len());
        if dm.buf.is_empty() {
            warn!("received empty derp packet");
            return Vec::new();
        }
        let region_id = dm.region_id;
        let ipp = SendAddr::Derp(region_id);

        let ep_quic_mapped_addr = match self.peer_map.endpoint_for_node_key_mut(&dm.src) {
            Some(ep) => {
                // NOTE: we don't update the derp region if there is already one but the new one is
                // different
                if ep.derp_region().is_none() {
                    ep.set_derp_region(region_id);
                }
                ep.quic_mapped_addr
            }
            None => {
                info!(peer=%dm.src, "no peer_map state found for peer");
                let id = self.peer_map.insert_endpoint(EndpointOptions {
                    public_key: dm.src,
                    derp_region: Some(region_id),
                    active: true,
                });
                let ep = self.peer_map.by_id_mut(&id).expect("inserted");
                ep.quic_mapped_addr
            }
        };

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
                    if self.handle_derp_disco_message(&part, ipp, dm.src).await {
                        // Message was internal, do not bubble up.
                        debug!("processed internal disco message from {:?}", dm.src);
                        continue;
                    }

                    let meta = quinn_udp::RecvMeta {
                        len: part.len(),
                        stride: part.len(),
                        addr: ep_quic_mapped_addr.0,
                        dst_ip,
                        ecn: None,
                    };
                    out.push(NetworkReadResult::Ok {
                        source: NetworkSource::Derp,
                        bytes: part,
                        meta,
                    });
                }
                Err(e) => {
                    out.push(NetworkReadResult::Error(e));
                }
            }
        }

        out
    }

    /// Split a number of transmits into individual packets.
    ///
    /// For each transmit, if it has a segment size, it will be split into
    /// multiple packets according to that segment size. If it does not have a
    /// segment size, the contents will be sent as a single packet.
    fn split_packets(transmits: Vec<quinn_udp::Transmit>) -> Vec<Bytes> {
        let mut res = Vec::with_capacity(transmits.len());
        for transmit in transmits {
            let contents = transmit.contents;
            if let Some(segment_size) = transmit.segment_size {
                for chunk in contents.chunks(segment_size) {
                    res.push(contents.slice_ref(chunk));
                }
            } else {
                res.push(contents);
            }
        }
        res
    }

    async fn send_network(&mut self, transmits: Vec<quinn_udp::Transmit>) {
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

        if transmits.is_empty() {
            return;
        }
        let current_destination = &transmits[0].destination;
        debug_assert!(
            transmits
                .iter()
                .all(|t| &t.destination == current_destination),
            "mixed destinations"
        );
        let current_destination = QuicMappedAddr(*current_destination);

        match self
            .peer_map
            .endpoint_for_quic_mapped_addr_mut(&current_destination)
        {
            Some(ep) => {
                let public_key = *ep.public_key();
                trace!(
                    "Sending to endpoint for {:?} ({:?})",
                    current_destination,
                    public_key
                );

                let (udp_addr, derp_region, msgs) = ep.get_send_addrs();
                self.handle_ping_actions(msgs).await;
                match (udp_addr, derp_region) {
                    (Some(udp_addr), Some(derp_region)) => {
                        let res = self.send_raw(udp_addr, transmits.clone()).await;
                        self.send_derp(derp_region, public_key, Self::split_packets(transmits));

                        if let Err(err) = res {
                            warn!("failed to send UDP: {:?}", err);
                        }
                    }
                    (None, Some(derp_region)) => {
                        self.send_derp(derp_region, public_key, Self::split_packets(transmits));
                    }
                    (Some(udp_addr), None) => {
                        if let Err(err) = self.send_raw(udp_addr, transmits).await {
                            warn!("failed to send UDP: {:?}", err);
                        }
                    }
                    (None, None) => {
                        warn!("no UDP or DERP addr")
                    }
                }
            }
            None => {
                // TODO: This should not be possible.  We should have errored during the
                // AsyncUdpSocket::poll_send call.
                error!(addr=%current_destination, "no endpoint for mapped address");
            }
        }
    }

    #[instrument(level = "debug", skip_all)]
    fn send_derp(&mut self, region_id: u16, peer: PublicKey, contents: Vec<Bytes>) {
        self.send_derp_actor(DerpActorMessage::Send {
            region_id,
            contents,
            peer,
        });
    }

    /// Triggers an address discovery. The provided why string is for debug logging only.
    #[instrument(level = "debug", skip_all, fields(reason=why))]
    async fn re_stun(&mut self, why: &'static str) {
        inc!(MagicsockMetrics, re_stun_calls);

        if self.endpoints_update_state.is_running() {
            if Some(why) != self.endpoints_update_state.want_update {
                debug!(
                    active_reason=?self.endpoints_update_state.want_update,
                    "endpoint update active, need another later",
                );
                self.endpoints_update_state.want_update.replace(why);
            }
        } else {
            debug!("started");
            self.endpoints_update_state
                .running
                .send(Some(why))
                .expect("update state not to go away");
        }
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

        match self.determine_endpoints().await {
            Ok(endpoints) => {
                if self.set_endpoints(&endpoints).await {
                    log_endpoint_change(&endpoints);
                    if let Some(ref cb) = self.inner.on_endpoints {
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
        if !self.inner.is_closed() {
            if let Some(new_why) = new_why {
                debug!("endpoint update: needed new ({})", new_why);
                self.endpoints_update_state
                    .running
                    .send(Some(new_why))
                    .expect("sender not go away");
                return;
            }
            self.periodic_re_stun_timer = new_re_stun_timer(true);
        }

        self.endpoints_update_state
            .running
            .send(None)
            .expect("sender not go away");

        debug!("endpoint update done ({})", why);
    }

    /// Returns the machine's endpoint addresses. It does a STUN lookup (via netcheck)
    /// to determine its public address.
    #[instrument(level = "debug", skip_all)]
    async fn determine_endpoints(&mut self) -> Result<Vec<config::Endpoint>> {
        self.port_mapper.procure_mapping();
        let portmap_watcher = self.port_mapper.watch_external_address();
        let nr = self.update_net_info().await.context("update_net_info")?;

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

        if !is_unspecified_v4 && local_addr_v4.is_some() {
            // Our local endpoint is bound to a particular address.
            // Do not offer addresses on other local interfaces.
            add_addr!(
                already,
                eps,
                local_addr_v4.unwrap(),
                config::EndpointType::Local
            );
        }

        if !is_unspecified_v6 && local_addr_v6.is_some() {
            // Our local endpoint is bound to a particular address.
            // Do not offer addresses on other local interfaces.
            add_addr!(
                already,
                eps,
                local_addr_v6.unwrap(),
                config::EndpointType::Local
            );
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

        Ok(eps)
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
            let net_info = net_info_last.clone();
            self.call_net_info_callback_locked(net_info);
        }
    }

    /// Calls the NetInfo callback (if previously
    /// registered with SetNetInfoCallback) if ni has substantially changed
    /// since the last state.
    ///
    /// callNetInfoCallback takes ownership of ni.
    #[instrument(level = "debug", skip_all)]
    async fn call_net_info_callback(&mut self, ni: config::NetInfo) {
        if let Some(ref net_info_last) = self.net_info_last {
            if ni.basically_equal(net_info_last) {
                return;
            }
        }

        self.call_net_info_callback_locked(ni);
    }

    #[instrument(level = "debug", skip_all)]
    fn call_net_info_callback_locked(&mut self, ni: config::NetInfo) {
        self.net_info_last = Some(ni.clone());
        if let Some(ref on_net_info) = self.inner.on_net_info {
            debug!("net_info update: {:?}", ni);
            on_net_info(ni);
        }
    }

    #[instrument(level = "debug", skip_all)]
    async fn update_net_info(&mut self) -> Result<Arc<netcheck::Report>> {
        if self.inner.derp_map.is_empty() {
            debug!("skipping netcheck, empty DerpMap");
            return Ok(Default::default());
        }

        let derp_map = self.inner.derp_map.clone();
        let net_checker = &mut self.net_checker;
        let pconn4 = Some(self.pconn4.as_socket());
        let pconn6 = self.pconn6.as_ref().map(|p| p.as_socket());

        debug!("requesting netcheck report");
        let report = time::timeout(Duration::from_secs(10), async move {
            net_checker.get_report(derp_map, pconn4, pconn6).await
        })
        .await??;
        self.inner
            .ipv6_reported
            .store(report.ipv6, Ordering::Relaxed);
        let r = &report;
        debug!(
            "setting no_v4_send {} -> {}",
            self.no_v4_send, !r.ipv4_can_send
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
            preferred_derp: r.preferred_derp,
            link_type: None,
        };
        for (rid, d) in r.region_v4_latency.iter() {
            ni.derp_latency.insert(format!("{rid}-v4"), d.as_secs_f64());
        }
        for (rid, d) in r.region_v6_latency.iter() {
            ni.derp_latency.insert(format!("{rid}-v6"), d.as_secs_f64());
        }

        if ni.preferred_derp == 0 {
            // Perhaps UDP is blocked. Pick a deterministic but arbitrary one.
            ni.preferred_derp = self.pick_derp_fallback().await;
        }

        if !self.set_nearest_derp(ni.preferred_derp).await {
            ni.preferred_derp = 0;
        }

        // TODO: set link type
        self.call_net_info_callback(ni).await;

        Ok(report)
    }

    async fn set_nearest_derp(&mut self, derp_num: u16) -> bool {
        {
            let my_derp = self.inner.my_derp();
            if derp_num == my_derp {
                // No change.
                return true;
            }
            if my_derp != 0 && derp_num != 0 {
                inc!(MagicsockMetrics, derp_home_change);
            }
            self.inner.set_my_derp(derp_num);

            // On change, notify all currently connected DERP servers and
            // start connecting to our home DERP if we are not already.
            match self.inner.derp_map.get_region(derp_num) {
                Some(dr) => {
                    info!("home is now derp-{} ({})", derp_num, dr.region_code);
                }
                None => {
                    warn!("derp_map.regions[{}] is empty", derp_num);
                }
            }
        }

        let my_derp = self.inner.my_derp();
        self.send_derp_actor(DerpActorMessage::NotePreferred(my_derp));
        self.send_derp_actor(DerpActorMessage::Connect {
            region_id: derp_num,
            peer: None,
        });
        true
    }

    /// Returns a deterministic DERP node to connect to. This is only used if netcheck
    /// couldn't find the nearest one, for instance, if UDP is blocked and thus STUN
    /// latency checks aren't working.
    ///
    /// If no the [`DerpMap`] is empty, returns `0`.
    async fn pick_derp_fallback(&self) -> u16 {
        let ids = {
            let ids = self.inner.derp_map.region_ids();
            if ids.is_empty() {
                // No DERP regions in map.
                return 0;
            }
            ids
        };

        // TODO: figure out which DERP region most of our peers are using,
        // and use that region as our fallback.
        //
        // If we already had selected something in the past and it has any
        // peers, we want to stay on it. If there are no peers at all,
        // stay on whatever DERP we previously picked. If we need to pick
        // one and have no peer info, pick a region randomly.
        //
        // We used to do the above for legacy clients, but never updated it for disco.

        let my_derp = self.inner.my_derp();
        if my_derp > 0 {
            return my_derp;
        }

        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        *ids.choose(&mut rng).unwrap()
    }

    /// Records the new endpoints, reporting whether they're changed.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    async fn set_endpoints(&mut self, endpoints: &[config::Endpoint]) -> bool {
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

    #[instrument(skip_all, fields(me = %self.inner.me))]
    async fn enqueue_call_me_maybe(&mut self, derp_region: u16, endpoint_id: usize) {
        let endpoint = self.peer_map.by_id(&endpoint_id);
        if endpoint.is_none() {
            warn!(
                "enqueue_call_me_maybe with invalid endpoint_id called: {} - {}",
                derp_region, endpoint_id
            );
            return;
        }
        let endpoint = endpoint.unwrap();
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
                endpoint_id,
                Box::new(move || {
                    let msg_sender = msg_sender.clone();
                    Box::pin(async move {
                        info!("STUN done; sending call-me-maybe",);
                        msg_sender
                            .send(ActorMessage::EnqueueCallMeMaybe {
                                derp_region,
                                endpoint_id,
                            })
                            .await
                            .unwrap();
                    })
                }),
            );

            self.msg_sender
                .send(ActorMessage::ReStun("refresh-for-peering"))
                .await
                .unwrap();
        } else {
            let public_key = *endpoint.public_key();
            let eps: Vec<_> = self.last_endpoints.iter().map(|ep| ep.addr).collect();
            let msg = disco::CallMeMaybe { my_number: eps };

            let msg_sender = self.msg_sender.clone();
            tokio::task::spawn(async move {
                warn!("sending call me maybe to {public_key:?}");
                if let Err(err) = msg_sender
                    .send(ActorMessage::SendCallMeMaybe {
                        dst: SendAddr::Derp(derp_region),
                        dst_key: public_key,
                        msg,
                    })
                    .await
                {
                    warn!("failed to send disco message to {}: {:?}", derp_region, err);
                }
            });
        }
    }

    #[instrument(skip_all, fields(me = %self.inner.me))]
    async fn rebind_all(&mut self) {
        inc!(MagicsockMetrics, rebind_calls);
        if let Err(err) = self.rebind(CurrentPortFate::Keep).await {
            debug!("{:?}", err);
            return;
        }

        let ifs = Default::default(); // TODO: load actual interfaces from the monitor
        self.send_derp_actor(DerpActorMessage::MaybeCloseDerpsOnRebind(ifs));
        self.reset_endpoint_states();
    }

    /// Resets the preferred address for all peers.
    /// This is called when connectivity changes enough that we no longer trust the old routes.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    fn reset_endpoint_states(&mut self) {
        for (_, ep) in self.peer_map.endpoints_mut() {
            ep.note_connectivity_change();
        }
    }

    /// Closes and re-binds the UDP sockets.
    /// We consider it successful if we manage to bind the IPv4 socket.
    #[instrument(skip_all, fields(me = %self.inner.me))]
    async fn rebind(&mut self, cur_port_fate: CurrentPortFate) -> Result<()> {
        let mut ipv6_addr = None;

        // TODO: rebind does not update the cloned connections in IpStream (and other places)
        // Need to send a message to do so, after successfull changes.

        if let Some(ref mut conn) = self.pconn6 {
            let port = conn.port();
            trace!("IPv6 rebind {} {:?}", port, cur_port_fate);
            // If we were not able to bind ipv6 at program start, dont retry
            if let Err(err) = conn.rebind(port, Network::Ipv6, cur_port_fate).await {
                info!("rebind ignoring IPv6 bind failure: {:?}", err);
            } else {
                ipv6_addr = conn.local_addr().ok();
            }
        }

        let port = self.local_port_v4();
        self.pconn4
            .rebind(port, Network::Ipv4, cur_port_fate)
            .await
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

    #[instrument(skip_all)]
    async fn send_disco_message(
        &mut self,
        dst: SendAddr,
        dst_key: PublicKey,
        msg: disco::Message,
    ) -> Result<bool> {
        debug!("sending disco message to {}: {:?}", dst, msg);
        if self.inner.is_closed() {
            bail!("connection closed");
        }
        let di = get_disco_info(&mut self.disco_info, &self.inner.secret_key, &dst_key);
        let mut seal = msg.as_bytes();
        di.shared_key.seal(&mut seal);

        let is_derp = dst.is_derp();
        if is_derp {
            inc!(MagicsockMetrics, send_disco_derp);
        } else {
            inc!(MagicsockMetrics, send_disco_udp);
        }

        let pkt = disco::encode_message(&self.inner.public_key(), seal);
        let sent = self.send_addr(dst, Some(&dst_key), pkt.into()).await;
        match sent {
            Ok(0) => {
                // Can't send. (e.g. no IPv6 locally)
                warn!("disco: failed to send {:?} to {}", msg, dst);
                Ok(false)
            }
            Ok(_n) => {
                debug!("disco: sent message to {}", dst);
                if is_derp {
                    inc!(MagicsockMetrics, sent_disco_derp);
                } else {
                    inc!(MagicsockMetrics, sent_disco_udp);
                }
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
                Ok(true)
            }
            Err(err) => {
                warn!("disco: failed to send {:?} to {}: {:?}", msg, dst, err);
                Err(err.into())
            }
        }
    }

    /// Sends either to UDP or DERP, depending on the IP.
    #[instrument(skip_all)]
    async fn send_addr(
        &mut self,
        addr: SendAddr,
        pub_key: Option<&PublicKey>,
        pkt: Bytes,
    ) -> io::Result<usize> {
        match addr {
            SendAddr::Udp(addr) => {
                let transmits = vec![quinn_udp::Transmit {
                    destination: addr,
                    contents: pkt,
                    ecn: None,
                    segment_size: None,
                    src_ip: None, // TODO
                }];
                self.send_raw(addr, transmits).await
            }
            SendAddr::Derp(region) => match pub_key {
                None => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "missing pub key for derp route",
                )),
                Some(pub_key) => {
                    self.send_derp(region, *pub_key, vec![pkt]);
                    Ok(1)
                }
            },
        }
    }

    async fn handle_derp_disco_message(
        &mut self,
        msg: &[u8],
        src: SendAddr,
        derp_node_src: PublicKey,
    ) -> bool {
        match disco::source_and_box(msg) {
            Some((source, sealed_box)) => {
                self.handle_disco_message(source, sealed_box, src, Some(derp_node_src))
                    .await
            }
            None => false,
        }
    }

    /// Handles a discovery message and reports whether `msg`f was a Tailscale inter-node discovery message.
    ///
    /// For messages received over DERP, the src.ip() will be DERP_MAGIC_IP (with src.port() being the region ID) and the
    /// derp_node_src will be the node key it was received from at the DERP layer. derp_node_src is None when received over UDP.
    #[instrument(skip_all)]
    async fn handle_disco_message(
        &mut self,
        sender: PublicKey,
        sealed_box: &[u8],
        src: SendAddr,
        derp_node_src: Option<PublicKey>,
    ) -> bool {
        debug!("handle_disco_message start {} - {:?}", src, derp_node_src);
        if self.inner.is_closed() {
            return true;
        }

        let mut unknown_sender = false;
        if self.peer_map.endpoint_for_node_key(&sender).is_none() {
            unknown_sender = match src {
                SendAddr::Udp(addr) => self.peer_map.endpoint_for_ip_port_mut(addr).is_none(),
                SendAddr::Derp(_) => true,
            };
        }

        if unknown_sender {
            // Disco Ping from unseen endpoint. We will have to add the
            // endpoint later if the message is a ping
            info!("disco: unknown sender {:?} - {}", sender, src);
        }

        // We're now reasonably sure we're expecting communication from
        // this peer, do the heavy crypto lifting to see what they want.

        let di = get_disco_info(&mut self.disco_info, &self.inner.secret_key, &sender);
        let mut sealed_box = sealed_box.to_vec();
        let payload = di.shared_key.open(&mut sealed_box);
        if payload.is_err() {
            // This could happen if we changed the key between restarts.
            warn!(
                "disco: [{:?}] failed to open box from {:?} (wrong rcpt?) {:?}",
                self.inner.public_key(),
                sender,
                payload,
            );
            inc!(MagicsockMetrics, recv_disco_bad_key);
            return true;
        }
        let dm = disco::Message::from_bytes(&sealed_box);
        debug!("disco: disco.parse = {:?}", dm);

        if dm.is_err() {
            // Couldn't parse it, but it was inside a correctly
            // signed box, so just ignore it, assuming it's from a
            // newer version of Tailscale that we don't
            // understand. Not even worth logging about, lest it
            // be too spammy for old clients.

            inc!(MagicsockMetrics, recv_disco_bad_parse);
            return true;
        }

        let dm = dm.unwrap();
        let is_derp = src.is_derp();
        if is_derp {
            inc!(MagicsockMetrics, recv_disco_derp);
        } else {
            inc!(MagicsockMetrics, recv_disco_udp);
        }

        debug!("got disco message: {:?}", dm);
        match dm {
            disco::Message::Ping(ping) => {
                inc!(MagicsockMetrics, recv_disco_ping);
                // if we get here we got a valid ping from an unknown sender
                // so insert an endpoint for them
                if unknown_sender {
                    warn!(
                        "unknown sender: {:?} with region id {:?}",
                        sender,
                        src.derp_region()
                    );
                    self.peer_map.insert_endpoint(EndpointOptions {
                        public_key: sender,
                        derp_region: src.derp_region(),
                        active: true,
                    });
                }
                self.handle_ping(ping, &sender, src, derp_node_src).await;
                true
            }
            disco::Message::Pong(pong) => {
                inc!(MagicsockMetrics, recv_disco_pong);
                if let Some(ep) = self.peer_map.endpoint_for_node_key_mut(&sender) {
                    let insert = ep
                        .handle_pong_conn(&self.inner.public_key(), &pong, di, src)
                        .await;
                    if let Some((src, key)) = insert {
                        self.peer_map.set_node_key_for_ip_port(src, &key);
                    }
                }
                true
            }
            disco::Message::CallMeMaybe(cm) => {
                inc!(MagicsockMetrics, recv_disco_call_me_maybe);
                if !is_derp || derp_node_src.is_none() {
                    // CallMeMaybe messages should only come via DERP.
                    debug!("[unexpected] CallMeMaybe packets should only come via DERP");
                    return true;
                }
                let node_key = derp_node_src.unwrap();
                match self.peer_map.endpoint_for_node_key_mut(&node_key) {
                    None => {
                        inc!(MagicsockMetrics, recv_disco_call_me_maybe_bad_disco);
                        debug!(
                            "disco: ignoring CallMeMaybe from {:?}; {:?} is unknown",
                            sender, node_key,
                        );
                    }
                    Some(ep) => {
                        info!(
                            "disco: {:?}<-{:?} ({:?})  got call-me-maybe, {} endpoints",
                            self.inner.public_key(),
                            ep.public_key(),
                            src,
                            cm.my_number.len()
                        );
                        ep.handle_call_me_maybe(cm).await;
                    }
                }
                true
            }
        }
    }

    /// di is the DiscoInfo of the source of the ping.
    /// derp_node_src is non-zero if the ping arrived via DERP.
    #[instrument(skip_all)]
    async fn handle_ping(
        &mut self,
        dm: disco::Ping,
        sender: &PublicKey,
        src: SendAddr,
        derp_node_src: Option<PublicKey>,
    ) {
        let di = get_disco_info(&mut self.disco_info, &self.inner.secret_key, sender);
        let likely_heart_beat = Some(src) == di.last_ping_from
            && di
                .last_ping_time
                .map(|s| s.elapsed() < Duration::from_secs(5))
                .unwrap_or_default();
        di.last_ping_from.replace(src);
        di.last_ping_time.replace(Instant::now());
        // If we got a ping over DERP, then derp_node_src is non-zero and we reply
        // over DERP (in which case ip_dst is also a DERP address).
        // But if the ping was over UDP (ip_dst is not a DERP address), then dst_key
        // will be zero here, but that's fine: send_disco_message only requires
        // a dstKey if the dst ip:port is DERP.

        let dst_key = match derp_node_src {
            Some(dst_key) => {
                if !src.is_derp() {
                    error!(%src, from=%sender.fmt_short(), "ignoring ping reported both as direct and relayed");
                    return debug_assert!(false, "`derp_node_src` is some but `src` is not derp");
                }
                dst_key
            }
            None => {
                if src.is_derp() {
                    error!(%src, from=%sender.fmt_short(), "ignoring ping reported both as direct and relayed");
                    return debug_assert!(false, "`derp_node_src` is none but `src` is derp");
                }
                di.node_key
            }
        };

        if let Some(ep) = self.peer_map.endpoint_for_node_key_mut(&dst_key) {
            if ep.endpoint_confirmed(src, dm.tx_id) {
                debug!("disco: ping got duplicate endpoint {} - {}", src, dm.tx_id);
                return;
            }
            if let SendAddr::Udp(addr) = src {
                self.peer_map.set_node_key_for_ip_port(addr, &dst_key);
            }
        }

        if !likely_heart_beat {
            info!(
                "disco: {:?}<-{:?} ({dst_key:?}, {src:?})  got ping tx={:?}",
                self.inner.public_key(),
                di.node_key,
                dm.tx_id
            );
        }

        let ip_dst = src;
        let pong = disco::Message::Pong(disco::Pong {
            tx_id: dm.tx_id,
            src: src.as_socket_addr(),
        });
        if let Err(err) = self.send_disco_message(ip_dst, dst_key, pong).await {
            warn!("disco: failed to send message to {ip_dst}: {err:?}");
        }
    }

    #[instrument(skip_all)]
    fn add_known_addr(&mut self, peer_addr: PeerAddr) {
        self.peer_map.add_peer_addr(peer_addr)
    }

    /// Returns the current IPv4 listener's port number.
    fn local_port_v4(&self) -> u16 {
        self.pconn4.port()
    }

    #[instrument(skip_all)]
    async fn send_raw(
        &self,
        addr: SocketAddr,
        mut transmits: Vec<quinn_udp::Transmit>,
    ) -> io::Result<usize> {
        debug!("send_raw: {} packets", transmits.len());

        if addr.is_ipv6() && self.pconn6.is_none() {
            return Err(io::Error::new(io::ErrorKind::Other, "no IPv6 connection"));
        }

        let conn = if addr.is_ipv6() {
            self.pconn6.as_ref().unwrap()
        } else {
            &self.pconn4
        };

        if transmits.iter().any(|t| t.destination != addr) {
            for t in &mut transmits {
                t.destination = addr;
            }
        }
        let sum =
            futures::future::poll_fn(|cx| conn.poll_send(&self.udp_state, cx, &transmits)).await?;
        let total_bytes: u64 = transmits
            .iter()
            .take(sum)
            .map(|x| x.contents.len() as u64)
            .sum();
        if addr.is_ipv6() {
            inc_by!(MagicsockMetrics, send_ipv6, total_bytes);
        } else {
            inc_by!(MagicsockMetrics, send_ipv4, total_bytes);
        }

        debug!("sent {} packets to {}", sum, addr);
        debug_assert!(
            sum <= transmits.len(),
            "too many msgs {} > {}",
            sum,
            transmits.len()
        );

        Ok(sum)
    }
}

/// Returns the previous or new DiscoInfo for `k`.
fn get_disco_info<'a>(
    disco_info: &'a mut HashMap<PublicKey, DiscoInfo>,
    node_private: &SecretKey,
    k: &PublicKey,
) -> &'a mut DiscoInfo {
    if !disco_info.contains_key(k) {
        let shared_key = node_private.shared(k);
        disco_info.insert(
            *k,
            DiscoInfo {
                node_key: *k,
                shared_key,
                last_ping_from: None,
                last_ping_time: None,
            },
        );
    }

    disco_info.get_mut(k).unwrap()
}

fn new_re_stun_timer(initial_delay: bool) -> time::Interval {
    // Pick a random duration between 20 and 26 seconds (just under 30s,
    // a common UDP NAT timeout on Linux,etc)
    let mut rng = rand::thread_rng();
    let d: Duration = rng.gen_range(Duration::from_secs(20)..=Duration::from_secs(26));
    debug!("scheduling periodic_stun to run in {}s", d.as_secs());
    if initial_delay {
        time::interval_at(time::Instant::now() + d, d)
    } else {
        time::interval(d)
    }
}

/// Initial connection setup.
async fn bind(port: u16) -> Result<(RebindingUdpConn, Option<RebindingUdpConn>)> {
    let ip6_port = if port != 0 { port + 1 } else { 0 };
    let pconn6 = match RebindingUdpConn::bind(ip6_port, Network::Ipv6).await {
        Ok(conn) => Some(conn),
        Err(err) => {
            info!("rebind ignoring IPv6 bind failure: {:?}", err);
            None
        }
    };

    let pconn4 = RebindingUdpConn::bind(port, Network::Ipv4)
        .await
        .context("rebind IPv4 failed")?;

    Ok((pconn4, pconn6))
}

fn log_endpoint_change(endpoints: &[config::Endpoint]) {
    debug!("endpoints changed: {}", {
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

/// Addresses to which to which we can send. This is either a UDP or a derp address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SendAddr {
    /// UDP, the ip addr.
    Udp(SocketAddr),
    /// Derp, region id.
    Derp(u16),
}

impl SendAddr {
    fn is_derp(&self) -> bool {
        matches!(self, Self::Derp(_))
    }

    fn derp_region(&self) -> Option<u16> {
        match self {
            Self::Derp(region) => Some(*region),
            Self::Udp(_) => None,
        }
    }

    /// Returns the mapped version or the actual `SocketAddr`.
    fn as_socket_addr(&self) -> SocketAddr {
        match self {
            Self::Derp(region) => SocketAddr::new(DERP_MAGIC_IP, *region),
            Self::Udp(addr) => *addr,
        }
    }
}

impl PartialEq<SocketAddr> for SendAddr {
    fn eq(&self, other: &SocketAddr) -> bool {
        match self {
            Self::Derp(_) => false,
            Self::Udp(addr) => addr.eq(other),
        }
    }
}

impl Display for SendAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendAddr::Derp(id) => write!(f, "Derp({})", id),
            SendAddr::Udp(addr) => write!(f, "UDP({})", addr),
        }
    }
}

/// A simple iterator to group [`Transmit`]s by destination.
///
/// [`Transmit`]: quinn_udp::Transmit
struct TransmitIter<'a> {
    transmits: &'a [quinn_udp::Transmit],
    offset: usize,
}

impl<'a> TransmitIter<'a> {
    fn new(transmits: &'a [quinn_udp::Transmit]) -> Self {
        TransmitIter {
            transmits,
            offset: 0,
        }
    }
}

impl Iterator for TransmitIter<'_> {
    type Item = Vec<quinn_udp::Transmit>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.transmits.len() {
            return None;
        }
        let current_dest = &self.transmits[self.offset].destination;
        let mut end = self.offset;
        for t in &self.transmits[self.offset..] {
            if current_dest != &t.destination {
                break;
            }
            end += 1;
        }

        let out = self.transmits[self.offset..end].to_vec();
        self.offset = end;
        Some(out)
    }
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

/// The fake address used by the QUIC layer to address a peer.
///
/// You can consider this as nothing more than a lookup key for a peer the [`MagicSock`] knows
/// about.
///
/// [`MagicSock`] can reach a peer by several real socket addresses, or maybe even via the derper
/// relay.  The QUIC layer however needs to address a peer by a stable [`SocketAddr`] so
/// that normal socket APIs can function.  Thus when a new peer is introduced to a [`MagicSock`]
/// it is given a new fake address.  This is the type of that address.
///
/// It is but a newtype.  And in our QUIC-facing socket APIs like [`AsyncUdpSocket`] it
/// comes in as the inner [`SocketAddr`], in those interfaces we have to be careful to do
/// the conversion to this type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub(crate) struct QuicMappedAddr(SocketAddr);

/// Counter to always generate unique addresses for [`QuicMappedAddr`].
static ADDR_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[cfg(test)]
pub(crate) mod tests {
    use anyhow::Context;
    use rand::RngCore;
    use std::net::Ipv4Addr;
    use tokio::{net, sync, task::JoinSet};
    use tracing::{debug_span, Instrument};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::*;
    use crate::{derp::DerpMode, test_utils::run_derper, tls, MagicEndpoint};

    fn make_transmit(destination: SocketAddr) -> quinn_udp::Transmit {
        quinn_udp::Transmit {
            destination,
            ecn: None,
            contents: destination.to_string().into(),
            segment_size: None,
            src_ip: None,
        }
    }

    #[test]
    fn test_transmit_iter() {
        let transmits = vec![
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 2)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 3)),
        ];

        let groups: Vec<_> = TransmitIter::new(&transmits).collect();
        dbg!(&groups);
        assert_eq!(groups.len(), 4);
        assert_eq!(groups[0].len(), 1);
        assert_eq!(groups[1].len(), 2);
        assert_eq!(groups[2].len(), 1);
        assert_eq!(groups[3].len(), 2);

        let transmits = vec![
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1)),
            make_transmit(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 1)),
        ];

        let groups: Vec<_> = TransmitIter::new(&transmits).collect();
        dbg!(&groups);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

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
        ep_ch: flume::Receiver<Vec<config::Endpoint>>,
        secret_key: SecretKey,
        endpoint: MagicEndpoint,
    }

    const ALPN: [u8; 9] = *b"n0/test/1";

    impl MagicStack {
        async fn new(derp_map: DerpMap) -> Result<Self> {
            let (on_derp_s, mut on_derp_r) = mpsc::channel(8);
            let (ep_s, ep_r) = flume::bounded(16);

            let secret_key = SecretKey::generate();

            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            let endpoint = MagicEndpoint::builder()
                .secret_key(secret_key.clone())
                .on_endpoints(Box::new(move |eps: &[config::Endpoint]| {
                    let _ = ep_s.send(eps.to_vec());
                }))
                .on_derp_active(Box::new(move || {
                    on_derp_s.try_send(()).ok();
                }))
                .transport_config(transport_config)
                .derp_mode(DerpMode::Custom(derp_map))
                .alpns(vec![ALPN.to_vec()])
                .bind(0)
                .await?;

            tokio::time::timeout(Duration::from_secs(10), on_derp_r.recv())
                .await
                .context("wait for derp connection")?;

            Ok(Self {
                ep_ch: ep_r,
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
    async fn mesh_stacks(stacks: Vec<MagicStack>) -> Result<impl FnOnce()> {
        async fn update_eps(ms: &[MagicStack], my_idx: usize, new_eps: Vec<config::Endpoint>) {
            let me = &ms[my_idx];
            for (i, m) in ms.iter().enumerate() {
                if i == my_idx {
                    continue;
                }
                let addr = PeerAddr {
                    peer_id: me.public(),
                    info: crate::AddrInfo {
                        derp_region: Some(1),
                        direct_addresses: new_eps.iter().map(|ep| ep.addr).collect(),
                    },
                };
                let _ = m.endpoint.magic_sock().add_peer_addr(addr).await;
            }
        }

        let mut tasks = JoinSet::new();

        for (my_idx, m) in stacks.iter().enumerate() {
            let m = m.clone();
            let stacks = stacks.clone();
            tasks.spawn(async move {
                loop {
                    tokio::select! {
                        res = m.ep_ch.recv_async() => match res {
                            Ok(new_eps) => {
                                debug!("conn{} endpoints update: {:?}", my_idx + 1, new_eps);
                                update_eps(&stacks, my_idx, new_eps).await;
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

    pub fn setup_multithreaded_logging() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_roundtrip_quinn_magic() -> Result<()> {
        setup_multithreaded_logging();
        let (derp_map, region, _cleanup) = run_derper().await?;

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
                println!("[{}] {:?}", a_name, a.endpoint.local_addr());
                println!("[{}] {:?}", b_name, b.endpoint.local_addr());

                let a_addr = b.endpoint.magic_sock().get_mapping_addr(&a.public()).await.unwrap();
                let b_addr = a.endpoint.magic_sock().get_mapping_addr(&b.public()).await.unwrap();
                let b_peer_id = b.endpoint.peer_id();

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
                async move {
                    println!("[{}] connecting to {}", a_name, b_addr);
                    let peer_b_data = PeerAddr::new(b_peer_id).with_derp_region(region).with_direct_addresses([b_addr]);
                    let conn = a
                        .endpoint
                        .connect(peer_b_data, &ALPN)
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

        for i in 0..10 {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_two_devices_setup_teardown() -> Result<()> {
        setup_multithreaded_logging();
        for _ in 0..10 {
            let (derp_map, _, _cleanup) = run_derper().await?;
            println!("setting up magic stack");
            let m1 = MagicStack::new(derp_map.clone()).await?;
            let m2 = MagicStack::new(derp_map.clone()).await?;

            let cleanup_mesh = mesh_stacks(vec![m1.clone(), m2.clone()]).await?;

            // Wait for magicsock to be told about peers from mesh_stacks.
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
                }
            })
            .await
            .context("failed to connect peers")?;

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

        let m1 = make_conn("127.0.0.1:8770".parse().unwrap())?;
        let m2 = make_conn("127.0.0.1:8771".parse().unwrap())?;

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

        async fn make_conn(addr: SocketAddr) -> anyhow::Result<quinn::Endpoint> {
            let key = SecretKey::generate();
            let conn = RebindingUdpConn::bind(addr.port(), addr.ip().into()).await?;

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

        let m1 = make_conn("127.0.0.1:7770".parse().unwrap()).await?;
        let m2 = make_conn("127.0.0.1:7771".parse().unwrap()).await?;

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
    fn split_packets() {
        fn mk_transmit(contents: &[u8], segment_size: Option<usize>) -> quinn_udp::Transmit {
            let destination = "127.0.0.1:12345".parse().unwrap();
            quinn_udp::Transmit {
                destination,
                ecn: None,
                contents: contents.to_vec().into(),
                segment_size,
                src_ip: None,
            }
        }
        fn mk_expected(parts: impl IntoIterator<Item = &'static str>) -> Vec<Bytes> {
            parts
                .into_iter()
                .map(|p| p.as_bytes().to_vec().into())
                .collect()
        }
        // no packets
        assert_eq!(Actor::split_packets(vec![]), Vec::<Bytes>::default());
        // no split
        assert_eq!(
            Actor::split_packets(vec![
                mk_transmit(b"hello", None),
                mk_transmit(b"world", None)
            ]),
            mk_expected(["hello", "world"])
        );
        // split without rest
        assert_eq!(
            Actor::split_packets(vec![mk_transmit(b"helloworld", Some(5)),]),
            mk_expected(["hello", "world"])
        );
        // split with rest and second transmit
        assert_eq!(
            Actor::split_packets(vec![
                mk_transmit(b"hello world", Some(5)),
                mk_transmit(b"!", None)
            ]),
            mk_expected(["hello", " worl", "d", "!"])
        );
        // split that results in 1 packet
        assert_eq!(
            Actor::split_packets(vec![
                mk_transmit(b"hello world", Some(1000)),
                mk_transmit(b"!", None)
            ]),
            mk_expected(["hello world", "!"])
        );
    }
}
