//! Implements a socket that can change its communication path while in use, actively searching for the best way to communicate.
//!
//!
//! ### `RelayOnly` path selection:
//! When set this will force all packets to be sent over
//! the relay connection, regardless of whether or
//! not we have a direct UDP address for the given endpoint.
//!
//! The intended use is for testing the relay protocol inside the Socket
//! to ensure that we can rely on the relay to send packets when two endpoints
//! are unable to find direct UDP connections to each other.
//!
//! This also prevent this endpoint from attempting to hole punch and prevents it
//! from responding to any hole punching attempts. This endpoint will still,
//! however, read any packets that come off the UDP sockets.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    future::poll_fn,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use iroh_base::{EndpointAddr, EndpointId, PublicKey, RelayUrl, SecretKey, TransportAddr};
use iroh_relay::{RelayConfig, RelayMap};
use n0_error::{bail, e, stack_error};
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{self, Duration, Instant},
};
use n0_watcher::{self, Watchable, Watcher};
#[cfg(not(wasm_browser))]
use netwatch::ip::LocalAddresses;
use netwatch::netmon;
use quinn::WeakConnectionHandle;
use rand::Rng;
use tokio::sync::{
    Mutex as AsyncMutex,
    mpsc::{self},
    oneshot,
};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Level, debug, event, info_span, instrument, trace, warn};
use transports::{LocalAddrsWatch, Transport, TransportConfig};
use url::Url;

use self::{
    remote_map::{RemoteMap, RemoteStateMessage},
    transports::{RelayActorConfig, Transports},
};
#[cfg(not(wasm_browser))]
use crate::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use crate::net_report::QuicConfig;
use crate::{
    address_lookup::{self, AddressLookup, EndpointData, Error as AddressLookupError, UserData},
    defaults::timeouts::NET_REPORT_TIMEOUT,
    endpoint::hooks::EndpointHooksList,
    metrics::EndpointMetrics,
    net_report::{self, IfStateDetails, Report},
    socket::{
        concurrent_read_map::ReadOnlyMap,
        remote_map::{MappedAddrs, PathsWatcher, RemoteInfo},
    },
};

mod metrics;

pub(crate) mod concurrent_read_map;
pub(crate) mod mapped_addrs;
pub(crate) mod remote_map;
pub(crate) mod transports;

use self::mapped_addrs::{EndpointIdMappedAddr, MappedAddr};
pub use self::{metrics::Metrics, remote_map::PathInfo};

// TODO: Use this
// /// How long we consider a QAD-derived endpoint valid for. UDP NAT mappings typically
// /// expire at 30 seconds, so this is a few seconds shy of that.
// const ENDPOINTS_FRESH_ENOUGH_DURATION: Duration = Duration::from_secs(27);

/// The duration in which we send keep-alives.
///
/// If a path is idle for this long, a PING frame will be sent to keep the connection
/// alive.
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// The maximum time a path can stay idle before being closed.
///
/// This is [`HEARTBEAT_INTERVAL`] + 1.5s.  This gives us a chance to send a PING frame and
/// some retries.
pub(crate) const PATH_MAX_IDLE_TIMEOUT: Duration = Duration::from_millis(6500);

/// Maximum number of concurrent QUIC multipath paths per connection.
///
/// Pretty arbitrary and high right now.
pub(crate) const MAX_MULTIPATH_PATHS: u32 = 12;

/// Error returned when the endpoint state actor stopped while waiting for a reply.
#[stack_error(add_meta, derive)]
#[error("endpoint state actor stopped")]
#[derive(Clone)]
pub(crate) struct RemoteStateActorStoppedError;

impl From<mpsc::error::SendError<RemoteStateMessage>> for RemoteStateActorStoppedError {
    #[track_caller]
    fn from(_value: mpsc::error::SendError<RemoteStateMessage>) -> Self {
        Self::new()
    }
}

/// Contains options for `Socket::listen`.
#[derive(derive_more::Debug)]
pub(crate) struct Options {
    /// The configuration for the different transports.
    pub(crate) transports: Vec<TransportConfig>,

    /// Secret key for this endpoint.
    pub(crate) secret_key: SecretKey,

    /// Optional user-defined Address Lookup data.
    pub(crate) address_lookup_user_data: Option<UserData>,

    /// A DNS resolver to use for resolving relay URLs.
    ///
    /// You can use [`crate::dns::DnsResolver::new`] for a resolver
    /// that uses the system's DNS configuration.
    #[cfg(not(wasm_browser))]
    pub(crate) dns_resolver: DnsResolver,

    /// Proxy configuration.
    pub(crate) proxy_url: Option<Url>,

    /// ServerConfig for the internal QUIC endpoint
    pub(crate) server_config: quinn_proto::ServerConfig,

    /// Skip verification of SSL certificates from relay servers
    ///
    /// May only be used in tests.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) insecure_skip_relay_cert_verify: bool,
    pub(crate) metrics: EndpointMetrics,
    pub(crate) hooks: EndpointHooksList,
}

/// Handle for [`Socket`].
///
/// Dereferences to [`Socket`], and handles closing.
#[derive(Clone, Debug, derive_more::Deref)]
pub(crate) struct Handle {
    #[deref(forward)]
    sock: Arc<Socket>,
    // empty when shutdown
    actor_task: Arc<Mutex<Option<AbortOnDropHandle<()>>>>,
    /// Channel to send to the internal actor.
    actor_sender: mpsc::Sender<ActorMessage>,
    // quinn endpoint
    endpoint: quinn::Endpoint,
}

#[derive(Debug)]
struct ShutdownState {
    at_close_start: CancellationToken,
    at_endpoint_closed: CancellationToken,
    closed: AtomicBool,
}

impl Default for ShutdownState {
    fn default() -> Self {
        Self {
            at_close_start: CancellationToken::new(),
            at_endpoint_closed: CancellationToken::new(),
            closed: AtomicBool::new(false),
        }
    }
}

impl ShutdownState {
    fn is_closing(&self) -> bool {
        self.at_close_start.is_cancelled()
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// Iroh connectivity layer.
///
/// This is responsible for routing packets to endpoints based on endpoint IDs, it will initially
/// route packets via a relay and transparently try and establish an endpoint-to-endpoint
/// connection and upgrade to it.  It will also keep looking for better connections as the
/// network details of both endpoints change.
///
/// It is usually only necessary to use a single [`Socket`] instance in an application, it
/// means any QUIC endpoints on top will be sharing as much information about endpoints as
/// possible.
#[derive(Debug)]
pub(crate) struct Socket {
    /// Channels for sending time-crucial messages to `RemoteStateActors`.
    ///
    /// Currently only exists to support sending `SendDatagram` messages.
    remote_actors: ReadOnlyMap<EndpointId, mpsc::Sender<RemoteStateMessage>>,

    /// EndpointId of this endpoint.
    public_key: PublicKey,

    // - Shutdown Management
    shutdown: ShutdownState,

    // - Networking Info
    /// Our discovered direct addresses.
    direct_addrs: DiscoveredDirectAddrs,
    /// Our latest net-report
    net_report: Watchable<(Option<Report>, UpdateReason)>,
    /// If the last net_report report, reports IPv6 to be available.
    ipv6_reported: Arc<AtomicBool>,
    /// Maps for resolving mapped addrs to/from IP and relay addresses.
    mapped_addrs: MappedAddrs,

    /// Local addresses
    local_addrs_watch: LocalAddrsWatch,
    /// Currently bound IP addresses of all sockets
    #[cfg(not(wasm_browser))]
    ip_bind_addrs: Vec<SocketAddr>,
    /// The DNS resolver to be used in this socket.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    relay_map: RelayMap,

    /// Optional Address Lookup
    address_lookup: address_lookup::ConcurrentAddressLookup,
    /// Optional user-defined discover data.
    address_lookup_user_data: RwLock<Option<UserData>>,

    /// Metrics
    pub(crate) metrics: EndpointMetrics,
    pub(crate) hooks: EndpointHooksList,
}

impl Socket {
    /// Creates a [`Socket`] listening.
    pub(crate) async fn spawn(opts: Options) -> Result<Handle, BindError> {
        Handle::new(opts).await
    }

    /// Returns the relay endpoint we are connected to, that has the best latency.
    ///
    /// If `None`, then we are not connected to any relay endpoints.
    pub(crate) fn my_relay(&self) -> Option<RelayUrl> {
        self.local_addr().into_iter().find_map(|a| {
            if let transports::Addr::Relay(url, _) = a {
                Some(url)
            } else {
                None
            }
        })
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.shutdown.is_closed()
    }

    fn is_closing(&self) -> bool {
        self.shutdown.is_closing()
    }

    /// Get the cached version of addresses.
    pub(crate) fn local_addr(&self) -> Vec<transports::Addr> {
        self.local_addrs_watch.clone().get()
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

    /// Tries to send a [`RemoteStateMessage`] to the `RemoteStateActor` for given [`EndpointId`].
    ///
    /// Returns an error if there currently is no remote state actor running for this, or when it
    /// is currently shutting down.
    pub(crate) fn try_send_remote_state_msg(
        &self,
        endpoint_id: EndpointId,
        message: RemoteStateMessage,
    ) -> Result<(), RemoteStateMessage> {
        let Some(sender) = self.remote_actors.get(&endpoint_id) else {
            return Err(message);
        };
        sender.try_send(message).map_err(|err| err.into_inner())
    }

    /// Returns a [`Watcher`] for this socket's direct addresses.
    ///
    /// The [`Socket`] continuously monitors the direct addresses, the network addresses
    /// it might be able to be contacted on, for changes.  Whenever changes are detected
    /// this [`Watcher`] will yield a new list of addresses.
    ///
    /// Upon the first creation on the [`Socket`] it may not yet have completed a first
    /// net report to discover IP addresses, in this case the current item in this [`Watcher`] will be
    /// [`None`].  Once the first set of ip addresses are discovered the [`Watcher`] will
    /// store [`Some`] set of addresses.
    ///
    /// To get the current direct addresses, use [`Watcher::initialized`].
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    pub(crate) fn ip_addrs(&self) -> n0_watcher::Direct<BTreeSet<DirectAddr>> {
        self.direct_addrs.addrs.watch()
    }

    /// Returns a [`Watcher`] for this socket's net-report.
    ///
    /// The [`Socket`] continuously monitors the network conditions for changes.
    /// Whenever changes are detected this [`Watcher`] will yield a new report.
    ///
    /// Upon the first creation on the [`Socket`] it may not yet have completed
    /// a first net-report. In this case, the current item in this [`Watcher`] will
    /// be [`None`].  Once the first report has been run, the [`Watcher`] will
    /// store [`Some`] report.
    ///
    /// To get the current `net-report`, use [`Watcher::initialized`].
    ///
    /// [`Watcher`]: n0_watcher::Watcher
    /// [`Watcher::initialized`]: n0_watcher::Watcher::initialized
    pub(crate) fn net_report(&self) -> impl Watcher<Value = Option<Report>> + use<> {
        self.net_report.watch().map(|(r, _)| r)
    }

    /// Watch for changes to the home relay.
    ///
    /// Note that this can be used to wait for the initial home relay to be known using
    /// [`Watcher::initialized`].
    pub(crate) fn home_relay(&self) -> impl Watcher<Value = Vec<RelayUrl>> + use<> {
        self.local_addrs_watch.clone().map(|addrs| {
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
        })
    }

    /// Stores a new set of direct addresses.
    ///
    /// If the direct addresses have changed from the previous set, they are published to
    /// the address lookup system.
    fn store_direct_addresses(&self, addrs: BTreeSet<DirectAddr>) {
        let updated = self.direct_addrs.update(addrs);
        if updated {
            self.publish_my_addr();
        }
    }

    /// Get a reference to the DNS resolver used in this [`Socket`].
    #[cfg(not(wasm_browser))]
    pub(crate) fn dns_resolver(&self) -> &DnsResolver {
        &self.dns_resolver
    }

    /// Reference to the internal Address Lookup
    pub(crate) fn address_lookup(&self) -> &address_lookup::ConcurrentAddressLookup {
        &self.address_lookup
    }

    /// Updates the user-defined Address Lookup data for this endpoint.
    pub(crate) fn set_user_data_for_address_lookup(&self, user_data: Option<UserData>) {
        let mut guard = self
            .address_lookup_user_data
            .write()
            .expect("lock poisened");
        if *guard != user_data {
            *guard = user_data;
            drop(guard);
            self.publish_my_addr();
        }
    }

    /// Process datagrams received from all the transports.
    ///
    /// All the `bufs` and `metas` should have initialized packets in them.
    ///
    /// This fixes up the datagrams to use the correct [`MultipathMappedAddr`] and extracts
    /// DISCO packets, processing them inside the socket.
    ///
    /// [`MultipathMappedAddr`]: mapped_addrs::MultipathMappedAddr
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

        // zip is slow :(
        for i in 0..metas.len() {
            let quinn_meta = &mut metas[i];
            let source_addr = &source_addrs[i];

            let datagram_count = quinn_meta.len.div_ceil(quinn_meta.stride);
            self.metrics
                .socket
                .recv_datagrams
                .inc_by(datagram_count as _);
            if quinn_meta.len > quinn_meta.stride {
                trace!(
                    src = ?source_addr,
                    len = quinn_meta.len,
                    stride = %quinn_meta.stride,
                    datagram_count = quinn_meta.len.div_ceil(quinn_meta.stride),
                    "GRO datagram received",
                );
                self.metrics.socket.recv_gro_datagrams.inc();
            } else {
                trace!(src = ?source_addr, len = quinn_meta.len, "datagram received");
            }
            match source_addr {
                transports::Addr::Ip(SocketAddr::V4(..)) => {
                    self.metrics
                        .socket
                        .recv_data_ipv4
                        .inc_by(quinn_meta.len as _);
                }
                transports::Addr::Ip(SocketAddr::V6(..)) => {
                    self.metrics
                        .socket
                        .recv_data_ipv6
                        .inc_by(quinn_meta.len as _);
                }
                transports::Addr::Relay(src_url, src_node) => {
                    self.metrics
                        .socket
                        .recv_data_relay
                        .inc_by(quinn_meta.len as _);

                    // Fill in the correct mapped address
                    let mapped_addr = self
                        .mapped_addrs
                        .relay_addrs
                        .get(&(src_url.clone(), *src_node));
                    quinn_meta.addr = mapped_addr.private_socket_addr();
                }
            }
        }
    }

    /// Publishes our address to an address lookup service, if configured.
    ///
    /// Called whenever our addresses or home relay endpoint changes.
    fn publish_my_addr(&self) {
        let relay_url = self.my_relay();
        let mut addrs: BTreeSet<_> = self
            .direct_addrs
            .sockaddrs()
            .map(TransportAddr::Ip)
            .collect();

        let user_data = self
            .address_lookup_user_data
            .read()
            .expect("lock poisened")
            .clone();
        if relay_url.is_none() && addrs.is_empty() && user_data.is_none() {
            // do not bother publishing if we don't have any information
            return;
        }
        if let Some(url) = relay_url {
            addrs.insert(TransportAddr::Relay(url));
        }

        let data = EndpointData::new(addrs).with_user_data(user_data);
        self.address_lookup.publish(&data);
    }
}

/// Manages currently running [`crate::NetReport`] to learn this endpoint's IP addresses.
///
/// Invariants:
/// - only one direct addr update must be running at a time
/// - if an update is scheduled while another one is running, remember that
///   and start a new one when the current one has finished
#[derive(Debug)]
struct DirectAddrUpdateState {
    /// If set, start a new update as soon as the current one is finished.
    want_update: Option<UpdateReason>,
    sock: Arc<Socket>,
    #[cfg(not(wasm_browser))]
    port_mapper: portmapper::Client,
    /// The prober that discovers local network conditions, including the closest relay relay and NAT mappings.
    net_reporter: Arc<AsyncMutex<net_report::Client>>,
    relay_map: RelayMap,
    run_done: mpsc::Sender<()>,
    shutdown_token: CancellationToken,
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Copy)]
enum UpdateReason {
    /// Initial state
    #[default]
    None,
    Periodic,
    PortmapUpdated,
    LinkChangeMajor,
    LinkChangeMinor,
    RelayMapChange,
}

impl UpdateReason {
    fn is_major(self) -> bool {
        matches!(self, Self::LinkChangeMajor | Self::RelayMapChange)
    }
}

impl DirectAddrUpdateState {
    fn new(
        sock: Arc<Socket>,
        #[cfg(not(wasm_browser))] port_mapper: portmapper::Client,
        net_reporter: Arc<AsyncMutex<net_report::Client>>,
        relay_map: RelayMap,
        run_done: mpsc::Sender<()>,
        shutdown_token: CancellationToken,
    ) -> Self {
        DirectAddrUpdateState {
            want_update: Default::default(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            net_reporter,
            sock,
            relay_map,
            run_done,
            shutdown_token,
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
        // Don't start a net report probe if we know
        // we are shutting down
        if self.shutdown_token.is_cancelled() {
            debug!("skipping net_report, socket is shutting down");
            // deactivate portmapper
            #[cfg(not(wasm_browser))]
            self.port_mapper.deactivate();
            return;
        }
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            self.sock.net_report.set((None, why)).ok();
            return;
        }

        #[cfg(not(wasm_browser))]
        self.port_mapper.procure_mapping();

        debug!("requesting net_report report");
        let sock = self.sock.clone();

        let run_done = self.run_done.clone();

        // Ensure that reports are cancelled when we shutdown
        let token = self.shutdown_token.child_token();
        let inner_token = token.child_token();
        task::spawn(
            async move {
                let fut = token.run_until_cancelled(time::timeout(
                    NET_REPORT_TIMEOUT,
                    net_reporter.get_report(if_state, why.is_major(), inner_token),
                ));

                match fut.await {
                    Some(Ok(report)) => {
                        sock.net_report.set((Some(report), why)).ok();
                    }
                    Some(Err(time::Elapsed { .. })) => {
                        warn!("net_report report timed out");
                    }
                    None => {
                        trace!("net_report cancelled");
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
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum BindError {
    #[error("Failed to bind sockets")]
    Sockets { source: io::Error },
    #[error("Failed to create internal QUIC endpoint")]
    CreateQuicEndpoint { source: io::Error },
    #[error("Failed to create netmon monitor")]
    CreateNetmonMonitor { source: netmon::Error },
    #[error("Invalid transport configuration")]
    InvalidTransportConfig,
    #[error("Failed to create an address lookup service")]
    AddressLookup {
        #[error(from)]
        source: crate::address_lookup::IntoAddressLookupError,
    },
}

impl Handle {
    /// Creates a [`Socket`].
    async fn new(opts: Options) -> Result<Self, BindError> {
        let Options {
            secret_key,
            transports: transport_configs,
            address_lookup_user_data,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            proxy_url,
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            metrics,
            hooks,
        } = opts;

        let address_lookup = address_lookup::ConcurrentAddressLookup::default();
        #[cfg(not(wasm_browser))]
        let port_mapper =
            portmapper::Client::with_metrics(Default::default(), metrics.portmapper.clone());

        let relay_transport_configs: Vec<_> = transport_configs
            .iter()
            .filter(|t| matches!(t, TransportConfig::Relay { .. }))
            .collect();

        // Currently we only support a single relay transport
        if relay_transport_configs.len() > 1 {
            bail!(BindError::InvalidTransportConfig);
        }
        let relay_map = relay_transport_configs
            .iter()
            .filter_map(|t| {
                #[allow(irrefutable_let_patterns)]
                if let TransportConfig::Relay { relay_map, .. } = t {
                    Some(relay_map.clone())
                } else {
                    None
                }
            })
            .next()
            .unwrap_or_else(RelayMap::empty);

        let my_relay = Watchable::new(None);
        let ipv6_reported = Arc::new(AtomicBool::new(false));

        let relay_actor_config = RelayActorConfig {
            my_relay: my_relay.clone(),
            secret_key: secret_key.clone(),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            proxy_url: proxy_url.clone(),
            ipv6_reported: ipv6_reported.clone(),
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
            metrics: metrics.socket.clone(),
        };

        let shutdown_state = ShutdownState::default();
        let shutdown_token = shutdown_state.at_endpoint_closed.child_token();

        let transports = Transports::bind(
            &transport_configs,
            relay_actor_config,
            &metrics,
            shutdown_token.child_token(),
        )
        .map_err(|err| e!(BindError::Sockets, err))?;

        #[cfg(not(wasm_browser))]
        {
            if let Some(v4_port) = transports.local_addrs().into_iter().find_map(|t| {
                if let transports::Addr::Ip(SocketAddr::V4(addr)) = t {
                    Some(addr.port())
                } else {
                    None
                }
            }) {
                // NOTE: we can end up with a zero port if `netwatch::UdpSocket::socket_addr` fails
                match v4_port.try_into() {
                    Ok(non_zero_port) => {
                        port_mapper.update_local_port(non_zero_port);
                    }
                    Err(_zero_port) => debug!("Skipping port mapping with zero local port"),
                }
            }
        }

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        #[cfg(not(wasm_browser))]
        let ipv6 = transports
            .ip_bind_addrs()
            .into_iter()
            .any(|addr| addr.is_ipv6());

        let direct_addrs = DiscoveredDirectAddrs::default();

        let remote_map = {
            RemoteMap::new(
                secret_key.public(),
                metrics.socket.clone(),
                direct_addrs.addrs.watch(),
                address_lookup.clone(),
                shutdown_token.child_token(),
            )
        };

        let sock = Arc::new(Socket {
            public_key: secret_key.public(),
            remote_actors: remote_map.senders(),
            shutdown: shutdown_state,
            ipv6_reported,
            mapped_addrs: remote_map.mapped_addrs.clone(),
            address_lookup,
            relay_map: relay_map.clone(),
            address_lookup_user_data: RwLock::new(address_lookup_user_data),
            direct_addrs,
            net_report: Watchable::new((None, UpdateReason::None)),
            #[cfg(not(wasm_browser))]
            dns_resolver: dns_resolver.clone(),
            metrics: metrics.clone(),
            local_addrs_watch: transports.local_addrs_watch(),
            #[cfg(not(wasm_browser))]
            ip_bind_addrs: transports.ip_bind_addrs(),
            hooks,
        });

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Setting this to false means that quinn will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to quinn. We set the first byte of the packet to zero, which makes quinn ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let local_addrs_watch = transports.local_addrs_watch();
        let network_change_sender = transports.create_network_change_sender();

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
            Some(server_config),
            Box::new(Transport::new(sock.clone(), transports)),
            #[cfg(not(wasm_browser))]
            Arc::new(quinn::TokioRuntime),
            #[cfg(wasm_browser)]
            Arc::new(crate::web_runtime::WebRuntime),
        )
        .map_err(|err| e!(BindError::CreateQuicEndpoint, err))?;

        let network_monitor = netmon::Monitor::new()
            .await
            .map_err(|err| e!(BindError::CreateNetmonMonitor, err))?;

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
            relay_map.clone(),
            net_report_config,
            metrics.net_report.clone(),
        );

        let (direct_addr_done_tx, direct_addr_done_rx) = mpsc::channel(8);
        let direct_addr_update_state = DirectAddrUpdateState::new(
            sock.clone(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            Arc::new(AsyncMutex::new(net_reporter)),
            relay_map,
            direct_addr_done_tx,
            sock.shutdown.at_close_start.child_token(),
        );

        let netmon_watcher = network_monitor.interface_state();

        #[cfg_attr(not(wasm_browser), allow(unused_mut))]
        let mut actor = Actor {
            sock: sock.clone(),
            remote_map,
            periodic_re_stun_timer: new_re_stun_timer(false),
            network_monitor,
            netmon_watcher,
            direct_addr_update_state,
            network_change_sender,
            direct_addr_done_rx,
        };
        // Initialize addresses
        #[cfg(not(wasm_browser))]
        actor.update_direct_addresses(None);

        let actor_task = task::spawn(
            actor
                .run(
                    actor_receiver,
                    shutdown_token.child_token(),
                    local_addrs_watch,
                )
                .instrument(info_span!("actor")),
        );

        let actor_task = Arc::new(Mutex::new(Some(AbortOnDropHandle::new(actor_task))));

        Ok(Handle {
            sock,
            actor_sender,
            actor_task,
            endpoint,
        })
    }

    /// The underlying [`quinn::Endpoint`]
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Closes the connection.
    ///
    /// Only the first close does anything. Any later closes return nil.  Polling the socket
    /// ([`quinn::AsyncUdpSocket::poll_recv`]) will return [`Poll::Pending`] indefinitely
    /// after this call.
    ///
    /// [`Poll::Pending`]: std::task::Poll::Pending
    #[instrument(skip_all)]
    pub(crate) async fn close(&self) {
        if self.sock.is_closed() || self.sock.is_closing() {
            return;
        }
        trace!(me = ?self.public_key, "socket closing...");

        // Cancel at_close_start token, which cancels running netreports.
        self.sock.shutdown.at_close_start.cancel();

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
        trace!("wait_idle start");
        self.endpoint.wait_idle().await;
        trace!("wait_idle done");

        // Start cancellation of all actors
        self.sock.shutdown.at_endpoint_closed.cancel();

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

        self.sock.shutdown.closed.store(true, Ordering::SeqCst);

        trace!("socket closed");
    }

    pub(crate) async fn insert_relay(
        &self,
        relay: RelayUrl,
        endpoint: Arc<RelayConfig>,
    ) -> Option<Arc<RelayConfig>> {
        let res = self.relay_map.insert(relay, endpoint);
        self.actor_sender
            .send(ActorMessage::RelayMapChange)
            .await
            .ok();
        res
    }

    pub(crate) async fn remove_relay(&self, relay: &RelayUrl) -> Option<Arc<RelayConfig>> {
        let res = self.relay_map.remove(relay);
        self.actor_sender
            .send(ActorMessage::RelayMapChange)
            .await
            .ok();
        res
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

    /// Resolves an [`EndpointAddr`] to an [`EndpointIdMappedAddr`] to connect to via [`Handle::endpoint`].
    ///
    /// This starts a `RemoteStateActor` for the remote if not running already, and then checks
    /// if the actor has any known paths to the remote. If not, it starts address lookup and waits for
    /// at least one result to arrive.
    ///
    /// Returns `Ok(Ok(EndpointIdMappedAddr))` if there is a known path or Address Lookup produced
    /// at least one result. This does not mean there is a working path, only that we have at least
    /// one transport address we can try to connect to.
    ///
    /// Returns `Ok(Err(address_lookup_error))` if there are no known paths to the remote and Address Lookup
    /// failed or produced no results. This means that we don't have any transport address for
    /// the remote, thus there is no point in trying to connect over the quinn endpoint.
    ///
    /// Returns `Err(RemoteStateActorStoppedError)` if the `RemoteStateActor` for the remote has stopped,
    /// which may never happen and thus is a bug if it does.
    pub(crate) async fn resolve_remote(
        &self,
        addr: EndpointAddr,
    ) -> Result<Result<EndpointIdMappedAddr, AddressLookupError>, RemoteStateActorStoppedError>
    {
        let (tx, rx) = oneshot::channel();
        self.actor_sender
            .send(ActorMessage::ResolveRemote(addr, tx))
            .await
            .ok();
        rx.await.map_err(|_| RemoteStateActorStoppedError::new())?
    }

    /// Fetches the [`RemoteInfo`] about a remote from the `RemoteStateActor`.
    ///
    /// Returns `None` if no actor is running for the remote.
    pub(crate) async fn remote_info(&self, id: EndpointId) -> Option<RemoteInfo> {
        let (tx, rx) = oneshot::channel();
        self.actor_sender
            .send(ActorMessage::RemoteInfo(id, tx))
            .await
            .ok()?;
        rx.await.ok()
    }

    /// Registers the connection in the `RemoteStateActor`.
    ///
    /// The actor is responsible for holepunching and opening additional paths to this
    /// connection.
    ///
    /// Returns a future that resolves to [`PathsWatcher`].
    ///
    /// The returned future is `'static`, so it can be stored without being liftetime-bound to `&self`.
    pub(crate) fn register_connection(
        &self,
        remote: EndpointId,
        conn: WeakConnectionHandle,
    ) -> impl Future<Output = Result<PathsWatcher, RemoteStateActorStoppedError>> + Send + 'static
    {
        let (tx, rx) = oneshot::channel();
        let sender = self.actor_sender.clone();
        async move {
            sender
                .send(ActorMessage::AddConnection(remote, conn, tx))
                .await
                .map_err(|_| RemoteStateActorStoppedError::new())?;
            rx.await.map_err(|_| RemoteStateActorStoppedError::new())
        }
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

#[derive(derive_more::Debug)]
#[allow(clippy::enum_variant_names)]
enum ActorMessage {
    NetworkChange,
    RelayMapChange,
    #[debug("ResolveRemote(..)")]
    ResolveRemote(
        EndpointAddr,
        oneshot::Sender<
            Result<Result<EndpointIdMappedAddr, AddressLookupError>, RemoteStateActorStoppedError>,
        >,
    ),
    #[debug("AddConnection(..)")]
    AddConnection(
        EndpointId,
        WeakConnectionHandle,
        oneshot::Sender<PathsWatcher>,
    ),
    #[debug("RemoteInfo(..)")]
    RemoteInfo(EndpointId, oneshot::Sender<RemoteInfo>),
    #[cfg(test)]
    ForceNetworkChange(bool),
}

struct Actor {
    sock: Arc<Socket>,
    /// Tracks the networkmap endpoint entity for each endpoint discovery key.
    remote_map: RemoteMap,
    /// When set, is an AfterFunc timer that will call Socket::do_periodic_stun.
    periodic_re_stun_timer: time::Interval,

    network_monitor: netmon::Monitor,
    netmon_watcher: n0_watcher::Direct<netmon::State>,
    network_change_sender: transports::NetworkChangeSender,
    /// Indicates the direct addr update state.
    direct_addr_update_state: DirectAddrUpdateState,
    direct_addr_done_rx: mpsc::Receiver<()>,
}

impl Actor {
    async fn run(
        mut self,
        mut msg_receiver: mpsc::Receiver<ActorMessage>,
        shutdown_token: CancellationToken,
        mut local_addrs_watcher: impl Watcher<Value = Vec<transports::Addr>> + Send + Sync,
    ) {
        // Setup network monitoring
        let mut current_netmon_state = self.netmon_watcher.get();

        #[cfg(not(wasm_browser))]
        let mut portmap_watcher = self
            .direct_addr_update_state
            .port_mapper
            .watch_external_address();

        let mut receiver_closed = false;
        #[cfg_attr(wasm_browser, allow(unused_mut))]
        let mut portmap_watcher_closed = false;

        let mut net_report_watcher = self.sock.net_report.watch();

        // ensure we are doing an initial publish of our addresses
        self.sock.publish_my_addr();

        while !shutdown_token.is_cancelled() {
            self.sock.metrics.socket.actor_tick_main.inc();
            #[cfg(not(wasm_browser))]
            let portmap_watcher_changed = portmap_watcher.changed();
            #[cfg(wasm_browser)]
            let portmap_watcher_changed = n0_future::future::pending();

            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    debug!("tick: shutting down");
                    return;
                }
                msg = msg_receiver.recv(), if !receiver_closed => {
                    let Some(msg) = msg else {
                        trace!("tick: socket receiver closed");
                        self.sock.metrics.socket.actor_tick_other.inc();

                        receiver_closed = true;
                        continue;
                    };

                    trace!(?msg, "tick: msg");
                    self.sock.metrics.socket.actor_tick_msg.inc();
                    self.handle_actor_message(msg).await;
                }
                tick = self.periodic_re_stun_timer.tick() => {
                    trace!("tick: re_stun {:?}", tick);
                    self.sock.metrics.socket.actor_tick_re_stun.inc();
                    self.re_stun(UpdateReason::Periodic);
                }
                new_addr = local_addrs_watcher.updated() => {
                    match new_addr {
                        Ok(addrs) => {
                            if !addrs.is_empty() {
                                trace!(?addrs, "local addrs");
                                self.sock.publish_my_addr();
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
                            let state = self.netmon_watcher.get();
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
                            self.sock.metrics.socket.actor_tick_other.inc();

                            portmap_watcher_closed = true;
                            continue;
                        }

                        trace!("tick: portmap changed");
                        self.sock.metrics.socket.actor_tick_portmap_changed.inc();
                        let new_external_address = *portmap_watcher.borrow();
                        debug!("external address updated: {new_external_address:?}");
                        self.re_stun(UpdateReason::PortmapUpdated);
                    }
                    #[cfg(wasm_browser)]
                    let _unused_in_browsers = change;
                },
                state = self.netmon_watcher.updated() => {
                    let Ok(state) = state else {
                        trace!("tick: link change receiver closed");
                        self.sock.metrics.socket.actor_tick_other.inc();
                        continue;
                    };
                    let is_major = state.is_major_change(&current_netmon_state);
                    event!(
                        target: "iroh::_events::link_change",
                        Level::DEBUG,
                        ?state,
                        is_major
                    );
                    current_netmon_state = state;
                    self.sock.metrics.socket.actor_link_change.inc();
                    self.handle_network_change(is_major).await;
                }
                eid = poll_fn(|cx| self.remote_map.poll_cleanup(cx)) => {
                    trace!(%eid, "cleaned up RemoteStateActor");
                }
                else => {
                    trace!("tick: else");
                }
            }
        }
    }

    async fn handle_network_change(&mut self, is_major: bool) {
        debug!(is_major, "link change detected");

        if is_major {
            if let Err(err) = self.network_change_sender.rebind() {
                warn!("failed to rebind transports: {err:?}");
            }

            #[cfg(not(wasm_browser))]
            self.sock.dns_resolver.reset().await;
            self.re_stun(UpdateReason::LinkChangeMajor);
        } else {
            self.re_stun(UpdateReason::LinkChangeMinor);
        }

        self.remote_map.on_network_change(is_major);
    }

    fn handle_relay_map_change(&mut self) {
        self.re_stun(UpdateReason::RelayMapChange);
    }

    fn re_stun(&mut self, why: UpdateReason) {
        let state = self.netmon_watcher.get();
        self.direct_addr_update_state
            .schedule_run(why, state.into());
    }

    /// Processes an incoming actor message.
    ///
    /// Returns `true` if it was a shutdown.
    async fn handle_actor_message(&mut self, msg: ActorMessage) {
        match msg {
            ActorMessage::NetworkChange => {
                self.network_monitor.network_change().await.ok();
            }
            ActorMessage::RelayMapChange => {
                self.handle_relay_map_change();
            }
            ActorMessage::ResolveRemote(addr, tx) => {
                tx.send(self.remote_map.resolve_remote(addr).await).ok();
            }
            ActorMessage::RemoteInfo(id, tx) => {
                if let Some(info) = self.remote_map.remote_info(id).await {
                    tx.send(info).ok();
                }
            }
            ActorMessage::AddConnection(remote, conn, tx) => {
                if let Some(watcher) = self.remote_map.add_connection(remote, conn).await {
                    tx.send(watcher).ok();
                }
            }
            #[cfg(test)]
            ActorMessage::ForceNetworkChange(is_major) => {
                self.handle_network_change(is_major).await;
            }
        }
    }

    /// Updates the direct addresses of this socket.
    ///
    /// Updates the [`DiscoveredDirectAddrs`] of this [`Socket`] with the current set of
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
                let port = self.sock.ip_bind_addrs().iter().find_map(|addr| {
                    if addr.port() != 0 {
                        Some(addr.port())
                    } else {
                        None
                    }
                });

                if let Some(port) = port
                    && net_report_report
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
            if let Some(global_v6) = net_report_report.global_v6 {
                addrs.entry(global_v6.into()).or_insert(DirectAddrType::Qad);
            }
        }

        self.collect_local_addresses(&mut addrs);

        // Finally create and store store all these direct addresses and send any
        // queued call-me-maybe messages.
        self.sock.store_direct_addresses(
            addrs
                .iter()
                .map(|(addr, typ)| DirectAddr {
                    addr: *addr,
                    typ: *typ,
                })
                .collect(),
        );
    }

    #[cfg(not(wasm_browser))]
    fn collect_local_addresses(&mut self, addrs: &mut BTreeMap<SocketAddr, DirectAddrType>) {
        // Matches the addresses that have been bound vs the requested ones.
        let local_addrs: Vec<(SocketAddr, SocketAddr)> = self
            .sock
            .ip_bind_addrs()
            .iter()
            .copied()
            .zip(self.sock.ip_local_addrs())
            .collect();

        // Do we listen on any IPv4 unspecified address?
        let has_ipv4_unspecified = local_addrs.iter().find_map(|(_, a)| {
            if a.is_ipv4() && a.ip().is_unspecified() {
                Some(a.port())
            } else {
                None
            }
        });
        // Do we listen on any IPv6 unspecified address?
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
            } = self.netmon_watcher.get().local_addresses;
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
    }

    fn handle_net_report_report(&mut self, mut report: Option<net_report::Report>) {
        if let Some(ref mut r) = report {
            self.sock.ipv6_reported.store(r.udp_v6, Ordering::Relaxed);
            if r.preferred_relay.is_none()
                && let Some(my_relay) = self.sock.my_relay()
            {
                r.preferred_relay.replace(my_relay);
            }

            // Notify all transports
            self.network_change_sender.on_network_change(r);
        }

        #[cfg(not(wasm_browser))]
        self.update_direct_addresses(report.as_ref());
    }
}

fn new_re_stun_timer(initial_delay: bool) -> time::Interval {
    // Pick a random duration between 20 and 26 seconds (just under 30s,
    // a common UDP NAT timeout on Linux,etc)
    let mut rng = rand::rng();
    let d: Duration = rng.random_range(Duration::from_secs(20)..=Duration::from_secs(26));
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

/// The discovered direct addresses of this [`Socket`].
///
/// These are all the [`DirectAddr`]s that this [`Socket`] is aware of for itself.
/// They include all locally bound ones as well as those discovered by other mechanisms like
/// QAD.
#[derive(derive_more::Debug, Clone, Default)]
struct DiscoveredDirectAddrs {
    /// The last set of discovered direct addresses.
    addrs: Watchable<BTreeSet<DirectAddr>>,

    /// The last time the direct addresses were updated, even if there was no change.
    ///
    /// This is only ever None at startup.
    updated_at: Arc<RwLock<Option<Instant>>>,
}

impl DiscoveredDirectAddrs {
    /// Updates the direct addresses, returns `true` if they changed, `false` if not.
    fn update(&self, addrs: BTreeSet<DirectAddr>) -> bool {
        *self.updated_at.write().expect("poisoned") = Some(Instant::now());
        let updated = self.addrs.set(addrs).is_ok();
        if updated {
            event!(
                target: "iroh::_events::direct_addrs",
                Level::DEBUG,
                addrs = ?self.addrs.get(),
            );
        }
        updated
    }

    fn sockaddrs(&self) -> impl Iterator<Item = SocketAddr> {
        self.addrs.get().into_iter().map(|da| da.addr)
    }
}

/// A *direct address* on which an iroh-endpoint might be contactable.
///
/// Direct addresses are UDP socket addresses on which an iroh endpoint could potentially be
/// contacted.  These can come from various sources depending on the network topology of the
/// iroh endpoint, see [`DirectAddrType`] for the several kinds of sources.
///
/// This is essentially a combination of our local addresses combined with any reflexive
/// transport addresses we discovered using QAD.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DirectAddr {
    /// The address.
    pub addr: SocketAddr,
    /// The origin of this direct address.
    pub typ: DirectAddrType,
}

/// The type of direct address.
///
/// These are the various sources or origins from which an iroh endpoint might have found a
/// possible [`DirectAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirectAddrType {
    /// Not yet determined..
    Unknown,
    /// A locally bound socket address.
    Local,
    /// Public internet address discovered via QAD.
    ///
    /// When possible an iroh endpoint will perform QAD to discover which is the address
    /// from which it sends data on the public internet.  This can be different from locally
    /// bound addresses when the endpoint is on a local network which performs NAT or similar.
    Qad,
    /// An address assigned by the router using port mapping.
    ///
    /// When possible an iroh endpoint will request a port mapping from the local router to
    /// get a publicly routable direct address.
    Portmapped,
    /// Hard NAT: QAD'ed IPv4 address + local fixed port.
    ///
    /// It is possible to configure iroh to bound to a specific port and independently
    /// configure the router to forward this port to the iroh endpoint.  This indicates a
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
    use std::{net::SocketAddrV4, sync::Arc, time::Duration};

    use data_encoding::HEXLOWER;
    use iroh_base::{EndpointAddr, EndpointId, TransportAddr};
    use n0_error::{Result, StackResultExt, StdResultExt};
    use n0_future::{MergeBounded, StreamExt, time};
    use n0_tracing_test::traced_test;
    use n0_watcher::Watcher;
    use rand::{CryptoRng, Rng, RngCore, SeedableRng};
    use tokio_util::task::AbortOnDropHandle;
    use tracing::{Instrument, error, info, info_span, instrument};

    use super::Options;
    use crate::{
        Endpoint, RelayMode, SecretKey,
        address_lookup::memory::MemoryLookup,
        dns::DnsResolver,
        endpoint::QuicTransportConfig,
        socket::{
            Handle, Socket, TransportConfig,
            mapped_addrs::{EndpointIdMappedAddr, MappedAddr},
        },
        tls::{self, DEFAULT_MAX_TLS_TICKETS},
    };

    const ALPN: &[u8] = b"n0/test/1";

    fn default_options<R: CryptoRng + ?Sized>(rng: &mut R) -> Options {
        let secret_key = SecretKey::generate(rng);
        let server_config = make_default_server_config(&secret_key);
        Options {
            transports: vec![
                TransportConfig::default_ipv4(),
                TransportConfig::default_ipv6(),
            ],
            secret_key,
            proxy_url: None,
            dns_resolver: DnsResolver::new(),
            server_config,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify: false,
            #[cfg(any(test, feature = "test-utils"))]
            address_lookup_user_data: None,
            metrics: Default::default(),
            hooks: Default::default(),
        }
    }

    /// Generate a server config with no ALPNS and a default transport configuration
    fn make_default_server_config(secret_key: &SecretKey) -> quinn::ServerConfig {
        let quic_server_config =
            crate::tls::TlsConfig::new(secret_key.clone(), DEFAULT_MAX_TLS_TICKETS)
                .make_server_config(vec![], false);
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        let transport = QuicTransportConfig::default();
        server_config.transport_config(transport.to_inner_arc());
        server_config
    }

    #[instrument(skip_all, fields(me = %ep.id().fmt_short()))]
    async fn echo_receiver(ep: Endpoint, loss: ExpectedLoss) -> Result {
        info!("accepting conn");
        let conn = ep.accept().await.expect("no conn");

        info!("accepting");
        let conn = conn.await.context("accepting")?;
        info!("accepting bi");
        let (mut send_bi, mut recv_bi) = conn.accept_bi().await.std_context("accept bi")?;

        info!("reading");
        let val = recv_bi
            .read_to_end(usize::MAX)
            .await
            .std_context("read to end")?;

        info!("replying");
        for chunk in val.chunks(12) {
            send_bi.write_all(chunk).await.std_context("write all")?;
        }

        info!("finishing");
        send_bi.finish().std_context("finish")?;
        send_bi.stopped().await.std_context("stopped")?;

        let stats = conn.stats();
        info!("stats: {:#?}", stats);
        if matches!(loss, ExpectedLoss::AlmostNone) {
            for info in conn.paths().get().iter() {
                assert!(
                    info.stats().lost_packets < 10,
                    "[receiver] path {:?} should not loose many packets",
                    info.remote_addr()
                );
            }
        }

        conn.closed().await;
        info!("closed");
        ep.endpoint().wait_idle().await;
        info!("idle");

        Ok(())
    }

    #[instrument(skip_all, fields(me = %ep.id().fmt_short()))]
    async fn echo_sender(
        ep: Endpoint,
        dest_id: EndpointId,
        msg: &[u8],
        loss: ExpectedLoss,
    ) -> Result {
        info!("connecting to {}", dest_id.fmt_short());
        let dest = EndpointAddr::new(dest_id);
        let conn = ep.connect(dest, ALPN).await?;

        info!("opening bi");
        let (mut send_bi, mut recv_bi) = conn.open_bi().await.std_context("open bi")?;

        info!("writing message");
        send_bi.write_all(msg).await.std_context("write all")?;

        info!("finishing");
        send_bi.finish().std_context("finish")?;
        send_bi.stopped().await.std_context("stopped")?;

        info!("reading_to_end");
        let val = recv_bi
            .read_to_end(usize::MAX)
            .await
            .std_context("read to end")?;
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
            for info in conn.paths().get() {
                assert!(
                    info.stats().lost_packets < 10,
                    "[sender] path {:?} should not loose many packets",
                    info.remote_addr()
                );
            }
        }

        conn.close(0u32.into(), b"done");
        info!("closed");
        ep.endpoint().wait_idle().await;
        info!("idle");
        Ok(())
    }

    #[derive(Debug, Copy, Clone)]
    enum ExpectedLoss {
        AlmostNone,
        YeahSure,
    }

    /// Runs a roundtrip between the [`echo_sender`] and [`echo_receiver`].
    async fn run_roundtrip(
        sender: Endpoint,
        receiver: Endpoint,
        payload: &[u8],
        loss: ExpectedLoss,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(4), async move {
            let send_endpoint_id = sender.id();
            let recv_endpoint_id = receiver.id();
            info!("\nroundtrip: {send_endpoint_id:#} -> {recv_endpoint_id:#}");

            let receiver_task = AbortOnDropHandle::new(tokio::spawn(echo_receiver(receiver, loss)));
            let sender_res = echo_sender(sender, recv_endpoint_id, payload, loss).await;
            let sender_is_err = match sender_res {
                Ok(()) => false,
                Err(err) => {
                    error!("[sender] Error:\n{err:#?}");
                    true
                }
            };
            let receiver_is_err = match receiver_task.await {
                Ok(Ok(())) => false,
                Ok(Err(err)) => {
                    error!("[receiver] Error:\n{err:#?}");
                    true
                }
                Err(joinerr) => {
                    if joinerr.is_panic() {
                        std::panic::resume_unwind(joinerr.into_panic());
                    } else {
                        error!("[receiver] Error:\n{joinerr:#?}");
                    }
                    true
                }
            };
            if sender_is_err || receiver_is_err {
                panic!("Sender or receiver errored");
            }
        })
        .await
        .std_context("timeout")?;
        Ok(())
    }

    /// Returns a pair of endpoints with a shared [`MemoryLookup`].
    ///
    /// The endpoints do not use a relay server but can connect to each other via local
    /// addresses.  Dialing by [`EndpointId`] is possible, and the addresses get updated even if
    /// the endpoints rebind.
    async fn endpoint_pair() -> (AbortOnDropHandle<()>, Endpoint, Endpoint) {
        let address_lookup = MemoryLookup::new();
        let ep1 = Endpoint::empty_builder(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .address_lookup(address_lookup.clone())
            .bind()
            .await
            .unwrap();
        let ep2 = Endpoint::empty_builder(RelayMode::Disabled)
            .alpns(vec![ALPN.to_vec()])
            .address_lookup(address_lookup.clone())
            .bind()
            .await
            .unwrap();
        address_lookup.add_endpoint_info(ep1.addr());
        address_lookup.add_endpoint_info(ep2.addr());

        let ep1_addr_stream = ep1.watch_addr().stream();
        let ep2_addr_stream = ep2.watch_addr().stream();
        let mut addr_stream = MergeBounded::from_iter([ep1_addr_stream, ep2_addr_stream]);
        let task = tokio::spawn(async move {
            while let Some(addr) = addr_stream.next().await {
                address_lookup.add_endpoint_info(addr);
            }
        });

        (AbortOnDropHandle::new(task), ep1, ep2)
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_quinn_small() -> Result {
        let (_guard, m1, m2) = endpoint_pair().await;

        run_roundtrip(
            m1.clone(),
            m2.clone(),
            b"hello m1",
            ExpectedLoss::AlmostNone,
        )
        .await?;
        run_roundtrip(
            m2.clone(),
            m1.clone(),
            b"hello m2",
            ExpectedLoss::AlmostNone,
        )
        .await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_quinn_large() -> Result {
        let (_guard, m1, m2) = endpoint_pair().await;
        let mut data = vec![0u8; 10 * 1024];
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        rng.fill_bytes(&mut data);
        run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::AlmostNone).await?;
        run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::AlmostNone).await?;

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_regression_network_change_rebind_wakes_connection_driver() -> Result {
        let (_guard, m1, m2) = endpoint_pair().await;

        println!("Net change");
        m1.socket().force_network_change(true).await;
        tokio::time::sleep(Duration::from_secs(1)).await; // wait for socket rebinding

        let _handle = AbortOnDropHandle::new(tokio::spawn({
            let endpoint = m2.clone();
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    println!("Incoming first conn!");
                    let conn = incoming.await.anyerr()?;
                    conn.closed().await;
                }

                n0_error::Ok(())
            }
        }));

        println!("first conn!");
        let conn = m1.connect(m2.addr(), ALPN).await?;
        println!("Closing first conn");
        conn.close(0u32.into(), b"bye lolz");
        conn.closed().await;
        println!("Closed first conn");

        Ok(())
    }

    fn offset(rng: &mut rand_chacha::ChaCha8Rng) -> Duration {
        let delay = rng.random_range(1..=5);
        Duration::from_millis(delay * 50)
    }

    /// Same structure as `test_two_devices_roundtrip_quinn`, but interrupts regularly
    /// with (simulated) network changes.
    /// Regular network changes to m1 only.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_network_change_only_a() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let (_guard, m1, m2) = endpoint_pair().await;

        let _network_change_guard = {
            let m1 = m1.clone();
            let mut rng = rng.clone();
            let task = tokio::spawn(async move {
                loop {
                    info!("[m1] network change");
                    m1.socket().force_network_change(true).await;
                    time::sleep(offset(&mut rng)).await;
                }
            });
            AbortOnDropHandle::new(task)
        };

        let mut data = vec![0u8; 10 * 1024];
        rng.fill_bytes(&mut data);
        run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await?;
        run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await?;

        Ok(())
    }

    /// Regular network changes to both m1 and m2.
    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_roundtrip_network_change_a_and_b() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let (_guard, m1, m2) = endpoint_pair().await;

        let _network_change_guard = {
            let m1 = m1.clone();
            let m2 = m2.clone();
            let mut rng = rng.clone();
            let task = tokio::spawn(async move {
                info!("-- [m1] network change");
                m1.socket().force_network_change(true).await;
                info!("-- [m2] network change");
                m2.socket().force_network_change(true).await;
                time::sleep(offset(&mut rng)).await;
            });
            AbortOnDropHandle::new(task)
        };

        let mut data = vec![0u8; 10 * 1024];
        rng.fill_bytes(&mut data);
        run_roundtrip(m1.clone(), m2.clone(), &data, ExpectedLoss::YeahSure).await?;
        run_roundtrip(m2.clone(), m1.clone(), &data, ExpectedLoss::YeahSure).await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_two_devices_setup_teardown() -> Result {
        for i in 0..10 {
            info!("-- round {i}");
            info!("setting up stack");
            let (_guard, m1, m2) = endpoint_pair().await;

            info!("closing endpoints");
            let sock1 = m1.socket();
            let sock2 = m2.socket();
            m1.close().await;
            m2.close().await;

            assert!(sock1.sock.is_closed());
            assert!(sock2.sock.is_closed());
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_direct_addresses() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let sock = Handle::new(default_options(&mut rng)).await.unwrap();

        // See if we can get endpoints.
        let eps0 = sock.ip_addrs().get();
        info!("{eps0:?}");
        assert!(!eps0.is_empty());

        // Getting the endpoints again immediately should give the same results.
        let eps1 = sock.ip_addrs().get();
        info!("{eps1:?}");
        assert_eq!(eps0, eps1);
    }

    /// Creates a new [`quinn::Endpoint`] hooked up to a [`Socket`].
    ///
    /// This is without involving [`crate::endpoint::Endpoint`].  The socket will accept
    /// connections using [`ALPN`].
    ///
    /// Use [`socket_connect`] to establish connections.
    #[instrument(name = "ep", skip_all, fields(me = %secret_key.public().fmt_short()))]
    async fn socket_ep(secret_key: SecretKey) -> Result<Handle> {
        let quic_server_config = tls::TlsConfig::new(secret_key.clone(), DEFAULT_MAX_TLS_TICKETS)
            .make_server_config(vec![ALPN.to_vec()], true);
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));
        server_config.transport_config(Arc::new(quinn::TransportConfig::default()));

        let dns_resolver = DnsResolver::new();
        let opts = Options {
            transports: vec![
                TransportConfig::default_ipv4(),
                TransportConfig::default_ipv6(),
            ],
            secret_key: secret_key.clone(),
            address_lookup_user_data: None,
            dns_resolver,
            proxy_url: None,
            server_config,
            insecure_skip_relay_cert_verify: false,
            metrics: Default::default(),
            hooks: Default::default(),
        };
        let sock = Socket::spawn(opts).await?;
        Ok(sock)
    }

    /// Connects from `ep` returned by [`socket_ep`] to the `endpoint_id`.
    ///
    /// Uses [`ALPN`], `endpoint_id`, must match `addr`.
    #[instrument(name = "connect", skip_all, fields(me = %ep_secret_key.public().fmt_short()))]
    async fn socket_connect(
        ep: &quinn::Endpoint,
        ep_secret_key: SecretKey,
        addr: EndpointIdMappedAddr,
        endpoint_id: EndpointId,
    ) -> Result<quinn::Connection> {
        // Endpoint::connect sets this, do the same to have similar behaviour.
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(1)));

        socket_connect_with_transport_config(
            ep,
            ep_secret_key,
            addr,
            endpoint_id,
            Arc::new(transport_config),
        )
        .await
    }

    /// Connects from `ep` returned by [`socket_ep`] to the `endpoint_id`.
    ///
    /// This version allows customising the transport config.
    ///
    /// Uses [`ALPN`], `endpoint_id`, must match `addr`.
    #[instrument(name = "connect", skip_all, fields(me = %ep_secret_key.public().fmt_short()))]
    async fn socket_connect_with_transport_config(
        ep: &quinn::Endpoint,
        ep_secret_key: SecretKey,
        mapped_addr: EndpointIdMappedAddr,
        endpoint_id: EndpointId,
        transport_config: Arc<quinn::TransportConfig>,
    ) -> Result<quinn::Connection> {
        let alpns = vec![ALPN.to_vec()];
        let quic_client_config =
            tls::TlsConfig::new(ep_secret_key.clone(), DEFAULT_MAX_TLS_TICKETS)
                .make_client_config(alpns, true);
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
        client_config.transport_config(transport_config);
        let connect = ep
            .connect_with(
                client_config,
                mapped_addr.private_socket_addr(),
                &tls::name::encode(endpoint_id),
            )
            .std_context("connect")?;
        let connection = connect.await.anyerr()?;
        Ok(connection)
    }

    #[tokio::test]
    #[traced_test]
    async fn test_try_send_no_send_addr() {
        // Regression test: if there is no send_addr we should keep being able to use the
        // Endpoint.

        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let endpoint_id_2 = secret_key_2.public();
        let secret_key_missing_endpoint = SecretKey::from_bytes(&[255u8; 32]);
        let endpoint_id_missing_endpoint = secret_key_missing_endpoint.public();

        let sock_1 = socket_ep(secret_key_1.clone()).await.unwrap();

        // Generate an address not present in the RemoteMap.
        let bad_addr = EndpointIdMappedAddr::generate();

        // 500ms is rather fast here.  Running this locally it should always be the correct
        // timeout.  If this is too slow however the test will not become flaky as we are
        // expecting the timeout, we might just get the timeout for the wrong reason.  But
        // this speeds up the test.
        let res = tokio::time::timeout(
            Duration::from_millis(500),
            socket_connect(
                sock_1.endpoint(),
                secret_key_1.clone(),
                bad_addr,
                endpoint_id_missing_endpoint,
            ),
        )
        .await;
        assert!(res.is_err(), "expecting timeout");

        // Now check we can still create another connection with this endpoint.
        let sock_2 = socket_ep(secret_key_2.clone()).await.unwrap();

        // This needs an accept task
        let accept_task = tokio::spawn({
            async fn accept(ep: quinn::Endpoint) -> Result<()> {
                let incoming = ep.accept().await.std_context("no incoming")?;
                let _conn = incoming
                    .accept()
                    .std_context("accept")?
                    .await
                    .std_context("accepting")?;

                // Keep this connection alive for a while
                tokio::time::sleep(Duration::from_secs(10)).await;
                info!("accept finished");
                Ok(())
            }
            let ep = sock_2.endpoint().clone();
            async move {
                if let Err(err) = accept(ep).await {
                    error!("{err:#}");
                }
            }
            .instrument(info_span!("ep2.accept, me = endpoint_id_2.fmt_short()"))
        });
        let _accept_task = AbortOnDropHandle::new(accept_task);

        let addrs = sock_2
            .ip_addrs()
            .get()
            .into_iter()
            .map(|x| TransportAddr::Ip(x.addr));
        let endpoint_addr_2 = EndpointAddr::from_parts(endpoint_id_2, addrs);
        let addr = sock_1
            .resolve_remote(endpoint_addr_2)
            .await
            .unwrap()
            .unwrap();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            socket_connect(sock_1.endpoint(), secret_key_1.clone(), addr, endpoint_id_2),
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
        // behaviour of Socket::try_send.

        let secret_key_1 = SecretKey::from_bytes(&[1u8; 32]);
        let secret_key_2 = SecretKey::from_bytes(&[2u8; 32]);
        let endpoint_id_2 = secret_key_2.public();

        let sock_1 = socket_ep(secret_key_1.clone()).await.unwrap();
        let sock_2 = socket_ep(secret_key_2.clone()).await.unwrap();
        let ep_2 = sock_2.endpoint().clone();

        // We need a task to accept the connection.
        let accept_task = tokio::spawn({
            async fn accept(ep: quinn::Endpoint) -> Result<()> {
                let incoming = ep.accept().await.std_context("no incoming")?;
                let conn = incoming
                    .accept()
                    .std_context("accept")?
                    .await
                    .std_context("connecting")?;
                let mut stream = conn.accept_uni().await.std_context("accept uni")?;
                stream
                    .read_to_end(1 << 16)
                    .await
                    .std_context("read to end")?;
                info!("accept finished");
                Ok(())
            }
            async move {
                if let Err(err) = accept(ep_2).await {
                    error!("{err:#}");
                }
            }
            .instrument(info_span!("ep2.accept", me = %endpoint_id_2.fmt_short()))
        });
        let _accept_task = AbortOnDropHandle::new(accept_task);

        // Add an entry in the RemoteMap of ep_1 with an invalid socket address
        let empty_addr_2 = EndpointAddr::from_parts(
            endpoint_id_2,
            [TransportAddr::Ip(
                // Reserved IP range for documentation (unreachable)
                SocketAddrV4::new([192, 0, 2, 1].into(), 12345).into(),
            )],
        );
        let addr_2 = sock_1.resolve_remote(empty_addr_2).await.unwrap().unwrap();

        // Set a low max_idle_timeout so quinn gives up on this quickly and our test does
        // not take forever.  You need to check the log output to verify this is really
        // triggering the correct error.
        // In test_try_send_no_send_addr() above you may have noticed we used
        // tokio::time::timeout() on the connection attempt instead.  Here however we want
        // Quinn itself to have fully given up on the connection attempt because we will
        // later connect to **the same** endpoint.  If Quinn did not give up on the connection
        // we'd close it on drop, and the retransmits of the close packets would interfere
        // with the next handshake, closing it during the handshake.  This makes the test a
        // little slower though.
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(Duration::from_millis(200).try_into().unwrap()));
        let res = socket_connect_with_transport_config(
            sock_1.endpoint(),
            secret_key_1.clone(),
            addr_2,
            endpoint_id_2,
            Arc::new(transport_config),
        )
        .await;
        assert!(res.is_err(), "expected timeout");
        info!("first connect timed out as expected");

        // Provide correct addressing information
        let correct_addr_2 = EndpointAddr::from_parts(
            endpoint_id_2,
            sock_2
                .ip_addrs()
                .get()
                .into_iter()
                .map(|x| TransportAddr::Ip(x.addr)),
        );
        let addr_2a = sock_1
            .resolve_remote(correct_addr_2)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr_2, addr_2a);

        // We can now connect
        tokio::time::timeout(Duration::from_secs(10), async move {
            info!("establishing new connection");
            let conn = socket_connect(
                sock_1.endpoint(),
                secret_key_1.clone(),
                addr_2,
                endpoint_id_2,
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
        // But we don't have that much private access to the RemoteMap.  This will do for now.
    }
}
