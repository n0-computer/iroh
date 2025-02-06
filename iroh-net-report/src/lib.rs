//! Checks the network conditions from the current host.
//!
//! NetReport is responsible for finding out the network conditions of the current host, like
//! whether it is connected to the internet via IPv4 and/or IPv6, what the NAT situation is
//! etc and reachability to the configured relays.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt::{self, Debug},
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use iroh_base::RelayUrl;
#[cfg(feature = "metrics")]
use iroh_metrics::inc;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::DnsResolver;
use iroh_relay::{protos::stun, RelayMap};
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{Duration, Instant},
};
#[cfg(not(wasm_browser))]
use netwatch::UdpSocket;
use tokio::sync::{self, mpsc, oneshot};
use tracing::{debug, error, info_span, trace, warn, Instrument};

mod defaults;
#[cfg(not(wasm_browser))]
mod dns;
#[cfg(not(wasm_browser))]
mod ip_mapped_addrs;
mod metrics;
#[cfg(not(wasm_browser))]
mod ping;
mod reportgen;

#[cfg(not(wasm_browser))]
pub use ip_mapped_addrs::{IpMappedAddr, IpMappedAddrError, IpMappedAddresses, MAPPED_ADDR_PORT};
pub use metrics::Metrics;
use reportgen::ProbeProto;
pub use reportgen::QuicConfig;
#[cfg(feature = "stun-utils")]
pub use stun_utils::bind_local_stun_socket;

const FULL_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The maximum latency of all nodes, if none are found yet.
///
/// Normally the max latency of all nodes is computed, but if we don't yet know any nodes
/// latencies we return this as default.  This is the value of the initial STUN probe
/// delays.  It is only used as time to wait for further latencies to arrive, which *should*
/// never happen unless there already is at least one latency.  Yet here we are, defining a
/// default which will never be used.
const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(100);

/// A net_report report.
///
/// Can be obtained by calling [`Client::get_report`].
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Report {
    /// A UDP STUN round trip completed.
    pub udp: bool,
    /// An IPv6 STUN round trip completed.
    pub ipv6: bool,
    /// An IPv4 STUN round trip completed.
    pub ipv4: bool,
    /// An IPv6 packet was able to be sent
    pub ipv6_can_send: bool,
    /// an IPv4 packet was able to be sent
    pub ipv4_can_send: bool,
    /// could bind a socket to ::1
    pub os_has_ipv6: bool,
    /// An ICMPv4 round trip completed, `None` if not checked.
    pub icmpv4: Option<bool>,
    /// An ICMPv6 round trip completed, `None` if not checked.
    pub icmpv6: Option<bool>,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv4).
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv6).
    ///
    /// Note that we don't really expect this to happen and are merely logging this if
    /// detecting rather than using it.  For now.
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// Whether the router supports communicating between two local devices through the NATted
    /// public IP address (on IPv4).
    pub hair_pinning: Option<bool>,
    /// Probe indicating the presence of port mapping protocols on the LAN.
    #[cfg(not(wasm_browser))]
    pub portmap_probe: Option<portmapper::ProbeOutput>,
    /// `None` for unknown
    pub preferred_relay: Option<RelayUrl>,
    /// keyed by relay Url
    pub relay_latency: RelayLatencies,
    /// keyed by relay Url
    pub relay_v4_latency: RelayLatencies,
    /// keyed by relay Url
    pub relay_v6_latency: RelayLatencies,
    /// ip:port of global IPv4
    pub global_v4: Option<SocketAddrV4>,
    /// `[ip]:port` of global IPv6
    pub global_v6: Option<SocketAddrV6>,
    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Latencies per relay node.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct RelayLatencies(BTreeMap<RelayUrl, Duration>);

impl RelayLatencies {
    fn new() -> Self {
        Default::default()
    }

    /// Updates a relay's latency, if it is faster than before.
    fn update_relay(&mut self, url: RelayUrl, latency: Duration) {
        let val = self.0.entry(url).or_insert(latency);
        if latency < *val {
            *val = latency;
        }
    }

    /// Merges another [`RelayLatencies`] into this one.
    ///
    /// For each relay the latency is updated using [`RelayLatencies::update_relay`].
    fn merge(&mut self, other: &RelayLatencies) {
        for (url, latency) in other.iter() {
            self.update_relay(url.clone(), latency);
        }
    }

    /// Returns the maximum latency for all relays.
    ///
    /// If there are not yet any latencies this will return [`DEFAULT_MAX_LATENCY`].
    fn max_latency(&self) -> Duration {
        self.0
            .values()
            .max()
            .copied()
            .unwrap_or(DEFAULT_MAX_LATENCY)
    }

    /// Returns an iterator over all the relays and their latencies.
    pub fn iter(&self) -> impl Iterator<Item = (&'_ RelayUrl, Duration)> + '_ {
        self.0.iter().map(|(k, v)| (k, *v))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, url: &RelayUrl) -> Option<Duration> {
        self.0.get(url).copied()
    }
}

/// Client to run net_reports.
///
/// Creating this creates a net_report actor which runs in the background.  Most of the time
/// it is idle unless [`Client::get_report`] is called, which is the main interface.
///
/// The [`Client`] struct can be cloned and results multiple handles to the running actor.
/// If all [`Client`]s are dropped the actor stops running.
///
/// While running the net_report actor expects to be passed all received stun packets using
/// `Addr::receive_stun_packet`.
#[derive(Debug)]
pub struct Client {
    /// Channel to send message to the [`Actor`].
    ///
    /// If all senders are dropped, in other words all clones of this struct are dropped,
    /// the actor will terminate.
    addr: Addr,
    /// Ensures the actor is terminated when the client is dropped.
    _drop_guard: Arc<AbortOnDropHandle<()>>,
}

#[derive(Debug)]
struct Reports {
    /// Do a full relay scan, even if last is `Some`.
    next_full: bool,
    /// Some previous reports.
    prev: HashMap<Instant, Arc<Report>>,
    /// Most recent report.
    last: Option<Arc<Report>>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
}

impl Default for Reports {
    fn default() -> Self {
        Self {
            next_full: Default::default(),
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

/// Options for running probes
///
/// By default, will run icmp over IPv4, icmp over IPv6, and Https probes.
///
/// Use [`Options::stun_v4`], [`Options::stun_v6`], and [`Options::quic_config`]
/// to enable STUN over IPv4, STUN over IPv6, and QUIC address discovery.
#[derive(Debug, Clone)]
pub struct Options {
    /// Socket to send IPv4 STUN probes from.
    ///
    /// Responses are never read from this socket, they must be passed in via internal
    /// messaging since, when used internally in iroh, the socket is also used to receive
    /// other packets from in the magicsocket (`MagicSock`).
    ///
    /// If not provided, STUN probes will not be sent over IPv4.
    #[cfg(not(wasm_browser))]
    stun_sock_v4: Option<Arc<UdpSocket>>,
    /// Socket to send IPv6 STUN probes from.
    ///
    /// Responses are never read from this socket, they must be passed in via internal
    /// messaging since, when used internally in iroh, the socket is also used to receive
    /// other packets from in the magicsocket (`MagicSock`).
    ///
    /// If not provided, STUN probes will not be sent over IPv6.
    #[cfg(not(wasm_browser))]
    stun_sock_v6: Option<Arc<UdpSocket>>,
    /// The configuration needed to launch QUIC address discovery probes.
    ///
    /// If not provided, will not run QUIC address discovery.
    #[cfg(not(wasm_browser))]
    quic_config: Option<QuicConfig>,
    /// Enable icmp_v4 probes
    ///
    /// On by default
    #[cfg(not(wasm_browser))]
    icmp_v4: bool,
    /// Enable icmp_v6 probes
    ///
    /// On by default
    #[cfg(not(wasm_browser))]
    icmp_v6: bool,
    /// Enable https probes
    ///
    /// On by default
    https: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            #[cfg(not(wasm_browser))]
            stun_sock_v4: None,
            #[cfg(not(wasm_browser))]
            stun_sock_v6: None,
            #[cfg(not(wasm_browser))]
            quic_config: None,
            #[cfg(not(wasm_browser))]
            icmp_v4: true,
            #[cfg(not(wasm_browser))]
            icmp_v6: true,
            https: true,
        }
    }
}

impl Options {
    /// Create an [`Options`] that disables all probes
    pub fn disabled() -> Self {
        Self {
            #[cfg(not(wasm_browser))]
            stun_sock_v4: None,
            #[cfg(not(wasm_browser))]
            stun_sock_v6: None,
            #[cfg(not(wasm_browser))]
            quic_config: None,
            #[cfg(not(wasm_browser))]
            icmp_v4: false,
            #[cfg(not(wasm_browser))]
            icmp_v6: false,
            https: false,
        }
    }

    /// Set the ipv4 stun socket and enable ipv4 stun probes
    #[cfg(not(wasm_browser))]
    pub fn stun_v4(mut self, sock: Option<Arc<UdpSocket>>) -> Self {
        self.stun_sock_v4 = sock;
        self
    }

    /// Set the ipv6 stun socket and enable ipv6 stun probes
    #[cfg(not(wasm_browser))]
    pub fn stun_v6(mut self, sock: Option<Arc<UdpSocket>>) -> Self {
        self.stun_sock_v6 = sock;
        self
    }

    /// Enable quic probes
    #[cfg(not(wasm_browser))]
    pub fn quic_config(mut self, quic_config: Option<QuicConfig>) -> Self {
        self.quic_config = quic_config;
        self
    }

    /// Enable or disable icmp_v4 probe
    #[cfg(not(wasm_browser))]
    pub fn icmp_v4(mut self, enable: bool) -> Self {
        self.icmp_v4 = enable;
        self
    }

    /// Enable or disable icmp_v6 probe
    #[cfg(not(wasm_browser))]
    pub fn icmp_v6(mut self, enable: bool) -> Self {
        self.icmp_v6 = enable;
        self
    }

    /// Enable or disable https probe
    pub fn https(mut self, enable: bool) -> Self {
        self.https = enable;
        self
    }

    /// Turn the options into set of valid protocols
    fn to_protocols(&self) -> BTreeSet<ProbeProto> {
        let mut protocols = BTreeSet::new();
        #[cfg(not(wasm_browser))]
        if self.stun_sock_v4.is_some() {
            protocols.insert(ProbeProto::StunIpv4);
        }
        #[cfg(not(wasm_browser))]
        if self.stun_sock_v6.is_some() {
            protocols.insert(ProbeProto::StunIpv6);
        }
        #[cfg(not(wasm_browser))]
        if let Some(ref quic) = self.quic_config {
            if quic.ipv4 {
                protocols.insert(ProbeProto::QuicIpv4);
            }
            if quic.ipv6 {
                protocols.insert(ProbeProto::QuicIpv6);
            }
        }
        #[cfg(not(wasm_browser))]
        if self.icmp_v4 {
            protocols.insert(ProbeProto::IcmpV4);
        }
        #[cfg(not(wasm_browser))]
        if self.icmp_v6 {
            protocols.insert(ProbeProto::IcmpV6);
        }
        if self.https {
            protocols.insert(ProbeProto::Https);
        }
        protocols
    }
}

impl Client {
    /// Creates a new net_report client.
    ///
    /// This starts a connected actor in the background.  Once the client is dropped it will
    /// stop running.
    pub fn new(
        #[cfg(not(wasm_browser))] port_mapper: Option<portmapper::Client>,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        #[cfg(not(wasm_browser))] ip_mapped_addrs: Option<IpMappedAddresses>,
    ) -> Result<Self> {
        let mut actor = Actor::new(
            #[cfg(not(wasm_browser))]
            port_mapper,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            ip_mapped_addrs,
        )?;
        let addr = actor.addr();
        let task = task::spawn(
            async move { actor.run().await }.instrument(info_span!("net_report.actor")),
        );
        let drop_guard = AbortOnDropHandle::new(task);
        Ok(Client {
            addr,
            _drop_guard: Arc::new(drop_guard),
        })
    }

    /// Returns a new address to send messages to this actor.
    ///
    /// Unlike the client itself the returned [`Addr`] does not own the actor task, it only
    /// allows sending messages to the actor.
    pub fn addr(&self) -> Addr {
        self.addr.clone()
    }

    /// Runs a net_report, returning the report.
    ///
    /// It may not be called concurrently with itself, `&mut self` takes care of that.
    ///
    /// The *stun_conn4* and *stun_conn6* endpoints are bound UDP sockets to use to send out
    /// STUN packets.  This function **will not read from the sockets**, as they may be
    /// receiving other traffic as well, normally they are the sockets carrying the real
    /// traffic. Thus all stun packets received on those sockets should be passed to
    /// `Addr::receive_stun_packet` in order for this function to receive the stun
    /// responses and function correctly.
    ///
    /// If these are not passed in this will bind sockets for STUN itself, though results
    /// may not be as reliable.
    ///
    /// The *quic_config* takes a [`QuicConfig`], a combination of a QUIC endpoint and
    /// a client configuration that can be use for verifying the relay server connection.
    /// When available, the report will attempt to get an observed public address
    /// using QUIC address discovery.
    ///
    /// When `None`, it will disable the QUIC address discovery probes.
    ///
    /// This will attempt to use *all* probe protocols.
    pub async fn get_report(
        &mut self,
        relay_map: RelayMap,
        #[cfg(not(wasm_browser))] stun_sock_v4: Option<Arc<UdpSocket>>,
        #[cfg(not(wasm_browser))] stun_sock_v6: Option<Arc<UdpSocket>>,
        #[cfg(not(wasm_browser))] quic_config: Option<QuicConfig>,
    ) -> Result<Arc<Report>> {
        #[cfg(not(wasm_browser))]
        let opts = Options::default()
            .stun_v4(stun_sock_v4)
            .stun_v6(stun_sock_v6)
            .quic_config(quic_config);
        #[cfg(wasm_browser)]
        let opts = Options::default();
        let rx = self.get_report_channel(relay_map.clone(), opts).await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("channel closed, actor awol")),
        }
    }

    /// Runs a net_report, returning the report.
    ///
    /// It may not be called concurrently with itself, `&mut self` takes care of that.
    ///
    /// Look at [`Options`] for the different configuration options.
    pub async fn get_report_with_opts(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
    ) -> Result<Arc<Report>> {
        let rx = self.get_report_channel(relay_map, opts).await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("channel closed, actor awol")),
        }
    }

    /// Get report with channel
    ///
    /// Look at [`Options`] for the different configuration options.
    pub async fn get_report_channel(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
    ) -> Result<oneshot::Receiver<Result<Arc<Report>>>> {
        let (tx, rx) = oneshot::channel();
        self.addr
            .send(Message::RunCheck {
                relay_map,
                opts,
                response_tx: tx,
            })
            .await?;
        Ok(rx)
    }
}

#[derive(Debug)]
pub(crate) struct Inflight {
    /// The STUN transaction ID.
    txn: stun::TransactionId,
    /// The time the STUN probe was sent.
    start: Instant,
    /// Response to send STUN results: latency of STUN response and the discovered address.
    s: sync::oneshot::Sender<(Duration, SocketAddr)>,
}

/// Messages to send to the [`Actor`].
#[derive(Debug)]
pub(crate) enum Message {
    /// Run a net_report.
    ///
    /// Only one net_report can be run at a time, trying to run multiple concurrently will
    /// fail.
    RunCheck {
        /// The map of relays we want to probe
        relay_map: RelayMap,
        /// Options for the report
        opts: Options,
        /// Channel to receive the response.
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    },
    /// A report produced by the [`reportgen`] actor.
    ReportReady { report: Box<Report> },
    /// The [`reportgen`] actor failed to produce a report.
    ReportAborted { err: anyhow::Error },
    /// An incoming STUN packet to parse.
    StunPacket {
        /// The raw UDP payload.
        payload: Bytes,
        /// The address this was claimed to be received from.
        from_addr: SocketAddr,
    },
    /// A probe wants to register an in-flight STUN request.
    ///
    /// The sender is signalled once the STUN packet is registered with the actor and will
    /// correctly accept the STUN response.
    InFlightStun(Inflight, oneshot::Sender<()>),
}

/// Sender to the main service.
///
/// Unlike [`Client`] this is the raw channel to send messages over.  Keeping this alive
/// will not keep the actor alive, which makes this handy to pass to internal tasks.
#[derive(Debug, Clone)]
pub struct Addr {
    sender: mpsc::Sender<Message>,
}

impl Addr {
    /// Pass a received STUN packet to the net_reporter.
    ///
    /// Normally the UDP sockets to send STUN messages from are passed in so that STUN
    /// packets are sent from the sockets that carry the real traffic.  However because
    /// these sockets carry real traffic they will also receive non-STUN traffic, thus the
    /// net_report actor does not read from the sockets directly.  If you receive a STUN
    /// packet on the socket you should pass it to this method.
    ///
    /// It is safe to call this even when the net_report actor does not currently have any
    /// in-flight STUN probes.  The actor will simply ignore any stray STUN packets.
    ///
    /// There is an implicit queue here which may drop packets if the actor does not keep up
    /// consuming them.
    pub fn receive_stun_packet(&self, payload: Bytes, src: SocketAddr) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.sender.try_send(Message::StunPacket {
            payload,
            from_addr: src,
        }) {
            #[cfg(feature = "metrics")]
            inc!(Metrics, stun_packets_dropped);
            warn!("dropping stun packet from {}", src);
        }
    }

    async fn send(&self, msg: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.sender.send(msg).await.inspect_err(|_| {
            error!("net_report actor lost");
        })
    }
}

/// The net_report actor.
///
/// This actor runs for the entire duration there's a [`Client`] connected.
#[derive(Debug)]
struct Actor {
    // Actor plumbing.
    /// Actor messages channel.
    ///
    /// If there are no more senders the actor stops.
    receiver: mpsc::Receiver<Message>,
    /// The sender side of the messages channel.
    ///
    /// This allows creating new [`Addr`]s from the actor.
    sender: mpsc::Sender<Message>,
    /// A collection of previously generated reports.
    ///
    /// Sometimes it is useful to look at past reports to decide what to do.
    reports: Reports,

    // Actor configuration.
    /// The port mapper client, if those are requested.
    ///
    /// The port mapper is responsible for talking to routers via UPnP and the like to try
    /// and open ports.
    #[cfg(not(wasm_browser))]
    port_mapper: Option<portmapper::Client>,

    // Actor state.
    /// Information about the currently in-flight STUN requests.
    ///
    /// This is used to complete the STUN probe when receiving STUN packets.
    in_flight_stun_requests: HashMap<stun::TransactionId, Inflight>,
    /// The [`reportgen`] actor currently generating a report.
    current_report_run: Option<ReportRun>,

    /// The DNS resolver to use for probes that need to perform DNS lookups
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,

    /// The [`IpMappedAddresses`] that allows you to do QAD in iroh
    #[cfg(not(wasm_browser))]
    ip_mapped_addrs: Option<IpMappedAddresses>,
}

impl Actor {
    /// Creates a new actor.
    ///
    /// This does not start the actor, see [`Actor::run`] for this.  You should not
    /// normally create this directly but rather create a [`Client`].
    fn new(
        #[cfg(not(wasm_browser))] port_mapper: Option<portmapper::Client>,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        #[cfg(not(wasm_browser))] ip_mapped_addrs: Option<IpMappedAddresses>,
    ) -> Result<Self> {
        // TODO: consider an instrumented flume channel so we have metrics.
        let (sender, receiver) = mpsc::channel(32);
        Ok(Self {
            receiver,
            sender,
            reports: Default::default(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            in_flight_stun_requests: Default::default(),
            current_report_run: None,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            ip_mapped_addrs,
        })
    }

    /// Returns the channel to send messages to the actor.
    fn addr(&self) -> Addr {
        Addr {
            sender: self.sender.clone(),
        }
    }

    /// Run the actor.
    ///
    /// It will now run and handle messages.  Once the connected [`Client`] (including all
    /// its clones) is dropped this will terminate.
    async fn run(&mut self) {
        debug!("net_report actor starting");
        while let Some(msg) = self.receiver.recv().await {
            trace!(?msg, "handling message");
            match msg {
                Message::RunCheck {
                    relay_map,
                    opts,
                    response_tx,
                } => {
                    self.handle_run_check(relay_map, opts, response_tx);
                }
                Message::ReportReady { report } => {
                    self.handle_report_ready(*report);
                }
                Message::ReportAborted { err } => {
                    self.handle_report_aborted(err);
                }
                Message::StunPacket { payload, from_addr } => {
                    self.handle_stun_packet(&payload, from_addr);
                }
                Message::InFlightStun(inflight, response_tx) => {
                    self.handle_in_flight_stun(inflight, response_tx);
                }
            }
        }
    }

    /// Starts a check run as requested by the [`Message::RunCheck`] message.
    ///
    /// If *stun_sock_v4* or *stun_sock_v6* are not provided this will bind the sockets
    /// itself.  This is not ideal since really you want to send STUN probes from the
    /// sockets you will be using.
    fn handle_run_check(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    ) {
        let protocols = opts.to_protocols();
        #[cfg(not(wasm_browser))]
        let Options {
            stun_sock_v4,
            stun_sock_v6,
            quic_config,
            ..
        } = opts;
        trace!("Attempting probes for protocols {protocols:#?}");
        if self.current_report_run.is_some() {
            response_tx
                .send(Err(anyhow!(
                    "ignoring RunCheck request: reportgen actor already running"
                )))
                .ok();
            return;
        }

        let now = Instant::now();

        let mut do_full = self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL;

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful net_report due to the
        // captive portal blocking us. If so, make this report a full (non-incremental) one.
        if !do_full {
            if let Some(ref last) = self.reports.last {
                do_full = !last.udp && last.captive_portal.unwrap_or_default();
            }
        }
        if do_full {
            self.reports.last = None; // causes ProbePlan::new below to do a full (initial) plan
            self.reports.next_full = false;
            self.reports.last_full = now;
            #[cfg(feature = "metrics")]
            inc!(Metrics, reports_full);
        }
        #[cfg(feature = "metrics")]
        inc!(Metrics, reports);

        let actor = reportgen::Client::new(
            self.addr(),
            self.reports.last.clone(),
            #[cfg(not(wasm_browser))]
            self.port_mapper.clone(),
            relay_map,
            #[cfg(not(wasm_browser))]
            stun_sock_v4,
            #[cfg(not(wasm_browser))]
            stun_sock_v6,
            #[cfg(not(wasm_browser))]
            quic_config,
            #[cfg(not(wasm_browser))]
            self.dns_resolver.clone(),
            protocols,
            #[cfg(not(wasm_browser))]
            self.ip_mapped_addrs.clone(),
        );

        self.current_report_run = Some(ReportRun {
            _reportgen: actor,
            report_tx: response_tx,
        });
    }

    fn handle_report_ready(&mut self, report: Report) {
        let report = self.finish_and_store_report(report);
        self.in_flight_stun_requests.clear();
        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Ok(report)).ok();
        }
    }

    fn handle_report_aborted(&mut self, err: anyhow::Error) {
        self.in_flight_stun_requests.clear();
        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Err(err.context("report aborted"))).ok();
        }
    }

    /// Handles [`Message::StunPacket`].
    ///
    /// If there are currently no in-flight stun requests registered this is dropped,
    /// otherwise forwarded to the probe.
    fn handle_stun_packet(&mut self, pkt: &[u8], src: SocketAddr) {
        trace!(%src, "received STUN packet");
        if self.in_flight_stun_requests.is_empty() {
            return;
        }

        #[cfg(feature = "metrics")]
        match &src {
            SocketAddr::V4(_) => {
                inc!(Metrics, stun_packets_recv_ipv4);
            }
            SocketAddr::V6(_) => {
                inc!(Metrics, stun_packets_recv_ipv6);
            }
        }

        match stun::parse_response(pkt) {
            Ok((txn, addr_port)) => match self.in_flight_stun_requests.remove(&txn) {
                Some(inf) => {
                    debug!(%src, %txn, "received known STUN packet");
                    let elapsed = inf.start.elapsed();
                    inf.s.send((elapsed, addr_port)).ok();
                }
                None => {
                    debug!(%src, %txn, "received unexpected STUN message response");
                }
            },
            Err(err) => {
                match stun::parse_binding_request(pkt) {
                    Ok(txn) => {
                        // Is this our hairpin request?
                        match self.in_flight_stun_requests.remove(&txn) {
                            Some(inf) => {
                                debug!(%src, %txn, "received our hairpin STUN request");
                                let elapsed = inf.start.elapsed();
                                inf.s.send((elapsed, src)).ok();
                            }
                            None => {
                                debug!(%src, %txn, "unknown STUN request");
                            }
                        }
                    }
                    Err(_) => {
                        debug!(%src, "received invalid STUN response: {err:#}");
                    }
                }
            }
        }
    }

    /// Handles [`Message::InFlightStun`].
    ///
    /// The in-flight request is added to [`Actor::in_flight_stun_requests`] so that
    /// [`Actor::handle_stun_packet`] can forward packets correctly.
    ///
    /// *response_tx* is to signal the actor message has been handled.
    fn handle_in_flight_stun(&mut self, inflight: Inflight, response_tx: oneshot::Sender<()>) {
        self.in_flight_stun_requests.insert(inflight.txn, inflight);
        response_tx.send(()).ok();
    }

    fn finish_and_store_report(&mut self, report: Report) -> Arc<Report> {
        let report = self.add_report_history_and_set_preferred_relay(report);
        debug!("{report:?}");
        report
    }

    /// Adds `r` to the set of recent Reports and mutates `r.preferred_relay` to contain the best recent one.
    /// `r` is stored ref counted and a reference is returned.
    fn add_report_history_and_set_preferred_relay(&mut self, mut r: Report) -> Arc<Report> {
        let mut prev_relay = None;
        if let Some(ref last) = self.reports.last {
            prev_relay.clone_from(&last.preferred_relay);
        }
        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // relay ID => its best recent latency in last MAX_AGE
        let mut best_recent = RelayLatencies::new();

        // chain the current report as we are still mutating it
        let prevs_iter = self
            .reports
            .prev
            .iter()
            .map(|(a, b)| -> (&Instant, &Report) { (a, b) })
            .chain(std::iter::once((&now, &r)));

        let mut to_remove = Vec::new();
        for (t, pr) in prevs_iter {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            best_recent.merge(&pr.relay_latency);
        }

        for t in to_remove {
            self.reports.prev.remove(&t);
        }

        // Then, pick which currently-alive relay server from the
        // current report has the best latency over the past MAX_AGE.
        let mut best_any = Duration::default();
        let mut old_relay_cur_latency = Duration::default();
        {
            for (url, duration) in r.relay_latency.iter() {
                if Some(url) == prev_relay.as_ref() {
                    old_relay_cur_latency = duration;
                }
                if let Some(best) = best_recent.get(url) {
                    if r.preferred_relay.is_none() || best < best_any {
                        best_any = best;
                        r.preferred_relay.replace(url.clone());
                    }
                }
            }

            // If we're changing our preferred relay but the old one's still
            // accessible and the new one's not much better, just stick with
            // where we are.
            if prev_relay.is_some()
                && r.preferred_relay != prev_relay
                && !old_relay_cur_latency.is_zero()
                && best_any > old_relay_cur_latency / 3 * 2
            {
                r.preferred_relay = prev_relay;
            }
        }

        let r = Arc::new(r);
        self.reports.prev.insert(now, r.clone());
        self.reports.last = Some(r.clone());

        r
    }
}

/// State the net_report actor needs for an in-progress report generation.
#[derive(Debug)]
struct ReportRun {
    /// The handle of the [`reportgen`] actor, cancels the actor on drop.
    _reportgen: reportgen::Client,
    /// Where to send the completed report.
    report_tx: oneshot::Sender<Result<Arc<Report>>>,
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
#[cfg(not(wasm_browser))]
pub fn os_has_ipv6() -> bool {
    UdpSocket::bind_local_v6(0).is_ok()
}

#[cfg(any(test, feature = "stun-utils"))]
pub(crate) mod stun_utils {
    use anyhow::Context as _;
    use netwatch::IpFamily;
    use tokio_util::sync::CancellationToken;

    use super::*;

    /// Attempts to bind a local socket to send STUN packets from.
    ///
    /// If successful this returns the bound socket and will forward STUN responses to the
    /// provided *actor_addr*.  The *cancel_token* serves to stop the packet forwarding when the
    /// socket is no longer needed.
    pub fn bind_local_stun_socket(
        network: IpFamily,
        actor_addr: Addr,
        cancel_token: CancellationToken,
    ) -> Option<Arc<UdpSocket>> {
        let sock = match UdpSocket::bind(network, 0) {
            Ok(sock) => Arc::new(sock),
            Err(err) => {
                debug!("failed to bind STUN socket: {}", err);
                return None;
            }
        };
        let span = info_span!(
            "stun_udp_listener",
            local_addr = sock
                .local_addr()
                .map(|a| a.to_string())
                .unwrap_or(String::from("-")),
        );
        {
            let sock = sock.clone();
            task::spawn(
                async move {
                    debug!("udp stun socket listener started");
                    // TODO: Can we do better for buffers here?  Probably doesn't matter much.
                    let mut buf = vec![0u8; 64 << 10];
                    loop {
                        tokio::select! {
                            biased;
                            _ = cancel_token.cancelled() => break,
                            res = recv_stun_once(&sock, &mut buf, &actor_addr) => {
                                if let Err(err) = res {
                                    warn!(%err, "stun recv failed");
                                    break;
                                }
                            }
                        }
                    }
                    debug!("udp stun socket listener stopped");
                }
                .instrument(span),
            );
        }
        Some(sock)
    }

    /// Receive STUN response from a UDP socket, pass it to the actor.
    async fn recv_stun_once(sock: &UdpSocket, buf: &mut [u8], actor_addr: &Addr) -> Result<()> {
        let (count, mut from_addr) = sock
            .recv_from(buf)
            .await
            .context("Error reading from stun socket")?;
        let payload = &buf[..count];
        from_addr.set_ip(from_addr.ip().to_canonical());
        let msg = Message::StunPacket {
            payload: Bytes::from(payload.to_vec()),
            from_addr,
        };
        actor_addr.send(msg).await.context("actor stopped")
    }
}

#[cfg(test)]
mod test_utils {
    //! Creates a relay server against which to perform tests

    use std::sync::Arc;

    use iroh_relay::{server, RelayNode, RelayQuicConfig};

    pub(crate) async fn relay() -> (server::Server, Arc<RelayNode>) {
        let server = server::Server::spawn(server::testing::server_config())
            .await
            .expect("should serve relay");
        let quic = Some(RelayQuicConfig {
            port: server.quic_addr().expect("server should run quic").port(),
        });
        let node_desc = RelayNode {
            url: server.https_url().expect("should work as relay"),
            stun_only: false, // the checks above and below guarantee both stun and relay
            stun_port: server.stun_addr().expect("server should serve stun").port(),
            quic,
        };

        (server, Arc::new(node_desc))
    }

    /// Create a [`crate::RelayMap`] of the given size.
    ///
    /// This function uses [`relay`]. Note that the returned map uses internal order that will
    /// often _not_ match the order of the servers.
    pub(crate) async fn relay_map(relays: usize) -> (Vec<server::Server>, crate::RelayMap) {
        let mut servers = Vec::with_capacity(relays);
        let mut nodes = Vec::with_capacity(relays);
        for _ in 0..relays {
            let (relay_server, node) = relay().await;
            servers.push(relay_server);
            nodes.push(node);
        }
        let map = crate::RelayMap::from_nodes(nodes).expect("unuque urls");
        (servers, map)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::BytesMut;
    use netwatch::IpFamily;
    use tokio_util::sync::CancellationToken;
    use tracing::info;
    use tracing_test::traced_test;

    use super::*;
    use crate::{ping::Pinger, stun_utils::bind_local_stun_socket};

    mod stun_utils {
        //! Utils for testing that expose a simple stun server.

        use std::{net::IpAddr, sync::Arc};

        use anyhow::Result;
        use iroh_base::RelayUrl;
        use iroh_relay::RelayNode;
        use tokio::{
            net,
            sync::{oneshot, Mutex},
        };
        use tracing::{debug, trace};

        use super::*;

        /// A drop guard to clean up test infrastructure.
        ///
        /// After dropping the test infrastructure will asynchronously shutdown and release its
        /// resources.
        // Nightly sees the sender as dead code currently, but we only rely on Drop of the
        // sender.
        #[derive(Debug)]
        pub struct CleanupDropGuard {
            _guard: oneshot::Sender<()>,
        }

        // (read_ipv4, read_ipv6)
        #[derive(Debug, Default, Clone)]
        pub struct StunStats(Arc<Mutex<(usize, usize)>>);

        impl StunStats {
            pub async fn total(&self) -> usize {
                let s = self.0.lock().await;
                s.0 + s.1
            }
        }

        pub fn relay_map_of(stun: impl Iterator<Item = SocketAddr>) -> RelayMap {
            relay_map_of_opts(stun.map(|addr| (addr, true)))
        }

        pub fn relay_map_of_opts(stun: impl Iterator<Item = (SocketAddr, bool)>) -> RelayMap {
            let nodes = stun.map(|(addr, stun_only)| {
                let host = addr.ip();
                let port = addr.port();

                let url: RelayUrl = format!("http://{host}:{port}").parse().unwrap();
                RelayNode {
                    url,
                    stun_port: port,
                    stun_only,
                    quic: None,
                }
            });
            RelayMap::from_nodes(nodes).expect("generated invalid nodes")
        }

        /// Sets up a simple STUN server binding to `0.0.0.0:0`.
        ///
        /// See [`serve`] for more details.
        pub(crate) async fn serve_v4() -> Result<(SocketAddr, StunStats, CleanupDropGuard)> {
            serve(std::net::Ipv4Addr::UNSPECIFIED.into()).await
        }

        /// Sets up a simple STUN server.
        pub(crate) async fn serve(ip: IpAddr) -> Result<(SocketAddr, StunStats, CleanupDropGuard)> {
            let stats = StunStats::default();

            let pc = net::UdpSocket::bind((ip, 0)).await?;
            let mut addr = pc.local_addr()?;
            match addr.ip() {
                IpAddr::V4(ip) => {
                    if ip.octets() == [0, 0, 0, 0] {
                        addr.set_ip("127.0.0.1".parse().unwrap());
                    }
                }
                _ => unreachable!("using ipv4"),
            }

            println!("STUN listening on {}", addr);
            let (_guard, r) = oneshot::channel();
            let stats_c = stats.clone();
            tokio::task::spawn(async move {
                run_stun(pc, stats_c, r).await;
            });

            Ok((addr, stats, CleanupDropGuard { _guard }))
        }

        async fn run_stun(pc: net::UdpSocket, stats: StunStats, mut done: oneshot::Receiver<()>) {
            let mut buf = vec![0u8; 64 << 10];
            loop {
                trace!("read loop");
                tokio::select! {
                    _ = &mut done => {
                        debug!("shutting down");
                        break;
                    }
                    res = pc.recv_from(&mut buf) => match res {
                        Ok((n, addr)) => {
                            trace!("read packet {}bytes from {}", n, addr);
                            let pkt = &buf[..n];
                            if !stun::is(pkt) {
                                debug!("received non STUN pkt");
                                continue;
                            }
                            if let Ok(txid) = stun::parse_binding_request(pkt) {
                                debug!("received binding request");
                                let mut s = stats.0.lock().await;
                                if addr.is_ipv4() {
                                    s.0 += 1;
                                } else {
                                    s.1 += 1;
                                }
                                drop(s);

                                let res = stun::response(txid, addr);
                                if let Err(err) = pc.send_to(&res, addr).await {
                                    eprintln!("STUN server write failed: {:?}", err);
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("failed to read: {:?}", err);
                        }
                    }
                }
            }
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_basic() -> Result<()> {
        let (stun_addr, stun_stats, _cleanup_guard) =
            stun_utils::serve("127.0.0.1".parse().unwrap()).await?;

        let resolver = crate::dns::tests::resolver();
        let mut client = Client::new(None, resolver.clone(), None)?;
        let dm = stun_utils::relay_map_of([stun_addr].into_iter());

        // Note that the ProbePlan will change with each iteration.
        for i in 0..5 {
            let cancel = CancellationToken::new();
            let sock = bind_local_stun_socket(IpFamily::V4, client.addr(), cancel.clone());
            println!("--round {}", i);
            let r = client.get_report(dm.clone(), sock, None, None).await?;

            assert!(r.udp, "want UDP");
            assert_eq!(
                r.relay_latency.len(),
                1,
                "expected 1 key in RelayLatency; got {}",
                r.relay_latency.len()
            );
            assert!(
                r.relay_latency.iter().next().is_some(),
                "expected key 1 in RelayLatency; got {:?}",
                r.relay_latency
            );
            assert!(r.global_v4.is_some(), "expected globalV4 set");
            assert!(r.preferred_relay.is_some(),);
            cancel.cancel();
        }

        assert!(
            stun_stats.total().await >= 5,
            "expected at least 5 stun, got {}",
            stun_stats.total().await,
        );

        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_udp_blocked() -> Result<()> {
        // Create a "STUN server", which will never respond to anything.  This is how UDP to
        // the STUN server being blocked will look like from the client's perspective.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let stun_addr = blackhole.local_addr()?;
        let dm = stun_utils::relay_map_of_opts([(stun_addr, false)].into_iter());

        // Now create a client and generate a report.
        let resolver = crate::dns::tests::resolver();
        let mut client = Client::new(None, resolver.clone(), None)?;

        let r = client.get_report(dm, None, None, None).await?;
        let mut r: Report = (*r).clone();
        r.portmap_probe = None;

        // This test wants to ensure that the ICMP part of the probe works when UDP is
        // blocked.  Unfortunately on some systems we simply don't have permissions to
        // create raw ICMP pings and we'll have to silently accept this test is useless (if
        // we could, this would be a skip instead).
        let pinger = Pinger::new();
        let can_ping = pinger.send(Ipv4Addr::LOCALHOST.into(), b"aa").await.is_ok();
        let want_icmpv4 = match can_ping {
            true => Some(true),
            false => None,
        };

        let want = Report {
            // The ICMP probe sets the can_ping flag.
            ipv4_can_send: can_ping,
            // OS IPv6 test is irrelevant here, accept whatever the current machine has.
            os_has_ipv6: r.os_has_ipv6,
            // Captive portal test is irrelevant; accept what the current report has.
            captive_portal: r.captive_portal,
            // If we can ping we expect to have this.
            icmpv4: want_icmpv4,
            // If we had a pinger, we'll have some latencies filled in and a preferred relay
            relay_latency: can_ping
                .then(|| r.relay_latency.clone())
                .unwrap_or_default(),
            preferred_relay: can_ping
                .then_some(r.preferred_relay.clone())
                .unwrap_or_default(),
            ..Default::default()
        };

        assert_eq!(r, want);

        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_add_report_history_set_preferred_relay() -> Result<()> {
        fn relay_url(i: u16) -> RelayUrl {
            format!("http://{i}.com").parse().unwrap()
        }

        // report returns a *Report from (relay host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Arc<Report>> {
            let mut report = Report::default();
            for (s, d) in a {
                assert!(s.starts_with('d'), "invalid relay server key");
                let id: u16 = s[1..].parse().unwrap();
                report
                    .relay_latency
                    .0
                    .insert(relay_url(id), Duration::from_secs(d));
            }

            Some(Arc::new(report))
        }
        struct Step {
            /// Delay in seconds
            after: u64,
            r: Option<Arc<Report>>,
        }
        struct Test {
            name: &'static str,
            steps: Vec<Step>,
            /// want PreferredRelay on final step
            want_relay: Option<RelayUrl>,
            // wanted len(c.prev)
            want_prev_len: usize,
        }

        let tests = [
            Test {
                name: "first_reading",
                steps: vec![Step {
                    after: 0,
                    r: report([("d1", 2), ("d2", 3)]),
                }],
                want_prev_len: 1,
                want_relay: Some(relay_url(1)),
            },
            Test {
                name: "with_two",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)), // t0's d1 of 2 is still best
            },
            Test {
                name: "but_now_d1_gone",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                ],
                want_prev_len: 3,
                want_relay: Some(relay_url(2)), // only option
            },
            Test {
                name: "d1_is_back",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 2), ("d2", 3)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d2", 3)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 4), ("d2", 3)]),
                    }, // same as 2 seconds ago
                ],
                want_prev_len: 4,
                want_relay: Some(relay_url(1)), // t0's d1 of 2 is still best
            },
            Test {
                name: "things_clean_up",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 2,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 3,
                        r: report([("d1", 1), ("d2", 2)]),
                    },
                    Step {
                        after: 10 * 60,
                        r: report([("d3", 3)]),
                    },
                ],
                want_prev_len: 1, // t=[0123]s all gone. (too old, older than 10 min)
                want_relay: Some(relay_url(3)), // only option
            },
            Test {
                name: "preferred_relay_hysteresis_no_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 3)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(1)), // 2 didn't get fast enough
            },
            Test {
                name: "preferred_relay_hysteresis_do_switch",
                steps: vec![
                    Step {
                        after: 0,
                        r: report([("d1", 4), ("d2", 5)]),
                    },
                    Step {
                        after: 1,
                        r: report([("d1", 4), ("d2", 1)]),
                    },
                ],
                want_prev_len: 2,
                want_relay: Some(relay_url(2)), // 2 got fast enough
            },
        ];
        let resolver = crate::dns::tests::resolver();
        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut actor = Actor::new(None, resolver.clone(), None).unwrap();
            for s in &mut tt.steps {
                // trigger the timer
                tokio::time::advance(Duration::from_secs(s.after)).await;
                let r = Arc::try_unwrap(s.r.take().unwrap()).unwrap();
                s.r = Some(actor.add_report_history_and_set_preferred_relay(r));
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            let got = actor.reports.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = &last_report.preferred_relay;
            let want = &tt.want_relay;
            assert_eq!(got, want, "preferred_relay");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_hairpin() -> Result<()> {
        // Hairpinning is initiated after we discover our own IPv4 socket address (IP +
        // port) via STUN, so the test needs to have a STUN server and perform STUN over
        // IPv4 first.  Hairpinning detection works by sending a STUN *request* to **our own
        // public socket address** (IP + port).  If the router supports hairpinning the STUN
        // request is returned back to us and received on our public address.  This doesn't
        // need to be a STUN request, but STUN already has a unique transaction ID which we
        // can easily use to identify the packet.

        // Setup STUN server and create relay_map.
        let (stun_addr, _stun_stats, _done) = stun_utils::serve_v4().await?;
        let dm = stun_utils::relay_map_of([stun_addr].into_iter());
        dbg!(&dm);

        let resolver = crate::dns::tests::resolver().clone();
        let mut client = Client::new(None, resolver, None)?;

        // Set up an external socket to send STUN requests from, this will be discovered as
        // our public socket address by STUN.  We send back any packets received on this
        // socket to the net_report client using Client::receive_stun_packet.  Once we sent
        // the hairpin STUN request (from a different randomly bound socket) we are sending
        // it to this socket, which is forwarnding it back to our net_report client, because
        // this dumb implementation just forwards anything even if it would be garbage.
        // Thus hairpinning detection will declare hairpinning to work.
        let sock = UdpSocket::bind_local(netwatch::IpFamily::V4, 0)?;
        let sock = Arc::new(sock);
        info!(addr=?sock.local_addr().unwrap(), "Using local addr");
        let task = {
            let sock = sock.clone();
            let addr = client.addr.clone();
            tokio::spawn(
                async move {
                    let mut buf = BytesMut::zeroed(64 << 10);
                    loop {
                        let (count, src) = sock.recv_from(&mut buf).await.unwrap();
                        info!(
                            addr=?sock.local_addr().unwrap(),
                            %count,
                            "Forwarding payload to net_report client",
                        );
                        let payload = buf.split_to(count).freeze();
                        addr.receive_stun_packet(payload, src);
                    }
                }
                .instrument(info_span!("pkt-fwd")),
            )
        };

        let r = client.get_report(dm, Some(sock), None, None).await?;
        dbg!(&r);
        assert_eq!(r.hair_pinning, Some(true));

        task.abort();
        Ok(())
    }
}
