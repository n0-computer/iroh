//! Checks the network conditions from the current host.
//!
//! NetReport is responsible for finding out the network conditions of the current host, like
//! whether it is connected to the internet via IPv4 and/or IPv6, what the NAT situation is
//! etc and reachability to the configured relays.
// Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

#![cfg_attr(iroh_docsrs, feature(doc_auto_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]
#![cfg_attr(wasm_browser, allow(unused))]

use std::{
    collections::BTreeMap,
    fmt::{self, Debug},
    net::{SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::DnsResolver;
use iroh_relay::RelayMap;
use n0_future::{
    task::{self, AbortOnDropHandle},
    time::{Duration, Instant},
};
use nested_enum_utils::common_fields;
#[cfg(not(wasm_browser))]
use netwatch::UdpSocket;
use reportgen::{ActorRunError, ProbeProto};
use snafu::Snafu;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info_span, trace, Instrument};

mod defaults;
#[cfg(not(wasm_browser))]
mod dns;
mod ip_mapped_addrs;
mod metrics;
mod reportgen;

mod options;

/// We "vendor" what we need of the library in browsers for simplicity.
///
/// We could consider making `portmapper` compile to wasm in the future,
/// but what we need is so little it's likely not worth it.
#[cfg(wasm_browser)]
pub(crate) mod portmapper {
    /// Output of a port mapping probe.
    #[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
    #[display("portmap={{ UPnP: {upnp}, PMP: {nat_pmp}, PCP: {pcp} }}")]
    pub struct ProbeOutput {
        /// If UPnP can be considered available.
        pub upnp: bool,
        /// If PCP can be considered available.
        pub pcp: bool,
        /// If PMP can be considered available.
        pub nat_pmp: bool,
    }
}

pub(crate) use ip_mapped_addrs::{IpMappedAddr, IpMappedAddresses};
pub use metrics::Metrics;
pub use options::Options;
pub use reportgen::QuicConfig;
#[cfg(not(wasm_browser))]
use reportgen::SocketState;

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
    /// An IPv6 round trip completed.
    pub ipv6: bool,
    /// An IPv4 round trip completed.
    pub ipv4: bool,
    /// An IPv6 packet was able to be sent
    pub ipv6_can_send: bool,
    /// an IPv4 packet was able to be sent
    pub ipv4_can_send: bool,
    /// could bind a socket to ::1
    pub os_has_ipv6: bool,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv4).
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv6).
    ///
    /// Note that we don't really expect this to happen and are merely logging this if
    /// detecting rather than using it.  For now.
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,
    /// `None` for unknown
    pub preferred_relay: Option<RelayUrl>,
    /// keyed by relay Url
    pub relay_latency: RelayLatencies,
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
pub struct RelayLatencies {
    #[cfg(not(wasm_browser))]
    ipv4: BTreeMap<RelayUrl, Duration>,
    #[cfg(not(wasm_browser))]
    ipv6: BTreeMap<RelayUrl, Duration>,
    https: BTreeMap<RelayUrl, Duration>,
}

impl RelayLatencies {
    fn new() -> Self {
        Default::default()
    }

    /// Updates a relay's latency, if it is faster than before.
    fn update_relay(&mut self, url: RelayUrl, latency: Duration, probe: ProbeProto) {
        let list = match probe {
            ProbeProto::Https => &mut self.https,
            #[cfg(not(wasm_browser))]
            ProbeProto::QuicIpv4 => &mut self.ipv4,
            #[cfg(not(wasm_browser))]
            ProbeProto::QuicIpv6 => &mut self.ipv6,
        };
        let old_latency = list.entry(url).or_insert(latency);
        if latency < *old_latency {
            *old_latency = latency;
        }
    }

    /// Merges another [`RelayLatencies`] into this one.
    ///
    /// For each relay the latency is updated using [`RelayLatencies::update_relay`].
    fn merge(&mut self, other: &RelayLatencies) {
        for (url, latency) in other.https.iter() {
            self.update_relay(url.clone(), *latency, ProbeProto::Https);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv4.iter() {
            self.update_relay(url.clone(), *latency, ProbeProto::QuicIpv4);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv6.iter() {
            self.update_relay(url.clone(), *latency, ProbeProto::QuicIpv6);
        }
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(not(wasm_browser))]
    pub fn iter(&self) -> impl Iterator<Item = (&'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .chain(self.ipv4.iter())
            .chain(self.ipv6.iter())
            .map(|(k, v)| (k, *v))
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(wasm_browser)]
    pub fn iter(&self) -> impl Iterator<Item = (&'_ RelayUrl, Duration)> + '_ {
        self.https.iter().map(|(k, v)| (k, *v))
    }

    #[cfg(not(wasm_browser))]
    fn is_empty(&self) -> bool {
        self.https.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    #[cfg(wasm_browser)]
    fn is_empty(&self) -> bool {
        self.https.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.https.len() + self.ipv4.len() + self.ipv6.len()
    }

    /// Returns the lowest latency across records.
    fn get(&self, url: &RelayUrl) -> Option<Duration> {
        let mut list = Vec::with_capacity(3);
        if let Some(val) = self.https.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv4.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv6.get(url) {
            list.push(*val);
        }
        list.into_iter().min()
    }

    #[cfg(not(wasm_browser))]
    fn ipv4(&self) -> &BTreeMap<RelayUrl, Duration> {
        &self.ipv4
    }

    #[cfg(not(wasm_browser))]
    fn ipv6(&self) -> &BTreeMap<RelayUrl, Duration> {
        &self.ipv6
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
    prev: BTreeMap<Instant, Report>,
    /// Most recent report.
    last: Option<Report>,
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

impl Client {
    /// Creates a new net_report client.
    ///
    /// This starts a connected actor in the background.  Once the client is dropped it will
    /// stop running.
    pub fn new(
        #[cfg(not(wasm_browser))] port_mapper: Option<portmapper::Client>,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        #[cfg(not(wasm_browser))] ip_mapped_addrs: Option<IpMappedAddresses>,
        metrics: Arc<Metrics>,
    ) -> Self {
        let mut actor = Actor::new(
            #[cfg(not(wasm_browser))]
            port_mapper,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            ip_mapped_addrs,
            metrics,
        );
        let addr = actor.addr();
        let task = task::spawn(
            async move { actor.run().await }.instrument(info_span!("net_report.actor")),
        );
        let drop_guard = AbortOnDropHandle::new(task);
        Client {
            addr,
            _drop_guard: Arc::new(drop_guard),
        }
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
    ///
    /// The *quic_config* takes a [`QuicConfig`], a combination of a QUIC endpoint and
    /// a client configuration that can be use for verifying the relay server connection.
    /// When available, the report will attempt to get an observed public address
    /// using QUIC address discovery.
    ///
    /// When `None`, it will disable the QUIC address discovery probes.
    ///
    /// This will attempt to use *all* probe protocols.
    #[cfg(test)]
    pub async fn get_report_all(
        &mut self,
        relay_map: RelayMap,
        #[cfg(not(wasm_browser))] quic_config: Option<QuicConfig>,
    ) -> Result<Report, ReportError> {
        #[cfg(not(wasm_browser))]
        let opts = Options::default().quic_config(quic_config);
        #[cfg(wasm_browser)]
        let opts = Options::default();

        let rx = self.get_report_channel(relay_map, opts).await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(ActorGoneSnafu.build()),
        }
    }

    /// Get report with channel
    ///
    /// Look at [`Options`] for the different configuration options.
    pub(crate) async fn get_report_channel(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
    ) -> Result<oneshot::Receiver<Result<Report, ReportError>>, ReportError> {
        let (tx, rx) = oneshot::channel();
        self.addr
            .send(Message::RunCheck {
                relay_map,
                opts,
                response_tx: tx,
            })
            .await
            .map_err(|_| ActorGoneSnafu.build())?;
        Ok(rx)
    }
}

/// Messages to send to the [`Actor`].
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
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
        response_tx: oneshot::Sender<Result<Report, ReportError>>,
    },
    /// A report produced by the [`reportgen`] actor.
    ReportReady { report: Box<Report> },
    /// The [`reportgen`] actor failed to produce a report.
    ReportAborted { err: ActorRunError },
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
    /// The [`reportgen`] actor currently generating a report.
    current_report_run: Option<ReportRun>,

    /// The DNS resolver to use for probes that need to perform DNS lookups
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,

    /// The [`IpMappedAddresses`] that allows you to do QAD in iroh
    #[cfg(not(wasm_browser))]
    ip_mapped_addrs: Option<IpMappedAddresses>,
    metrics: Arc<Metrics>,
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
        metrics: Arc<Metrics>,
    ) -> Self {
        // TODO: consider an instrumented flume channel so we have metrics.
        let (sender, receiver) = mpsc::channel(32);
        Self {
            receiver,
            sender,
            reports: Default::default(),
            #[cfg(not(wasm_browser))]
            port_mapper,
            current_report_run: None,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            ip_mapped_addrs,
            metrics,
        }
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
            }
        }
    }

    /// Starts a check run as requested by the [`Message::RunCheck`] message.
    fn handle_run_check(
        &mut self,
        relay_map: RelayMap,
        opts: Options,
        response_tx: oneshot::Sender<Result<Report, ReportError>>,
    ) {
        let protocols = opts.to_protocols();
        #[cfg(not(wasm_browser))]
        let socket_state = SocketState {
            port_mapper: self.port_mapper.clone(),
            quic_config: opts.quic_config,
            dns_resolver: self.dns_resolver.clone(),
            ip_mapped_addrs: self.ip_mapped_addrs.clone(),
        };
        trace!("Attempting probes for protocols {protocols:#?}");
        if self.current_report_run.is_some() {
            response_tx.send(Err(AlreadyRunningSnafu.build())).ok();
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
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        let actor = reportgen::Client::new(
            self.addr(),
            self.reports.last.clone(),
            relay_map,
            protocols,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(any(test, feature = "test-utils"))]
            opts.insecure_skip_relay_cert_verify,
        );

        self.current_report_run = Some(ReportRun {
            _reportgen: actor,
            report_tx: response_tx,
        });
    }

    fn handle_report_ready(&mut self, mut report: Report) {
        self.add_report_history_and_set_preferred_relay(&mut report);
        debug!("{report:?}");

        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Ok(report)).ok();
        }
    }

    fn handle_report_aborted(&mut self, reason: ActorRunError) {
        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Err(AbortSnafu { reason }.build())).ok();
        }
    }

    /// Adds `r` to the set of recent Reports and mutates `r.preferred_relay` to contain the best recent one.
    fn add_report_history_and_set_preferred_relay(&mut self, r: &mut Report) {
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
            .map(|(a, b)| -> (&Instant, &Report) { (a, b) });

        let mut to_remove = Vec::new();
        for (t, pr) in prevs_iter {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            best_recent.merge(&pr.relay_latency);
        }
        // merge in current run
        best_recent.merge(&r.relay_latency);

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

        self.reports.prev.insert(now, r.clone());
        self.reports.last = Some(r.clone());
    }
}

/// State the net_report actor needs for an in-progress report generation.
#[derive(Debug)]
struct ReportRun {
    /// The handle of the [`reportgen`] actor, cancels the actor on drop.
    _reportgen: reportgen::Client,
    /// Where to send the completed report.
    report_tx: oneshot::Sender<Result<Report, ReportError>>,
}

#[allow(missing_docs)]
#[common_fields({
    backtrace: Option<snafu::Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ReportError {
    #[snafu(display("Report aborted early"))]
    Abort { reason: ActorRunError },
    #[snafu(display("Report generation is already running"))]
    AlreadyRunning {},
    #[snafu(display("Internal actor is gone"))]
    ActorGone {},
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
#[cfg(not(wasm_browser))]
fn os_has_ipv6() -> bool {
    UdpSocket::bind_local_v6(0).is_ok()
}

/// Always returns false in browsers
#[cfg(wasm_browser)]
fn os_has_ipv6() -> bool {
    false
}

#[cfg(test)]
mod test_utils {
    //! Creates a relay server against which to perform tests

    use iroh_relay::{server, RelayNode, RelayQuicConfig};

    pub(crate) async fn relay() -> (server::Server, RelayNode) {
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

        (server, node_desc)
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
        (servers, crate::RelayMap::from_iter(nodes))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use n0_snafu::{Result, ResultExt};
    use netwatch::IpFamily;
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;

    use super::*;
    use crate::net_report::dns;

    #[tokio::test]
    #[traced_test]
    async fn test_basic() -> Result<()> {
        let (server, relay) = test_utils::relay().await;
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).e()?;
        let quic_addr_disc = QuicConfig {
            ep: ep.clone(),
            client_config,
            ipv4: true,
            ipv6: true,
        };
        let relay_map = RelayMap::from(relay);

        let resolver = dns::tests::resolver();
        let mut client = Client::new(None, resolver.clone(), None, Default::default());

        // Note that the ProbePlan will change with each iteration.
        for i in 0..5 {
            let cancel = CancellationToken::new();
            println!("--round {}", i);
            let r = client
                .get_report_all(relay_map.clone(), Some(quic_addr_disc.clone()))
                .await?;

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

        ep.wait_idle().await;
        server.shutdown().await?;

        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_add_report_history_set_preferred_relay() -> Result {
        fn relay_url(i: u16) -> RelayUrl {
            format!("http://{i}.com").parse().unwrap()
        }

        // report returns a *Report from (relay host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Report> {
            let mut report = Report::default();
            for (s, d) in a {
                assert!(s.starts_with('d'), "invalid relay server key");
                let id: u16 = s[1..].parse().unwrap();
                report
                    .relay_latency
                    .ipv4
                    .insert(relay_url(id), Duration::from_secs(d));
            }

            Some(report)
        }
        struct Step {
            /// Delay in seconds
            after: u64,
            r: Option<Report>,
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
        let resolver = dns::tests::resolver();
        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut actor = Actor::new(None, resolver.clone(), None, Default::default());
            for s in &mut tt.steps {
                // trigger the timer
                tokio::time::advance(Duration::from_secs(s.after)).await;
                actor.add_report_history_and_set_preferred_relay(s.r.as_mut().unwrap());
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
}
