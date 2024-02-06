//! Checks the network conditions from the current host.
//!
//! Based on <https://github.com/tailscale/tailscale/blob/main/net/netcheck/netcheck.go>

use std::collections::{BTreeMap, HashMap};
use std::fmt::{self, Debug};
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use iroh_metrics::inc;
use tokio::sync::{self, mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info_span, trace, warn, Instrument};

use crate::derp::DerpUrl;
use crate::net::ip::to_canonical;
use crate::net::{IpFamily, UdpSocket};
use crate::util::CancelOnDrop;

use super::derp::DerpMap;
use super::portmapper;
use super::stun;

mod metrics;
mod reportgen;

pub use metrics::Metrics;
use Metrics as NetcheckMetrics;

const FULL_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The maximum latency of all nodes, if none are found yet.
///
/// Normally the max latency of all nodes is computed, but if we don't yet know any nodes
/// latencies we return this as default.  This is the value of the initial STUN probe
/// delays.  It is only used as time to wait for further latencies to arrive, which *should*
/// never happen unless there already is at least one latency.  Yet here we are, defining a
/// default which will never be used.
const DEFAULT_MAX_LATENCY: Duration = Duration::from_millis(100);

/// A netcheck report.
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
    /// an ICMPv4 round trip completed
    pub icmpv4: bool,
    /// Whether STUN results depend which STUN server you're talking to (on IPv4).
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether the router supports communicating between two local devices through the NATted
    /// public IP address (on IPv4).
    pub hair_pinning: Option<bool>,
    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,
    /// `None` for unknown
    pub preferred_derp: Option<DerpUrl>,
    /// keyed by DERP Url
    pub derp_latency: DerpLatencies,
    /// keyed by DERP Url
    pub derp_v4_latency: DerpLatencies,
    /// keyed by DERP Url
    pub derp_v6_latency: DerpLatencies,
    /// ip:port of global IPv4
    pub global_v4: Option<SocketAddr>,
    /// `[ip]:port` of global IPv6
    pub global_v6: Option<SocketAddr>,
    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
    pub captive_portal: Option<bool>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Latencies per DERP node.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct DerpLatencies(BTreeMap<DerpUrl, Duration>);

impl DerpLatencies {
    fn new() -> Self {
        Default::default()
    }

    /// Updates a derp's latency, if it is faster than before.
    fn update_derp(&mut self, url: DerpUrl, latency: Duration) {
        let val = self.0.entry(url).or_insert(latency);
        if latency < *val {
            *val = latency;
        }
    }

    /// Merges another [`DerpLatencies`] into this one.
    ///
    /// For each derp the latency is updated using [`DerpLatencies::update_derp`].
    fn merge(&mut self, other: &DerpLatencies) {
        for (url, latency) in other.iter() {
            self.update_derp(url.clone(), latency);
        }
    }

    /// Returns the maximum latency for all derps.
    ///
    /// If there are not yet any latencies this will return [`DEFAULT_MAX_LATENCY`].
    fn max_latency(&self) -> Duration {
        self.0
            .values()
            .max()
            .copied()
            .unwrap_or(DEFAULT_MAX_LATENCY)
    }

    /// Returns an iterator over all the derps and their latencies.
    pub fn iter(&self) -> impl Iterator<Item = (&'_ DerpUrl, Duration)> + '_ {
        self.0.iter().map(|(k, v)| (k, *v))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, url: &DerpUrl) -> Option<Duration> {
        self.0.get(url).copied()
    }
}

/// Client to run netchecks.
///
/// Creating this creates a netcheck actor which runs in the background.  Most of the time
/// it is idle unless [`Client::get_report`] is called, which is the main interface.
///
/// The [`Client`] struct can be cloned and results multiple handles to the running actor.
/// If all [`Client`]s are dropped the actor stops running.
///
/// While running the netcheck actor expects to be passed all received stun packets using
/// [`Client::receive_stun_packet`], the [`crate::magicsock::MagicSock`] using this
/// client needs to be wired up to do so.
#[derive(Debug, Clone)]
pub struct Client {
    /// Channel to send message to the [`Actor`].
    ///
    /// If all senders are dropped, in other words all clones of this struct are dropped,
    /// the actor will terminate.
    addr: Addr,
    /// Ensures the actor is terminated when the client is dropped.
    _drop_guard: Arc<CancelOnDrop>,
}

#[derive(Debug)]
struct Reports {
    /// Do a full derp scan, even if last is `Some`.
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

impl Client {
    /// Creates a new netcheck client.
    ///
    /// This starts a connected actor in the background.  Once the client is dropped it will
    /// stop running.
    pub fn new(port_mapper: Option<portmapper::Client>) -> Result<Self> {
        let mut actor = Actor::new(port_mapper)?;
        let addr = actor.addr();
        let task =
            tokio::spawn(async move { actor.run().await }.instrument(info_span!("netcheck.actor")));
        let drop_guard = CancelOnDrop::new("netcheck actor", task.abort_handle());
        Ok(Client {
            addr,
            _drop_guard: Arc::new(drop_guard),
        })
    }

    /// Pass a received STUN packet to the netchecker.
    ///
    /// Normally the UDP sockets to send STUN messages from are passed in so that STUN
    /// packets are sent from the sockets that carry the real traffic.  However because
    /// these sockets carry real traffic they will also receive non-STUN traffic, thus the
    /// netcheck actor does not read from the sockets directly.  If you receive a STUN
    /// packet on the socket you should pass it to this method.
    ///
    /// It is safe to call this even when the netcheck actor does not currently have any
    /// in-flight STUN probes.  The actor will simply ignore any stray STUN packets.
    ///
    /// There is an implicit queue here which may drop packets if the actor does not keep up
    /// consuming them.
    pub fn receive_stun_packet(&self, payload: Bytes, src: SocketAddr) {
        if let Err(mpsc::error::TrySendError::Full(_)) = self.addr.try_send(Message::StunPacket {
            payload,
            from_addr: src,
        }) {
            inc!(NetcheckMetrics, stun_packets_dropped);
            warn!("dropping stun packet from {}", src);
        }
    }

    /// Runs a netcheck, returning the report.
    ///
    /// It may not be called concurrently with itself, `&mut self` takes care of that.
    ///
    /// The *stun_conn4* and *stun_conn6* endpoints are bound UDP sockets to use to send out
    /// STUN packets.  This function **will not read from the sockets**, as they may be
    /// receiving other traffic as well, normally they are the sockets carrying the real
    /// traffic. Thus all stun packets received on those sockets should be passed to
    /// [`Client::receive_stun_packet`] in order for this function to receive the stun
    /// responses and function correctly.
    ///
    /// If these are not passed in this will bind sockets for STUN itself, though results
    /// may not be as reliable.
    pub async fn get_report(
        &mut self,
        dm: DerpMap,
        stun_conn4: Option<Arc<UdpSocket>>,
        stun_conn6: Option<Arc<UdpSocket>>,
    ) -> Result<Arc<Report>> {
        let rx = self.get_report_channel(dm, stun_conn4, stun_conn6).await?;
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(anyhow!("channel closed, actor awol")),
        }
    }

    /// Get report with channel
    pub async fn get_report_channel(
        &mut self,
        dm: DerpMap,
        stun_conn4: Option<Arc<UdpSocket>>,
        stun_conn6: Option<Arc<UdpSocket>>,
    ) -> Result<oneshot::Receiver<Result<Arc<Report>>>> {
        // TODO: consider if DerpMap should be made to easily clone?  It seems expensive
        // right now.
        let (tx, rx) = oneshot::channel();
        self.addr
            .send(Message::RunCheck {
                derp_map: dm,
                stun_sock_v4: stun_conn4,
                stun_sock_v6: stun_conn6,
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
    /// Run a netcheck.
    ///
    /// Only one netcheck can be run at a time, trying to run multiple concurrently will
    /// fail.
    RunCheck {
        /// The derp configuration.
        derp_map: DerpMap,
        /// Socket to send IPv4 STUN probes from.
        ///
        /// Responses are never read from this socket, they must be passed in via the
        /// [`Message::StunPacket`] message since the socket is also used to receive
        /// other packets from in the magicsocket (`MagicSock`).
        ///
        /// If not provided this will attempt to bind a suitable socket itself.
        stun_sock_v4: Option<Arc<UdpSocket>>,
        /// Socket to send IPv6 STUN probes from.
        ///
        /// Like `stun_sock_v4` but for IPv6.
        stun_sock_v6: Option<Arc<UdpSocket>>,
        /// Channel to receive the response.
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    },
    /// A report produced by the [`reportgen`] actor.
    ReportReady { report: Box<Report> },
    /// The [`reportgen`] actor failed to produce a report.
    ReportAborted,
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

/// Sender to the [`Actor`].
///
/// Unlike [`Client`] this is the raw channel to send messages over.  Keeping this alive
/// will not keep the actor alive, which makes this handy to pass to internal tasks.
#[derive(Debug, Clone)]
struct Addr {
    sender: mpsc::Sender<Message>,
}

impl Addr {
    async fn send(&self, msg: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.sender.send(msg).await.map_err(|err| {
            error!("netcheck actor lost");
            err
        })
    }

    fn try_send(&self, msg: Message) -> Result<(), mpsc::error::TrySendError<Message>> {
        self.sender.try_send(msg).map_err(|err| {
            match &err {
                mpsc::error::TrySendError::Full(_) => {
                    // TODO: metrics, though the only place that uses this already does its
                    // own metrics.
                    warn!("netcheck actor inbox full");
                }
                mpsc::error::TrySendError::Closed(_) => error!("netcheck actor lost"),
            }
            err
        })
    }
}

/// The netcheck actor.
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
    /// Whether the client should try to reach things other than localhost.
    ///
    /// This is set to true in tests to avoid probing the local LAN's router, etc.
    skip_external_network: bool,
    /// The port mapper client, if those are requested.
    ///
    /// The port mapper is responsible for talking to routers via UPnP and the like to try
    /// and open ports.
    port_mapper: Option<portmapper::Client>,

    // Actor state.
    /// Information about the currently in-flight STUN requests.
    ///
    /// This is used to complete the STUN probe when receiving STUN packets.
    in_flight_stun_requests: HashMap<stun::TransactionId, Inflight>,
    /// The [`reportgen`] actor currently generating a report.
    current_report_run: Option<ReportRun>,
}

impl Actor {
    /// Creates a new actor.
    ///
    /// This does not start the actor, see [`Actor::run`] for this.  You should not
    /// normally create this directly but rather create a [`Client`].
    fn new(port_mapper: Option<portmapper::Client>) -> Result<Self> {
        // TODO: consider an instrumented flume channel so we have metrics.
        let (sender, receiver) = mpsc::channel(32);
        Ok(Self {
            receiver,
            sender,
            reports: Default::default(),
            skip_external_network: false,
            port_mapper,
            in_flight_stun_requests: Default::default(),
            current_report_run: None,
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
        debug!("netcheck actor starting");
        while let Some(msg) = self.receiver.recv().await {
            trace!(?msg, "handling message");
            match msg {
                Message::RunCheck {
                    derp_map,
                    stun_sock_v4,
                    stun_sock_v6,
                    response_tx,
                } => {
                    self.handle_run_check(derp_map, stun_sock_v4, stun_sock_v6, response_tx);
                }
                Message::ReportReady { report } => {
                    self.handle_report_ready(report);
                }
                Message::ReportAborted => {
                    self.handle_report_aborted();
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
        derp_map: DerpMap,
        stun_sock_v4: Option<Arc<UdpSocket>>,
        stun_sock_v6: Option<Arc<UdpSocket>>,
        response_tx: oneshot::Sender<Result<Arc<Report>>>,
    ) {
        if self.current_report_run.is_some() {
            response_tx
                .send(Err(anyhow!(
                    "ignoring RunCheck request: reportgen actor already running"
                )))
                .ok();
            return;
        }

        let now = Instant::now();

        let cancel_token = CancellationToken::new();
        let stun_sock_v4 = match stun_sock_v4 {
            Some(sock) => Some(sock),
            None => bind_local_stun_socket(IpFamily::V4, self.addr(), cancel_token.clone()),
        };
        let stun_sock_v6 = match stun_sock_v6 {
            Some(sock) => Some(sock),
            None => bind_local_stun_socket(IpFamily::V6, self.addr(), cancel_token.clone()),
        };
        let mut do_full = self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL;

        // If the last report had a captive portal and reported no UDP access,
        // it's possible that we didn't get a useful netcheck due to the
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
            inc!(NetcheckMetrics, reports_full);
        }
        inc!(NetcheckMetrics, reports);

        let actor = reportgen::Client::new(
            self.addr(),
            self.reports.last.clone(),
            self.port_mapper.clone(),
            self.skip_external_network,
            derp_map,
            stun_sock_v4,
            stun_sock_v6,
        );

        self.current_report_run = Some(ReportRun {
            _reportgen: actor,
            _drop_guard: cancel_token.drop_guard(),
            report_tx: response_tx,
        });
    }

    fn handle_report_ready(&mut self, report: Box<Report>) {
        let report = self.finish_and_store_report(*report);
        self.in_flight_stun_requests.clear();
        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Ok(report)).ok();
        }
    }

    fn handle_report_aborted(&mut self) {
        self.in_flight_stun_requests.clear();
        if let Some(ReportRun { report_tx, .. }) = self.current_report_run.take() {
            report_tx.send(Err(anyhow!("report aborted"))).ok();
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

        match &src {
            SocketAddr::V4(_) => {
                inc!(NetcheckMetrics, stun_packets_recv_ipv4);
            }
            SocketAddr::V6(_) => {
                inc!(NetcheckMetrics, stun_packets_recv_ipv6);
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
        let report = self.add_report_history_and_set_preferred_derp(report);
        debug!("{report:?}");
        report
    }

    /// Adds `r` to the set of recent Reports and mutates `r.preferred_derp` to contain the best recent one.
    /// `r` is stored ref counted and a reference is returned.
    fn add_report_history_and_set_preferred_derp(&mut self, mut r: Report) -> Arc<Report> {
        let mut prev_derp = None;
        if let Some(ref last) = self.reports.last {
            prev_derp = last.preferred_derp.clone();
        }
        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // derp ID => its best recent latency in last MAX_AGE
        let mut best_recent = DerpLatencies::new();

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
            best_recent.merge(&pr.derp_latency);
        }

        for t in to_remove {
            self.reports.prev.remove(&t);
        }

        // Then, pick which currently-alive DERP server from the
        // current report has the best latency over the past MAX_AGE.
        let mut best_any = Duration::default();
        let mut old_derp_cur_latency = Duration::default();
        {
            for (url, d) in r.derp_latency.iter() {
                if Some(url) == prev_derp.as_ref() {
                    old_derp_cur_latency = d;
                }
                let best = best_recent.get(url).unwrap();
                if r.preferred_derp.is_none() || best < best_any {
                    best_any = best;
                    r.preferred_derp.replace(url.clone());
                }
            }

            // If we're changing our preferred DERP but the old one's still
            // accessible and the new one's not much better, just stick with
            // where we are.
            if prev_derp.is_some()
                && r.preferred_derp != prev_derp
                && !old_derp_cur_latency.is_zero()
                && best_any > old_derp_cur_latency / 3 * 2
            {
                r.preferred_derp = prev_derp;
            }
        }

        let r = Arc::new(r);
        self.reports.prev.insert(now, r.clone());
        self.reports.last = Some(r.clone());

        r
    }
}

/// State the netcheck actor needs for an in-progress report generation.
#[derive(Debug)]
struct ReportRun {
    /// The handle of the [`reportgen`] actor, cancels the actor on drop.
    _reportgen: reportgen::Client,
    /// Drop guard to optionally kill workers started by netcheck to support reportgen.
    _drop_guard: tokio_util::sync::DropGuard,
    /// Where to send the completed report.
    report_tx: oneshot::Sender<Result<Arc<Report>>>,
}

/// Attempts to bind a local socket to send STUN packets from.
///
/// If successful this returns the bound socket and will forward STUN responses to the
/// provided *actor_addr*.  The *cancel_token* serves to stop the packet forwarding when the
/// socket is no longer needed.
fn bind_local_stun_socket(
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
        tokio::spawn(
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
    from_addr.set_ip(to_canonical(from_addr.ip()));
    let msg = Message::StunPacket {
        payload: Bytes::from(payload.to_vec()),
        from_addr,
    };
    actor_addr.send(msg).await.context("actor stopped")
}

/// Test if IPv6 works at all, or if it's been hard disabled at the OS level.
pub(crate) fn os_has_ipv6() -> bool {
    UdpSocket::bind_local_v6(0).is_ok()
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;
    use tokio::time;
    use tracing::info;

    use crate::defaults::{DEFAULT_DERP_STUN_PORT, EU_DERP_HOSTNAME};
    use crate::derp::DerpNode;
    use crate::net::IpFamily;
    use crate::ping::Pinger;

    use super::*;

    #[tokio::test]
    async fn test_basic() -> Result<()> {
        let _guard = iroh_test::logging::setup();
        let (stun_addr, stun_stats, _cleanup_guard) =
            stun::test::serve("0.0.0.0".parse().unwrap()).await?;

        let mut client = Client::new(None)?;
        let dm = stun::test::derp_map_of([stun_addr].into_iter());

        // Note that the ProbePlan will change with each iteration.
        for i in 0..5 {
            println!("--round {}", i);
            let r = client.get_report(dm.clone(), None, None).await?;

            assert!(r.udp, "want UDP");
            assert_eq!(
                r.derp_latency.len(),
                1,
                "expected 1 key in DERPLatency; got {}",
                r.derp_latency.len()
            );
            assert!(
                r.derp_latency.iter().next().is_some(),
                "expected key 1 in DERPLatency; got {:?}",
                r.derp_latency
            );
            assert!(r.global_v4.is_some(), "expected globalV4 set");
            assert!(r.preferred_derp.is_some(),);
        }

        assert!(
            stun_stats.total().await >= 5,
            "expected at least 5 stun, got {}",
            stun_stats.total().await,
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_iroh_computer_stun() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        let mut client = Client::new(None).context("failed to create netcheck client")?;
        let url: DerpUrl = format!("https://{}", EU_DERP_HOSTNAME).parse().unwrap();

        let dm = DerpMap::from_nodes([DerpNode {
            url: url.clone(),
            stun_only: true,
            stun_port: DEFAULT_DERP_STUN_PORT,
        }])
        .expect("hardcoded");

        for i in 0..10 {
            println!("starting report {}", i + 1);
            let now = Instant::now();

            let r = client
                .get_report(dm.clone(), None, None)
                .await
                .context("failed to get netcheck report")?;

            if r.udp {
                assert_eq!(
                    r.derp_latency.len(),
                    1,
                    "expected 1 key in DERPLatency; got {}",
                    r.derp_latency.len()
                );
                assert!(
                    r.derp_latency.iter().next().is_some(),
                    "expected key 1 in DERPLatency; got {:?}",
                    r.derp_latency
                );
                assert!(r.global_v4.is_some(), "expected globalV4 set");
                assert!(r.preferred_derp.is_some());
            } else {
                eprintln!("missing UDP, probe not returned by network");
            }

            println!("report {} done in {:?}", i + 1, now.elapsed());
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_udp_blocked() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        // Create a "STUN server", which will never respond to anything.  This is how UDP to
        // the STUN server being blocked will look like from the client's perspective.
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let stun_addr = blackhole.local_addr()?;
        let dm = stun::test::derp_map_of_opts([(stun_addr, true)].into_iter());

        // Now create a client and generate a report.
        let mut client = Client::new(None)?;

        let r = client.get_report(dm, None, None).await?;
        let mut r: Report = (*r).clone();
        r.portmap_probe = None;

        // This test wants to ensure that the ICMP part of the probe works when UDP is
        // blocked.  Unfortunately on some systems we simply don't have permissions to
        // create raw ICMP pings and we'll have to silently accept this test is useless (if
        // we could, this would be a skip instead).
        let have_pinger = Pinger::new().is_ok();
        if !have_pinger {
            error!("pinger disabled, test effectively skipped");
        } else {
            info!("pinger enabled");
        }

        // This is the test: we will fall back to sending ICMP pings.  These should
        // succeed when we have a working pinger.
        // TODO: fix the test on all environments
        let icmpv4 = r.icmpv4; // have_pinger;
        dbg!(have_pinger, r.icmpv4);

        let want = Report {
            // The ip_v4_can_send flag gets set differently across platforms.
            // On Windows this test detects false, while on Linux detects true.
            // That's not relevant to this test, so just accept what we're given.
            ipv4_can_send: r.ipv4_can_send,
            // OS IPv6 test is irrelevant here, accept whatever the current machine has.
            os_has_ipv6: r.os_has_ipv6,
            // Captive portal test is irrelevant; accept what the current report has.
            captive_portal: r.captive_portal,
            icmpv4,
            // If we had a pinger, we'll have some latencies filled in and a preferred derp
            derp_latency: have_pinger
                .then(|| r.derp_latency.clone())
                .unwrap_or_default(),
            preferred_derp: have_pinger
                .then_some(r.preferred_derp.clone())
                .unwrap_or_default(),
            ..Default::default()
        };

        assert_eq!(r, want);

        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_add_report_history_set_preferred_derp() -> Result<()> {
        fn derp_url(i: u16) -> DerpUrl {
            format!("http://{i}.com").parse().unwrap()
        }

        // report returns a *Report from (DERP host, Duration)+ pairs.
        fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Arc<Report>> {
            let mut report = Report::default();
            for (s, d) in a {
                assert!(s.starts_with('d'), "invalid derp server key");
                let id: u16 = s[1..].parse().unwrap();
                report
                    .derp_latency
                    .0
                    .insert(derp_url(id), Duration::from_secs(d));
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
            /// want PreferredDERP on final step
            want_derp: Option<DerpUrl>,
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
                want_derp: Some(derp_url(1)),
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
                want_derp: Some(derp_url(1)), // t0's d1 of 2 is still best
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
                want_derp: Some(derp_url(2)), // only option
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
                want_derp: Some(derp_url(1)), // t0's d1 of 2 is still best
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
                want_derp: Some(derp_url(3)), // only option
            },
            Test {
                name: "preferred_derp_hysteresis_no_switch",
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
                want_derp: Some(derp_url(1)), // 2 didn't get fast enough
            },
            Test {
                name: "preferred_derp_hysteresis_do_switch",
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
                want_derp: Some(derp_url(2)), // 2 got fast enough
            },
        ];
        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut actor = Actor::new(None).unwrap();
            for s in &mut tt.steps {
                // trigger the timer
                time::advance(Duration::from_secs(s.after)).await;
                let r = Arc::try_unwrap(s.r.take().unwrap()).unwrap();
                s.r = Some(actor.add_report_history_and_set_preferred_derp(r));
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            let got = actor.reports.prev.len();
            let want = tt.want_prev_len;
            assert_eq!(got, want, "prev length");
            let got = &last_report.preferred_derp;
            let want = &tt.want_derp;
            assert_eq!(got, want, "preferred_derp");
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

        // Setup STUN server and create derpmap.
        let (stun_addr, _stun_stats, _done) = stun::test::serve_v4().await?;
        let dm = stun::test::derp_map_of([stun_addr].into_iter());
        dbg!(&dm);

        let mut client = Client::new(None)?;

        // Set up an external socket to send STUN requests from, this will be discovered as
        // our public socket address by STUN.  We send back any packets received on this
        // socket to the netcheck client using Client::receive_stun_packet.  Once we sent
        // the hairpin STUN request (from a different randomly bound socket) we are sending
        // it to this socket, which is forwarnding it back to our netcheck client, because
        // this dumb implementation just forwards anything even if it would be garbage.
        // Thus hairpinning detection will declare hairpinning to work.
        let sock = UdpSocket::bind_local(IpFamily::V4, 0)?;
        let sock = Arc::new(sock);
        info!(addr=?sock.local_addr().unwrap(), "Using local addr");
        let task = {
            let sock = sock.clone();
            let client = client.clone();
            tokio::spawn(
                async move {
                    let mut buf = BytesMut::zeroed(64 << 10);
                    loop {
                        let (count, src) = sock.recv_from(&mut buf).await.unwrap();
                        info!(
                            addr=?sock.local_addr().unwrap(),
                            %count,
                            "Forwarding payload to netcheck client",
                        );
                        let payload = buf.split_to(count).freeze();
                        client.receive_stun_packet(payload, src);
                    }
                }
                .instrument(info_span!("pkt-fwd")),
            )
        };

        let r = client.get_report(dm, Some(sock), None).await?;
        dbg!(&r);
        assert_eq!(r.hair_pinning, Some(true));

        task.abort();
        Ok(())
    }
}
