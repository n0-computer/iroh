//! The reportgen actor is responsible for generating a single netcheck report.
//!
//! It is implemented as an actor with [`Client`] as handle.
//!
//! The actor starts generating the report as soon as it is created, it does not receive any
//! messages from the client.  It follows roughly these steps:
//!
//! - Determines host IPv6 support.
//! - Creates hairpin actor.
//! - Creates portmapper future.
//! - Creates captive portal detection future.
//! - Creates Probe Set futures.
//!   - These send messages to the reportgen actor.
//! - Loops driving the futures and handling actor messages:
//!   - Disables futures as they are completed or aborted.
//!   - Stop if there are no outstanding tasks/futures, or on timeout.
//! - Sends the completed report to the netcheck actor.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use iroh_metrics::inc;
use rand::seq::IteratorRandom;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::{self, Instant};
use tracing::{debug, debug_span, error, info_span, trace, warn, Instrument, Span};

use super::NetcheckMetrics;
use crate::defaults::DEFAULT_DERP_STUN_PORT;
use crate::derp::{DerpMap, DerpNode, DerpUrl};
use crate::dns::{lookup_ipv4, lookup_ipv6};
use crate::net::interfaces;
use crate::net::ip;
use crate::net::UdpSocket;
use crate::netcheck::{self, Report};
use crate::ping::{PingError, Pinger};
use crate::util::{CancelOnDrop, MaybeFuture};
use crate::{portmapper, stun};

mod hairpin;
mod probes;

use probes::{Probe, ProbePlan, ProbeProto};

/// The maximum amount of time netcheck will spend gathering a single report.
const OVERALL_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// The total time we wait for all the probes.
///
/// This includes the STUN, ICMP and HTTPS probes, which will all
/// start at different times based on the [`ProbePlan`].
const PROBES_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to await for a captive-portal result.
///
/// This delay is chosen so it starts after good-working STUN probes
/// would have finished, but not too long so the delay is bearable if
/// STUN is blocked.
const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

/// Timeout for captive portal checks
///
/// Must be lower than [`OVERALL_REPORT_TIMEOUT`] minus
/// [`CAPTIVE_PORTAL_DELAY`].
const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

const ENOUGH_NODES: usize = 3;

const DNS_TIMEOUT: Duration = Duration::from_secs(1);

/// Holds the state for a single invocation of [`netcheck::Client::get_report`].
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug)]
pub(super) struct Client {
    // Addr is currently only used by child actors, so not yet exposed here.
    _drop_guard: CancelOnDrop,
}

impl Client {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    pub(super) fn new(
        netcheck: netcheck::Addr,
        last_report: Option<Arc<Report>>,
        port_mapper: Option<portmapper::Client>,
        derp_map: DerpMap,
        stun_sock4: Option<Arc<UdpSocket>>,
        stun_sock6: Option<Arc<UdpSocket>>,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let addr = Addr {
            sender: msg_tx.clone(),
        };
        let incremental = last_report.is_some();
        let mut actor = Actor {
            msg_tx,
            msg_rx,
            netcheck: netcheck.clone(),
            last_report,
            port_mapper,
            incremental,
            derp_map,
            stun_sock4,
            stun_sock6,
            report: Report::default(),
            hairpin_actor: hairpin::Client::new(netcheck, addr),
            outstanding_tasks: OutstandingTasks::default(),
        };
        let task = tokio::spawn(
            async move { actor.run().await }.instrument(info_span!("reportgen.actor")),
        );
        Self {
            _drop_guard: CancelOnDrop::new("reportgen actor", task.abort_handle()),
        }
    }
}

/// The address of the reportstate [`Actor`].
///
/// Unlike the [`Client`] struct itself this is the raw channel to send message over.
/// Keeping this alive will not keep the actor alive, which makes this handy to pass to
/// internal tasks.
#[derive(Debug, Clone)]
pub(super) struct Addr {
    sender: mpsc::Sender<Message>,
}

impl Addr {
    /// Blocking send to the actor, to be used from a non-actor future.
    async fn send(&self, msg: Message) -> Result<(), mpsc::error::SendError<Message>> {
        trace!(
            "sending {:?} to channel with cap {}",
            msg,
            self.sender.capacity()
        );
        self.sender.send(msg).await
    }
}

/// Messages to send to the reportstate [`Actor`].
#[derive(Debug)]
enum Message {
    /// Set the hairpinning availability in the report.
    HairpinResult(bool),
    /// Check whether executing a probe would still help.
    // TODO: Ideally we remove the need for this message and the logic is inverted: once we
    // get a probe result we cancel all probes that are no longer needed.  But for now it's
    // this way around to ease conversion.
    ProbeWouldHelp(Probe, Arc<DerpNode>, oneshot::Sender<bool>),
    /// Abort all remaining probes.
    AbortProbes,
}

/// The reportstate actor.
///
/// This actor starts, generates a single report and exits.
#[derive(Debug)]
struct Actor {
    /// The sender of the message channel, so we can give out [`Addr`].
    msg_tx: mpsc::Sender<Message>,
    /// The receiver of the message channel.
    msg_rx: mpsc::Receiver<Message>,
    /// The address of the netcheck actor.
    netcheck: super::Addr,

    // Provided state
    /// The previous report, if it exists.
    last_report: Option<Arc<Report>>,
    /// The portmapper client, if there is one.
    port_mapper: Option<portmapper::Client>,
    /// The DERP configuration.
    derp_map: DerpMap,
    /// Socket to send IPv4 STUN requests from.
    stun_sock4: Option<Arc<UdpSocket>>,
    /// Socket so send IPv6 STUN requests from.
    stun_sock6: Option<Arc<UdpSocket>>,

    // Internal state.
    /// Whether we're doing an incremental report.
    incremental: bool,
    /// The report being built.
    report: Report,
    /// The hairping actor.
    hairpin_actor: hairpin::Client,
    /// Which tasks the [`Actor`] is still waiting on.
    ///
    /// This is essentially the summary of all the work the [`Actor`] is doing.
    outstanding_tasks: OutstandingTasks,
}

impl Actor {
    fn addr(&self) -> Addr {
        Addr {
            sender: self.msg_tx.clone(),
        }
    }

    async fn run(&mut self) {
        match self.run_inner().await {
            Ok(_) => debug!("reportgen actor finished"),
            Err(err) => {
                error!("reportgen actor failed: {err:#}");
                self.netcheck
                    .send(netcheck::Message::ReportAborted)
                    .await
                    .ok();
            }
        }
    }

    /// Runs the main reportgen actor logic.
    ///
    /// This actor runs by:
    ///
    /// - Creates a hairpin actor.
    /// - Creates a captive portal future.
    /// - Creates ProbeSet futures in a group of futures.
    /// - Runs a main loop:
    ///   - Drives all the above futures.
    ///   - Receives actor messages (sent by those futures).
    ///   - Updates the report, cancels unneeded futures.
    /// - Sends the report to the netcheck actor.
    async fn run_inner(&mut self) -> Result<()> {
        debug!(
            port_mapper = %self.port_mapper.is_some(),
            "reportstate actor starting",
        );

        self.report.os_has_ipv6 = super::os_has_ipv6();

        let mut port_mapping = self.prepare_portmapper_task();
        let mut captive_task = self.prepare_captive_portal_task();
        let mut probes = self.spawn_probes_task().await?;

        let total_timer = tokio::time::sleep(OVERALL_REPORT_TIMEOUT);
        tokio::pin!(total_timer);
        let probe_timer = tokio::time::sleep(PROBES_TIMEOUT);
        tokio::pin!(probe_timer);

        loop {
            trace!(awaiting = ?self.outstanding_tasks, "tick; awaiting tasks");
            if self.outstanding_tasks.all_done() {
                debug!("all tasks done");
                break;
            }
            tokio::select! {
                biased;
                _ = &mut total_timer => {
                    trace!("tick: total_timer expired");
                    bail!("report timed out");
                }

                _ = &mut probe_timer => {
                    warn!("tick: probes timed out");
                    probes.abort_all();
                    self.handle_abort_probes();
                }

                // Drive the portmapper.
                pm = &mut port_mapping, if self.outstanding_tasks.port_mapper => {
                    debug!(report=?pm, "tick: portmapper probe report");
                    self.report.portmap_probe = pm;
                    port_mapping.inner = None;
                    self.outstanding_tasks.port_mapper = false;
                }

                // Check for probes finishing.
                set_result = probes.join_next(), if self.outstanding_tasks.probes => {
                    trace!("tick: probes done: {:?}", set_result);
                    match set_result {
                        Some(Ok(Ok(report))) => self.handle_probe_report(report),
                        Some(Ok(Err(_))) => (),
                        Some(Err(e)) => {
                            warn!("probes task error: {:?}", e);
                        }
                        None => {
                            self.handle_abort_probes();
                        }
                    }
                    trace!("tick: probes handled");
                }

                // Drive the captive task.
                found = &mut captive_task, if self.outstanding_tasks.captive_task => {
                    trace!("tick: captive portal task done");
                    self.report.captive_portal = found;
                    captive_task.inner = None;
                    self.outstanding_tasks.captive_task = false;
                }

                // Handle actor messages.
                msg = self.msg_rx.recv() => {
                    trace!("tick: msg recv: {:?}", msg);
                    match msg {
                        Some(msg) => self.handle_message(msg),
                        None => bail!("msg_rx closed, reportgen client must be dropped"),
                    }
                }
            }
        }

        if !probes.is_empty() {
            debug!(
                "aborting {} probe sets, already have enough reports",
                probes.len()
            );
            drop(probes);
        }

        debug!("Sending report to netcheck actor");
        self.netcheck
            .send(netcheck::Message::ReportReady {
                report: Box::new(self.report.clone()),
            })
            .await?;

        Ok(())
    }

    /// Handles an actor message.
    ///
    /// Returns `true` if all the probes need to be aborted.
    fn handle_message(&mut self, msg: Message) {
        trace!(?msg, "handling message");
        match msg {
            Message::HairpinResult(works) => {
                self.report.hair_pinning = Some(works);
                self.outstanding_tasks.hairpin = false;
            }
            Message::ProbeWouldHelp(probe, derp_node, response_tx) => {
                let res = self.probe_would_help(probe, derp_node);
                if response_tx.send(res).is_err() {
                    debug!("probe dropped before ProbeWouldHelp response sent");
                }
            }
            Message::AbortProbes => {
                self.handle_abort_probes();
            }
        }
    }

    fn handle_probe_report(&mut self, probe_report: ProbeReport) {
        debug!(?probe_report, "finished probe");
        update_report(&mut self.report, probe_report);

        // When we discover the first IPv4 address we want to start the hairpin actor.
        if let Some(ref addr) = self.report.global_v4 {
            if !self.hairpin_actor.has_started() {
                self.hairpin_actor.start_check(*addr);
                self.outstanding_tasks.hairpin = true;
            }
        }

        // Once we've heard from enough derpers (3), start a timer to give up on the other
        // probes. The timer's duration is a function of whether this is our initial full
        // probe or an incremental one. For incremental ones, wait for the duration of the
        // slowest derp. For initial ones, double that.
        let enough_derpers = std::cmp::min(self.derp_map.len(), ENOUGH_NODES);
        if self.report.derp_latency.len() == enough_derpers {
            let timeout = self.report.derp_latency.max_latency();
            let timeout = match self.incremental {
                true => timeout,
                false => timeout * 2,
            };
            let reportcheck = self.addr();
            debug!(
                reports=self.report.derp_latency.len(),
                delay=?timeout,
                "Have enough probe reports, aborting further probes soon",
            );
            tokio::spawn(
                async move {
                    time::sleep(timeout).await;
                    // Because we do this after a timeout it is entirely normal that the
                    // actor is no longer there by the time we send this message.
                    reportcheck
                        .send(Message::AbortProbes)
                        .await
                        .map_err(|err| trace!("Failed to abort all probes: {err:#}"))
                        .ok();
                }
                .instrument(Span::current()),
            );
        }
    }

    /// Whether running this probe would still improve our report.
    fn probe_would_help(&mut self, probe: Probe, derp_node: Arc<DerpNode>) -> bool {
        // If the probe is for a derp we don't yet know about, that would help.
        if self.report.derp_latency.get(&derp_node.url).is_none() {
            return true;
        }

        // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
        if probe.proto() == ProbeProto::StunIpv6 && self.report.derp_v6_latency.is_empty() {
            return true;
        }

        // For IPv4, we need at least two IPv4 results overall to
        // determine whether we're behind a NAT that shows us as
        // different source IPs and/or ports depending on who we're
        // talking to. If we don't yet have two results yet
        // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
        // would be good.
        if probe.proto() == ProbeProto::StunIpv4 && self.report.mapping_varies_by_dest_ip.is_none()
        {
            return true;
        }

        // Otherwise not interesting.
        false
    }

    /// Stops further probes.
    ///
    /// This makes sure that no further probes are run and also cancels the captive portal
    /// and portmapper tasks if there were successful probes.  Be sure to only handle this
    /// after all the required [`ProbeReport`]s have been processed.
    fn handle_abort_probes(&mut self) {
        trace!("handle abort probes");
        self.outstanding_tasks.probes = false;
        if self.report.udp {
            self.outstanding_tasks.port_mapper = false;
            self.outstanding_tasks.captive_task = false;
        }
    }

    /// Creates the future which will perform the portmapper task.
    ///
    /// The returned future will run the portmapper, if enabled, resolving to it's result.
    fn prepare_portmapper_task(
        &mut self,
    ) -> MaybeFuture<Pin<Box<impl Future<Output = Option<portmapper::ProbeOutput>>>>> {
        let mut port_mapping = MaybeFuture::default();
        if let Some(port_mapper) = self.port_mapper.clone() {
            port_mapping.inner = Some(Box::pin(async move {
                match port_mapper.probe().await {
                    Ok(Ok(res)) => Some(res),
                    Ok(Err(err)) => {
                        warn!("skipping port mapping: {err:?}");
                        None
                    }
                    Err(recv_err) => {
                        warn!("skipping port mapping: {recv_err:?}");
                        None
                    }
                }
            }));
            self.outstanding_tasks.port_mapper = true;
        }
        port_mapping
    }

    /// Creates the future which will perform the captive portal check.
    fn prepare_captive_portal_task(
        &mut self,
    ) -> MaybeFuture<Pin<Box<impl Future<Output = Option<bool>>>>> {
        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        if !self.incremental {
            // Even if we're doing a non-incremental update, we may want to try our
            // preferred DERP derp for captive portal detection.
            let preferred_derp = self
                .last_report
                .as_ref()
                .and_then(|l| l.preferred_derp.clone());

            let dm = self.derp_map.clone();
            self.outstanding_tasks.captive_task = true;
            MaybeFuture {
                inner: Some(Box::pin(async move {
                    tokio::time::sleep(CAPTIVE_PORTAL_DELAY).await;
                    debug!("Captive portal check started after {CAPTIVE_PORTAL_DELAY:?}");
                    let captive_portal_check = tokio::time::timeout(
                        CAPTIVE_PORTAL_TIMEOUT,
                        check_captive_portal(&dm, preferred_derp)
                            .instrument(debug_span!("captive-portal")),
                    );
                    match captive_portal_check.await {
                        Ok(Ok(found)) => Some(found),
                        Ok(Err(err)) => {
                            let err: Result<reqwest::Error, _> = err.downcast();
                            match err {
                                Ok(req_err) if req_err.is_connect() => {
                                    debug!("check_captive_portal failed: {req_err:#}");
                                }
                                Ok(req_err) => warn!("check_captive_portal error: {req_err:#}"),
                                Err(any_err) => warn!("check_captive_portal error: {any_err:#}"),
                            }
                            None
                        }
                        Err(_) => {
                            warn!("check_captive_portal timed out");
                            None
                        }
                    }
                })),
            }
        } else {
            self.outstanding_tasks.captive_task = false;
            MaybeFuture::default()
        }
    }

    /// Prepares the future which will run all the probes as per generated ProbePlan.
    ///
    /// Probes operate like the following:
    ///
    /// - A future is created for each probe in all probe sets.
    /// - All probes in a set are grouped in [`JoinSet`].
    /// - All those probe sets are grouped in one overall [`JoinSet`].
    ///   - This future is polled by the main actor loop to make progress.
    /// - Once a probe future is polled:
    ///   - Many probes start with a delay, they sleep during this time.
    ///   - When a probe starts it first asks the reportgen [`Actor`] if it is still useful
    ///     to run.  If not it aborts the entire probe set.
    ///   - When a probe finishes, its [`ProbeReport`] is yielded to the reportgen actor.
    /// - Probes get aborted in several ways:
    ///   - A running it can fail and abort the entire probe set if it deems the
    ///     failure permanent.  Probes in a probe set are essentially retries.
    ///   - Once there are [`ProbeReport`]s from enough nodes, all remaining probes are
    ///     aborted.  That is, the main actor loop stops polling them.
    async fn spawn_probes_task(&mut self) -> Result<JoinSet<Result<ProbeReport>>> {
        let if_state = interfaces::State::new().await;
        debug!(%if_state, "Local interfaces");
        let plan = match self.last_report {
            Some(ref report) => ProbePlan::with_last_report(&self.derp_map, &if_state, report),
            None => ProbePlan::initial(&self.derp_map, &if_state),
        };
        trace!(%plan, "probe plan");

        // The pinger is created here so that any sockets that might be bound for it are
        // shared between the probes that use it.  It binds sockets lazily, so we can always
        // create it.
        let pinger = Pinger::new();

        // A collection of futures running probe sets.
        let mut probes = JoinSet::default();
        for probe_set in plan.iter() {
            let mut set = JoinSet::default();
            for probe in probe_set {
                let reportstate = self.addr();
                let stun_sock4 = self.stun_sock4.clone();
                let stun_sock6 = self.stun_sock6.clone();
                let derp_node = probe.node().clone();
                let probe = probe.clone();
                let netcheck = self.netcheck.clone();
                let pinger = pinger.clone();

                set.spawn(
                    run_probe(
                        reportstate,
                        stun_sock4,
                        stun_sock6,
                        derp_node,
                        probe.clone(),
                        netcheck,
                        pinger,
                    )
                    .instrument(debug_span!("run_probe", %probe)),
                );
            }

            // Add the probe set to all futures of probe sets.  Handle aborting a probe set
            // if needed, only normal errors means the set continues.
            probes.spawn(async move {
                // Hack because ProbeSet is not it's own type yet.
                let mut probe_proto = None;
                while let Some(res) = set.join_next().await {
                    match res {
                        Ok(Ok(report)) => return Ok(report),
                        Ok(Err(ProbeError::Error(err, probe))) => {
                            probe_proto = Some(probe.proto());
                            warn!(?probe, "probe failed: {:#}", err);
                            continue;
                        }
                        Ok(Err(ProbeError::AbortSet(err, probe))) => {
                            debug!(?probe, "probe set aborted: {:#}", err);
                            set.abort_all();
                            return Err(err);
                        }
                        Err(err) => {
                            warn!("fatal probe set error, aborting: {:#}", err);
                            continue;
                        }
                    }
                }
                warn!(?probe_proto, "no successful probes in ProbeSet");
                Err(anyhow!("All probes in ProbeSet failed"))
            });
        }
        self.outstanding_tasks.probes = true;

        Ok(probes)
    }
}

/// Tasks on which the reportgen [`Actor`] is still waiting.
///
/// There is no particular progression, e.g. hairpin starts `false`, moves to `true` when a
/// check is started and then becomes `false` again once it is finished.
#[derive(Debug, Default)]
struct OutstandingTasks {
    probes: bool,
    port_mapper: bool,
    captive_task: bool,
    hairpin: bool,
}

impl OutstandingTasks {
    fn all_done(&self) -> bool {
        !(self.probes || self.port_mapper || self.captive_task || self.hairpin)
    }
}

/// The success result of [`run_probe`].
#[derive(Debug, Clone)]
struct ProbeReport {
    /// Whether we can send IPv4 UDP packets.
    ipv4_can_send: bool,
    /// Whether we can send IPv6 UDP packets.
    ipv6_can_send: bool,
    /// Whether we can send ICMPv4 packets, `None` if not checked.
    icmpv4: Option<bool>,
    /// Whether we can send ICMPv6 packets, `None` if not checked.
    icmpv6: Option<bool>,
    /// The latency to the derp node.
    latency: Option<Duration>,
    /// The probe that generated this report.
    probe: Probe,
    /// The discovered public address.
    addr: Option<SocketAddr>,
}

impl ProbeReport {
    fn new(probe: Probe) -> Self {
        ProbeReport {
            probe,
            ipv4_can_send: false,
            ipv6_can_send: false,
            icmpv4: None,
            icmpv6: None,
            latency: None,
            addr: None,
        }
    }
}

/// Errors for [`run_probe`].
///
/// The main purpose is to signal whether other probes in this probe set should still be
/// run.  Recall that a probe set is normally a set of identical probes with delays,
/// effectively creating retries, and the first successful probe of a probe set will cancel
/// the others in the set.  So this allows an unsuccessful probe to cancel the remainder of
/// the set or not.
#[derive(Debug)]
enum ProbeError {
    /// Abort the current set.
    AbortSet(anyhow::Error, Probe),
    /// Continue the other probes in the set.
    Error(anyhow::Error, Probe),
}

/// Executes a particular [`Probe`], including using a delayed start if needed.
///
/// If *stun_sock4* and *stun_sock6* are `None` the STUN probes are disabled.
#[allow(clippy::too_many_arguments)]
async fn run_probe(
    reportstate: Addr,
    stun_sock4: Option<Arc<UdpSocket>>,
    stun_sock6: Option<Arc<UdpSocket>>,
    derp_node: Arc<DerpNode>,
    probe: Probe,
    netcheck: netcheck::Addr,
    pinger: Pinger,
) -> Result<ProbeReport, ProbeError> {
    if !probe.delay().is_zero() {
        trace!("delaying probe");
        tokio::time::sleep(probe.delay()).await;
    }
    debug!("starting probe");

    let (would_help_tx, would_help_rx) = oneshot::channel();
    if let Err(err) = reportstate
        .send(Message::ProbeWouldHelp(
            probe.clone(),
            derp_node.clone(),
            would_help_tx,
        ))
        .await
    {
        // this happens on shutdown or if the report is already finished
        debug!("Failed to check if probe would help: {err:#}");
        return Err(ProbeError::AbortSet(err.into(), probe.clone()));
    }

    if !would_help_rx.await.map_err(|_| {
        ProbeError::AbortSet(
            anyhow!("ReportCheck actor dropped sender while waiting for ProbeWouldHelp response"),
            probe.clone(),
        )
    })? {
        return Err(ProbeError::AbortSet(
            anyhow!("ReportCheck says probe set no longer useful"),
            probe,
        ));
    }

    let derp_addr = get_derp_addr(&derp_node, probe.proto())
        .await
        .context("no derp node addr")
        .map_err(|e| ProbeError::AbortSet(e, probe.clone()))?;

    let mut result = ProbeReport::new(probe.clone());
    match probe {
        Probe::StunIpv4 { .. } | Probe::StunIpv6 { .. } => {
            let maybe_sock = if matches!(probe, Probe::StunIpv4 { .. }) {
                stun_sock4.as_ref()
            } else {
                stun_sock6.as_ref()
            };
            match maybe_sock {
                Some(sock) => {
                    result = run_stun_probe(sock, derp_addr, netcheck, probe).await?;
                }
                None => {
                    return Err(ProbeError::AbortSet(
                        anyhow!("No socket for {}, aborting probeset", probe.proto()),
                        probe.clone(),
                    ));
                }
            }
        }
        Probe::IcmpV4 { .. } | Probe::IcmpV6 { .. } => {
            result = run_icmp_probe(probe, derp_addr, pinger).await?
        }
        Probe::Https { ref node, .. } => {
            debug!("sending probe HTTPS");
            match measure_https_latency(node).await {
                Ok((latency, ip)) => {
                    result.latency = Some(latency);
                    // We set these IPv4 and IPv6 but they're not really used
                    // and we don't necessarily set them both. If UDP is blocked
                    // and both IPv4 and IPv6 are available over TCP, it's basically
                    // random which fields end up getting set here.
                    // Since they're not needed, that's fine for now.
                    match ip {
                        IpAddr::V4(_) => result.ipv4_can_send = true,
                        IpAddr::V6(_) => result.ipv6_can_send = true,
                    }
                }
                Err(err) => {
                    warn!("https latency measurement failed: {:?}", err);
                }
            }
        }
    }

    trace!("probe successful");
    Ok(result)
}

/// Run a STUN IPv4 or IPv6 probe.
async fn run_stun_probe(
    sock: &Arc<UdpSocket>,
    derp_addr: SocketAddr,
    netcheck: netcheck::Addr,
    probe: Probe,
) -> Result<ProbeReport, ProbeError> {
    let txid = stun::TransactionId::default();
    let req = stun::request(txid);

    // Setup netcheck to give us back the incoming STUN response.
    let (stun_tx, stun_rx) = oneshot::channel();
    let (inflight_ready_tx, inflight_ready_rx) = oneshot::channel();
    netcheck
        .send(netcheck::Message::InFlightStun(
            netcheck::Inflight {
                txn: txid,
                start: Instant::now(),
                s: stun_tx,
            },
            inflight_ready_tx,
        ))
        .await
        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
    inflight_ready_rx
        .await
        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;

    // Send the probe.
    match sock.send_to(&req, derp_addr).await {
        Ok(n) if n == req.len() => {
            debug!(%derp_addr, %txid, "sending {} probe", probe.proto());
            let mut result = ProbeReport::new(probe.clone());

            if matches!(probe, Probe::StunIpv4 { .. }) {
                result.ipv4_can_send = true;
                inc!(NetcheckMetrics, stun_packets_sent_ipv4);
            } else {
                result.ipv6_can_send = true;
                inc!(NetcheckMetrics, stun_packets_sent_ipv6);
            }
            let (delay, addr) = stun_rx
                .await
                .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
            result.latency = Some(delay);
            result.addr = Some(addr);
            Ok(result)
        }
        Ok(n) => {
            let err = anyhow!("Failed to send full STUN request: {}", probe.proto());
            error!(%derp_addr, sent_len=n, req_len=req.len(), "{err:#}");
            Err(ProbeError::Error(err, probe.clone()))
        }
        Err(err) => {
            let kind = err.kind();
            let err = anyhow::Error::new(err)
                .context(format!("Failed to send STUN request: {}", probe.proto()));

            // It is entirely normal that we are on a dual-stack machine with no
            // routed IPv6 network.  So silence that case.
            // NetworkUnreachable is still experimental (io_error_more #86442)
            // but it is already emitted.  So hack around this.
            match format!("{kind:?}").as_str() {
                "NetworkUnreachable" => {
                    debug!(%derp_addr, "{err:#}");
                    Err(ProbeError::AbortSet(err, probe.clone()))
                }
                _ => {
                    // No need to log this, our caller does already log this.
                    Err(ProbeError::Error(err, probe.clone()))
                }
            }
        }
    }
}

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
async fn check_captive_portal(dm: &DerpMap, preferred_derp: Option<DerpUrl>) -> Result<bool> {
    // If we have a preferred DERP node and we can use it for non-STUN requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.
    let preferred_derp = preferred_derp.and_then(|url| match dm.get_node(&url) {
        Some(node) if node.stun_only => Some(url),
        _ => None,
    });

    let url = match preferred_derp {
        Some(url) => url,
        None => {
            let urls: Vec<_> = dm
                .nodes()
                .filter(|n| !n.stun_only)
                .map(|n| n.url.clone())
                .collect();
            if urls.is_empty() {
                debug!("No suitable Derp node for captive portal check");
                return Ok(false);
            }

            let i = (0..urls.len())
                .choose(&mut rand::thread_rng())
                .unwrap_or_default();
            urls[i].clone()
        }
    };

    let client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Note: the set of valid characters in a challenge and the total
    // length is limited; see is_challenge_char in bin/derper for more
    // details.

    let host_name = url.host_str().unwrap_or_default();
    let challenge = format!("ts_{}", host_name);
    let portal_url = format!("http://{}/generate_204", host_name);
    let res = client
        .request(reqwest::Method::GET, portal_url)
        .header("X-Tailscale-Challenge", &challenge)
        .send()
        .await?;

    let expected_response = format!("response {challenge}");
    let is_valid_response = res
        .headers()
        .get("X-Tailscale-Response")
        .map(|s| s.to_str().unwrap_or_default())
        == Some(&expected_response);

    debug!(
        "check_captive_portal url={} status_code={} valid_response={}",
        res.url(),
        res.status(),
        is_valid_response,
    );
    let has_captive = res.status() != 204 || !is_valid_response;

    Ok(has_captive)
}

/// Returns the IP address to use to communicate to this derp node.
///
/// *proto* specifies the protocol of the probe.  Depending on the protocol we may return
/// different results.  Obviously IPv4 vs IPv6 but a [`DerpNode`] may also have disabled
/// some protocols.
async fn get_derp_addr(derp_node: &DerpNode, proto: ProbeProto) -> Result<SocketAddr> {
    let port = if derp_node.stun_port == 0 {
        DEFAULT_DERP_STUN_PORT
    } else {
        derp_node.stun_port
    };

    if derp_node.stun_only && !matches!(proto, ProbeProto::StunIpv4 | ProbeProto::StunIpv6) {
        bail!("Derp node not suitable for non-STUN probes");
    }

    match proto {
        ProbeProto::StunIpv4 | ProbeProto::IcmpV4 => match derp_node.url.host() {
            Some(url::Host::Domain(hostname)) => {
                debug!(?proto, %hostname, "Performing DNS A lookup for derp addr");
                match lookup_ipv4(hostname, DNS_TIMEOUT).await {
                    Ok(addrs) => addrs
                        .first()
                        .map(|addr| ip::to_canonical(*addr))
                        .map(|addr| SocketAddr::new(addr, port))
                        .ok_or(anyhow!("No suitable derp addr found")),
                    Err(err) => Err(err.context("No suitable derp addr found")),
                }
            }
            Some(url::Host::Ipv4(addr)) => Ok(SocketAddr::new(addr.into(), port)),
            Some(url::Host::Ipv6(_addr)) => Err(anyhow!("No suitable derp addr found")),
            None => Err(anyhow!("No valid hostname in DerpUrl")),
        },

        ProbeProto::StunIpv6 | ProbeProto::IcmpV6 => match derp_node.url.host() {
            Some(url::Host::Domain(hostname)) => {
                debug!(?proto, %hostname, "Performing DNS AAAA lookup for derp addr");
                match lookup_ipv6(hostname, DNS_TIMEOUT).await {
                    Ok(addrs) => addrs
                        .first()
                        .map(|addr| ip::to_canonical(*addr))
                        .map(|addr| SocketAddr::new(addr, port))
                        .ok_or(anyhow!("No suitable derp addr found")),
                    Err(err) => Err(err.context("No suitable derp addr found")),
                }
            }
            Some(url::Host::Ipv4(_addr)) => Err(anyhow!("No suitable derp addr found")),
            Some(url::Host::Ipv6(addr)) => Ok(SocketAddr::new(addr.into(), port)),
            None => Err(anyhow!("No valid hostname in DerpUrl")),
        },

        ProbeProto::Https => Err(anyhow!("Not implemented")),
    }
}

/// Runs an ICMP IPv4 or IPv6 probe.
///
/// The `pinger` is passed in so the ping sockets are only bound once
/// for the probe set.
async fn run_icmp_probe(
    probe: Probe,
    derp_addr: SocketAddr,
    pinger: Pinger,
) -> Result<ProbeReport, ProbeError> {
    const DATA: &[u8; 15] = b"iroh icmp probe";
    debug!(dst = %derp_addr, len = DATA.len(), "ICMP Ping started");
    let latency = pinger
        .send(derp_addr.ip(), DATA)
        .await
        .map_err(|err| match err {
            PingError::Client(err) => ProbeError::AbortSet(
                anyhow!("Failed to create pinger ({err:#}), aborting probeset"),
                probe.clone(),
            ),
            PingError::Ping(err) => ProbeError::Error(err.into(), probe.clone()),
        })?;
    debug!(dst = %derp_addr, len = DATA.len(), ?latency, "ICMP ping done");
    let mut report = ProbeReport::new(probe);
    report.latency = Some(latency);
    match derp_addr {
        SocketAddr::V4(_) => {
            report.ipv4_can_send = true;
            report.icmpv4 = Some(true);
        }
        SocketAddr::V6(_) => {
            report.ipv6_can_send = true;
            report.icmpv6 = Some(true);
        }
    }
    Ok(report)
}

#[allow(clippy::unused_async)]
async fn measure_https_latency(_node: &DerpNode) -> Result<(Duration, IpAddr)> {
    bail!("not implemented");
    // TODO:
    // - needs derphttp::Client
    // - measurement hooks to measure server processing time

    // metricHTTPSend.Add(1)
    // let ctx, cancel := context.WithTimeout(httpstat.WithHTTPStat(ctx, &result), overallProbeTimeout);
    // let dc := derphttp.NewNetcheckClient(c.logf);
    // let tlsConn, tcpConn, node := dc.DialRegionTLS(ctx, reg)?;
    // if ta, ok := tlsConn.RemoteAddr().(*net.TCPAddr);
    // req, err := http.NewRequestWithContext(ctx, "GET", "https://"+node.HostName+"/derp/latency-check", nil);
    // resp, err := hc.Do(req);

    // // DERPs should give us a nominal status code, so anything else is probably
    // // an access denied by a MITM proxy (or at the very least a signal not to
    // // trust this latency check).
    // if resp.StatusCode > 299 {
    //     return 0, ip, fmt.Errorf("unexpected status code: %d (%s)", resp.StatusCode, resp.Status)
    // }
    // _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10));
    // result.End(c.timeNow())

    // // TODO: decide best timing heuristic here.
    // // Maybe the server should return the tcpinfo_rtt?
    // return result.ServerProcessing, ip, nil
}

/// Updates a netcheck [`Report`] with a new [`ProbeReport`].
fn update_report(report: &mut Report, probe_report: ProbeReport) {
    let derp_node = probe_report.probe.node();
    if let Some(latency) = probe_report.latency {
        report
            .derp_latency
            .update_derp(derp_node.url.clone(), latency);

        if matches!(
            probe_report.probe.proto(),
            ProbeProto::StunIpv4 | ProbeProto::StunIpv6
        ) {
            report.udp = true;

            match probe_report.addr {
                Some(ipp @ SocketAddr::V4(_)) => {
                    report.ipv4 = true;
                    report
                        .derp_v4_latency
                        .update_derp(derp_node.url.clone(), latency);
                    if report.global_v4.is_none() {
                        report.global_v4 = Some(ipp);
                    } else if report.global_v4 != Some(ipp) {
                        report.mapping_varies_by_dest_ip = Some(true);
                    } else if report.mapping_varies_by_dest_ip.is_none() {
                        report.mapping_varies_by_dest_ip = Some(false);
                    }
                }
                Some(ipp @ SocketAddr::V6(_)) => {
                    report.ipv6 = true;
                    report
                        .derp_v6_latency
                        .update_derp(derp_node.url.clone(), latency);
                    report.global_v6 = Some(ipp);
                    // TODO: Should we track mapping_varies_by_dest_ip for IPv6 too?  Would
                    // be sad if so, but in theory is possible.
                }
                None => {
                    // If we are here we had a derper latency reported from a STUN probe.
                    // Thus we must have a reported address.
                    debug_assert!(probe_report.addr.is_some());
                }
            }
        }
    }
    report.ipv4_can_send |= probe_report.ipv4_can_send;
    report.ipv6_can_send |= probe_report.ipv6_can_send;
    report.icmpv4 = report
        .icmpv4
        .map(|val| val || probe_report.icmpv4.unwrap_or_default())
        .or(probe_report.icmpv4);
    report.icmpv6 = report
        .icmpv6
        .map(|val| val || probe_report.icmpv6.unwrap_or_default())
        .or(probe_report.icmpv6);
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    use crate::defaults::{default_eu_derp_node, default_na_derp_node};

    #[test]
    fn test_update_report_stun_working() {
        let eu_derper = Arc::new(default_eu_derp_node());
        let na_derper = Arc::new(default_na_derp_node());

        let mut report = Report::default();

        // An STUN IPv4 probe from the EU derper.
        let probe_report_eu = ProbeReport {
            ipv4_can_send: true,
            ipv6_can_send: false,
            icmpv4: None,
            icmpv6: None,
            latency: Some(Duration::from_millis(5)),
            probe: Probe::StunIpv4 {
                delay: Duration::ZERO,
                node: eu_derper.clone(),
            },
            addr: Some((Ipv4Addr::new(203, 0, 113, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_eu.clone());

        assert!(report.udp);
        assert_eq!(
            report.derp_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(5)
        );
        assert_eq!(
            report.derp_v4_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(5)
        );
        assert!(report.ipv4_can_send);
        assert!(!report.ipv6_can_send);

        // A second STUN IPv4 probe, same external IP detected but slower.
        let probe_report_na = ProbeReport {
            latency: Some(Duration::from_millis(8)),
            probe: Probe::StunIpv4 {
                delay: Duration::ZERO,
                node: na_derper.clone(),
            },
            ..probe_report_eu
        };
        update_report(&mut report, probe_report_na);

        assert!(report.udp);
        assert_eq!(
            report.derp_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(5)
        );
        assert_eq!(
            report.derp_v4_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(5)
        );
        assert!(report.ipv4_can_send);
        assert!(!report.ipv6_can_send);

        // A STUN IPv6 probe, this one is faster.
        let probe_report_eu_ipv6 = ProbeReport {
            ipv4_can_send: false,
            ipv6_can_send: true,
            icmpv4: None,
            icmpv6: None,
            latency: Some(Duration::from_millis(4)),
            probe: Probe::StunIpv6 {
                delay: Duration::ZERO,
                node: eu_derper.clone(),
            },
            addr: Some((Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_eu_ipv6);

        assert!(report.udp);
        assert_eq!(
            report.derp_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(4)
        );
        assert_eq!(
            report.derp_v6_latency.get(&eu_derper.url).unwrap(),
            Duration::from_millis(4)
        );
        assert!(report.ipv4_can_send);
        assert!(report.ipv6_can_send);
    }

    #[test]
    fn test_update_report_icmp() {
        let eu_derper = Arc::new(default_eu_derp_node());
        let na_derper = Arc::new(default_na_derp_node());

        let mut report = Report::default();

        // An ICMPv4 probe from the EU derper.
        let probe_report_eu = ProbeReport {
            ipv4_can_send: true,
            ipv6_can_send: false,
            icmpv4: Some(true),
            icmpv6: None,
            latency: Some(Duration::from_millis(5)),
            probe: Probe::IcmpV4 {
                delay: Duration::ZERO,
                node: eu_derper.clone(),
            },
            addr: Some((Ipv4Addr::new(203, 0, 113, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_eu.clone());

        assert!(!report.udp);
        assert!(report.ipv4_can_send);
        assert_eq!(report.icmpv4, Some(true));

        // A second ICMPv4 probe which did not work.
        let probe_report_na = ProbeReport {
            ipv4_can_send: false,
            ipv6_can_send: false,
            icmpv4: Some(false),
            icmpv6: None,
            latency: None,
            probe: Probe::IcmpV4 {
                delay: Duration::ZERO,
                node: na_derper.clone(),
            },
            addr: None,
        };
        update_report(&mut report, probe_report_na);

        assert_eq!(report.icmpv4, Some(true));

        // Behold, a STUN probe arrives!
        let probe_report_eu_stun = ProbeReport {
            ipv4_can_send: true,
            ipv6_can_send: false,
            icmpv4: None,
            icmpv6: None,
            latency: Some(Duration::from_millis(5)),
            probe: Probe::StunIpv4 {
                delay: Duration::ZERO,
                node: eu_derper.clone(),
            },
            addr: Some((Ipv4Addr::new(203, 0, 113, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_eu_stun);

        assert!(report.udp);
        assert_eq!(report.icmpv4, Some(true));
    }

    // # ICMP permissions on Linux
    //
    // ## Using capabilities: CAP_NET_RAW
    //
    // To run ICMP tests on Linux you need CAP_NET_RAW capabilities.  When running tests
    // this means you first need to build the binary, set the capabilities and finally run
    // the tests.
    //
    // Build the test binary:
    //
    //    cargo nextest run -p iroh_net netcheck::reportgen::tests --no-run
    //
    // Find out the test binary location:
    //
    //    cargo nextest list --message-format json -p iroh-net netcheck::reportgen::tests \
    //       | jq '."rust-suites"."iroh-net"."binary-path"' | tr -d \"
    //
    // Set the CAP_NET_RAW permission, note that nextest runs each test in a chile process
    // so the capabilities need to be inherited:
    //
    //    sudo setcap CAP_NET_RAW=eip target/debug/deps/iroh_net-abc123
    //
    // Finally run the test:
    //
    //    cargo nextest run -p iroh_net netcheck::reportgen::tests
    //
    // This allows the pinger to create a SOCK_RAW socket for IPPROTO_ICMP.
    //
    //
    // ## Using sysctl
    //
    // Now you know the hard way, you can also get this permission a little easier, but
    // slightly less secure, by allowing any process running with your group ID to create an
    // SOCK_DGRAM for IPPROTO_ICMP.
    //
    // First find out your group ID:
    //
    //    id --group
    //
    // Then allow allow this group to send pings.  Note that this is an inclusive range:
    //
    //    sudo sysctl net.ipv4.ping_group_range="1234 1234"
    //
    // Note that this does not survive a reboot usually, commonly you need to edit
    // /etc/sysctl.conf or /etc/sysctl.d/* to persist this accross reboots.
    //
    // TODO: Not sure what about IPv6 pings using sysctl.
    #[tokio::test]
    async fn test_icmp_probe_eu_derper() {
        let _logging_guard = iroh_test::logging::setup();
        let pinger = Pinger::new();
        let derper = default_eu_derp_node();
        let addr = get_derp_addr(&derper, ProbeProto::IcmpV4).await.unwrap();
        let probe = Probe::IcmpV4 {
            delay: Duration::from_secs(0),
            node: Arc::new(derper),
        };
        match run_icmp_probe(probe, addr, pinger).await {
            Ok(report) => {
                dbg!(&report);
                assert_eq!(report.icmpv4, Some(true));
                assert!(report.latency.expect("should have a latency") > Duration::from_secs(0));
            }
            Err(ProbeError::Error(err, _probe)) => panic!("Ping error: {err:#}"),
            Err(ProbeError::AbortSet(err, _probe)) => {
                // We don't have permission, too bad.
                panic!("no ping permission: {err:#}");
            }
        }
    }
}
