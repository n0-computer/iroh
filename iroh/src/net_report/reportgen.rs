//! The reportgen actor is responsible for generating a single net_report report.
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
//! - Sends the completed report to the net_report actor.

use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{anyhow, bail, Context as _, Result};
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::DnsResolver;
use iroh_relay::{
    defaults::{DEFAULT_RELAY_QUIC_PORT, DEFAULT_STUN_PORT},
    http::RELAY_PROBE_PATH,
    protos::stun,
    RelayMap, RelayNode,
};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
use n0_future::{
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration, Instant},
    StreamExt as _,
};
#[cfg(not(wasm_browser))]
use netwatch::{interfaces, UdpSocket};
use rand::seq::IteratorRandom;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, debug_span, error, info_span, trace, warn, Instrument, Span};
use url::Host;

#[cfg(wasm_browser)]
use crate::net_report::portmapper; // We stub the library
use crate::net_report::{self, Metrics, Report};
#[cfg(not(wasm_browser))]
use crate::net_report::{
    defaults::timeouts::DNS_TIMEOUT,
    dns::DNS_STAGGERING_MS,
    ip_mapped_addrs::IpMappedAddresses,
    ping::{PingError, Pinger},
};

#[cfg(not(wasm_browser))]
mod hairpin;
mod probes;

pub use probes::ProbeProto;
use probes::{Probe, ProbePlan};

use crate::net_report::defaults::timeouts::{
    CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, OVERALL_REPORT_TIMEOUT, PROBES_TIMEOUT,
};

const ENOUGH_NODES: usize = 3;

/// Holds the state for a single invocation of [`net_report::Client::get_report`].
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug)]
pub(super) struct Client {
    // Addr is currently only used by child actors, so not yet exposed here.
    _drop_guard: AbortOnDropHandle<()>,
}

/// Any state that depends on sockets being available in the current environment.
///
/// Factored out so it can be disabled easily in browsers.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone)]
pub(crate) struct SocketState {
    /// The portmapper client, if there is one.
    pub(crate) port_mapper: Option<portmapper::Client>,
    /// Socket to send IPv4 STUN requests from.
    pub(crate) stun_sock4: Option<Arc<UdpSocket>>,
    /// Socket so send IPv6 STUN requests from.
    pub(crate) stun_sock6: Option<Arc<UdpSocket>>,
    /// QUIC configuration to do QUIC address Discovery
    pub(crate) quic_config: Option<QuicConfig>,
    /// The DNS resolver to use for probes that need to resolve DNS records.
    pub(crate) dns_resolver: DnsResolver,
    /// Optional [`IpMappedAddresses`] used to enable QAD in iroh
    pub(crate) ip_mapped_addrs: Option<IpMappedAddresses>,
}

impl Client {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    pub(super) fn new(
        net_report: net_report::Addr,
        last_report: Option<Arc<Report>>,
        relay_map: RelayMap,
        protocols: BTreeSet<ProbeProto>,
        metrics: Arc<Metrics>,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let addr = Addr {
            sender: msg_tx.clone(),
        };
        let mut actor = Actor {
            msg_tx,
            msg_rx,
            net_report: net_report.clone(),
            last_report,
            relay_map,
            report: Report::default(),
            outstanding_tasks: OutstandingTasks::default(),
            protocols,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(not(wasm_browser))]
            hairpin_actor: hairpin::Client::new(net_report, addr),
            metrics,
        };
        let task =
            task::spawn(async move { actor.run().await }.instrument(info_span!("reportgen.actor")));
        Self {
            _drop_guard: AbortOnDropHandle::new(task),
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
    ProbeWouldHelp(Probe, Arc<RelayNode>, oneshot::Sender<bool>),
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
    /// The address of the net_report actor.
    net_report: super::Addr,

    // Provided state
    /// The previous report, if it exists.
    last_report: Option<Arc<Report>>,
    /// The relay configuration.
    relay_map: RelayMap,

    // Internal state.
    /// The report being built.
    report: Report,
    /// Which tasks the [`Actor`] is still waiting on.
    ///
    /// This is essentially the summary of all the work the [`Actor`] is doing.
    outstanding_tasks: OutstandingTasks,
    /// Protocols we should attempt to create probes for, if we have the correct
    /// configuration for that protocol.
    protocols: BTreeSet<ProbeProto>,

    /// Any socket-related state that doesn't exist/work in browsers
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    /// The hairpin actor.
    #[cfg(not(wasm_browser))]
    hairpin_actor: hairpin::Client,
    metrics: Arc<Metrics>,
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
                self.net_report
                    .send(net_report::Message::ReportAborted { err })
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
    /// - Sends the report to the net_report actor.
    async fn run_inner(&mut self) -> Result<()> {
        #[cfg(not(wasm_browser))]
        let port_mapper = self.socket_state.port_mapper.is_some();
        #[cfg(wasm_browser)]
        let port_mapper = false;
        debug!(%port_mapper, "reportstate actor starting");

        self.report.os_has_ipv6 = super::os_has_ipv6();

        let mut port_mapping = self.prepare_portmapper_task();
        let mut captive_task = self.prepare_captive_portal_task();
        let mut probes = self.spawn_probes_task().await?;

        let total_timer = time::sleep(OVERALL_REPORT_TIMEOUT);
        tokio::pin!(total_timer);
        let probe_timer = time::sleep(PROBES_TIMEOUT);
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
                    // Set new timeout to not go into this branch multiple times.  We need
                    // the abort to finish all probes normally.  PROBES_TIMEOUT is
                    // sufficiently far in the future.
                    probe_timer.as_mut().reset(Instant::now() + PROBES_TIMEOUT);
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

        debug!("Sending report to net_report actor");
        self.net_report
            .send(net_report::Message::ReportReady {
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
            Message::ProbeWouldHelp(probe, relay_node, response_tx) => {
                let res = self.probe_would_help(probe, relay_node);
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
        #[cfg(not(wasm_browser))]
        if let Some(ref addr) = self.report.global_v4 {
            if !self.hairpin_actor.has_started() {
                self.hairpin_actor.start_check(*addr);
                self.outstanding_tasks.hairpin = true;
            }
        }

        // Once we've heard from enough relay servers (3), start a timer to give up on the other
        // probes. The timer's duration is a function of whether this is our initial full
        // probe or an incremental one. For incremental ones, wait for the duration of the
        // slowest relay. For initial ones, double that.
        let enough_relays = std::cmp::min(self.relay_map.len(), ENOUGH_NODES);
        if self.report.relay_latency.len() == enough_relays {
            let timeout = self.report.relay_latency.max_latency();
            let timeout = match self.last_report.is_some() {
                true => timeout,
                false => timeout * 2,
            };
            let reportcheck = self.addr();
            debug!(
                reports=self.report.relay_latency.len(),
                delay=?timeout,
                "Have enough probe reports, aborting further probes soon",
            );
            task::spawn(
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
    fn probe_would_help(&mut self, probe: Probe, relay_node: Arc<RelayNode>) -> bool {
        // If the probe is for a relay we don't yet know about, that would help.
        if self.report.relay_latency.get(&relay_node.url).is_none() {
            return true;
        }

        // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
        #[cfg(not(wasm_browser))]
        if probe.proto() == ProbeProto::StunIpv6 && self.report.relay_v6_latency.is_empty() {
            return true;
        }

        // For IPv4, we need at least two IPv4 results overall to
        // determine whether we're behind a NAT that shows us as
        // different source IPs and/or ports depending on who we're
        // talking to. If we don't yet have two results yet
        // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
        // would be good.
        #[cfg(not(wasm_browser))]
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
        // In the browser, the compiler struggles to infer the type of future inside, because it's never set.
        #[cfg(wasm_browser)]
        let port_mapping: MaybeFuture<Pin<Box<Pending<Option<portmapper::ProbeOutput>>>>> =
            MaybeFuture::default();

        #[cfg(not(wasm_browser))]
        let mut port_mapping = MaybeFuture::default();

        #[cfg(not(wasm_browser))]
        if let Some(port_mapper) = self.socket_state.port_mapper.clone() {
            port_mapping.inner = Some(Box::pin(async move {
                match port_mapper.probe().await {
                    Ok(Ok(res)) => Some(res),
                    Ok(Err(err)) => {
                        debug!("skipping port mapping: {err:?}");
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
        // In the browser case the compiler cannot infer the type of the future, because it's never set:
        #[cfg(wasm_browser)]
        let captive_task: MaybeFuture<Pin<Box<Pending<Option<bool>>>>> = MaybeFuture::default();

        #[cfg(not(wasm_browser))]
        let mut captive_task = MaybeFuture::default();

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        #[cfg(not(wasm_browser))]
        if self.last_report.is_none() {
            // Even if we're doing a non-incremental update, we may want to try our
            // preferred relay for captive portal detection.
            let preferred_relay = self
                .last_report
                .as_ref()
                .and_then(|l| l.preferred_relay.clone());

            let dns_resolver = self.socket_state.dns_resolver.clone();
            let dm = self.relay_map.clone();
            self.outstanding_tasks.captive_task = true;
            captive_task.inner = Some(Box::pin(async move {
                time::sleep(CAPTIVE_PORTAL_DELAY).await;
                debug!("Captive portal check started after {CAPTIVE_PORTAL_DELAY:?}");
                let captive_portal_check = time::timeout(
                    CAPTIVE_PORTAL_TIMEOUT,
                    check_captive_portal(&dns_resolver, &dm, preferred_relay)
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
            }));
        }

        self.outstanding_tasks.captive_task = false;
        captive_task
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
        #[cfg(not(wasm_browser))]
        let if_state = interfaces::State::new().await;
        #[cfg(not(wasm_browser))]
        debug!(%if_state, "Local interfaces");
        let plan = match self.last_report {
            Some(ref report) => ProbePlan::with_last_report(
                &self.relay_map,
                report,
                &self.protocols,
                #[cfg(not(wasm_browser))]
                &if_state,
            ),
            None => ProbePlan::initial(
                &self.relay_map,
                &self.protocols,
                #[cfg(not(wasm_browser))]
                &if_state,
            ),
        };
        trace!(%plan, "probe plan");

        // The pinger is created here so that any sockets that might be bound for it are
        // shared between the probes that use it.  It binds sockets lazily, so we can always
        // create it.
        #[cfg(not(wasm_browser))]
        let pinger = Pinger::new();

        // A collection of futures running probe sets.
        let mut probes = JoinSet::default();
        for probe_set in plan.iter() {
            let mut set = JoinSet::default();
            for probe in probe_set {
                let reportstate = self.addr();
                let relay_node = probe.node().clone();
                let probe = probe.clone();
                let net_report = self.net_report.clone();

                #[cfg(not(wasm_browser))]
                let pinger = pinger.clone();
                #[cfg(not(wasm_browser))]
                let socket_state = self.socket_state.clone();

                let metrics = self.metrics.clone();
                set.spawn(
                    run_probe(
                        reportstate,
                        relay_node,
                        probe.clone(),
                        net_report,
                        metrics,
                        #[cfg(not(wasm_browser))]
                        pinger,
                        #[cfg(not(wasm_browser))]
                        socket_state,
                    )
                    .instrument(debug_span!("run_probe", %probe)),
                );
            }

            // Add the probe set to all futures of probe sets.  Handle aborting a probe set
            // if needed, only normal errors means the set continues.
            probes.spawn(
                async move {
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
                }
                .instrument(info_span!("probe")),
            );
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
    /// The latency to the relay node.
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

/// Pieces needed to do QUIC address discovery.
#[derive(derive_more::Debug, Clone)]
pub struct QuicConfig {
    /// A QUIC Endpoint
    #[debug("quinn::Endpoint")]
    pub ep: quinn::Endpoint,
    /// A client config.
    pub client_config: rustls::ClientConfig,
    /// Enable ipv4 QUIC address discovery probes
    pub ipv4: bool,
    /// Enable ipv6 QUIC address discovery probes
    pub ipv6: bool,
}

/// Executes a particular [`Probe`], including using a delayed start if needed.
///
/// If *stun_sock4* and *stun_sock6* are `None` the STUN probes are disabled.
async fn run_probe(
    reportstate: Addr,
    relay_node: Arc<RelayNode>,
    probe: Probe,
    net_report: net_report::Addr,
    metrics: Arc<Metrics>,
    #[cfg(not(wasm_browser))] pinger: Pinger,
    #[cfg(not(wasm_browser))] socket_state: SocketState,
) -> Result<ProbeReport, ProbeError> {
    if !probe.delay().is_zero() {
        trace!("delaying probe");
        time::sleep(probe.delay()).await;
    }
    debug!("starting probe");

    let (would_help_tx, would_help_rx) = oneshot::channel();
    if let Err(err) = reportstate
        .send(Message::ProbeWouldHelp(
            probe.clone(),
            relay_node.clone(),
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

    #[cfg(not(wasm_browser))]
    let relay_addr = get_relay_addr(&socket_state.dns_resolver, &relay_node, probe.proto())
        .await
        .context("no relay node addr")
        .map_err(|e| ProbeError::AbortSet(e, probe.clone()))?;

    let mut result = ProbeReport::new(probe.clone());
    match probe {
        #[cfg(not(wasm_browser))]
        Probe::StunIpv4 { .. } | Probe::StunIpv6 { .. } => {
            let maybe_sock = if matches!(probe, Probe::StunIpv4 { .. }) {
                socket_state.stun_sock4.as_ref()
            } else {
                socket_state.stun_sock6.as_ref()
            };
            match maybe_sock {
                Some(sock) => {
                    result = run_stun_probe(sock, relay_addr, net_report, probe, &metrics).await?;
                }
                None => {
                    return Err(ProbeError::AbortSet(
                        anyhow!("No socket for {}, aborting probeset", probe.proto()),
                        probe.clone(),
                    ));
                }
            }
        }
        #[cfg(not(wasm_browser))]
        Probe::IcmpV4 { .. } | Probe::IcmpV6 { .. } => {
            result = run_icmp_probe(probe, relay_addr, pinger).await?
        }
        Probe::Https { ref node, .. } => {
            debug!("sending probe HTTPS");
            match measure_https_latency(
                #[cfg(not(wasm_browser))]
                &socket_state.dns_resolver,
                node,
                None,
            )
            .await
            {
                Ok((latency, ip)) => {
                    debug!(?latency, "latency");
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

        #[cfg(not(wasm_browser))]
        Probe::QuicIpv4 { ref node, .. } | Probe::QuicIpv6 { ref node, .. } => {
            debug!("sending QUIC address discovery probe");
            let url = node.url.clone();
            match socket_state.quic_config {
                Some(quic_config) => {
                    result = run_quic_probe(
                        quic_config,
                        url,
                        relay_addr,
                        probe,
                        socket_state.ip_mapped_addrs,
                    )
                    .await?;
                }
                None => {
                    return Err(ProbeError::AbortSet(
                        anyhow!("No QUIC endpoint for {}", probe.proto()),
                        probe.clone(),
                    ));
                }
            }
        }
    }

    trace!("probe successful");
    Ok(result)
}

/// Run a STUN IPv4 or IPv6 probe.
#[cfg(not(wasm_browser))]
async fn run_stun_probe(
    sock: &Arc<UdpSocket>,
    relay_addr: SocketAddr,
    net_report: net_report::Addr,
    probe: Probe,
    metrics: &Metrics,
) -> Result<ProbeReport, ProbeError> {
    match probe.proto() {
        ProbeProto::StunIpv4 => debug_assert!(relay_addr.is_ipv4()),
        ProbeProto::StunIpv6 => debug_assert!(relay_addr.is_ipv6()),
        _ => debug_assert!(false, "wrong probe"),
    }
    let txid = stun::TransactionId::default();
    let req = stun::request(txid);

    // Setup net_report to give us back the incoming STUN response.
    let (stun_tx, stun_rx) = oneshot::channel();
    let (inflight_ready_tx, inflight_ready_rx) = oneshot::channel();
    net_report
        .send(net_report::Message::InFlightStun(
            net_report::Inflight {
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
    match sock.send_to(&req, relay_addr).await {
        Ok(n) if n == req.len() => {
            debug!(%relay_addr, %txid, "sending {} probe", probe.proto());
            let mut result = ProbeReport::new(probe.clone());

            if matches!(probe, Probe::StunIpv4 { .. }) {
                result.ipv4_can_send = true;
                metrics.stun_packets_sent_ipv4.inc();
            } else {
                result.ipv6_can_send = true;
                metrics.stun_packets_sent_ipv6.inc();
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
            error!(%relay_addr, sent_len=n, req_len=req.len(), "{err:#}");
            Err(ProbeError::Error(err, probe.clone()))
        }
        Err(err) => {
            let kind = err.kind();
            let err = anyhow::Error::new(err)
                .context(format!("Failed to send STUN request: {}", probe.proto()));

            // It is entirely normal that we are on a dual-stack machine with no
            // routed IPv6 network.  So silence that case.
            // NetworkUnreachable and HostUnreachable are still experimental (io_error_more
            // #86442) but it is already emitted.  So hack around this.
            match format!("{kind:?}").as_str() {
                "NetworkUnreachable" | "HostUnreachable" => {
                    debug!(%relay_addr, "{err:#}");
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

#[cfg(not(wasm_browser))]
fn maybe_to_mapped_addr(
    ip_mapped_addrs: Option<IpMappedAddresses>,
    addr: SocketAddr,
) -> SocketAddr {
    if let Some(ip_mapped_addrs) = ip_mapped_addrs.as_ref() {
        return ip_mapped_addrs.get_or_register(addr).private_socket_addr();
    }
    addr
}

/// Run a QUIC address discovery probe.
#[cfg(not(wasm_browser))]
async fn run_quic_probe(
    quic_config: QuicConfig,
    url: RelayUrl,
    relay_addr: SocketAddr,
    probe: Probe,
    ip_mapped_addrs: Option<IpMappedAddresses>,
) -> Result<ProbeReport, ProbeError> {
    match probe.proto() {
        ProbeProto::QuicIpv4 => debug_assert!(relay_addr.is_ipv4()),
        ProbeProto::QuicIpv6 => debug_assert!(relay_addr.is_ipv6()),
        _ => debug_assert!(false, "wrong probe"),
    }
    let relay_addr = maybe_to_mapped_addr(ip_mapped_addrs, relay_addr);
    let host = match url.host_str() {
        Some(host) => host,
        None => {
            return Err(ProbeError::Error(
                anyhow!("URL must have 'host' to use QUIC address discovery probes"),
                probe.clone(),
            ));
        }
    };
    let quic_client = iroh_relay::quic::QuicClient::new(quic_config.ep, quic_config.client_config)
        .map_err(|e| ProbeError::Error(e, probe.clone()))?;
    let (addr, latency) = quic_client
        .get_addr_and_latency(relay_addr, host)
        .await
        .map_err(|e| ProbeError::Error(e, probe.clone()))?;
    let mut result = ProbeReport::new(probe.clone());
    if matches!(probe, Probe::QuicIpv4 { .. }) {
        result.ipv4_can_send = true;
    } else {
        result.ipv6_can_send = true;
    }
    result.addr = Some(addr);
    result.latency = Some(latency);
    Ok(result)
}

/// Reports whether or not we think the system is behind a
/// captive portal, detected by making a request to a URL that we know should
/// return a "204 No Content" response and checking if that's what we get.
///
/// The boolean return is whether we think we have a captive portal.
#[cfg(not(wasm_browser))]
async fn check_captive_portal(
    dns_resolver: &DnsResolver,
    dm: &RelayMap,
    preferred_relay: Option<RelayUrl>,
) -> Result<bool> {
    // If we have a preferred relay node and we can use it for non-STUN requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.
    let preferred_relay = preferred_relay.and_then(|url| match dm.get_node(&url) {
        Some(node) if node.stun_only => Some(url),
        _ => None,
    });

    let url = match preferred_relay {
        Some(url) => url,
        None => {
            let urls: Vec<_> = dm
                .nodes()
                .filter(|n| !n.stun_only)
                .map(|n| n.url.clone())
                .collect();
            if urls.is_empty() {
                debug!("No suitable relay node for captive portal check");
                return Ok(false);
            }

            let i = (0..urls.len())
                .choose(&mut rand::thread_rng())
                .unwrap_or_default();
            urls[i].clone()
        }
    };

    let mut builder = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none());

    if let Some(Host::Domain(domain)) = url.host() {
        // Use our own resolver rather than getaddrinfo
        //
        // Be careful, a non-zero port will override the port in the URI.
        //
        // Ideally we would try to resolve **both** IPv4 and IPv6 rather than purely race
        // them.  But our resolver doesn't support that yet.
        let addrs: Vec<_> = dns_resolver
            .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
            .await?
            .map(|ipaddr| SocketAddr::new(ipaddr, 0))
            .collect();
        builder = builder.resolve_to_addrs(domain, &addrs);
    }
    let client = builder.build()?;

    // Note: the set of valid characters in a challenge and the total
    // length is limited; see is_challenge_char in bin/iroh-relay for more
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

/// Returns the proper port based on the protocol of the probe.
fn get_port(relay_node: &RelayNode, proto: &ProbeProto) -> Result<u16> {
    match proto {
        #[cfg(not(wasm_browser))]
        ProbeProto::QuicIpv4 | ProbeProto::QuicIpv6 => {
            if let Some(ref quic) = relay_node.quic {
                if quic.port == 0 {
                    Ok(DEFAULT_RELAY_QUIC_PORT)
                } else {
                    Ok(quic.port)
                }
            } else {
                bail!("Relay node not suitable for QUIC address discovery probes");
            }
        }
        _ => {
            if relay_node.stun_port == 0 {
                Ok(DEFAULT_STUN_PORT)
            } else {
                Ok(relay_node.stun_port)
            }
        }
    }
}

/// Returns the IP address to use to communicate to this relay node.
///
/// *proto* specifies the protocol of the probe.  Depending on the protocol we may return
/// different results.  Obviously IPv4 vs IPv6 but a [`RelayNode`] may also have disabled
/// some protocols.
///
/// If the protocol is `QuicIpv4` or `QuicIpv6`, and `IpMappedAddresses` is not `None`, we
/// assume that we are running this net report with `iroh`, and need to provide mapped
/// addresses to the probe in order for it to function in the specialize iroh-quinn
/// endpoint that expects mapped addresses.
#[cfg(not(wasm_browser))]
async fn get_relay_addr(
    dns_resolver: &DnsResolver,
    relay_node: &RelayNode,
    proto: ProbeProto,
) -> Result<SocketAddr> {
    if relay_node.stun_only && !matches!(proto, ProbeProto::StunIpv4 | ProbeProto::StunIpv6) {
        bail!("Relay node not suitable for non-STUN probes");
    }
    let port = get_port(relay_node, &proto)?;

    match proto {
        ProbeProto::StunIpv4 | ProbeProto::IcmpV4 | ProbeProto::QuicIpv4 => {
            relay_lookup_ipv4_staggered(dns_resolver, relay_node, port).await
        }

        ProbeProto::StunIpv6 | ProbeProto::IcmpV6 | ProbeProto::QuicIpv6 => {
            relay_lookup_ipv6_staggered(dns_resolver, relay_node, port).await
        }

        ProbeProto::Https => Err(anyhow!("Not implemented")),
    }
}

/// Do a staggared ipv4 DNS lookup based on [`RelayNode`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv4_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayNode,
    port: u16,
) -> Result<SocketAddr> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            debug!(%hostname, "Performing DNS A lookup for relay addr");
            match dns_resolver
                .lookup_ipv4_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|ip| ip.to_canonical())
                    .map(|addr| SocketAddr::new(addr, port))
                    .ok_or(anyhow!("No suitable relay addr found")),
                Err(err) => Err(err.context("No suitable relay addr found")),
            }
        }
        Some(url::Host::Ipv4(addr)) => Ok(SocketAddr::new(addr.into(), port)),
        Some(url::Host::Ipv6(_addr)) => Err(anyhow!("No suitable relay addr found")),
        None => Err(anyhow!("No valid hostname in RelayUrl")),
    }
}

/// Do a staggared ipv6 DNS lookup based on [`RelayNode`]
///
/// `port` is combined with the resolved [`std::net::Ipv6Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv6_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayNode,
    port: u16,
) -> Result<SocketAddr> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            debug!(%hostname, "Performing DNS AAAA lookup for relay addr");
            match dns_resolver
                .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|ip| ip.to_canonical())
                    .map(|addr| SocketAddr::new(addr, port))
                    .ok_or(anyhow!("No suitable relay addr found")),
                Err(err) => Err(err.context("No suitable relay addr found")),
            }
        }
        Some(url::Host::Ipv4(_addr)) => Err(anyhow!("No suitable relay addr found")),
        Some(url::Host::Ipv6(addr)) => Ok(SocketAddr::new(addr.into(), port)),
        None => Err(anyhow!("No valid hostname in RelayUrl")),
    }
}

/// Runs an ICMP IPv4 or IPv6 probe.
///
/// The `pinger` is passed in so the ping sockets are only bound once
/// for the probe set.
#[cfg(not(wasm_browser))]
async fn run_icmp_probe(
    probe: Probe,
    relay_addr: SocketAddr,
    pinger: Pinger,
) -> Result<ProbeReport, ProbeError> {
    match probe.proto() {
        ProbeProto::IcmpV4 => debug_assert!(relay_addr.is_ipv4()),
        ProbeProto::IcmpV6 => debug_assert!(relay_addr.is_ipv6()),
        _ => debug_assert!(false, "wrong probe"),
    }
    const DATA: &[u8; 15] = b"iroh icmp probe";
    debug!(dst = %relay_addr, len = DATA.len(), "ICMP Ping started");
    let latency = pinger
        .send(relay_addr.ip(), DATA)
        .await
        .map_err(|err| match err {
            PingError::Client(err) => ProbeError::AbortSet(
                anyhow!("Failed to create pinger ({err:#}), aborting probeset"),
                probe.clone(),
            ),
            #[cfg(not(wasm_browser))]
            PingError::Ping(err) => ProbeError::Error(err.into(), probe.clone()),
        })?;
    debug!(dst = %relay_addr, len = DATA.len(), ?latency, "ICMP ping done");
    let mut report = ProbeReport::new(probe);
    report.latency = Some(latency);
    match relay_addr {
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

/// Executes an HTTPS probe.
///
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[allow(clippy::unused_async)]
async fn measure_https_latency(
    #[cfg(not(wasm_browser))] dns_resolver: &DnsResolver,
    node: &RelayNode,
    certs: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
) -> Result<(Duration, IpAddr)> {
    let url = node.url.join(RELAY_PROBE_PATH)?;

    // This should also use same connection establishment as relay client itself, which
    // needs to be more configurable so users can do more crazy things:
    // https://github.com/n0-computer/iroh/issues/2901
    let mut builder = reqwest::ClientBuilder::new();

    #[cfg(not(wasm_browser))]
    {
        builder = builder.redirect(reqwest::redirect::Policy::none());
    }

    #[cfg(not(wasm_browser))]
    if let Some(Host::Domain(domain)) = url.host() {
        // Use our own resolver rather than getaddrinfo
        //
        // Be careful, a non-zero port will override the port in the URI.
        //
        // The relay Client uses `.lookup_ipv4_ipv6` to connect, so use the same function
        // but staggered for reliability.  Ideally this tries to resolve **both** IPv4 and
        // IPv6 though.  But our resolver does not have a function for that yet.
        let addrs: Vec<_> = dns_resolver
            .lookup_ipv4_ipv6_staggered(domain, DNS_TIMEOUT, DNS_STAGGERING_MS)
            .await?
            .map(|ipaddr| SocketAddr::new(ipaddr, 0))
            .collect();
        builder = builder.resolve_to_addrs(domain, &addrs);
    }

    #[cfg(not(wasm_browser))]
    if let Some(certs) = certs {
        for cert in certs {
            let cert = reqwest::Certificate::from_der(&cert)?;
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build()?;

    let start = Instant::now();
    let response = client.request(reqwest::Method::GET, url).send().await?;
    let latency = start.elapsed();
    if response.status().is_success() {
        // Only `None` if a different hyper HttpConnector in the request.
        #[cfg(not(wasm_browser))]
        let remote_ip = response
            .remote_addr()
            .context("missing HttpInfo from HttpConnector")?
            .ip();
        #[cfg(wasm_browser)]
        let remote_ip = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

        // Drain the response body to be nice to the server, up to a limit.
        const MAX_BODY_SIZE: usize = 8 << 10; // 8 KiB
        let mut body_size = 0;
        let mut stream = response.bytes_stream();
        // ignore failing frames
        while let Some(Ok(chunk)) = stream.next().await {
            body_size += chunk.len();
            if body_size >= MAX_BODY_SIZE {
                break;
            }
        }

        Ok((latency, remote_ip))
    } else {
        Err(anyhow!(
            "Error response from server: '{}'",
            response.status().canonical_reason().unwrap_or_default()
        ))
    }
}

/// Updates a net_report [`Report`] with a new [`ProbeReport`].
fn update_report(report: &mut Report, probe_report: ProbeReport) {
    let relay_node = probe_report.probe.node();
    if let Some(latency) = probe_report.latency {
        report
            .relay_latency
            .update_relay(relay_node.url.clone(), latency);

        #[cfg(not(wasm_browser))]
        if matches!(
            probe_report.probe.proto(),
            ProbeProto::StunIpv4
                | ProbeProto::StunIpv6
                | ProbeProto::QuicIpv4
                | ProbeProto::QuicIpv6
        ) {
            report.udp = true;

            match probe_report.addr {
                Some(SocketAddr::V4(ipp)) => {
                    report.ipv4 = true;
                    report
                        .relay_v4_latency
                        .update_relay(relay_node.url.clone(), latency);
                    if report.global_v4.is_none() {
                        report.global_v4 = Some(ipp);
                    } else if report.global_v4 != Some(ipp) {
                        report.mapping_varies_by_dest_ip = Some(true);
                    } else if report.mapping_varies_by_dest_ip.is_none() {
                        report.mapping_varies_by_dest_ip = Some(false);
                    }
                }
                Some(SocketAddr::V6(ipp)) => {
                    report.ipv6 = true;
                    report
                        .relay_v6_latency
                        .update_relay(relay_node.url.clone(), latency);
                    if report.global_v6.is_none() {
                        report.global_v6 = Some(ipp);
                    } else if report.global_v6 != Some(ipp) {
                        report.mapping_varies_by_dest_ipv6 = Some(true);
                        warn!("IPv6 Address detected by STUN varies by destination");
                    } else if report.mapping_varies_by_dest_ipv6.is_none() {
                        report.mapping_varies_by_dest_ipv6 = Some(false);
                    }
                }
                None => {
                    // If we are here we had a relay server latency reported from a STUN probe.
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

/// Resolves to pending if the inner is `None`.
#[derive(Debug)]
pub(crate) struct MaybeFuture<T> {
    /// Future to be polled.
    pub inner: Option<T>,
}

// NOTE: explicit implementation to bypass derive unnecessary bounds
impl<T> Default for MaybeFuture<T> {
    fn default() -> Self {
        MaybeFuture { inner: None }
    }
}

impl<T: Future + Unpin> Future for MaybeFuture<T> {
    type Output = T::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.inner {
            Some(ref mut t) => Pin::new(t).poll(cx),
            None => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use testresult::TestResult;
    use tracing_test::traced_test;

    use super::{super::test_utils, *};
    use crate::net_report::dns;

    #[tokio::test]
    #[traced_test]
    async fn test_update_report_stun_working() {
        let (_server_a, relay_a) = test_utils::relay().await;
        let (_server_b, relay_b) = test_utils::relay().await;

        let mut report = Report::default();

        // A STUN IPv4 probe from the the first relay server.
        let probe_report_a = ProbeReport {
            ipv4_can_send: true,
            ipv6_can_send: false,
            icmpv4: None,
            icmpv6: None,
            latency: Some(Duration::from_millis(5)),
            probe: Probe::StunIpv4 {
                delay: Duration::ZERO,
                node: relay_a.clone(),
            },
            addr: Some((Ipv4Addr::new(203, 0, 113, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_a.clone());

        assert!(report.udp);
        assert_eq!(
            report.relay_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(5)
        );
        assert_eq!(
            report.relay_v4_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(5)
        );
        assert!(report.ipv4_can_send);
        assert!(!report.ipv6_can_send);

        // A second STUN IPv4 probe, same external IP detected but slower.
        let probe_report_b = ProbeReport {
            latency: Some(Duration::from_millis(8)),
            probe: Probe::StunIpv4 {
                delay: Duration::ZERO,
                node: relay_b.clone(),
            },
            ..probe_report_a
        };
        update_report(&mut report, probe_report_b);

        assert!(report.udp);
        assert_eq!(
            report.relay_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(5)
        );
        assert_eq!(
            report.relay_v4_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(5)
        );
        assert!(report.ipv4_can_send);
        assert!(!report.ipv6_can_send);

        // A STUN IPv6 probe, this one is faster.
        let probe_report_a_ipv6 = ProbeReport {
            ipv4_can_send: false,
            ipv6_can_send: true,
            icmpv4: None,
            icmpv6: None,
            latency: Some(Duration::from_millis(4)),
            probe: Probe::StunIpv6 {
                delay: Duration::ZERO,
                node: relay_a.clone(),
            },
            addr: Some((Ipv6Addr::new(2001, 0xdb8, 0, 0, 0, 0, 0, 1), 1234).into()),
        };
        update_report(&mut report, probe_report_a_ipv6);

        assert!(report.udp);
        assert_eq!(
            report.relay_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(4)
        );
        assert_eq!(
            report.relay_v6_latency.get(&relay_a.url).unwrap(),
            Duration::from_millis(4)
        );
        assert!(report.ipv4_can_send);
        assert!(report.ipv6_can_send);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_update_report_icmp() {
        let (_server_a, relay_a) = test_utils::relay().await;
        let (_server_b, relay_b) = test_utils::relay().await;

        let mut report = Report::default();

        // An ICMPv4 probe from the EU relay server.
        let probe_report_eu = ProbeReport {
            ipv4_can_send: true,
            ipv6_can_send: false,
            icmpv4: Some(true),
            icmpv6: None,
            latency: Some(Duration::from_millis(5)),
            probe: Probe::IcmpV4 {
                delay: Duration::ZERO,
                node: relay_a.clone(),
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
                node: relay_b.clone(),
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
                node: relay_a.clone(),
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
    //    cargo nextest run -p iroh net_report::reportgen::tests --no-run
    //
    // Find out the test binary location:
    //
    //    cargo nextest list --message-format json -p iroh net_report::reportgen::tests \
    //       | jq '."rust-suites"."iroh"."binary-path"' | tr -d \"
    //
    // Set the CAP_NET_RAW permission, note that nextest runs each test in a child process
    // so the capabilities need to be inherited:
    //
    //    sudo setcap CAP_NET_RAW=eip target/debug/deps/iroh-abc123
    //
    // Finally run the test:
    //
    //    cargo nextest run -p iroh net_report::reportgen::tests
    //
    // This allows the pinger to create a SOCK_RAW socket for IPPROTO_ICMP.
    //
    //
    // ## Using sysctl
    //
    // Now you know the hard way, you can also get this permission a little easier, but
    // slightly less secure, by allowing any process running with your group ID to create a
    // SOCK_DGRAM for IPPROTO_ICMP.
    //
    // First find out your group ID:
    //
    //    id --group
    //
    // Then allow this group to send pings.  Note that this is an inclusive range:
    //
    //    sudo sysctl net.ipv4.ping_group_range="1234 1234"
    //
    // Note that this does not survive a reboot usually, commonly you need to edit
    // /etc/sysctl.conf or /etc/sysctl.d/* to persist this across reboots.
    //
    // TODO: Not sure what about IPv6 pings using sysctl.
    #[tokio::test]
    #[traced_test]
    async fn test_icmpk_probe() {
        let pinger = Pinger::new();
        let (server, node) = test_utils::relay().await;
        let addr = server.stun_addr().expect("test relay serves stun");
        let probe = Probe::IcmpV4 {
            delay: Duration::from_secs(0),
            node,
        };

        // A single ICMP packet might get lost.  Try several and take the first.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();
        for i in 0..8 {
            let probe = probe.clone();
            let pinger = pinger.clone();
            let tx = tx.clone();
            tasks.spawn(async move {
                time::sleep(Duration::from_millis(i * 100)).await;
                let res = run_icmp_probe(probe, addr, pinger).await;
                tx.send(res).ok();
            });
        }
        let mut last_err = None;
        while let Some(res) = rx.recv().await {
            match res {
                Ok(report) => {
                    dbg!(&report);
                    assert_eq!(report.icmpv4, Some(true));
                    assert!(
                        report.latency.expect("should have a latency") > Duration::from_secs(0)
                    );
                    break;
                }
                Err(ProbeError::Error(err, _probe)) => {
                    last_err = Some(err);
                }
                Err(ProbeError::AbortSet(_err, _probe)) => {
                    // We don't have permission, too bad.
                    // panic!("no ping permission: {err:#}");
                    break;
                }
            }
        }
        if let Some(err) = last_err {
            panic!("Ping error: {err:#}");
        }
    }

    #[tokio::test]
    async fn test_measure_https_latency() -> TestResult {
        let (server, relay) = test_utils::relay().await;
        let dns_resolver = dns::tests::resolver();
        tracing::info!(relay_url = ?relay.url , "RELAY_URL");
        let (latency, ip) =
            measure_https_latency(&dns_resolver, &relay, server.certificates()).await?;

        assert!(latency > Duration::ZERO);

        let relay_url_ip = relay
            .url
            .host_str()
            .context("host")?
            .parse::<std::net::IpAddr>()?;
        assert_eq!(ip, relay_url_ip);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_quic_probe() -> TestResult {
        let (server, relay) = test_utils::relay().await;
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))?;
        let client_addr = ep.local_addr()?;
        let quic_addr_disc = QuicConfig {
            ep: ep.clone(),
            client_config,
            ipv4: true,
            ipv6: true,
        };
        let url = relay.url.clone();
        let port = server.quic_addr().unwrap().port();
        let probe = Probe::QuicIpv4 {
            delay: Duration::from_secs(0),
            node: relay.clone(),
        };
        let probe = match run_quic_probe(
            quic_addr_disc,
            url,
            (Ipv4Addr::LOCALHOST, port).into(),
            probe,
            None,
        )
        .await
        {
            Ok(probe) => probe,
            Err(e) => match e {
                ProbeError::AbortSet(err, _) | ProbeError::Error(err, _) => {
                    return Err(err.into());
                }
            },
        };
        assert!(probe.ipv4_can_send);
        assert_eq!(probe.addr.unwrap(), client_addr);
        ep.wait_idle().await;
        server.shutdown().await?;
        Ok(())
    }
}
