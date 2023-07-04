//! The reportstate is responsible for generating a single netcheck report.
//!
//! It is implemented as an actor with [`ReportState`] as client or handle.
//!
//! The actor starts generating the report as soon as it is created, it does not receive any
//! messages from the client.  It follows roughly these steps:
//!
//! - Determines host IPv6 support.
//! - Creates hairpin actor.
//! - Creates portmapper future.
//! - Creates captive portal detection future.
//! - Creates Probe Set futures.
//!   - These send messages to the ReportState actor, including their result.
//! - Loops driving the futures and handling actor messages:
//!   - Disables futures as they are completed or aborted.
//!   - Stop if there are no outstanding tasks/futures, or on timeout.
//! - Sends the completed report to the netcheck actor.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use iroh_metrics::inc;
use iroh_metrics::netcheck::NetcheckMetrics;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;
use tokio::time::{self, Instant};
use tracing::{debug, error, info, instrument, trace, warn};

use crate::hp::derp::{DerpMap, DerpNode};
use crate::hp::netcheck::probe::{Probe, ProbePlan, ProbeProto};
use crate::hp::netcheck::{self, MaybeFuture, ProbeError, ProbeReport, Report};
use crate::hp::ping::Pinger;
use crate::hp::{portmapper, stun};

mod hairpin;

/// Holds the state for a single invocation of [`netcheck::Client::get_report`].
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug, Clone)]
pub(super) struct ReportState {
    // actor: Addr,
    _drop_guard: Arc<DropGuard>,
}

impl ReportState {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    pub(super) fn new(
        netcheck: netcheck::ActorAddr,
        last_report: Option<Arc<Report>>,
        plan: ProbePlan,
        port_mapper: Option<portmapper::Client>,
        skip_external_network: bool,
        incremental: bool,
        derpmap: DerpMap,
        stun_sock4: Option<Arc<UdpSocket>>,
        stun_sock6: Option<Arc<UdpSocket>>,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let addr = Addr {
            sender: msg_tx.clone(),
        };
        let mut actor = Actor {
            msg_tx,
            msg_rx,
            netcheck: netcheck.clone(),
            plan,
            last: last_report,
            port_mapper,
            skip_external_network,
            incremental,
            derpmap,
            stun_sock4,
            stun_sock6,
            report: Report::default(),
            hairpin_actor: hairpin::Client::new(netcheck, addr),
            outstanding_tasks: OutstandingTasks::default(),
        };
        // let addr = actor.addr();
        let task = tokio::spawn(async move { actor.run().await });
        Self {
            // actor: addr,
            _drop_guard: Arc::new(DropGuard {
                handle: task.abort_handle(),
            }),
        }
    }
}

#[derive(Debug)]
struct DropGuard {
    handle: AbortHandle,
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

/// The address of the reportstate [`Actor`].
///
/// Unlike the [`ReportState`] struct itself this is the raw channel to send message over.
/// Keeping this alive will not keep the actor alive, which makes this handy to pass to
/// internal tasks.
#[derive(Debug, Clone)]
pub(super) struct Addr {
    sender: mpsc::Sender<Message>,
}

impl Addr {
    /// Blocking send to the actor, to be used from a non-actor future.
    async fn send(&self, msg: Message) -> Result<(), mpsc::error::SendError<Message>> {
        self.sender.send(msg).await.map_err(|err| {
            error!("reportstate actor lost");
            err
        })
    }

    // /// Non-blocking send to the actor.
    // fn try_send(&self, msg: Message) -> Result<(), mpsc::error::TrySendError<Message>> {
    //     self.sender.try_send(msg).map_err(|err| {
    //         match &err {
    //             mpsc::error::TrySendError::Full(_) => {
    //                 // TODO: metrics
    //                 warn!("reportstate actor inbox full");
    //             }
    //             mpsc::error::TrySendError::Closed(_) => error!("netcheck actor lost"),
    //         }
    //         err
    //     })
    // }
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
    ProbeWouldHelp(Probe, DerpNode, oneshot::Sender<bool>),
    /// Abort all remaining probes.
    AbortProbes,
}

/// The reportstate actor.
///
/// This actor starts, generates a single reports and exits.
#[derive(Debug)]
struct Actor {
    /// The sender of the message channel, so we can give out [`Addr`].
    msg_tx: mpsc::Sender<Message>,
    /// The receiver of the message channel.
    msg_rx: mpsc::Receiver<Message>,
    /// The address of the netcheck actor.
    netcheck: super::ActorAddr,

    // Provided state
    /// Which probes to run.
    plan: ProbePlan,
    /// The previous report, if it exists.
    last: Option<Arc<Report>>,
    /// The portmapper client, if there is one.
    port_mapper: Option<portmapper::Client>,
    skip_external_network: bool,
    /// Whether we're doing an incremental report.
    incremental: bool,
    /// The DERP configuration.
    derpmap: DerpMap,
    /// Socket to send IPv4 STUN requests from.
    stun_sock4: Option<Arc<UdpSocket>>,
    /// Socket so send IPv6 STUN requests from.
    stun_sock6: Option<Arc<UdpSocket>>,

    // Internal state.
    /// The report being built.
    report: Report,
    /// The hairping actor.
    hairpin_actor: hairpin::Client,
    /// Which tasks ReportState is still waiting on.
    ///
    /// This is essentially the summary of all the work the ReportState actor is doing.
    outstanding_tasks: OutstandingTasks,
}

impl Actor {
    fn addr(&self) -> Addr {
        Addr {
            sender: self.msg_tx.clone(),
        }
    }

    #[instrument(name = "reportstate.actor", skip_all)]
    async fn run(&mut self) {
        match self.run_inner().await {
            Ok(_) => debug!("ReportState actor finished"),
            Err(err) => {
                error!("ReportState actor failed: {err:#}");
                self.netcheck
                    .send(netcheck::ActorMessage::ReportAborted)
                    .await
                    .ok();
            }
        }
    }

    /// Runs the main ReportState actor logic.
    ///
    /// This actor runs by:
    ///
    /// - Creates a hairpin actor.
    /// - Creates a captive portal future.
    /// - Creates ProbeSet futures in a group of futures.
    /// TODO: pinger
    /// - Runs a main loop:
    ///   - Drives all the above futures.
    ///   - Receives actor messages (sent by those futures).
    ///   - Updates the report, cancels unneeded futures.
    /// - Sends the report to the netcheck actor.
    async fn run_inner(&mut self) -> Result<()> {
        debug!(
            port_mapper = %self.port_mapper.is_some(),
            skip_external_network=%self.skip_external_network,
            "reportstate actor starting",
        );
        trace!(plan=%self.plan, "probe plan");
        let start_time = Instant::now();

        self.report.os_has_ipv6 = super::os_has_ipv6().await;

        // TODO: Update the port_mapper
        let mut port_mapping = super::MaybeFuture::default();
        if !self.skip_external_network {
            if let Some(ref port_mapper) = self.port_mapper {
                let port_mapper = port_mapper.clone();
                port_mapping.inner = Some(Box::pin(async move {
                    match port_mapper.probe().await {
                        Ok(res) => Some((res.upnp, res.pmp, res.pcp)),
                        Err(err) => {
                            warn!("skipping port mapping: {:?}", err);
                            None
                        }
                    }
                }));
                self.outstanding_tasks.port_mapper = true;
            }
        }

        // Even if we're doing a non-incremental update, we may want to try our
        // preferred DERP region for captive portal detection. Save that, if we have it.
        let preferred_derp = self.last.as_ref().map(|l| l.preferred_derp);

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        let mut captive_task = if !self.incremental {
            let dm = self.derpmap.clone();
            self.outstanding_tasks.captive_task = true;
            MaybeFuture {
                inner: Some(Box::pin(async move {
                    // wait
                    tokio::time::sleep(super::CAPTIVE_PORTAL_DELAY).await;
                    let captive_portal_check = tokio::time::timeout(
                        super::CAPTIVE_PORTAL_TIMEOUT,
                        super::check_captive_portal(&dm, preferred_derp),
                    );
                    match captive_portal_check.await {
                        Ok(Ok(found)) => Some(found),
                        Ok(Err(err)) => {
                            info!("check_captive_portal error: {:?}", err);
                            None
                        }
                        Err(_) => {
                            info!("check_captive_portal timed out");
                            None
                        }
                    }
                })),
            }
        } else {
            self.outstanding_tasks.captive_task = false;
            MaybeFuture::default()
        };

        let pinger = if self.plan.has_https_probes() {
            match Pinger::new().await {
                Ok(pinger) => Some(pinger),
                Err(err) => {
                    debug!("failed to create pinger: {err:#}");
                    None
                }
            }
        } else {
            None
        };

        // A collection of futures running probe sets.
        let mut probes = FuturesUnordered::default();

        for probe_set in self.plan.values() {
            let mut set = FuturesUnordered::default();
            for probe in probe_set {
                let reportstate = self.addr();
                let stun_sock4 = self.stun_sock4.clone();
                let stun_sock6 = self.stun_sock6.clone();
                let node = super::named_node(&self.derpmap, probe.node());
                ensure!(node.is_some(), "missing named node {}", probe.node());
                let node = node.unwrap().clone();
                let probe = probe.clone();
                let netcheck = self.netcheck.clone();
                let pinger = pinger.clone();

                set.push(Box::pin(async move {
                    run_probe(
                        reportstate,
                        stun_sock4,
                        stun_sock6,
                        node,
                        probe,
                        netcheck,
                        pinger,
                    )
                    .await
                }));
            }

            // Add the probe set to all futures of probe sets.  Handle aborting a probe set
            // if needed, only normal errors means the set continues.
            probes.push(Box::pin(async move {
                // Hack because ProbeSet is not it's own type yet.
                let mut probe_proto = None;
                while let Some(res) = set.next().await {
                    match res {
                        Ok(report) => return Ok(report),
                        Err(ProbeError::Error(err, probe)) => {
                            probe_proto = Some(probe.proto());
                            warn!(?probe, "probe failed: {:#}", err);
                            continue;
                        }
                        Err(ProbeError::AbortSet(err, probe)) => {
                            probe_proto = Some(probe.proto());
                            debug!(?probe, "probe set aborted: {:#}", err);
                            return Err(err);
                        }
                    }
                }
                warn!(?probe_proto, "no successfull probes in ProbeSet");
                Err(anyhow!("All probes in ProbeSet failed"))
            }));
        }
        self.outstanding_tasks.probes = true;

        loop {
            trace!(awaiting = ?self.outstanding_tasks, "tick; awaiting tasks");
            if self.outstanding_tasks.all_done() {
                debug!("all tasks done");
                break;
            }
            let remaining_time = super::OVERALL_PROBE_TIMEOUT.saturating_sub(start_time.elapsed());
            let remaining_probe_time =
                super::STUN_PROBE_TIMEOUT.saturating_sub(start_time.elapsed());

            tokio::select! {
                _ = tokio::time::sleep(remaining_time) => {
                    bail!("report timed out");
                }

                _ = tokio::time::sleep(remaining_probe_time) => {
                    debug!("probes timed out");
                    self.handle_abort_probes();
                }

                // Drive the portmapper.
                pm = &mut port_mapping, if self.outstanding_tasks.port_mapper => {
                    match pm {
                        Some((upnp, pmp, pcp)) => {
                            self.report.upnp = Some(upnp);
                            self.report.pmp = Some(pmp);
                            self.report.pcp = Some(pcp);
                        }
                        None => {
                            self.report.upnp = None;
                            self.report.pmp = None;
                            self.report.pcp = None;
                        }
                    }
                    port_mapping.inner = None;
                    self.outstanding_tasks.port_mapper = false;
                    trace!("portmapper future done");
                }

                // Drive the probes.
                set_result = probes.next(), if self.outstanding_tasks.probes => {
                    match set_result {
                        Some(Ok(report)) => self.handle_probe_report(report),
                        Some(Err(_)) => (),
                        None => self.handle_abort_probes(),
                    }
                }

                // Drive the captive task.
                found = &mut captive_task, if self.outstanding_tasks.captive_task => {
                    self.report.captive_portal = found;
                    captive_task.inner = None;
                    self.outstanding_tasks.captive_task = false;
                    trace!("captive portal task future done");
                }

                // Handle actor messages.
                msg = self.msg_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_message(msg),
                        None => bail!("msg_rx closed, ReportState client must be dropped"),
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

        // TODO: consider if we can have the report live in a box from start to finish so
        // there are no moves involves from building it here till it gets dropped by the
        // netcheck actor.
        debug!("Sending report to netcheck actor");
        self.netcheck
            .send(netcheck::ActorMessage::ReportReady {
                report: Box::new(self.report.clone()),
                derp_map: self.derpmap.clone(),
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
        debug!("finished probe: {:?}", probe_report);
        match probe_report.probe {
            Probe::Https { region, .. } => {
                if let Some(delay) = probe_report.delay {
                    let l = self
                        .report
                        .region_latency
                        .entry(region.region_id)
                        .or_insert(delay);
                    if *l >= delay {
                        *l = delay;
                    }
                }
            }
            Probe::Ipv4 { node, .. } | Probe::Ipv6 { node, .. } => {
                if let Some(delay) = probe_report.delay {
                    self.add_stun_addr_latency(node, probe_report.addr, delay);
                    if let Some(ref addr) = self.report.global_v4 {
                        // Only needed for the first IPv4 address discovered, but hairpin
                        // actor ignores subsequent messages.
                        self.hairpin_actor.start_check(*addr);
                        self.outstanding_tasks.hairpin = true;
                    }
                }
            }
        }
        self.report.ipv4_can_send = probe_report.ipv4_can_send;
        self.report.ipv6_can_send = probe_report.ipv6_can_send;
        self.report.icmpv4 = probe_report.icmpv4;
    }

    /// Whether running this probe would still improve our report.
    fn probe_would_help(&mut self, probe: Probe, derp_node: DerpNode) -> bool {
        // If the probe is for a region we don't yet know about, that would help.
        if !self
            .report
            .region_latency
            .contains_key(&derp_node.region_id)
        {
            return true;
        }

        // If the probe is for IPv6 and we don't yet have an IPv6 report, that would help.
        if probe.proto() == ProbeProto::Ipv6 && self.report.region_v6_latency.is_empty() {
            return true;
        }

        // For IPv4, we need at least two IPv4 results overall to
        // determine whether we're behind a NAT that shows us as
        // different source IPs and/or ports depending on who we're
        // talking to. If we don't yet have two results yet
        // (`mapping_varies_by_dest_ip` is blank), then another IPv4 probe
        // would be good.
        if probe.proto() == ProbeProto::Ipv4 && self.report.mapping_varies_by_dest_ip.is_none() {
            return true;
        }

        // Otherwise not interesting.
        false
    }

    /// Updates the report to note that node's latency and discovered address from STUN.
    ///
    /// Since this is only called for STUN probes, in other words [`Probe::Ipv4`] and
    /// [`Prove::Ipv6`], *ipp` is always `Some`.
    fn add_stun_addr_latency(
        &mut self,
        derp_node: String,
        ipp: Option<SocketAddr>,
        latency: Duration,
    ) {
        let node =
            super::named_node(&self.derpmap, &derp_node).expect("derp node missing from derp map");

        debug!(node = %node.name, ?latency, "add udp node latency");
        self.report.udp = true;

        super::update_latency(&mut self.report.region_latency, node.region_id, latency);

        // Once we've heard from enough regions (3), start a timer to
        // give up on the other ones. The timer's duration is a
        // function of whether this is our initial full probe or an
        // incremental one. For incremental ones, wait for the
        // duration of the slowest region. For initial ones, double that.
        if self.report.region_latency.len() == super::ENOUGH_REGIONS {
            let mut timeout = super::max_duration_value(&self.report.region_latency);
            if !self.incremental {
                timeout *= 2;
            }
            let reportcheck = self.addr();
            tokio::spawn(async move {
                time::sleep(timeout).await;
                reportcheck.send(Message::AbortProbes).await.ok();
            });
        }

        if let Some(ipp) = ipp {
            if ipp.is_ipv6() {
                super::update_latency(&mut self.report.region_v6_latency, node.region_id, latency);
                self.report.ipv6 = true;
                self.report.global_v6 = Some(ipp);
                // TODO: track MappingVariesByDestIP for IPv6 too? Would be sad if so, but
                // who knows.
            } else if ipp.is_ipv4() {
                super::update_latency(&mut self.report.region_v4_latency, node.region_id, latency);
                self.report.ipv4 = true;
                if self.report.global_v4.is_none() {
                    self.report.global_v4 = Some(ipp);
                } else if self.report.global_v4 != Some(ipp) {
                    self.report.mapping_varies_by_dest_ip = Some(true);
                } else if self.report.mapping_varies_by_dest_ip.is_none() {
                    self.report.mapping_varies_by_dest_ip = Some(false);
                }
            }
        }
    }

    /// Stops further probes.
    ///
    /// This makes sure that no further probes are run and also cancels the captive portal
    /// task if there were successful probes.  Be sure to only handle this after all the
    /// required [`ProbeReport`]s have been processed.
    fn handle_abort_probes(&mut self) {
        self.outstanding_tasks.probes = false;
        if self.report.udp {
            self.outstanding_tasks.captive_task = false;
        }
    }
}

/// Tasks on which the ReportState [`Actor`] is still waiting.
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

/// Executes a particular [`Probe`], including using a delayed start if needed.
///
/// If *stun_sock4* and *stun_sock6* are `None` the STUN probes are disabled.
#[allow(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all, fields(probe = %probe))]
async fn run_probe(
    reportstate: Addr,
    stun_sock4: Option<Arc<UdpSocket>>,
    stun_sock6: Option<Arc<UdpSocket>>,
    derp_node: DerpNode,
    probe: Probe,
    netcheck: netcheck::ActorAddr,
    pinger: Option<Pinger>,
) -> Result<ProbeReport, ProbeError> {
    if !probe.delay().is_zero() {
        debug!("delaying probe");
        tokio::time::sleep(probe.delay()).await;
    }
    debug!("starting probe");

    let (would_help_tx, would_help_rx) = oneshot::channel();
    reportstate
        .send(Message::ProbeWouldHelp(
            probe.clone(),
            derp_node.clone(),
            would_help_tx,
        ))
        .await
        .map_err(|err| ProbeError::AbortSet(err.into(), probe.clone()))?;
    if !would_help_rx.await.map_err(|_| {
        ProbeError::AbortSet(anyhow!("ReportCheck actor dropped sender"), probe.clone())
    })? {
        return Err(ProbeError::AbortSet(
            anyhow!("ReportCheck says probe set no longer useful"),
            probe,
        ));
    }

    let derp_addr = super::get_node_addr(&derp_node, probe.proto())
        .await
        .context("no derp node addr")
        .map_err(|e| ProbeError::AbortSet(e, probe.clone()))?;
    let txid = stun::TransactionId::default();
    let req = stun::request(txid);

    let (stun_tx, stun_rx) = oneshot::channel();
    let (stun_ready_tx, stun_ready_rx) = oneshot::channel();
    netcheck
        .send(netcheck::ActorMessage::InFlightStun(
            netcheck::Inflight {
                txn: txid,
                start: Instant::now(),
                s: stun_tx,
            },
            stun_ready_tx,
        ))
        .await
        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
    stun_ready_rx
        .await
        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
    let mut result = ProbeReport::new(probe.clone());

    match probe {
        Probe::Ipv4 { .. } => {
            if let Some(ref sock) = stun_sock4 {
                let n = sock.send_to(&req, derp_addr).await;
                inc!(NetcheckMetrics::StunPacketsSentIpv4);
                debug!(%derp_addr, send_res=?n, %txid, "sending probe Ipv4");
                // TODO:  || neterror.TreatAsLostUDP(err)
                if n.is_ok() && n.unwrap() == req.len() {
                    result.ipv4_can_send = true;

                    let (delay, addr) = stun_rx
                        .await
                        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
                    result.delay = Some(delay);
                    result.addr = Some(addr);
                }
            }
        }
        Probe::Ipv6 { .. } => {
            if let Some(ref pc6) = stun_sock6 {
                let n = pc6.send_to(&req, derp_addr).await;
                inc!(NetcheckMetrics::StunPacketsSentIpv6);
                debug!(%derp_addr, snd_res=?n, %txid, "sending probe Ipv6");
                // TODO:  || neterror.TreatAsLostUDP(err)
                if n.is_ok() && n.unwrap() == req.len() {
                    result.ipv6_can_send = true;

                    let (delay, addr) = stun_rx
                        .await
                        .map_err(|e| ProbeError::Error(e.into(), probe.clone()))?;
                    result.delay = Some(delay);
                    result.addr = Some(addr);
                }
            }
        }
        Probe::Https { ref region, .. } => {
            debug!(icmp=%pinger.is_some(), "sending probe HTTPS");

            let res = if let Some(ref pinger) = pinger {
                tokio::join!(
                    time::timeout(
                        super::ICMP_PROBE_TIMEOUT,
                        super::measure_icmp_latency(region, pinger).map(Some)
                    ),
                    super::measure_https_latency(region)
                )
            } else {
                (Ok(None), super::measure_https_latency(region).await)
            };
            if let Ok(Some(icmp_res)) = res.0 {
                match icmp_res {
                    Ok(d) => {
                        result.delay = Some(d);
                        result.ipv4_can_send = true;
                        result.icmpv4 = true;
                    }
                    Err(err) => {
                        warn!("icmp latency measurement failed: {:?}", err);
                    }
                }
            }
            match res.1 {
                Ok((d, ip)) => {
                    result.delay = Some(d);
                    // We set these IPv4 and IPv6 but they're not really used
                    // and we don't necessarily set them both. If UDP is blocked
                    // and both IPv4 and IPv6 are available over TCP, it's basically
                    // random which fields end up getting set here.
                    // Since they're not needed, that's fine for now.
                    if ip.is_ipv4() {
                        result.ipv4_can_send = true
                    }
                    if ip.is_ipv6() {
                        result.ipv6_can_send = true
                    }
                }
                Err(err) => {
                    warn!("https latency measurement failed: {:?}", err);
                }
            }
        }
    }

    trace!(probe = ?probe, "probe successfull");
    Ok(result)
}
