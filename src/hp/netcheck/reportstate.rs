//! The reportstate is responsible for generating a single netcheck report.
//!
//! It is implemented as an actor with [`ReportState`] as client or handle.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, ensure, Context, Result};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::AbortHandle;
use tracing::{debug, error, info, instrument, trace, warn};
use trust_dns_resolver::TokioAsyncResolver;

use crate::hp::derp::{DerpMap, DerpNode};
use crate::hp::netcheck::probe::ProbePlan;
use crate::hp::netcheck::{self, MaybeFuture, ProbeError, Report};
use crate::hp::ping::Pinger;
use crate::hp::{portmapper, stun};

use super::probe::Probe;
use super::ActorAddr;

mod hairpin;

/// Holds the state for a single invocation of [`netcheck::Client::get_report`].
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug, Clone)]
pub(super) struct ReportState {
    actor: Addr,
    _drop_guard: Arc<DropGuard>,
}

impl ReportState {
    fn new(
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
        let mut actor = Actor {
            msg_tx,
            msg_rx,
            netcheck,
            plan,
            last: last_report,
            port_mapper,
            skip_external_network,
            incremental,
            derpmap,
            stun_sock4,
            stun_sock6,
            report: Report::default(),
        };
        let addr = actor.addr();
        let task = tokio::spawn(async move { actor.run().await });
        Self {
            actor: addr,
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

    /// Non-blocking send to the actor.
    fn try_send(&self, msg: Message) -> Result<(), mpsc::error::TrySendError<Message>> {
        self.sender.try_send(msg).map_err(|err| {
            match &err {
                mpsc::error::TrySendError::Full(_) => {
                    // TODO: metrics
                    warn!("reportstate actor inbox full");
                }
                mpsc::error::TrySendError::Closed(_) => error!("netcheck actor lost"),
            }
            err
        })
    }
}

/// Messages to send to the reportstate [`Actor`].
#[derive(Debug)]
enum Message {
    /// Set the hairpinning availability in the report.
    HairpinResult(bool),
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
    // hair_tx: stun::TransactionId,
    // got_hair_stun: broadcast::Receiver<SocketAddr>,
    // // notified on hair pin timeout
    // hair_timeout: Arc<sync::Notify>,
    // /// Doing a lite, follow-up netcheck
    // stop_probe: Arc<sync::Notify>,
    // wait_port_map: wg::AsyncWaitGroup,
    // sent_hair_check: bool,
    // got_ep4: Option<SocketAddr>,
    // timers: JoinSet<()>,
}

impl Actor {
    fn addr(&self) -> Addr {
        Addr {
            sender: self.msg_tx.clone(),
        }
    }

    #[instrument(name = "actor", skip_all)]
    async fn run(&mut self) {
        match self.run_inner().await {
            Ok(_) => debug!("ReportState actor finished"),
            Err(err) => error!("ReportState actor failed: {err:#}"),
        }
    }
    async fn run_inner(&mut self) -> Result<()> {
        // TODO
        debug!(
            port_mapper = %self.port_mapper.is_some(),
            skip_external_network=%self.skip_external_network,
            "reportstate actor starting",
        );

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
            }
        }

        // Prepare hairpin detection infrastructure, needs to be created early.
        let hairpin_actor = hairpin::Client::new(self.netcheck.clone(), self.addr());

        // Even if we're doing a non-incremental update, we may want to try our
        // preferred DERP region for captive portal detection. Save that, if we have it.
        let preferred_derp = self.last.as_ref().map(|l| l.preferred_derp);

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        let mut captive_task = if !self.incremental {
            let dm = self.derpmap.clone();
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
            MaybeFuture::default()
        };

        let pinger = if self.plan.has_https_probes() {
            Some(Pinger::new().await.context("failed to create pinger")?)
        } else {
            None
        };

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

            probes.push(Box::pin(async move {
                while let Some(res) = set.next().await {
                    match res {
                        Ok(res) => {
                            trace!(probe = ?res.probe, "probe successfull");
                            return Ok(res);
                        }
                        Err(ProbeError::Transient(err, probe)) => {
                            debug!(?probe, "probe failed: {:#}", err);
                            continue;
                        }
                        Err(ProbeError::Fatal(err, probe)) => {
                            debug!(?probe, "probe error fatal: {:#}", err);
                            return Err(err);
                        }
                    }
                }
                bail!("no successfull probes");
            }));
        }

        Ok(())
    }
}

/// Executes a particular [`Probe`], including using a delayed start if needed.
///
/// If *stun_sock4* and *stun_sock6* are `None` the STUN probes are disabled.
#[allow(clippy::too_many_arguments)]
#[instrument(level = "debug", skip_all, fields(probe = ?probe))]
async fn run_probe(
    reportstate: Addr,
    stun_sock4: Option<Arc<UdpSocket>>,
    stun_sock6: Option<Arc<UdpSocket>>,
    node: DerpNode,
    probe: Probe,
    actor_addr: ActorAddr,
    pinger: Option<Pinger>,
) -> Result<super::ProbeReport, ProbeError> {
    // TODO: use the global resolver
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    if !probe.delay().is_zero() {
        debug!("delaying probe");
        tokio::time::sleep(*probe.delay()).await;
    }

    // TODO: this is some horrible kludge.  doesn't the probe plan handle this.  But it
    if !super::probe_would_help(&*report.read().await, &probe, &node) {
        return Err(ProbeError::Fatal(anyhow!("probe would not help"), probe));
    }

    let addr = super::get_derp_node_addr(&resolver, &node, probe.proto())
        .await
        .context("no derp node addr")
        .map_err(|e| ProbeError::Transient(e, probe.clone()))?;
    let txid = stun::TransactionId::default();
    let req = stun::request(txid);
    let sent = Instant::now(); // after DNS lookup above

    let (stun_tx, stun_rx) = oneshot::channel();
    let (msg_response_tx, msg_response_rx) = oneshot::channel();
    actor_addr
        .send(netcheck::ActorMessage::InFlightStun(
            netcheck::Inflight {
                txn: txid,
                start: sent,
                s: stun_tx,
            },
            msg_response_tx,
        ))
        .await
        .map_err(|e| ProbeError::Transient(e.into(), probe.clone()))?;
    msg_response_rx
        .await
        .map_err(|e| ProbeError::Transient(e.into(), probe.clone()))?;
    let mut result = ProbeReport::new(probe.clone());

    match probe {
        Probe::Ipv4 { .. } => {
            if let Some(ref pc4) = pc4 {
                let n = pc4.send_to(&req, addr).await;
                inc!(NetcheckMetrics::StunPacketsSentIpv4);
                debug!(%addr, send_res=?n, %txid, "sending probe IPV4");
                // TODO:  || neterror.TreatAsLostUDP(err)
                if n.is_ok() && n.unwrap() == req.len() {
                    result.ipv4_can_send = true;

                    let (delay, addr) = stun_rx
                        .await
                        .map_err(|e| ProbeError::Transient(e.into(), probe))?;
                    result.delay = Some(delay);
                    result.addr = Some(addr);
                }
            }
        }
        Probe::Ipv6 { .. } => {
            if let Some(ref pc6) = pc6 {
                let n = pc6.send_to(&req, addr).await;
                inc!(NetcheckMetrics::StunPacketsSentIpv6);
                debug!(%addr, snd_res=?n, %txid, "sending probe IPV6");
                // TODO:  || neterror.TreatAsLostUDP(err)
                if n.is_ok() && n.unwrap() == req.len() {
                    result.ipv6_can_send = true;

                    let (delay, addr) = stun_rx
                        .await
                        .map_err(|e| ProbeError::Transient(e.into(), probe))?;
                    result.delay = Some(delay);
                    result.addr = Some(addr);
                }
            }
        }
        Probe::Https { region, .. } => {
            debug!(icmp=%pinger.is_some(), "sending probe HTTPS");

            let res = if let Some(ref pinger) = pinger {
                tokio::join!(
                    time::timeout(
                        ICMP_PROBE_TIMEOUT,
                        measure_icmp_latency(resolver, &region, pinger).map(Some)
                    ),
                    measure_https_latency(&region)
                )
            } else {
                (Ok(None), measure_https_latency(&region).await)
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

    Ok(result)
}
