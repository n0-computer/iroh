//! The reportgen actor is responsible for generating a single net_report report.
//!
//! It is implemented as an actor with [`Client`] as handle.
//!
//! The actor starts generating the report as soon as it is created, it does not receive any
//! messages from the client.  It follows roughly these steps:
//!
//! - Determines host IPv6 support.
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
    pin::{pin, Pin},
    sync::Arc,
};

use http::StatusCode;
use iroh_base::RelayUrl;
#[cfg(not(wasm_browser))]
use iroh_relay::dns::{DnsError, DnsResolver, StaggeredError};
use iroh_relay::{defaults::DEFAULT_RELAY_QUIC_PORT, http::RELAY_PROBE_PATH, RelayMap, RelayNode};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
use n0_future::{
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration, Instant},
    StreamExt as _,
};
#[cfg(not(wasm_browser))]
use netwatch::interfaces;
use rand::seq::IteratorRandom;
use snafu::{IntoError, OptionExt, ResultExt, Snafu};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, debug_span, info_span, trace, warn, Instrument};
use url::Host;

#[cfg(wasm_browser)]
use crate::net_report::portmapper; // We stub the library
#[cfg(not(wasm_browser))]
use crate::net_report::{
    defaults::timeouts::DNS_TIMEOUT, dns::DNS_STAGGERING_MS, ip_mapped_addrs::IpMappedAddresses,
};
use crate::{net_report::Report, util::MaybeFuture};

mod probes;

pub use probes::ProbeProto;
use probes::{Probe, ProbePlan};

use crate::net_report::defaults::timeouts::{
    CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, OVERALL_REPORT_TIMEOUT, PROBES_TIMEOUT,
};

/// Holds the state for a single report generation.
///
/// Dropping this will cancel the actor and stop the report generation.
#[derive(Debug)]
pub(super) struct Client {
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
        last_report: Option<Report>,
        relay_map: RelayMap,
        protocols: BTreeSet<ProbeProto>,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
    ) -> (Self, mpsc::Receiver<ProbeFinished>) {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let mut actor = Actor {
            msg_tx,
            last_report,
            relay_map,
            protocols,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(any(test, feature = "test-utils"))]
            insecure_skip_relay_cert_verify,
        };
        let task =
            task::spawn(async move { actor.run().await }.instrument(info_span!("reportgen.actor")));
        (
            Self {
                _drop_guard: AbortOnDropHandle::new(task),
            },
            msg_rx,
        )
    }
}

/// The reportstate actor.
///
/// This actor starts, generates a single report and exits.
#[derive(Debug)]
struct Actor {
    msg_tx: mpsc::Sender<ProbeFinished>,

    // Provided state
    /// The previous report, if it exists.
    last_report: Option<Report>,
    /// The relay configuration.
    relay_map: RelayMap,

    // Internal state.
    /// Protocols we should attempt to create probes for, if we have the correct
    /// configuration for that protocol.
    protocols: BTreeSet<ProbeProto>,

    /// Any socket-related state that doesn't exist/work in browsers
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(any(test, feature = "test-utils"))]
    insecure_skip_relay_cert_verify: bool,
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ActorRunError {
    #[snafu(display("Report generation timed out"))]
    Timeout,
    #[snafu(display("Client that requested the report is gone"))]
    ClientGone,
    #[snafu(display("Internal NetReport actor is gone"))]
    ActorGone,
    #[snafu(transparent)]
    Probes { source: ProbesError },
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ProbesError {
    #[snafu(display("Probe failed"))]
    ProbeFailure { source: ProbeError },
    #[snafu(display("All probes failed"))]
    AllProbesFailed,
}

#[derive(Debug)]
pub(super) enum ProbeFinished {
    Regular(Result<ProbeReport, ProbesError>),
    #[cfg(not(wasm_browser))]
    Portmap(Option<portmapper::ProbeOutput>),
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

impl Actor {
    async fn run(&mut self) {
        match self.run_inner().await {
            Ok(()) => debug!("reportgen actor finished"),
            Err(err) => {
                warn!("reportgen failed: {:?}", err);
            }
        }
    }

    /// Runs the main reportgen actor logic.
    ///
    /// This actor runs by:
    ///
    /// - Creates a captive portal future.
    /// - Creates ProbeSet futures in a group of futures.
    /// - Runs a main loop:
    ///   - Drives all the above futures.
    ///   - Receives actor messages (sent by those futures).
    ///   - Updates the report, cancels unneeded futures.
    /// - Sends the report to the net_report actor.
    async fn run_inner(&mut self) -> Result<(), ActorRunError> {
        #[cfg(not(wasm_browser))]
        let port_mapper = self.socket_state.port_mapper.is_some();
        #[cfg(wasm_browser)]
        let port_mapper = false;
        debug!(%port_mapper, "reportstate actor starting");

        let probes_token = CancellationToken::new();
        let captive_token = CancellationToken::new();
        let port_token = CancellationToken::new();

        let port_task = self.prepare_portmapper_task();
        let mut port_done = !port_task.is_some();

        let captive_task = self.prepare_captive_portal_task();
        let mut captive_done = !captive_task.is_some();

        let mut port_mapping = pin!(port_token.clone().run_until_cancelled_owned(port_task));
        let mut captive_task = pin!(captive_token
            .clone()
            .run_until_cancelled_owned(captive_task));

        let mut probes = self.spawn_probes_task(probes_token.clone()).await;

        let total_timer = time::sleep(OVERALL_REPORT_TIMEOUT);
        tokio::pin!(total_timer);
        let probe_timer = time::sleep(PROBES_TIMEOUT);
        tokio::pin!(probe_timer);

        // any reports of working UDP/QUIC?
        let mut have_udp = false;

        loop {
            if probes.is_empty() && port_done && captive_done {
                debug!("all tasks done");
                break;
            }

            tokio::select! {
                biased;
                _ = &mut total_timer => {
                    trace!("tick: total_timer expired");
                    return Err(TimeoutSnafu.build());
                }

                _ = &mut probe_timer => {
                    warn!("tick: probes timed out");
                    // Set new timeout to not go into this branch multiple times.  We need
                    // the abort to finish all probes normally.  PROBES_TIMEOUT is
                    // sufficiently far in the future.
                    probe_timer.as_mut().reset(Instant::now() + PROBES_TIMEOUT);
                    probes_token.cancel();
                    if have_udp {
                        port_token.cancel();
                        captive_token.cancel();
                    }
                }

                // Drive the portmapper.
                pm = &mut port_mapping => {
                    #[cfg(not(wasm_browser))]
                    {
                        debug!(report=?pm, "tick: portmapper probe report");
                        if let Some(pm) = pm {
                            self.msg_tx.send(ProbeFinished::Portmap(pm)).await.ok();
                        }
                        port_done = true;
                    }
                }

                // Check for probes finishing.
                set_result = probes.join_next() => {
                    trace!("tick: probes done: {:?}", set_result);
                    match set_result {
                        Some(Ok(Some(report))) => {
                            have_udp |= report.as_ref().map(|r| r.probe.is_udp()).unwrap_or_default();
                            self.msg_tx.send(ProbeFinished::Regular(report)).await.ok();
                        },
                        Some(Ok(None)) => {
                            debug!("probe cancelled");
                        }
                        Some(Err(e)) => {
                            warn!("probes task join error: {:?}", e);
                        }
                        None => {
                            if have_udp {
                                port_token.cancel();
                                captive_token.cancel();
                            }
                        }
                    }
                    trace!("tick: probes handled");
                }

                // Drive the captive task.
                found = &mut captive_task => {
                    #[cfg(not(wasm_browser))]
                    {
                        trace!("tick: captive portal task done");
                        if let Some(found) = found {
                            self.msg_tx.send(ProbeFinished::CaptivePortal(found)).await.ok();
                        }
                        captive_done = true;
                    }
                }
            }
        }

        Ok(())
    }

    /// Creates the future which will perform the portmapper task.
    ///
    /// The returned future will run the portmapper, if enabled, resolving to it's result.
    #[cfg(wasm_browser)]
    fn prepare_portmapper_task(
        &mut self,
    ) -> MaybeFuture<Pin<Box<Pending<Option<portmapper::ProbeOutput>>>>> {
        MaybeFuture::none()
    }

    /// Creates the future which will perform the portmapper task.
    ///
    /// The returned future will run the portmapper, if enabled, resolving to it's result.
    #[cfg(not(wasm_browser))]
    fn prepare_portmapper_task(
        &mut self,
    ) -> MaybeFuture<Pin<Box<impl Future<Output = Option<portmapper::ProbeOutput>>>>> {
        if let Some(port_mapper) = self.socket_state.port_mapper.clone() {
            MaybeFuture::Some(Box::pin(async move {
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
            }))
        } else {
            MaybeFuture::None
        }
    }

    /// Creates the future which will perform the captive portal check.
    #[cfg(wasm_browser)]
    fn prepare_captive_portal_task(&mut self) -> MaybeFuture<Pin<Box<Pending<Option<bool>>>>> {
        MaybeFuture::default()
    }

    /// Creates the future which will perform the captive portal check.
    #[cfg(not(wasm_browser))]
    fn prepare_captive_portal_task(
        &mut self,
    ) -> MaybeFuture<Pin<Box<impl Future<Output = Option<bool>>>>> {
        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP STUN to finish, to avoid the probe if
        // it's unnecessary.
        if self.last_report.is_none() {
            // Even if we're doing a non-incremental update, we may want to try our
            // preferred relay for captive portal detection.
            let preferred_relay = self
                .last_report
                .as_ref()
                .and_then(|l| l.preferred_relay.clone());

            let dns_resolver = self.socket_state.dns_resolver.clone();
            let dm = self.relay_map.clone();
            MaybeFuture::Some(Box::pin(async move {
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
                        match err {
                            CaptivePortalError::CreateReqwestClient { ref source }
                            | CaptivePortalError::HttpRequest { ref source } => {
                                if source.is_connect() {
                                    debug!("check_captive_portal failed: {err:#}");
                                }
                            }
                            _ => warn!("check_captive_portal error: {err:#}"),
                        }
                        None
                    }
                    Err(_) => {
                        warn!("check_captive_portal timed out");
                        None
                    }
                }
            }))
        } else {
            MaybeFuture::None
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
    async fn spawn_probes_task(
        &mut self,
        token: CancellationToken,
    ) -> JoinSet<Option<Result<ProbeReport, ProbesError>>> {
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

        // A collection of futures running probe sets.
        let mut probes = JoinSet::default();
        for probe_set in plan.iter() {
            let mut set = JoinSet::default();
            for probe in probe_set {
                let relay_node = probe.node().clone();
                let probe = probe.clone();

                #[cfg(not(wasm_browser))]
                let socket_state = self.socket_state.clone();

                set.spawn(
                    token.clone().run_until_cancelled_owned(
                        run_probe(
                            relay_node,
                            probe.clone(),
                            #[cfg(not(wasm_browser))]
                            socket_state,
                            #[cfg(any(test, feature = "test-utils"))]
                            self.insecure_skip_relay_cert_verify,
                        )
                        .instrument(debug_span!("run_probe", %probe)),
                    ),
                );
            }

            // Add the probe set to all futures of probe sets.  Handle aborting a probe set
            // if needed, only normal errors means the set continues.
            probes.spawn(
                token.clone().run_until_cancelled_owned(
                    async move {
                        // Hack because ProbeSet is not it's own type yet.
                        let mut probe_proto = None;
                        while let Some(res) = set.join_next().await {
                            match res {
                                Ok(Some(Ok(report))) => return Ok(report),
                                Ok(Some(Err(ProbeErrorWithProbe::Error(err, probe)))) => {
                                    probe_proto = Some(probe.proto());
                                    warn!(?probe, "probe failed: {:#}", err);
                                    continue;
                                }
                                Ok(Some(Err(ProbeErrorWithProbe::AbortSet(err, probe)))) => {
                                    debug!(?probe, "probe set aborted: {:#}", err);
                                    set.abort_all();
                                    return Err(err);
                                }
                                Ok(None) => {
                                    debug!("probe cancelled");
                                }
                                Err(err) => {
                                    warn!("fatal probe set error, aborting: {:#}", err);
                                    continue;
                                }
                            }
                        }
                        warn!(?probe_proto, "no successful probes in ProbeSet");
                        Err(AllProbesFailedSnafu.build())
                    }
                    .instrument(info_span!("probe")),
                ),
            );
        }

        probes
    }
}

/// The success result of [`run_probe`].
#[derive(Debug, Clone)]
pub(super) struct ProbeReport {
    /// Whether we can send IPv4 UDP packets.
    pub(super) ipv4_can_send: bool,
    /// Whether we can send IPv6 UDP packets.
    pub(super) ipv6_can_send: bool,
    /// The latency to the relay node.
    pub(super) latency: Option<Duration>,
    /// The probe that generated this report.
    pub(super) probe: Probe,
    /// The discovered public address.
    pub(super) addr: Option<SocketAddr>,
}

impl ProbeReport {
    fn new(probe: Probe) -> Self {
        ProbeReport {
            probe,
            ipv4_can_send: false,
            ipv6_can_send: false,
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
enum ProbeErrorWithProbe {
    /// Abort the current set.
    AbortSet(ProbeError, Probe),
    /// Continue the other probes in the set.
    Error(ProbeError, Probe),
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum ProbeError {
    #[snafu(display("Client is gone"))]
    ClientGone,
    #[snafu(display("Probe is no longer useful"))]
    NotUseful,
    #[cfg(not(wasm_browser))]
    #[snafu(display("Failed to retrieve the relay address"))]
    GetRelayAddr { source: GetRelayAddrError },
    #[snafu(display("Failed to run stun probe"))]
    Stun { source: StunError },
    #[snafu(display("Failed to run QUIC probe"))]
    Quic { source: QuicError },
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum StunError {
    #[snafu(display("No UDP socket available"))]
    NoSocket,
    #[snafu(display("Stun channel is gone"))]
    StunChannelGone,
    #[snafu(display("Failed to send full STUN request"))]
    SendFull,
    #[snafu(display("Failed to send STUN request"))]
    Send { source: std::io::Error },
}

#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum QuicError {
    #[snafu(display("No QUIC endpoint available"))]
    NoEndpoint,
    #[snafu(display("URL must have 'host' to use QUIC address discovery probes"))]
    InvalidUrl,
    #[snafu(display("Failed to create QUIC endpoint"))]
    CreateClient { source: iroh_relay::quic::Error },
    #[snafu(display("Failed to get address and latency"))]
    GetAddr { source: iroh_relay::quic::Error },
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
#[allow(clippy::too_many_arguments)]
async fn run_probe(
    relay_node: Arc<RelayNode>,
    probe: Probe,
    #[cfg(not(wasm_browser))] socket_state: SocketState,
    #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
) -> Result<ProbeReport, ProbeErrorWithProbe> {
    if !probe.delay().is_zero() {
        trace!("delaying probe");
        time::sleep(probe.delay()).await;
    }
    debug!("starting probe");

    let mut result = ProbeReport::new(probe.clone());
    match probe {
        Probe::Https { ref node, .. } => {
            debug!("sending probe HTTPS");
            match measure_https_latency(
                #[cfg(not(wasm_browser))]
                &socket_state.dns_resolver,
                node,
                #[cfg(any(test, feature = "test-utils"))]
                insecure_skip_relay_cert_verify,
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
        Probe::QadIpv4 { ref node, .. } | Probe::QadIpv6 { ref node, .. } => {
            debug!("sending QUIC address discovery probe");
            match socket_state.quic_config {
                Some(quic_config) => {
                    let relay_addr = match probe.proto() {
                        ProbeProto::QadIpv4 => {
                            get_relay_addr_ipv4(&socket_state.dns_resolver, &relay_node).await
                        }
                        ProbeProto::QadIpv6 => {
                            get_relay_addr_ipv6(&socket_state.dns_resolver, &relay_node).await
                        }
                        _ => unreachable!(),
                    }
                    .map_err(|e| {
                        ProbeErrorWithProbe::AbortSet(
                            probe_error::GetRelayAddrSnafu.into_error(e),
                            probe.clone(),
                        )
                    })?;

                    let url = node.url.clone();
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
                    return Err(ProbeErrorWithProbe::AbortSet(
                        probe_error::QuicSnafu.into_error(quic_error::NoEndpointSnafu.build()),
                        probe.clone(),
                    ));
                }
            }
        }
    }

    trace!("probe successful");
    Ok(result)
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
) -> Result<ProbeReport, ProbeErrorWithProbe> {
    match probe.proto() {
        ProbeProto::QadIpv4 => debug_assert!(relay_addr.is_ipv4()),
        ProbeProto::QadIpv6 => debug_assert!(relay_addr.is_ipv6()),
        _ => debug_assert!(false, "wrong probe"),
    }
    let relay_addr = maybe_to_mapped_addr(ip_mapped_addrs, relay_addr);
    let host = match url.host_str() {
        Some(host) => host,
        None => {
            return Err(ProbeErrorWithProbe::Error(
                probe_error::QuicSnafu.into_error(quic_error::InvalidUrlSnafu.build()),
                probe.clone(),
            ));
        }
    };
    let quic_client = iroh_relay::quic::QuicClient::new(quic_config.ep, quic_config.client_config)
        .map_err(|e| {
            ProbeErrorWithProbe::Error(
                probe_error::QuicSnafu.into_error(quic_error::CreateClientSnafu.into_error(e)),
                probe.clone(),
            )
        })?;
    let (addr, latency) = quic_client
        .get_addr_and_latency(relay_addr, host)
        .await
        .map_err(|e| {
            ProbeErrorWithProbe::Error(
                probe_error::QuicSnafu.into_error(quic_error::GetAddrSnafu.into_error(e)),
                probe.clone(),
            )
        })?;
    let mut result = ProbeReport::new(probe.clone());
    if matches!(probe, Probe::QadIpv4 { .. }) {
        result.ipv4_can_send = true;
    } else {
        result.ipv6_can_send = true;
    }
    result.addr = Some(addr);
    result.latency = Some(latency);
    Ok(result)
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
enum CaptivePortalError {
    #[snafu(transparent)]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Creating HTTP client failed"))]
    CreateReqwestClient { source: reqwest::Error },
    #[snafu(display("HTTP request failed"))]
    HttpRequest { source: reqwest::Error },
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
) -> Result<bool, CaptivePortalError> {
    // If we have a preferred relay node and we can use it for non-STUN requests, try that;
    // otherwise, pick a random one suitable for non-STUN requests.
    let preferred_relay = preferred_relay.and_then(|url| dm.get_node(&url).map(|_| url));

    let url = match preferred_relay {
        Some(url) => url,
        None => {
            let urls: Vec<_> = dm.nodes().map(|n| n.url.clone()).collect();
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
    let client = builder
        .build()
        .context(captive_portal_error::CreateReqwestClientSnafu)?;

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
        .await
        .context(captive_portal_error::HttpRequestSnafu)?;

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
fn get_quic_port(relay_node: &RelayNode) -> Option<u16> {
    if let Some(ref quic) = relay_node.quic {
        if quic.port == 0 {
            Some(DEFAULT_RELAY_QUIC_PORT)
        } else {
            Some(quic.port)
        }
    } else {
        None
    }
}

#[cfg(not(wasm_browser))]
#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
pub enum GetRelayAddrError {
    #[snafu(display("No valid hostname in the relay URL"))]
    InvalidHostname,
    #[snafu(display("No suitable relay address found"))]
    NoAddrFound,
    #[snafu(display("DNS lookup failed"))]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Relay node is not suitable for non-STUN probes"))]
    UnsupportedRelayNode,
    #[snafu(display("HTTPS probes are not implemented"))]
    UnsupportedHttps,
    #[snafu(display("No port available for this protocol"))]
    MissingPort,
}

/// Returns the IP address to use to communicate to this relay node for quic.
#[cfg(not(wasm_browser))]
async fn get_relay_addr_ipv4(
    dns_resolver: &DnsResolver,
    relay_node: &RelayNode,
) -> Result<SocketAddr, GetRelayAddrError> {
    let port = get_quic_port(relay_node).context(get_relay_addr_error::MissingPortSnafu)?;
    relay_lookup_ipv4_staggered(dns_resolver, relay_node, port).await
}

#[cfg(not(wasm_browser))]
async fn get_relay_addr_ipv6(
    dns_resolver: &DnsResolver,
    relay_node: &RelayNode,
) -> Result<SocketAddr, GetRelayAddrError> {
    let port = get_quic_port(relay_node).context(get_relay_addr_error::MissingPortSnafu)?;
    relay_lookup_ipv6_staggered(dns_resolver, relay_node, port).await
}

/// Do a staggared ipv4 DNS lookup based on [`RelayNode`]
///
/// `port` is combined with the resolved [`std::net::Ipv4Addr`] to return a [`SocketAddr`]
#[cfg(not(wasm_browser))]
async fn relay_lookup_ipv4_staggered(
    dns_resolver: &DnsResolver,
    relay: &RelayNode,
    port: u16,
) -> Result<SocketAddr, GetRelayAddrError> {
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
                    .map(|addr| {
                        debug_assert!(addr.is_ipv4(), "bad DNS lookup: {:?}", addr);
                        SocketAddr::new(addr, port)
                    })
                    .ok_or(get_relay_addr_error::NoAddrFoundSnafu.build()),
                Err(err) => Err(get_relay_addr_error::DnsLookupSnafu.into_error(err)),
            }
        }
        Some(url::Host::Ipv4(addr)) => Ok(SocketAddr::new(addr.into(), port)),
        Some(url::Host::Ipv6(_addr)) => Err(get_relay_addr_error::NoAddrFoundSnafu.build()),
        None => Err(get_relay_addr_error::InvalidHostnameSnafu.build()),
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
) -> Result<SocketAddr, GetRelayAddrError> {
    match relay.url.host() {
        Some(url::Host::Domain(hostname)) => {
            debug!(%hostname, "Performing DNS AAAA lookup for relay addr");
            match dns_resolver
                .lookup_ipv6_staggered(hostname, DNS_TIMEOUT, DNS_STAGGERING_MS)
                .await
            {
                Ok(mut addrs) => addrs
                    .next()
                    .map(|addr| {
                        debug_assert!(addr.is_ipv6(), "bad DNS lookup: {:?}", addr);
                        SocketAddr::new(addr, port)
                    })
                    .ok_or(get_relay_addr_error::NoAddrFoundSnafu.build()),
                Err(err) => Err(get_relay_addr_error::DnsLookupSnafu.into_error(err)),
            }
        }
        Some(url::Host::Ipv4(_addr)) => Err(get_relay_addr_error::NoAddrFoundSnafu.build()),
        Some(url::Host::Ipv6(addr)) => Ok(SocketAddr::new(addr.into(), port)),
        None => Err(get_relay_addr_error::InvalidHostnameSnafu.build()),
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
#[non_exhaustive]
enum MeasureHttpsLatencyError {
    #[snafu(transparent)]
    InvalidUrl { source: url::ParseError },
    #[cfg(not(wasm_browser))]
    #[snafu(transparent)]
    DnsLookup { source: StaggeredError<DnsError> },
    #[snafu(display("Creating HTTP client failed"))]
    CreateReqwestClient { source: reqwest::Error },
    #[snafu(display("HTTP request failed"))]
    HttpRequest { source: reqwest::Error },
    #[snafu(display("Error response from server {status}: {:?}", status.canonical_reason()))]
    InvalidResponse { status: StatusCode },
}

/// Executes an HTTPS probe.
///
/// If `certs` is provided they will be added to the trusted root certificates, allowing the
/// use of self-signed certificates for servers.  Currently this is used for testing.
#[allow(clippy::unused_async)]
async fn measure_https_latency(
    #[cfg(not(wasm_browser))] dns_resolver: &DnsResolver,
    node: &RelayNode,
    #[cfg(any(test, feature = "test-utils"))] insecure_skip_relay_cert_verify: bool,
) -> Result<(Duration, IpAddr), MeasureHttpsLatencyError> {
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

    #[cfg(all(not(wasm_browser), any(test, feature = "test-utils")))]
    let builder = builder.danger_accept_invalid_certs(insecure_skip_relay_cert_verify);

    let client = builder
        .build()
        .context(measure_https_latency_error::CreateReqwestClientSnafu)?;

    let start = Instant::now();
    let response = client
        .request(reqwest::Method::GET, url)
        .send()
        .await
        .context(measure_https_latency_error::HttpRequestSnafu)?;
    let latency = start.elapsed();
    if response.status().is_success() {
        // Only `None` if a different hyper HttpConnector in the request.
        #[cfg(not(wasm_browser))]
        let remote_ip = response
            .remote_addr()
            .expect("missing HttpInfo from HttpConnector")
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
        Err(measure_https_latency_error::InvalidResponseSnafu {
            status: response.status(),
        }
        .build())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use n0_snafu::{Result, ResultExt};
    use tracing_test::traced_test;

    use super::{super::test_utils, *};
    use crate::net_report::dns;

    #[tokio::test]
    async fn test_measure_https_latency() -> Result {
        let (_server, relay) = test_utils::relay().await;
        let dns_resolver = dns::tests::resolver();
        tracing::info!(relay_url = ?relay.url , "RELAY_URL");
        let (latency, ip) = measure_https_latency(&dns_resolver, &relay, true).await?;

        assert!(latency > Duration::ZERO);

        let relay_url_ip = relay
            .url
            .host_str()
            .unwrap()
            .parse::<std::net::IpAddr>()
            .e()?;
        assert_eq!(ip, relay_url_ip);
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_quic_probe() -> Result {
        let (server, relay) = test_utils::relay().await;
        let relay = Arc::new(relay);
        let client_config = iroh_relay::client::make_dangerous_client_config();
        let ep = quinn::Endpoint::client(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)).e()?;
        let client_addr = ep.local_addr().e()?;
        let quic_addr_disc = QuicConfig {
            ep: ep.clone(),
            client_config,
            ipv4: true,
            ipv6: true,
        };
        let url = relay.url.clone();
        let port = server.quic_addr().unwrap().port();
        let probe = Probe::QadIpv4 {
            delay: Duration::from_secs(0),
            node: relay,
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
                ProbeErrorWithProbe::AbortSet(err, _) | ProbeErrorWithProbe::Error(err, _) => {
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
