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

use std::{collections::BTreeSet, sync::Arc};

#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::QuicClient;
use iroh_relay::{RelayConfig, RelayMap};
use n0_error::{e, stack_error};
#[cfg(wasm_browser)]
use n0_future::future::Pending;
use n0_future::{
    task::{self, AbortOnDropHandle, JoinSet},
    time::{self, Duration},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info_span, trace, warn};

#[cfg(not(wasm_browser))]
use super::captive_portal::{CaptivePortalError, check_captive_portal};
use super::https::{HttpsProbeReport, MeasureHttpsLatencyError, run_https_probe};
#[cfg(not(wasm_browser))]
use super::qad::QadProbeReport;
use super::{
    Report,
    probes::{Probe, ProbePlan},
};
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

/// Some details required from the interface state of the device.
#[derive(Debug, Clone, Default)]
pub(crate) struct IfStateDetails {
    /// Do we have IPv4 capbilities
    pub(crate) have_v4: bool,
    /// Do we have IPv6 capbilities
    pub(crate) have_v6: bool,
}

impl IfStateDetails {
    #[cfg(test)]
    pub(super) fn fake() -> Self {
        IfStateDetails {
            have_v4: true,
            have_v6: true,
        }
    }
}

impl From<netwatch::netmon::State> for IfStateDetails {
    fn from(value: netwatch::netmon::State) -> Self {
        IfStateDetails {
            have_v4: value.have_v4,
            have_v6: value.have_v6,
        }
    }
}

/// Any state that depends on sockets being available in the current environment.
///
/// Factored out so it can be disabled easily in browsers.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone)]
pub(super) struct SocketState {
    /// QUIC client to do QUIC address Discovery
    pub(super) quic_client: Option<QuicClient>,
    /// The DNS resolver to use for probes that need to resolve DNS records.
    pub(super) dns_resolver: DnsResolver,
}

impl Client {
    /// Creates a new actor generating a single report.
    ///
    /// The actor starts running immediately and only generates a single report, after which
    /// it shuts down.  Dropping this handle will abort the actor.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        last_report: Option<Report>,
        relay_map: RelayMap,
        protocols: BTreeSet<Probe>,
        captive_portal_check: bool,
        if_state: IfStateDetails,
        shutdown_token: CancellationToken,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
    ) -> (Self, mpsc::Receiver<ProbeFinished>) {
        let (msg_tx, msg_rx) = mpsc::channel(32);
        let actor = Actor {
            msg_tx,
            last_report,
            relay_map,
            protocols,
            captive_portal_check,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(not(wasm_browser))]
            tls_config,
            if_state,
        };
        let task = task::spawn(
            actor
                .run(shutdown_token)
                .instrument(info_span!("reportgen-actor")),
        );
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
    protocols: BTreeSet<Probe>,

    /// Whether to check for captive portals.
    captive_portal_check: bool,

    /// Any socket-related state that doesn't exist/work in browsers
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    if_state: IfStateDetails,
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum ProbesError {
    #[error("Probe failed")]
    ProbeFailure { source: ProbeError },
    #[error("All probes failed")]
    AllProbesFailed,
    #[error("Probe cancelled")]
    Cancelled,
    #[error("Probe timed out")]
    Timeout,
}

#[derive(Debug)]
pub(super) enum ProbeFinished {
    Regular(Result<ProbeReport, ProbesError>),
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

impl Actor {
    async fn run(self, shutdown_token: CancellationToken) {
        shutdown_token
            .run_until_cancelled_owned(async {
                match time::timeout(OVERALL_REPORT_TIMEOUT, self.run_inner()).await {
                    Ok(()) => trace!("reportgen actor finished"),
                    Err(time::Elapsed { .. }) => {
                        warn!("reportgen timed out");
                    }
                }
            })
            .await;
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
    async fn run_inner(self) {
        trace!("reportgen actor starting");

        let mut probes = JoinSet::default();

        let _probes_token = self.spawn_probes_task(self.if_state.clone(), &mut probes);
        let mut num_probes = probes.len();

        let captive_token = self.prepare_captive_portal_task(&mut probes);

        // any reports of working UDP/QUIC?
        let mut have_udp = false;

        // Check for probes finishing.
        while let Some(probe_result) = probes.join_next().await {
            trace!(?probe_result, num_probes, "processing finished probe");
            match probe_result {
                Ok(report) => {
                    #[cfg_attr(wasm_browser, allow(irrefutable_let_patterns))]
                    if let ProbeFinished::Regular(report) = &report {
                        have_udp |= report.as_ref().map(|r| r.is_udp()).unwrap_or_default();
                        num_probes -= 1;

                        // If all probes are done & we have_udp cancel captive
                        if num_probes == 0 {
                            trace!("all regular probes done");
                            debug_assert!(probes.len() <= 1, "{} probes", probes.len());

                            if have_udp {
                                captive_token.cancel();
                            }
                        }
                    }
                    self.msg_tx.send(report).await.ok();
                }
                Err(e) => {
                    if e.is_panic() {
                        error!("Task panicked {:?}", e);
                        break;
                    }
                    warn!("probes task join error: {:?}", e);
                }
            }
        }
    }

    /// Creates the future which will perform the captive portal check.
    fn prepare_captive_portal_task(&self, tasks: &mut JoinSet<ProbeFinished>) -> CancellationToken {
        let token = CancellationToken::new();

        // If we're doing a full probe, also check for a captive portal. We
        // delay by a bit to wait for UDP QAD to finish, to avoid the probe if
        // it's unnecessary.
        #[cfg(not(wasm_browser))]
        if self.captive_portal_check && self.last_report.is_none() {
            // Even if we're doing a non-incremental update, we may want to try our
            // preferred relay for captive portal detection.
            let preferred_relay = self
                .last_report
                .as_ref()
                .and_then(|l| l.preferred_relay.clone());

            let dns_resolver = self.socket_state.dns_resolver.clone();
            let dm = self.relay_map.clone();
            let token = token.clone();
            #[cfg(not(wasm_browser))]
            let tls_config = self.tls_config.clone();
            tasks.spawn(
                async move {
                    let res = token
                        .run_until_cancelled_owned(async move {
                            time::sleep(CAPTIVE_PORTAL_DELAY).await;
                            trace!("check started after {CAPTIVE_PORTAL_DELAY:?}");
                            time::timeout(
                                CAPTIVE_PORTAL_TIMEOUT,
                                check_captive_portal(
                                    &dns_resolver,
                                    &dm,
                                    preferred_relay,
                                    tls_config,
                                ),
                            )
                            .await
                        })
                        .await;
                    let res = match res {
                        Some(Ok(Ok(found))) => Some(found),
                        Some(Ok(Err(err))) => {
                            match err {
                                CaptivePortalError::CreateReqwestClient { source, .. }
                                | CaptivePortalError::HttpRequest { source, .. }
                                    if source.is_connect() =>
                                {
                                    debug!("check_captive_portal failed: {source:#}");
                                }
                                err => warn!("check_captive_portal error: {err:#}"),
                            }
                            None
                        }
                        Some(Err(time::Elapsed { .. })) => {
                            warn!("probe timed out");
                            None
                        }
                        None => {
                            trace!("probe cancelled");
                            None
                        }
                    };
                    ProbeFinished::CaptivePortal(res)
                }
                .instrument(info_span!("captive-portal")),
            );
        }
        token
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
    ///   - Once there are [`ProbeReport`]s from enough relays, all remaining probes are
    ///     aborted.  That is, the main actor loop stops polling them.
    fn spawn_probes_task(
        &self,
        if_state: IfStateDetails,
        probes: &mut JoinSet<ProbeFinished>,
    ) -> CancellationToken {
        trace!(?if_state, "local interface details");
        let plan = match self.last_report {
            Some(ref report) => {
                ProbePlan::with_last_report(&self.relay_map, report, &self.protocols)
            }
            None => ProbePlan::initial(&self.relay_map, &self.protocols),
        };
        trace!(%plan, "probe plan");

        let token = CancellationToken::new();

        for probe_set in plan.iter() {
            let set_token = token.child_token();
            let proto = probe_set.proto();
            for (delay, relay) in probe_set.params() {
                let probe_token = set_token.child_token();

                let fut = probe_token.run_until_cancelled_owned(time::timeout(
                    PROBES_TIMEOUT,
                    proto.run(
                        *delay,
                        relay.clone(),
                        #[cfg(not(wasm_browser))]
                        self.socket_state.clone(),
                        #[cfg(not(wasm_browser))]
                        self.tls_config.clone(),
                    ),
                ));
                probes.spawn(
                    async move {
                        let res = fut.await;
                        let res = match res {
                            Some(Ok(Ok(report))) => Ok(report),
                            Some(Ok(Err(err))) => {
                                warn!("probe failed: {:#}", err);
                                Err(e!(ProbesError::ProbeFailure, err))
                            }
                            Some(Err(time::Elapsed { .. })) => Err(e!(ProbesError::Timeout)),
                            None => Err(e!(ProbesError::Cancelled)),
                        };
                        ProbeFinished::Regular(res)
                    }
                    .instrument(info_span!(
                        "run-probe",
                        ?proto,
                        ?delay,
                        relay=%relay.url,
                    )),
                );
            }
        }

        token
    }
}

/// The result of running a probe.
#[derive(Debug, Clone)]
pub(super) enum ProbeReport {
    #[cfg(not(wasm_browser))]
    QadIpv4(QadProbeReport),
    #[cfg(not(wasm_browser))]
    QadIpv6(QadProbeReport),
    Https(HttpsProbeReport),
}

impl ProbeReport {
    #[cfg(not(wasm_browser))]
    pub(super) fn is_udp(&self) -> bool {
        matches!(self, Self::QadIpv4(_) | Self::QadIpv6(_))
    }

    #[cfg(wasm_browser)]
    pub(super) fn is_udp(&self) -> bool {
        false
    }
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(super) enum ProbeError {
    #[error("Client is gone")]
    ClientGone,
    #[error("Probe is no longer useful")]
    NotUseful,
    #[error("Failed to run HTTPS probe")]
    Https { source: MeasureHttpsLatencyError },
}

impl Probe {
    /// Executes this particular [`Probe`], including using a delayed start if needed.
    async fn run(
        self,
        delay: Duration,
        relay: Arc<RelayConfig>,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
    ) -> Result<ProbeReport, ProbeError> {
        if !delay.is_zero() {
            trace!("delaying probe");
            time::sleep(delay).await;
        }
        trace!("starting probe");

        let report = match self {
            Probe::Https => {
                match run_https_probe(
                    #[cfg(not(wasm_browser))]
                    &socket_state.dns_resolver,
                    relay.url.clone(),
                    #[cfg(not(wasm_browser))]
                    tls_config,
                )
                .await
                {
                    Ok(report) => Ok(ProbeReport::Https(report)),
                    Err(err) => Err(e!(ProbeError::Https, err)),
                }
            }
            #[cfg(not(wasm_browser))]
            Probe::QadIpv4 | Probe::QadIpv6 => unreachable!("must not be used"),
        };
        debug!(?report, "probe finished");
        report
    }
}
