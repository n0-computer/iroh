//! Long-lived actor that drives network condition probes and publishes
//! results incrementally.
//!
//! [`NetReportActor`] owns all probe state (QAD connections, report
//! history) and coordinates three probe types:
//!
//! - **QAD** (QUIC Address Discovery): discovers the endpoint's public address.
//! - **HTTPS**: measures latency to each relay server.
//! - **Captive portal**: detects HTTP-intercepting networks.
//!
//! Probe results are emitted via a [`Watchable`] as they arrive, so
//! consumers see address updates within milliseconds of discovery. Two
//! deadlines bound each cycle: [`REPORT_TIMEOUT`] guarantees a report
//! is emitted within three seconds, and [`ABORT_TIMEOUT`] cancels
//! remaining HTTPS probes while letting QAD probes finish on degraded
//! links.

use std::{collections::BTreeSet, sync::Arc};

use iroh_relay::RelayMap;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON};
use n0_future::{
    MaybeFuture,
    time::{self, Duration, Instant},
};
use n0_watcher::{Watchable, Watcher};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

#[cfg(not(wasm_browser))]
use super::reportgen::QadProbeReport;
#[cfg(not(wasm_browser))]
use super::{
    QadConn, QadConns, QadProbeError, defaults::timeouts::QAD_PROBE_TIMEOUT, reportgen::SocketState,
};
use super::{
    Report,
    defaults::timeouts::{
        ABORT_TIMEOUT, CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, PROBES_TIMEOUT, REPORT_TIMEOUT,
    },
    metrics::Metrics,
    probes::{Probe, ProbePlan},
    report::RelayLatencies,
    reportgen::{HttpsProbeReport, ProbesError},
};

const FULL_REPORT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A coalesced probe request waiting to be picked up by the actor.
///
/// Multiple [`Client::run_probes`](super::Client::run_probes) calls
/// between actor ticks merge into a single request. The `is_major` flag
/// is sticky: once set, it stays set until the actor consumes the request.
pub(super) struct PendingProbeRequest {
    pub if_state: super::reportgen::IfStateDetails,
    pub is_major: bool,
}

/// Shared slot for delivering probe requests from [`Client`](super::Client)
/// to the [`NetReportActor`].
///
/// Debug output omits the slot contents to avoid locking.
///
/// Writers merge into the existing request (if any), preserving the
/// `is_major` flag via OR. The actor takes the request atomically.
pub(super) struct ProbeRequestSlot {
    slot: std::sync::Mutex<Option<PendingProbeRequest>>,
    notify: tokio::sync::Notify,
}

impl std::fmt::Debug for ProbeRequestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeRequestSlot").finish_non_exhaustive()
    }
}

impl ProbeRequestSlot {
    pub(super) fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Merge a probe request into the slot.
    ///
    /// If a request is already pending, `is_major` is OR-ed in and
    /// `if_state` is overwritten with the latest value. If no request
    /// is pending, a new one is created.
    pub(super) fn request(&self, if_state: super::reportgen::IfStateDetails, is_major: bool) {
        let mut guard = self.slot.lock().expect("not poisoned");
        match guard.as_mut() {
            Some(pending) => {
                pending.is_major |= is_major;
                pending.if_state = if_state;
            }
            None => {
                *guard = Some(PendingProbeRequest { if_state, is_major });
            }
        }
        drop(guard);
        self.notify.notify_one();
    }

    /// Take the pending request, leaving the slot empty.
    fn take(&self) -> Option<PendingProbeRequest> {
        self.slot.lock().expect("not poisoned").take()
    }
}

/// Outcome of a single probe task in the actor's [`JoinSet`].
enum ProbeResult {
    /// Completed QAD IPv4 probe with connection for reuse.
    #[cfg(not(wasm_browser))]
    QadV4(Result<(QadProbeReport, QadConn), QadProbeError>),
    /// Completed QAD IPv6 probe with connection for reuse.
    #[cfg(not(wasm_browser))]
    QadV6(Result<(QadProbeReport, QadConn), QadProbeError>),
    /// Completed HTTPS latency probe.
    Https(Result<HttpsProbeReport, ProbesError>),
    /// Completed captive portal detection check.
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

/// Tracks report history across cycles.
#[derive(Debug)]
struct Reports {
    /// Force a full report on the next cycle.
    next_full: bool,
    /// Recent reports keyed by time.
    prev: std::collections::BTreeMap<Instant, Report>,
    /// The most recent completed report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
}

impl Default for Reports {
    fn default() -> Self {
        Self {
            next_full: true,
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

/// Actor that owns all probe state and emits report updates via
/// `report_out` as probe results arrive.
///
/// See the [module documentation](self) for an overview of the probe
/// lifecycle and timeout strategy.
pub(super) struct NetReportActor {
    // -- probe tasks --
    probes: JoinSet<Option<ProbeResult>>,

    // -- QAD connection state --
    #[cfg(not(wasm_browser))]
    qad_conns: QadConns,

    // -- configuration --
    relay_map: RelayMap,
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    protocols: BTreeSet<Probe>,

    // -- report state --
    current_report: Report,
    reports: Reports,
    report_out: Watchable<Option<Report>>,

    /// When the current probe cycle started, or `None` if idle.
    cycle_start: Option<Instant>,

    /// Fires at [`REPORT_TIMEOUT`] after a cycle starts. Forces a report
    /// emission even if no probes have completed, so consumers always get
    /// a report within a bounded time. `None` when no cycle is active or
    /// after the deadline has already fired.
    report_deadline: Option<Instant>,

    /// Fires at [`ABORT_TIMEOUT`] after a cycle starts. Cancels remaining
    /// HTTPS probes to bound total network activity. QAD probes are
    /// unaffected and keep running until [`QAD_PROBE_TIMEOUT`]. `None`
    /// when no cycle is active or after it has already fired.
    abort_deadline: Option<Instant>,

    // -- probe cancellation --
    #[cfg(not(wasm_browser))]
    cancel_qad_v4: CancellationToken,
    #[cfg(not(wasm_browser))]
    cancel_qad_v6: CancellationToken,
    cancel_https: CancellationToken,
    #[cfg(not(wasm_browser))]
    captive_portal_cancel: CancellationToken,

    // -- input / lifecycle --
    probe_requests: Arc<ProbeRequestSlot>,
    shutdown: CancellationToken,
    metrics: Arc<Metrics>,
}

impl NetReportActor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        probe_requests: Arc<ProbeRequestSlot>,
        report_out: Watchable<Option<Report>>,
        relay_map: RelayMap,
        #[cfg(not(wasm_browser))] socket_state: SocketState,
        #[cfg(not(wasm_browser))] tls_config: rustls::ClientConfig,
        protocols: BTreeSet<Probe>,
        shutdown: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            probes: JoinSet::new(),
            #[cfg(not(wasm_browser))]
            qad_conns: QadConns::default(),
            relay_map,
            #[cfg(not(wasm_browser))]
            socket_state,
            #[cfg(not(wasm_browser))]
            tls_config,
            protocols,
            current_report: Report::default(),
            reports: Reports::default(),
            report_out,
            cycle_start: None,
            report_deadline: None,
            abort_deadline: None,
            #[cfg(not(wasm_browser))]
            cancel_qad_v4: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            cancel_qad_v6: CancellationToken::new(),
            cancel_https: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            captive_portal_cancel: CancellationToken::new(),
            probe_requests,
            shutdown,
            metrics,
        }
    }

    /// Runs the actor until the shutdown token is cancelled.
    ///
    /// The select loop processes probe requests, drains probe results,
    /// and watches existing QAD connections for address changes.
    pub(super) async fn run(mut self) {
        loop {
            // Recreate QAD watcher each iteration. This is cheap (just
            // clones watcher handles) and avoids tracking whether
            // connections changed since the last iteration.
            #[cfg(not(wasm_browser))]
            let mut qad_watch = self.qad_conns.watch();
            #[cfg(wasm_browser)]
            let mut qad_watch = n0_watcher::Watchable::new((None, None)).watch();

            let report_deadline = match self.report_deadline {
                Some(t) => MaybeFuture::Some(time::sleep_until(t)),
                None => MaybeFuture::None,
            };
            let abort_deadline = match self.abort_deadline {
                Some(t) => MaybeFuture::Some(time::sleep_until(t)),
                None => MaybeFuture::None,
            };
            n0_future::pin!(report_deadline);
            n0_future::pin!(abort_deadline);

            tokio::select! {
                biased;

                _ = self.shutdown.cancelled() => break,

                _ = self.probe_requests.notify.notified() => {
                    if let Some(req) = self.probe_requests.take() {
                        self.handle_probe_request(req);
                    }
                }

                Some(result) = self.probes.join_next() => {
                    self.handle_probe_result(result);
                }

                // Report deadline: emit whatever we have so consumers
                // get a report within REPORT_TIMEOUT (3s).
                _ = &mut report_deadline => {
                    debug!("report deadline fired, emitting current report");
                    self.report_deadline = None;
                    self.force_emit();
                }

                // Abort deadline: cancel remaining HTTPS probes. QAD
                // probes are unaffected and keep running until
                // QAD_PROBE_TIMEOUT.
                _ = &mut abort_deadline => {
                    debug!("abort deadline fired, cancelling HTTPS probes");
                    self.abort_deadline = None;
                    self.cancel_https.cancel();
                }

                Ok((v4, v6)) = qad_watch.updated() => {
                    #[cfg(not(wasm_browser))]
                    {
                        if let Some(r) = v4 {
                            trace!(?r, "QAD v4 address update from existing conn");
                            self.current_report.update_qad_v4(&r);
                            self.maybe_emit();
                        }
                        if let Some(r) = v6 {
                            trace!(?r, "QAD v6 address update from existing conn");
                            self.current_report.update_qad_v6(&r);
                            self.maybe_emit();
                        }
                    }
                }
            }
        }
    }

    /// Starts a new probe cycle from a [`PendingProbeRequest`].
    ///
    /// Non-major requests are coalesced (skipped) when probes are already
    /// running. Major requests abort the current cycle and start fresh.
    fn handle_probe_request(&mut self, req: PendingProbeRequest) {
        let PendingProbeRequest { if_state, is_major } = req;

        // Nothing to probe if we have no relays configured.
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            return;
        }

        // Coalesce: skip if non-major and probes already running.
        if !is_major && !self.probes.is_empty() {
            debug!("coalescing probe request, probes already running");
            return;
        }

        if is_major {
            self.probes.abort_all();
        }

        // Full vs incremental determination
        let now = Instant::now();
        let do_full = is_major
            || self.reports.next_full
            || now.duration_since(self.reports.last_full) > FULL_REPORT_INTERVAL
            || self
                .reports
                .last
                .as_ref()
                .is_some_and(|r| !r.has_udp() && r.captive_portal == Some(true));

        debug!(%do_full, %is_major, "starting probe cycle");

        if do_full {
            #[cfg(not(wasm_browser))]
            self.qad_conns.clear();
            self.reports.last = None;
            self.reports.next_full = false;
            self.reports.last_full = now;
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();
        self.cycle_start = Some(now);
        self.report_deadline = Some(now + REPORT_TIMEOUT);
        self.abort_deadline = Some(now + ABORT_TIMEOUT);
        self.current_report = Report::default();

        // Reset cancellation tokens for the new cycle.
        #[cfg(not(wasm_browser))]
        {
            self.cancel_qad_v4 = CancellationToken::new();
            self.cancel_qad_v6 = CancellationToken::new();
        }
        self.cancel_https = CancellationToken::new();

        #[cfg(not(wasm_browser))]
        self.spawn_qad_probes(&if_state);
        self.spawn_https_probes();

        #[cfg(not(wasm_browser))]
        if do_full {
            self.spawn_captive_portal();
        }
    }

    /// Processes a completed probe task from the [`JoinSet`].
    ///
    /// Updates `current_report`, stores QAD connections, cancels redundant
    /// probes, and triggers report emission.
    fn handle_probe_result(&mut self, result: Result<Option<ProbeResult>, tokio::task::JoinError>) {
        let Ok(Some(result)) = result else {
            // JoinError or cancelled (None).
            return;
        };

        match result {
            #[cfg(not(wasm_browser))]
            ProbeResult::QadV4(Ok((report, conn))) => {
                debug!(?report, "QAD v4 probe completed");
                self.current_report.update_qad_v4(&report);
                let url = report.relay;
                if self.qad_conns.v4.is_none() {
                    self.qad_conns.v4 = Some((url, conn));
                    // Cancel remaining v4 QAD probes, we have a winner.
                    self.cancel_qad_v4.cancel();
                } else {
                    conn.conn
                        .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                }
                self.captive_portal_cancel.cancel();
                self.maybe_emit();
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::QadV6(Ok((report, conn))) => {
                debug!(?report, "QAD v6 probe completed");
                self.current_report.update_qad_v6(&report);
                let url = report.relay;
                if self.qad_conns.v6.is_none() {
                    self.qad_conns.v6 = Some((url, conn));
                    // Cancel remaining v6 QAD probes, we have a winner.
                    self.cancel_qad_v6.cancel();
                } else {
                    conn.conn
                        .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                }
                self.captive_portal_cancel.cancel();
                self.maybe_emit();
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::QadV4(Err(e)) => {
                debug!("QAD v4 probe failed: {e:#}");
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::QadV6(Err(e)) => {
                debug!("QAD v6 probe failed: {e:#}");
            }
            ProbeResult::Https(Ok(report)) => {
                debug!(?report, "HTTPS probe completed");
                self.current_report.update_https(&report);
                // If we have latency data for all relays, cancel remaining HTTPS probes.
                if self.have_all_relay_latencies() {
                    self.cancel_https.cancel();
                }
                self.maybe_emit();
            }
            ProbeResult::Https(Err(e)) => {
                trace!("HTTPS probe error: {e:?}");
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::CaptivePortal(result) => {
                debug!(?result, "captive portal check completed");
                self.current_report.captive_portal = result;
                self.maybe_emit();
            }
        }

        // Cycle complete when all probes finished.
        if self.probes.is_empty() && self.cycle_start.is_some() {
            self.finalize_cycle();
        }
    }

    /// Publishes the current report if it contains meaningful probe data.
    ///
    /// The underlying [`Watchable`] deduplicates, so calling this with an
    /// unchanged report is a no-op.
    fn maybe_emit(&mut self) {
        let has_data = self.current_report.global_v4.is_some()
            || self.current_report.global_v6.is_some()
            || self.current_report.has_udp()
            || !self.current_report.relay_latency.is_empty();

        if !has_data {
            return;
        }

        self.report_out.set(Some(self.current_report.clone())).ok();
    }

    /// Unconditionally publishes the current report, even if empty.
    fn force_emit(&mut self) {
        self.report_out.set(Some(self.current_report.clone())).ok();
    }

    /// Finalizes the current probe cycle.
    ///
    /// Called when the [`JoinSet`] is empty (all probes completed or timed
    /// out). Commits the report to history, selects the preferred relay,
    /// and emits the final report.
    fn finalize_cycle(&mut self) {
        let mut report = std::mem::take(&mut self.current_report);
        self.add_report_history_and_set_preferred_relay(&mut report);
        self.current_report = report;

        // Final emission with preferred_relay set.
        self.report_out.set(Some(self.current_report.clone())).ok();

        debug!(
            report = ?self.current_report,
            duration = ?self.cycle_start.map(|s| s.elapsed()),
            "net_report cycle complete",
        );
        self.cycle_start = None;
    }

    /// Returns `true` when we have at least one latency measurement for
    /// every relay in the relay map. Used to cancel remaining HTTPS probes
    /// once we have complete coverage.
    fn have_all_relay_latencies(&self) -> bool {
        let num_relays = self.relay_map.len();
        if num_relays == 0 {
            return true;
        }
        // Count distinct relay URLs across all probe types.
        let mut seen = std::collections::BTreeSet::new();
        for (_, url, _) in self.current_report.relay_latency.iter() {
            seen.insert(url);
        }
        seen.len() >= num_relays
    }

    /// Spawns QAD probes for IPv4 and IPv6 if needed. Reuses existing
    /// connections when available, and validates that they are still alive.
    #[cfg(not(wasm_browser))]
    fn spawn_qad_probes(&mut self, if_state: &super::reportgen::IfStateDetails) {
        use tracing::{Instrument, warn_span};

        let Some(ref quic_client) = self.socket_state.quic_client else {
            return;
        };

        // Validate existing connections
        if let Some((url, conn)) = &self.qad_conns.v4
            && let Some(reason) = conn.conn.close_reason()
        {
            trace!(?url, "QAD v4 conn closed: {}", reason);
            self.qad_conns.v4.take();
        }
        if let Some((url, conn)) = &self.qad_conns.v6
            && let Some(reason) = conn.conn.close_reason()
        {
            trace!(?url, "QAD v6 conn closed: {}", reason);
            self.qad_conns.v6.take();
        }

        let v4_report = self.qad_conns.current_v4();
        let v6_report = self.qad_conns.current_v6();

        if let Some(ref r) = v4_report {
            self.current_report.update_qad_v4(r);
        }
        if let Some(ref r) = v6_report {
            self.current_report.update_qad_v6(r);
        }

        let needs_v4 = self.qad_conns.v4.is_none() && if_state.have_v4;
        let needs_v6 = (self.qad_conns.v6.is_some() != if_state.have_v6) && if_state.have_v6;

        if !needs_v4 && !needs_v6 {
            return;
        }

        trace!(needs_v4, needs_v6, "spawning QAD probes");

        const MAX_RELAYS: usize = 5;
        let relays = self.relay_map.relays::<Vec<_>>();
        for relay in relays.into_iter().take(MAX_RELAYS) {
            if needs_v4 {
                let relay = relay.clone();
                let dns_resolver = self.socket_state.dns_resolver.clone();
                let quic_client = quic_client.clone();
                let relay_url = relay.url.clone();
                let inner_token = self.shutdown.child_token();
                let cancel = self.cancel_qad_v4.child_token();
                self.probes.spawn(
                    cancel
                        .run_until_cancelled_owned(async move {
                            match time::timeout(
                                QAD_PROBE_TIMEOUT,
                                super::run_probe_v4(relay, quic_client, dns_resolver, inner_token),
                            )
                            .await
                            {
                                Ok(result) => ProbeResult::QadV4(result),
                                Err(_) => {
                                    debug!("QAD v4 probe timed out");
                                    ProbeResult::QadV4(Err(n0_error::e!(
                                        QadProbeError::ReceiverDropped
                                    )))
                                }
                            }
                        })
                        .instrument(warn_span!("QADv4", %relay_url)),
                );
            }
            if needs_v6 {
                let relay = relay.clone();
                let dns_resolver = self.socket_state.dns_resolver.clone();
                let quic_client = quic_client.clone();
                let relay_url = relay.url.clone();
                let inner_token = self.shutdown.child_token();
                let cancel = self.cancel_qad_v6.child_token();
                self.probes.spawn(
                    cancel
                        .run_until_cancelled_owned(async move {
                            match time::timeout(
                                QAD_PROBE_TIMEOUT,
                                super::run_probe_v6(relay, quic_client, dns_resolver, inner_token),
                            )
                            .await
                            {
                                Ok(result) => ProbeResult::QadV6(result),
                                Err(_) => {
                                    debug!("QAD v6 probe timed out");
                                    ProbeResult::QadV6(Err(n0_error::e!(
                                        QadProbeError::ReceiverDropped
                                    )))
                                }
                            }
                        })
                        .instrument(warn_span!("QADv6", %relay_url)),
                );
            }
        }
    }

    /// Spawns HTTPS latency probes according to the current [`ProbePlan`].
    fn spawn_https_probes(&mut self) {
        let plan = match self.reports.last {
            Some(ref report) => {
                ProbePlan::with_last_report(&self.relay_map, report, &self.protocols)
            }
            None => ProbePlan::initial(&self.relay_map, &self.protocols),
        };
        trace!(%plan, "probe plan");

        for probe_set in plan.iter() {
            for (delay, relay) in probe_set.params() {
                let delay = *delay;
                let relay = relay.clone();
                let cancel = self.cancel_https.child_token();
                #[cfg(not(wasm_browser))]
                let socket_state = self.socket_state.clone();
                #[cfg(not(wasm_browser))]
                let tls_config = self.tls_config.clone();
                self.probes.spawn(async move {
                    let result = cancel
                        .run_until_cancelled(time::timeout(PROBES_TIMEOUT, async move {
                            if !delay.is_zero() {
                                time::sleep(delay).await;
                            }
                            super::reportgen::run_https_probe(
                                #[cfg(not(wasm_browser))]
                                &socket_state.dns_resolver,
                                relay.url.clone(),
                                #[cfg(not(wasm_browser))]
                                tls_config,
                            )
                            .await
                        }))
                        .await;
                    Some(match result {
                        Some(Ok(Ok(report))) => ProbeResult::Https(Ok(report)),
                        Some(Ok(Err(e))) => {
                            ProbeResult::Https(Err(n0_error::e!(ProbesError::ProbeFailure, e)))
                        }
                        Some(Err(_)) => ProbeResult::Https(Err(n0_error::e!(ProbesError::Timeout))),
                        None => ProbeResult::Https(Err(n0_error::e!(ProbesError::Cancelled))),
                    })
                });
            }
        }
    }

    /// Spawns a captive portal detection check. Delayed by
    /// [`CAPTIVE_PORTAL_DELAY`] to give QAD probes time to succeed first,
    /// and cancelled if QAD confirms UDP connectivity.
    #[cfg(not(wasm_browser))]
    fn spawn_captive_portal(&mut self) {
        self.captive_portal_cancel = CancellationToken::new();
        let cancel = self.captive_portal_cancel.clone();
        let dns = self.socket_state.dns_resolver.clone();
        let relay_map = self.relay_map.clone();
        let tls = self.tls_config.clone();
        let preferred = self
            .reports
            .last
            .as_ref()
            .and_then(|r| r.preferred_relay.clone());

        self.probes.spawn(async move {
            time::sleep(CAPTIVE_PORTAL_DELAY).await;
            if cancel.is_cancelled() {
                return Some(ProbeResult::CaptivePortal(None));
            }
            let result = time::timeout(
                CAPTIVE_PORTAL_TIMEOUT,
                super::reportgen::check_captive_portal(&dns, &relay_map, preferred, tls),
            )
            .await;
            Some(match result {
                Ok(Ok(found)) => ProbeResult::CaptivePortal(Some(found)),
                Ok(Err(e)) => {
                    warn!("captive portal check error: {e:#}");
                    ProbeResult::CaptivePortal(None)
                }
                Err(_) => {
                    warn!("captive portal check timed out");
                    ProbeResult::CaptivePortal(None)
                }
            })
        });
    }

    /// Delegates to [`update_report_history`].
    fn add_report_history_and_set_preferred_relay(&mut self, r: &mut Report) {
        update_report_history(&mut self.reports, r);
    }
}

/// Adds a report to the history and selects a preferred relay.
///
/// Merges latency data from the last five minutes of reports to find the
/// relay with the best recent performance. Applies hysteresis: the
/// preferred relay only changes when the new candidate is at least 33%
/// faster than the current one.
///
/// This is a free function (rather than a method on [`NetReportActor`])
/// so the relay selection logic can be tested independently.
fn update_report_history(reports: &mut Reports, r: &mut Report) {
    let mut prev_relay = None;
    if let Some(ref last) = reports.last {
        prev_relay.clone_from(&last.preferred_relay);

        if r.mapping_varies_by_dest_ipv4.is_none() {
            r.mapping_varies_by_dest_ipv4 = last.mapping_varies_by_dest_ipv4;
        }
        if r.mapping_varies_by_dest_ipv6.is_none() {
            r.mapping_varies_by_dest_ipv6 = last.mapping_varies_by_dest_ipv6;
        }
    }

    let now = Instant::now();
    const MAX_AGE: Duration = Duration::from_secs(5 * 60);

    let mut best_recent = RelayLatencies::default();

    let mut to_remove = Vec::new();
    for (t, pr) in reports.prev.iter() {
        if now.duration_since(*t) > MAX_AGE {
            to_remove.push(*t);
            continue;
        }
        best_recent.merge(&pr.relay_latency);
    }
    best_recent.merge(&r.relay_latency);

    for t in to_remove {
        reports.prev.remove(&t);
    }

    let mut best_any = Duration::default();
    let mut old_relay_cur_latency = Duration::default();
    for (_, url, duration) in r.relay_latency.iter() {
        if Some(url) == prev_relay.as_ref() {
            old_relay_cur_latency = duration;
        }
        if let Some(best) = best_recent.get(url)
            && (r.preferred_relay.is_none() || best < best_any)
        {
            best_any = best;
            r.preferred_relay.replace(url.clone());
        }
    }

    // Hysteresis: don't switch if the new relay isn't much better.
    if prev_relay.is_some()
        && r.preferred_relay != prev_relay
        && !old_relay_cur_latency.is_zero()
        && best_any > old_relay_cur_latency / 3 * 2
    {
        r.preferred_relay = prev_relay;
    }

    reports.prev.insert(now, r.clone());
    reports.last = Some(r.clone());
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::time::Duration;

    use iroh_base::RelayUrl;
    use n0_error::Result;

    use super::*;
    use crate::net_report::probes::Probe;

    fn relay_url(i: u16) -> RelayUrl {
        format!("http://{i}.com").parse().unwrap()
    }

    fn report(a: impl IntoIterator<Item = (&'static str, u64)>) -> Option<Report> {
        let mut report = Report::default();
        for (s, d) in a {
            assert!(s.starts_with('d'), "invalid relay server key");
            let id: u16 = s[1..].parse().unwrap();
            report.relay_latency.update_relay(
                relay_url(id),
                Duration::from_secs(d),
                Probe::QadIpv4,
            );
        }
        Some(report)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_report_history_and_preferred_relay() -> Result {
        struct Step {
            after: u64,
            r: Option<Report>,
        }
        struct Test {
            name: &'static str,
            steps: Vec<Step>,
            want_relay: Option<RelayUrl>,
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
                want_relay: Some(relay_url(1)),
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
                want_relay: Some(relay_url(2)),
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
                    },
                ],
                want_prev_len: 4,
                want_relay: Some(relay_url(1)),
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
                want_prev_len: 1,
                want_relay: Some(relay_url(3)),
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
                want_relay: Some(relay_url(1)),
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
                want_relay: Some(relay_url(2)),
            },
        ];

        for mut tt in tests {
            println!("test: {}", tt.name);
            let mut reports = Reports::default();
            for s in &mut tt.steps {
                tokio::time::advance(Duration::from_secs(s.after)).await;
                update_report_history(&mut reports, s.r.as_mut().unwrap());
            }
            let last_report = tt.steps.last().unwrap().r.clone().unwrap();
            assert_eq!(reports.prev.len(), tt.want_prev_len, "prev length");
            assert_eq!(
                &last_report.preferred_relay, &tt.want_relay,
                "preferred_relay"
            );
        }

        Ok(())
    }
}
