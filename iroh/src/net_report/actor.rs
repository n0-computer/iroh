//! Long-lived actor that drives network condition probes and publishes
//! results incrementally.
//!
//! [`NetReportActor`] owns all probe state (QAD connections, report
//! history) and coordinates three probe types:
//!
//! - QAD (QUIC Address Discovery): discovers the endpoint's public address.
//! - HTTPS: measures latency to each relay server.
//! - Captive portal: detects HTTP-intercepting networks.
//!
//! Probe results are emitted via a [`Watchable`] as they arrive, so
//! consumers see address updates within milliseconds of discovery.
//! [`REPORT_TIMEOUT`] bounds the time to first emission;
//! [`ABORT_TIMEOUT`] bounds total HTTPS activity while letting QAD probes
//! run to their own per-probe deadline.

use std::{collections::BTreeSet, sync::Arc};

use iroh_relay::RelayMap;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON};
use n0_future::{
    MaybeFuture,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::{Watchable, Watcher};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

#[cfg(not(wasm_browser))]
use super::qad::{AddrFamily, QadConn, QadConns, QadProbeError, QadProbeReport, QadUpdate};
use super::{
    IfStateDetails, Report,
    defaults::timeouts::{
        ABORT_TIMEOUT, CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, FULL_REPORT_INTERVAL,
        PROBES_TIMEOUT, REPORT_TIMEOUT,
    },
    https::{HttpsProbeReport, ProbesError},
    metrics::Metrics,
    probes::{Probe, ProbePlan},
    report::RelayLatencies,
};
#[cfg(not(wasm_browser))]
use super::{SocketState, defaults::timeouts::QAD_PROBE_TIMEOUT};

/// A coalesced probe request waiting to be picked up by the actor.
///
/// Multiple [`Client::run_probes`](super::Client::run_probes) calls
/// between actor ticks merge into a single request. The `is_major` flag
/// is sticky: once set, it stays set until the actor consumes the request.
pub(super) struct PendingProbeRequest {
    pub if_state: IfStateDetails,
    pub is_major: bool,
}

/// Shared slot for delivering probe requests from [`Client`](super::Client)
/// to the [`NetReportActor`].
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

    /// Merges a probe request into the slot.
    ///
    /// If a request is already pending, `is_major` is OR-ed in and
    /// `if_state` is overwritten with the latest value. If no request
    /// is pending, a new one is created.
    pub(super) fn request(&self, if_state: IfStateDetails, is_major: bool) {
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

    /// Takes the pending request, leaving the slot empty.
    fn take(&self) -> Option<PendingProbeRequest> {
        self.slot.lock().expect("not poisoned").take()
    }
}

/// Outcome of a single probe task in the actor's [`JoinSet`].
enum ProbeResult {
    #[cfg(not(wasm_browser))]
    Qad(AddrFamily, Result<(QadProbeReport, QadConn), QadProbeError>),
    Https(Result<HttpsProbeReport, ProbesError>),
    /// `None` when the check was cancelled or timed out.
    #[cfg(not(wasm_browser))]
    CaptivePortal(Option<bool>),
}

/// Tracks recent reports for preferred-relay selection and full-cycle
/// cadence.
#[derive(Debug)]
struct ReportHistory {
    /// When true, the next cycle runs as a full (non-incremental) probe.
    next_full: bool,
    /// Reports from the last five minutes, keyed by completion time.
    prev: std::collections::BTreeMap<Instant, Report>,
    /// The most recent completed report.
    last: Option<Report>,
    /// Time of last full (non-incremental) report.
    last_full: Instant,
}

impl Default for ReportHistory {
    fn default() -> Self {
        Self {
            next_full: true,
            prev: Default::default(),
            last: Default::default(),
            last_full: Instant::now(),
        }
    }
}

impl ReportHistory {
    /// Records `r` and sets `r.preferred_relay` to the best candidate
    /// across the last five minutes of reports.
    ///
    /// Applies hysteresis: the preferred relay only changes when the new
    /// candidate is at least 33% faster than the current one.
    fn record(&mut self, r: &mut Report) {
        let mut prev_relay = None;
        if let Some(ref last) = self.last {
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
        for (t, pr) in self.prev.iter() {
            if now.duration_since(*t) > MAX_AGE {
                to_remove.push(*t);
                continue;
            }
            best_recent.merge(&pr.relay_latency);
        }
        best_recent.merge(&r.relay_latency);

        for t in to_remove {
            self.prev.remove(&t);
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

        self.prev.insert(now, r.clone());
        self.last = Some(r.clone());
    }
}

/// Actor that owns all probe state and emits report updates via
/// `report_out` as probe results arrive.
///
/// See the [module documentation](self) for an overview of the probe
/// lifecycle and timeout strategy.
pub(super) struct NetReportActor {
    probes: JoinSet<Option<ProbeResult>>,

    /// Winning QAD connections, reused across probe cycles.
    #[cfg(not(wasm_browser))]
    qad_conns: QadConns,

    relay_map: RelayMap,
    #[cfg(not(wasm_browser))]
    socket_state: SocketState,
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    protocols: BTreeSet<Probe>,
    /// Whether to run captive portal detection on full cycles.
    #[cfg(not(wasm_browser))]
    captive_portal_check: bool,

    /// The report being assembled during the current probe cycle.
    current_report: Report,
    /// Historical reports used for preferred relay selection.
    reports: ReportHistory,
    /// Sink for publishing report updates to consumers.
    report_out: Watchable<Option<Report>>,

    /// When the current probe cycle started, or `None` if idle.
    cycle_start: Option<Instant>,

    /// Deadline at [`REPORT_TIMEOUT`] for emitting a report even when
    /// probes are still running. `None` while idle.
    report_deadline: Option<Instant>,

    /// Deadline at [`ABORT_TIMEOUT`] for aborting remaining probes to cap
    /// network activity per cycle. `None` while idle.
    abort_deadline: Option<Instant>,

    /// Cancelled when every relay has at least one latency sample.
    cancel_https: CancellationToken,
    /// Cancelled when a QAD probe confirms UDP works.
    #[cfg(not(wasm_browser))]
    cancel_captive_portal: CancellationToken,

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
        #[cfg(not(wasm_browser))] captive_portal_check: bool,
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
            #[cfg(not(wasm_browser))]
            captive_portal_check,
            current_report: Report::default(),
            reports: ReportHistory::default(),
            report_out,
            cycle_start: None,
            report_deadline: None,
            abort_deadline: None,
            cancel_https: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            cancel_captive_portal: CancellationToken::new(),
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
            // Recreate the QAD watcher each iteration. Building it is
            // cheap (just cloning Arc handles) and sidesteps tracking
            // whether the QAD connection slots changed since last loop.
            // On wasm, QAD is disabled; use a watcher that never fires.
            #[cfg(not(wasm_browser))]
            let mut qad_watch = self.qad_conns.watch();
            #[cfg(wasm_browser)]
            let mut qad_watch = n0_watcher::Watchable::<()>::default().watch();

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

                // Report deadline: publish any partial data we have so
                // consumers see a report within REPORT_TIMEOUT.
                _ = &mut report_deadline => {
                    debug!("report deadline fired");
                    self.report_deadline = None;
                    // maybe_publish does nothing when current_report is
                    // still empty: an empty report would clobber
                    // previously good addresses downstream.
                    self.maybe_publish();
                }

                // Abort deadline: kill all remaining probes.
                _ = &mut abort_deadline => {
                    debug!("abort deadline fired, aborting all probes");
                    self.abort_deadline = None;
                    self.probes.abort_all();
                }

                Ok(_update) = qad_watch.updated() => {
                    #[cfg(not(wasm_browser))]
                    self.apply_qad_update(_update);
                }
            }
        }
    }

    #[cfg(not(wasm_browser))]
    fn apply_qad_update(&mut self, update: QadUpdate) {
        if let Some(r) = update.v4 {
            trace!(?r, "QAD v4 address update from existing conn");
            self.current_report.update_qad_v4(&r);
            self.maybe_publish();
        }
        if let Some(r) = update.v6 {
            trace!(?r, "QAD v6 address update from existing conn");
            self.current_report.update_qad_v6(&r);
            self.maybe_publish();
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
            // Replace the JoinSet outright so any already-completed but
            // undrained results from the previous cycle are discarded.
            // abort_all() leaves ready results behind, which would leak
            // into the new cycle's current_report.
            self.probes = JoinSet::new();
        }

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

        #[cfg(not(wasm_browser))]
        self.spawn_qad_probes(&if_state);
        self.spawn_https_probes();

        #[cfg(not(wasm_browser))]
        if do_full && self.captive_portal_check {
            self.spawn_captive_portal();
        }
    }

    /// Processes a completed probe task from the [`JoinSet`].
    ///
    /// Updates `current_report`, stores QAD connections, cancels redundant
    /// probes, and triggers report emission.
    fn handle_probe_result(
        &mut self,
        result: Result<Option<ProbeResult>, n0_future::task::JoinError>,
    ) {
        let probe = match result {
            Ok(probe) => probe,
            Err(err) if err.is_panic() => {
                error!("probe task panicked: {err:#}");
                None
            }
            Err(err) if err.is_cancelled() => None,
            Err(err) => {
                warn!("probe task join failed: {err:#}");
                None
            }
        };

        if let Some(result) = probe {
            self.apply_probe_result(result);
        }

        // Cycle complete when all probes finished, regardless of how the last
        // task exited. Without this check on cancelled/panicked tasks, a cycle
        // that ends with cancelled QAD probes (after a winner) would never
        // commit to history.
        if self.probes.is_empty() && self.cycle_start.is_some() {
            self.finalize_cycle();
        }
    }

    /// Applies a single successful probe task's output to the current report.
    fn apply_probe_result(&mut self, result: ProbeResult) {
        match result {
            #[cfg(not(wasm_browser))]
            ProbeResult::Qad(family, Ok((report, conn))) => {
                debug!(?family, ?report, "QAD probe completed");
                match family {
                    AddrFamily::V4 => self.current_report.update_qad_v4(&report),
                    AddrFamily::V6 => self.current_report.update_qad_v6(&report),
                };
                let slot = self.qad_conns.slot_mut(family);
                if slot.is_none() {
                    *slot = Some((report.relay_url, conn));
                    // Cancel remaining probes for this family now that we have a winner.
                    self.qad_conns.cancel(family).cancel();
                } else {
                    conn.conn
                        .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                }
                self.cancel_captive_portal.cancel();
                self.maybe_publish();
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::Qad(family, Err(e)) => {
                debug!(?family, "QAD probe failed: {e:#}");
            }
            ProbeResult::Https(Ok(report)) => {
                debug!(?report, "HTTPS probe completed");
                self.current_report.update_https(&report);
                if self.have_all_relay_latencies() {
                    self.cancel_https.cancel();
                }
                self.maybe_publish();
            }
            ProbeResult::Https(Err(e)) => {
                debug!("HTTPS probe failed: {e:#}");
            }
            #[cfg(not(wasm_browser))]
            ProbeResult::CaptivePortal(result) => {
                debug!(?result, "captive portal check completed");
                self.current_report.captive_portal = result;
                self.maybe_publish();
            }
        }
    }

    /// Publishes the current report if it contains meaningful probe data.
    ///
    /// The underlying [`Watchable`] deduplicates, so calling this with an
    /// unchanged report is a no-op.
    fn maybe_publish(&mut self) {
        let has_data = self.current_report.global_v4.is_some()
            || self.current_report.global_v6.is_some()
            || self.current_report.has_udp()
            || !self.current_report.relay_latency.is_empty();

        if !has_data {
            return;
        }

        self.report_out.set(Some(self.current_report.clone())).ok();
    }

    /// Commits the current cycle to history, selects the preferred relay,
    /// and emits the final report.
    fn finalize_cycle(&mut self) {
        let mut report = std::mem::take(&mut self.current_report);
        self.reports.record(&mut report);
        self.current_report = report;
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

    /// Spawns QAD probes for IPv4 and IPv6 if needed, reusing existing
    /// connections when they are still alive.
    #[cfg(not(wasm_browser))]
    fn spawn_qad_probes(&mut self, if_state: &IfStateDetails) {
        let Some(quic_client) = self.socket_state.quic_client.clone() else {
            return;
        };

        // Drop any existing winner whose connection has closed, and
        // surface the latest observed address from any retained one.
        for family in [AddrFamily::V4, AddrFamily::V6] {
            if let Some((url, conn)) = self.qad_conns.slot(family)
                && let Some(reason) = conn.conn.close_reason()
            {
                trace!(?family, ?url, "QAD conn closed: {reason}");
                self.qad_conns.slot_mut(family).take();
            }
            if let Some(r) = self.qad_conns.current(family) {
                match family {
                    AddrFamily::V4 => self.current_report.update_qad_v4(&r),
                    AddrFamily::V6 => self.current_report.update_qad_v6(&r),
                }
            }
        }

        self.qad_conns.reset_cancels();

        let families = [
            (
                AddrFamily::V4,
                self.qad_conns.v4.is_none() && if_state.have_v4,
            ),
            (
                AddrFamily::V6,
                self.qad_conns.v6.is_none() && if_state.have_v6,
            ),
        ];
        if families.iter().all(|(_, needed)| !*needed) {
            return;
        }

        const MAX_RELAYS: usize = 5;
        for relay in self
            .relay_map
            .relays::<Vec<_>>()
            .into_iter()
            .take(MAX_RELAYS)
        {
            for (family, needed) in families {
                if needed {
                    self.spawn_qad_probe(family, relay.clone(), quic_client.clone());
                }
            }
        }
    }

    #[cfg(not(wasm_browser))]
    fn spawn_qad_probe(
        &mut self,
        family: AddrFamily,
        relay: Arc<iroh_relay::RelayConfig>,
        quic_client: iroh_relay::quic::QuicClient,
    ) {
        use tracing::{Instrument, warn_span};

        let dns_resolver = self.socket_state.dns_resolver.clone();
        let relay_url = relay.url.clone();
        let shutdown = self.shutdown.child_token();
        let cancel = self.qad_conns.cancel(family).child_token();
        let span = warn_span!("QAD", ?family, %relay_url);
        self.probes.spawn(
            cancel
                .run_until_cancelled_owned(async move {
                    let result = time::timeout(
                        QAD_PROBE_TIMEOUT,
                        super::qad::run_probe(family, relay, quic_client, dns_resolver, shutdown),
                    )
                    .await
                    .unwrap_or_else(|_| Err(n0_error::e!(QadProbeError::Timeout)));
                    ProbeResult::Qad(family, result)
                })
                .instrument(span),
        );
    }

    /// Spawns HTTPS latency probes according to the current [`ProbePlan`].
    fn spawn_https_probes(&mut self) {
        self.cancel_https = CancellationToken::new();
        let plan = match self.reports.last {
            Some(ref report) => {
                ProbePlan::with_last_report(&self.relay_map, report, &self.protocols)
            }
            None => ProbePlan::initial(&self.relay_map, &self.protocols),
        };
        trace!(%plan, "HTTPS probe plan");

        for probe_set in plan.iter() {
            for (delay, relay) in probe_set.params() {
                self.spawn_https_probe(*delay, Arc::clone(relay));
            }
        }
    }

    fn spawn_https_probe(&mut self, delay: Duration, relay: Arc<iroh_relay::RelayConfig>) {
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
                    super::https::run_https_probe(
                        #[cfg(not(wasm_browser))]
                        &socket_state.dns_resolver,
                        relay.url.clone(),
                        #[cfg(not(wasm_browser))]
                        tls_config,
                    )
                    .await
                }))
                .await;
            let probe = match result {
                Some(Ok(Ok(r))) => Ok(r),
                Some(Ok(Err(e))) => Err(n0_error::e!(ProbesError::ProbeFailure, e)),
                Some(Err(_)) => Err(n0_error::e!(ProbesError::Timeout)),
                None => Err(n0_error::e!(ProbesError::Cancelled)),
            };
            Some(ProbeResult::Https(probe))
        });
    }

    /// Spawns a captive portal detection check. Delayed by
    /// [`CAPTIVE_PORTAL_DELAY`] to give QAD probes time to succeed first,
    /// and cancelled if QAD confirms UDP connectivity.
    #[cfg(not(wasm_browser))]
    fn spawn_captive_portal(&mut self) {
        self.cancel_captive_portal = CancellationToken::new();
        let cancel = self.cancel_captive_portal.clone();
        let dns = self.socket_state.dns_resolver.clone();
        let relay_map = self.relay_map.clone();
        let tls = self.tls_config.clone();
        let preferred = self
            .reports
            .last
            .as_ref()
            .and_then(|r| r.preferred_relay.clone());

        self.probes.spawn(async move {
            trace!("captive portal check scheduled");
            time::sleep(CAPTIVE_PORTAL_DELAY).await;
            if cancel.is_cancelled() {
                return Some(ProbeResult::CaptivePortal(None));
            }
            let result = time::timeout(
                CAPTIVE_PORTAL_TIMEOUT,
                super::captive_portal::check_captive_portal(&dns, &relay_map, preferred, tls),
            )
            .await;
            Some(match result {
                Ok(Ok(found)) => ProbeResult::CaptivePortal(Some(found)),
                Ok(Err(e)) => {
                    debug!("captive portal check failed: {e:#}");
                    ProbeResult::CaptivePortal(None)
                }
                Err(_) => {
                    debug!("captive portal check timed out");
                    ProbeResult::CaptivePortal(None)
                }
            })
        });
    }
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
            let mut reports = ReportHistory::default();
            for s in &mut tt.steps {
                tokio::time::advance(Duration::from_secs(s.after)).await;
                reports.record(s.r.as_mut().unwrap());
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
