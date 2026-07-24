//! The actor that runs network probes and publishes a [`Report`].
//!
//! [`NetReportActor`] runs in the background for as long as the endpoint is
//! alive. It learns about the network in three ways and writes what it finds
//! into a [`Report`] that callers watch:
//!
//! - QAD (QUIC Address Discovery) opens a QUIC connection to a relay. The
//!   relay reports the public address it sees us coming from, and the round
//!   trip measures our latency to that relay.
//! - An HTTPS probe measures latency to a relay with a plain GET request. It
//!   finds no address, but it still works on networks that block QUIC.
//! - The captive portal check looks for a network that intercepts HTTP.
//!
//! QAD connections are long-lived, and that shapes the rest. For each
//! address family the actor races a probe to several relays, keeps the
//! connection that answers first, and closes the others. It then holds that
//! connection open. The relay only sees our address from the packets we
//! send, so a change is not reported the instant it happens: the
//! connection's keep-alive prompts the relay to re-observe within seconds,
//! and a network change we notice ourselves starts a fresh probe at once.
//! Either way the actor folds the update into the same [`Report`] as probe
//! results, so everything it learns lands in one place.
//!
//! A probe cycle is a round of probing triggered by a request. Because the
//! open QAD connections already keep addresses current, a cycle is mostly
//! about the rest: measuring latency to every relay over HTTPS, picking the
//! preferred relay, and checking for a captive portal. [`ProbeScope`] sets
//! how much of that a cycle does, and [`ProbeCycle`] holds the one in
//! flight. A cycle publishes a first report within [`FIRST_REPORT_TIMEOUT`]
//! even while probes are still running, and gives up on any stragglers after
//! [`ABORT_TIMEOUT`].

use std::{collections::BTreeSet, future::Future, sync::Arc};

#[cfg(not(wasm_browser))]
use iroh_dns::dns::DnsResolver;
use iroh_relay::RelayMap;
#[cfg(not(wasm_browser))]
use iroh_relay::quic::{QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON, QuicClient};
use n0_future::{
    MaybeFuture,
    task::JoinSet,
    time::{self, Duration, Instant},
};
use n0_watcher::Watchable;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, Span, debug, error, info_span, trace};

#[cfg(not(wasm_browser))]
use super::captive_portal::CaptivePortalError;
#[cfg(not(wasm_browser))]
use super::qad::{AddrFamily, QadConn, QadProbeError, QadProbeReport};
use super::{
    IfState, Options, Report,
    defaults::timeouts::{
        ABORT_TIMEOUT, CAPTIVE_PORTAL_DELAY, CAPTIVE_PORTAL_TIMEOUT, FIRST_REPORT_TIMEOUT,
        FULL_REPORT_INTERVAL, HTTPS_PROBE_TIMEOUT,
    },
    https::{HttpsProbeError, HttpsProbeReport},
    metrics::Metrics,
    probes::{Probe, ProbePlan},
    report::RelayLatencies,
};
#[cfg(not(wasm_browser))]
use super::{NetReportConfig, defaults::timeouts::QAD_PROBE_TIMEOUT};

/// The result of running a probe under a timeout and a cancellation token.
///
/// The probe either succeeded, failed with its own error, timed out, or was
/// cancelled. Keeping timeout and cancellation out of the probe's error type
/// lets each error stay a pure domain error.
pub(super) enum ProbeResult<T, E> {
    Ok(T),
    Err(E),
    Timeout,
    Cancelled,
}

/// Requires `Send` on native targets and imposes no bound in the browser.
///
/// Browser tasks run on a single thread and their futures are not `Send`, so
/// this lets a spawn helper stay generic over both.
#[cfg(not(wasm_browser))]
trait MaybeSend: Send {}
#[cfg(not(wasm_browser))]
impl<T: Send + ?Sized> MaybeSend for T {}
#[cfg(wasm_browser)]
trait MaybeSend {}
#[cfg(wasm_browser)]
impl<T: ?Sized> MaybeSend for T {}

/// A timer that fires at `at`, or never completes when `at` is `None`.
///
/// Used to turn the cycle's optional deadlines into `select!` arms.
fn sleep_until_opt(at: Option<Instant>) -> MaybeFuture<impl Future<Output = ()>> {
    match at {
        Some(t) => MaybeFuture::Some(time::sleep_until(t)),
        None => MaybeFuture::None,
    }
}

/// A probe request waiting for the actor to pick it up.
///
/// Several [`Client::run_probes`](super::Client::run_probes) calls can
/// arrive before the actor handles them. They collapse into this one
/// request, which takes the most urgent [`ProbeScope`] of the batch and
/// waits here until the actor takes it.
pub(super) struct ProbeRequest {
    /// Interface state captured when the request was made.
    pub if_state: IfState,
    /// How much of the probe set to run.
    pub scope: ProbeScope,
}

/// A one-slot mailbox carrying a [`ProbeRequest`] to the [`NetReportActor`].
///
/// It holds at most one request. A second request that arrives before the
/// actor has taken the first does not queue behind it; it merges into it,
/// raising the [`ProbeScope`] to the more urgent of the two and keeping the
/// newer interface state. This is why it is a hand-written slot and not a
/// channel: a channel would queue the requests, and probing twice in a row
/// wastes work when one probe with the combined scope would do.
pub(super) struct RequestSlot {
    /// The pending request, if any.
    slot: std::sync::Mutex<Option<ProbeRequest>>,
    /// Notifies the actor that the slot changed.
    notify: tokio::sync::Notify,
}

impl std::fmt::Debug for RequestSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSlot").finish_non_exhaustive()
    }
}

impl RequestSlot {
    pub(super) fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Merges a probe request into the slot.
    ///
    /// If a request is already pending, the scope is escalated to the more
    /// urgent of the two and `if_state` is overwritten with the latest
    /// value. If no request is pending, a new one is created.
    pub(super) fn request(&self, if_state: IfState, scope: ProbeScope) {
        let mut guard = self.slot.lock().expect("not poisoned");
        match guard.as_mut() {
            Some(pending) => {
                pending.scope = pending.scope.max(scope);
                pending.if_state = if_state;
            }
            None => {
                *guard = Some(ProbeRequest { if_state, scope });
            }
        }
        drop(guard);
        self.notify.notify_one();
    }

    /// Takes the pending request, leaving the slot empty.
    fn take(&self) -> Option<ProbeRequest> {
        self.slot.lock().expect("not poisoned").take()
    }
}

/// The final result of a probe a cycle started.
///
/// Returned from the actor's [`JoinSet`]. Each probe a cycle starts yields
/// exactly one of these, and the actor
/// counts them to know when the cycle is done. Streaming address updates from
/// the open QAD connections are separate: they belong to no cycle and arrive
/// through the actor's `qad_observed` watch channel instead.
pub(super) enum ProbeOutput {
    /// A QAD probe finished. On success it carries the connection to keep
    /// open.
    #[cfg(not(wasm_browser))]
    Qad(
        AddrFamily,
        ProbeResult<(QadProbeReport, QadConn), QadProbeError>,
    ),
    /// An HTTPS latency probe finished.
    Https(ProbeResult<HttpsProbeReport, HttpsProbeError>),
    /// The captive portal check finished.
    #[cfg(not(wasm_browser))]
    CaptivePortal(ProbeResult<bool, CaptivePortalError>),
}

/// The latest address observation from each open QAD connection.
///
/// The open connections' observer tasks publish into a [`watch`] channel of
/// this, one slot per family. Because a watch channel keeps only the newest
/// value, the actor always sees each family's most recent report and never a
/// backlog. Concurrent updates from the two families stay correct because the
/// observers merge through [`watch::Sender::send_modify`], which is atomic.
#[cfg(not(wasm_browser))]
#[derive(Debug, Clone, Default)]
pub(super) struct QadObserved {
    /// The latest IPv4 observation, if any.
    v4: Option<QadProbeReport>,
    /// The latest IPv6 observation, if any.
    v6: Option<QadProbeReport>,
}

#[cfg(not(wasm_browser))]
impl QadObserved {
    /// Stores `probe_report` as `family`'s latest observation.
    pub(super) fn set(&mut self, family: AddrFamily, probe_report: QadProbeReport) {
        match family {
            AddrFamily::V4 => self.v4 = Some(probe_report),
            AddrFamily::V6 => self.v6 = Some(probe_report),
        }
    }

    /// The latest observation for `family`, if any.
    fn get(&self, family: AddrFamily) -> Option<&QadProbeReport> {
        match family {
            AddrFamily::V4 => self.v4.as_ref(),
            AddrFamily::V6 => self.v6.as_ref(),
        }
    }
}

/// How much of the probe set a cycle runs.
///
/// The scope plays two roles. On the request that starts a cycle it says how
/// urgent the trigger is: a `Full` request comes from a real network change,
/// so it aborts any cycle in progress and starts over, while a `Refresh`
/// request waits for the current cycle to finish. On the cycle itself it
/// says how much to probe.
///
/// The open QAD connections keep our address up to date on their own, within
/// their keep-alive interval (see the [module docs](self)), so neither scope
/// has to probe QAD just to stay current. The difference is what else a cycle
/// does:
///
/// - `Full` throws away the open QAD connections and starts from nothing. It
///   opens a fresh QAD connection for every available family, measures
///   latency to every relay over HTTPS, and runs the captive portal check.
///   This is what a real network change calls for.
/// - `Refresh` keeps the open QAD connections and only does the work they do
///   not cover. It re-picks the preferred relay from the current QAD
///   latencies, and it opens a QAD connection only for a family that has none,
///   because its connection dropped or its interface just came up. It does not
///   re-measure HTTPS latency (that happens only on `Full`) and it skips the
///   captive portal check.
///
/// A `Refresh` request can still turn into a `Full` cycle: the actor forces
/// one when the full-report interval has elapsed, or when the last report
/// found a captive portal and no working UDP.
///
/// The variants order `Refresh < Full` so that merging two pending requests
/// can just take the more urgent one with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProbeScope {
    /// Keep the open QAD connections. Re-pick the preferred relay and
    /// reconnect any family that has no open connection.
    Refresh,
    /// Close the open QAD connections and run every probe from scratch.
    Full,
}

impl ProbeScope {
    /// Maps a netmon "is major change" flag to a [`ProbeScope`].
    pub(crate) fn from_major(is_major: bool) -> Self {
        if is_major { Self::Full } else { Self::Refresh }
    }
}

/// Per-family QAD progress within a cycle.
#[derive(Debug, Clone, Copy, Default)]
struct QadFamily {
    /// This cycle is probing the family.
    probing: bool,
    /// The family is determined: it has an address, or all of its probes have
    /// finished (so the family is genuinely down).
    determined: bool,
    /// QAD probes still outstanding for the family.
    #[cfg(not(wasm_browser))]
    outstanding: usize,
}

impl QadFamily {
    /// Creates the per-family state for `probes` started QAD probes.
    fn new(probes: usize) -> Self {
        QadFamily {
            probing: probes > 0,
            determined: false,
            #[cfg(not(wasm_browser))]
            outstanding: probes,
        }
    }
}

/// QAD progress for both address families within a cycle.
#[derive(Debug, Clone, Copy, Default)]
struct QadState {
    v4: QadFamily,
    v6: QadFamily,
}

impl QadState {
    /// Builds the cycle's QAD gate state from the per-family probe counts.
    fn new(v4_probes: usize, v6_probes: usize) -> Self {
        QadState {
            v4: QadFamily::new(v4_probes),
            v6: QadFamily::new(v6_probes),
        }
    }

    /// Returns `true` once every family this cycle is probing is determined.
    ///
    /// The first report is held until this holds (or [`FIRST_REPORT_TIMEOUT`]
    /// fires), so consumers do not see a v4-only report a moment before v6.
    fn all_determined(&self) -> bool {
        (!self.v4.probing || self.v4.determined) && (!self.v6.probing || self.v6.determined)
    }

    /// Records that one of `family`'s probes finished with `result`.
    ///
    /// The family becomes determined on its first success or once all of its
    /// probes are done, so a fast failure does not gate a premature
    /// family-negative first report.
    #[cfg(not(wasm_browser))]
    fn record_result<T, E>(&mut self, family: AddrFamily, result: &ProbeResult<T, E>) {
        let fam = self.family_mut(family);
        fam.outstanding = fam.outstanding.saturating_sub(1);
        if matches!(result, ProbeResult::Ok(_)) || fam.outstanding == 0 {
            fam.determined = true;
        }
    }

    #[cfg(not(wasm_browser))]
    fn family_mut(&mut self, family: AddrFamily) -> &mut QadFamily {
        match family {
            AddrFamily::V4 => &mut self.v4,
            AddrFamily::V6 => &mut self.v6,
        }
    }
}

/// Tracks recent reports for preferred-relay selection and cadence.
#[derive(Debug)]
struct ReportHistory {
    /// When true, the next cycle is forced to be `Full` rather than `Refresh`.
    next_full: bool,
    /// Reports from the last five minutes, keyed by completion time.
    prev: std::collections::BTreeMap<Instant, Report>,
    /// The most recent completed report.
    last: Option<Report>,
    /// Time of the last `Full` report.
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
    /// Records `r` and sets its preferred relay from recent history.
    ///
    /// The preferred relay is the best candidate across the last five minutes
    /// of reports, chosen with hysteresis: it only changes when the new
    /// candidate is at least 33% faster than the current one.
    fn record(&mut self, r: &mut Report) {
        if let Some(last) = &self.last {
            // Carry forward a mapping-varies verdict this cycle did not reach.
            r.mapping_varies_by_dest_ipv4 = r
                .mapping_varies_by_dest_ipv4
                .or(last.mapping_varies_by_dest_ipv4);
            r.mapping_varies_by_dest_ipv6 = r
                .mapping_varies_by_dest_ipv6
                .or(last.mapping_varies_by_dest_ipv6);
        }
        let prev_relay = self.last.as_ref().and_then(|l| l.preferred_relay.clone());

        let now = Instant::now();
        const MAX_AGE: Duration = Duration::from_secs(5 * 60);

        // Best latency per relay over the last five minutes, dropping stale
        // reports as we go.
        let mut best_recent = RelayLatencies::default();
        self.prev.retain(|t, pr| {
            let fresh = now.duration_since(*t) <= MAX_AGE;
            if fresh {
                best_recent.merge(&pr.relay_latency);
            }
            fresh
        });
        best_recent.merge(&r.relay_latency);

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

    /// Decides the scope of the next cycle.
    ///
    /// A `Full` request always yields a `Full` cycle. A `Refresh` request is
    /// promoted to `Full` on the first cycle, once the full-report interval has
    /// elapsed, or when the last report saw a captive portal without UDP.
    fn scope_for(&self, request: ProbeScope, now: Instant) -> ProbeScope {
        let full = request == ProbeScope::Full
            || self.next_full
            || now.duration_since(self.last_full) > FULL_REPORT_INTERVAL
            || self
                .last
                .as_ref()
                .is_some_and(|r| !r.has_udp() && r.captive_portal == Some(true));
        ProbeScope::from_major(full)
    }
}

/// State of the currently running probe cycle.
struct ProbeCycle {
    /// When the cycle started, for logging its duration.
    started: Instant,
    /// Per-family QAD progress, used to gate the first report.
    qad: QadState,
    /// Whether the first report of this cycle has been published yet.
    published: bool,
    /// A `Refresh` request that arrived mid-cycle, run when this one ends.
    rerun: Option<ProbeRequest>,
    /// Fires at [`FIRST_REPORT_TIMEOUT`]; `None` once fired.
    report_deadline: Option<Instant>,
    /// Fires at [`ABORT_TIMEOUT`]; `None` once fired.
    abort_deadline: Option<Instant>,
}

/// Owns all probe state and emits report updates as results arrive.
///
/// Updates are written to `report_out`. See the [module
/// documentation](self) for an overview.
pub(super) struct NetReportActor {
    /// Inbox for probe triggers from the [`Client`](super::Client).
    probe_requests: Arc<RequestSlot>,
    /// Cancelled to stop the actor and abort every task it owns.
    shutdown: CancellationToken,
    /// Shared metrics counters.
    metrics: Arc<Metrics>,

    /// The relays to probe.
    relay_map: RelayMap,
    /// QUIC client for QAD probes, or `None` when QAD is disabled.
    ///
    /// Cloned into each QAD probe task.
    #[cfg(not(wasm_browser))]
    quic_client: Option<QuicClient>,
    /// DNS resolver, cloned into each probe task that resolves relay hosts.
    #[cfg(not(wasm_browser))]
    dns_resolver: DnsResolver,
    /// TLS config, cloned into each HTTPS and captive-portal task.
    #[cfg(not(wasm_browser))]
    tls_config: rustls::ClientConfig,
    /// The probe protocols enabled for this run.
    protocols: BTreeSet<Probe>,
    /// User-facing configuration for the optional checks.
    ///
    /// Covers captive portal detection and the QAD probe stagger delay;
    /// `https_probes` is already resolved into `protocols`.
    #[cfg(not(wasm_browser))]
    user_config: NetReportConfig,

    /// Owns every one-shot probe task.
    ///
    /// Each task returns its result as a [`ProbeOutput`], collected through
    /// `join_next`; the number of outstanding tasks is how the actor knows a
    /// cycle is done. Dropping the set on shutdown or a restart aborts every
    /// task.
    tasks: JoinSet<ProbeOutput>,
    /// The latest address observation per family from open QAD connections.
    ///
    /// Carried over a [`watch`] channel, so only the newest report per family
    /// is kept. Probe results do not use this channel; they come back through
    /// `join_next`. The actor keeps the sender so the receiver's `changed()`
    /// never errors when no observer is running.
    #[cfg(not(wasm_browser))]
    qad_observed_tx: watch::Sender<QadObserved>,
    /// Receiver for [`Self::qad_observed_tx`].
    #[cfg(not(wasm_browser))]
    qad_observed_rx: watch::Receiver<QadObserved>,
    // In the browser QAD does not run. Hold an empty sender so the receiver's
    // `changed()` in `run` stays pending forever instead of firing.
    #[cfg(wasm_browser)]
    _qad_observed_tx: watch::Sender<()>,
    #[cfg(wasm_browser)]
    qad_observed_rx: watch::Receiver<()>,
    /// The open QAD connection kept for each family, reused across cycles.
    ///
    /// Each one owns its observer task through an `AbortOnDropHandle`, so
    /// dropping or replacing a connection stops that task.
    #[cfg(not(wasm_browser))]
    qad_conns: super::qad::QadConns,
    /// Cancelled when every relay has at least one latency sample.
    cancel_https: CancellationToken,
    /// Cancelled when a QAD probe confirms UDP works.
    #[cfg(not(wasm_browser))]
    cancel_captive_portal: CancellationToken,

    /// The report currently being built.
    ///
    /// Cleared at the start of each cycle and refilled from the open QAD
    /// connections; between cycles, address observations update it in place.
    current: Report,
    /// Recent completed reports, used for preferred-relay selection and to
    /// decide when a cycle must be `Full`.
    history: ReportHistory,
    /// The published report that callers watch.
    report_out: Watchable<Option<Report>>,
    /// The in-flight cycle, or `None` when idle.
    cycle: Option<ProbeCycle>,
}

impl NetReportActor {
    /// Creates the actor from its dependencies and [`Options`].
    pub(super) fn new(
        probe_requests: Arc<RequestSlot>,
        report_out: Watchable<Option<Report>>,
        relay_map: RelayMap,
        opts: Options,
        #[cfg(not(wasm_browser))] dns_resolver: DnsResolver,
        shutdown: CancellationToken,
        metrics: Arc<Metrics>,
    ) -> Self {
        let protocols = opts.as_protocols();
        #[cfg(not(wasm_browser))]
        let (qad_observed_tx, qad_observed_rx) = watch::channel(QadObserved::default());
        #[cfg(wasm_browser)]
        let (_qad_observed_tx, qad_observed_rx) = watch::channel(());

        #[cfg(not(wasm_browser))]
        let quic_client = opts
            .quic_config
            .map(|c| QuicClient::new(c.ep, c.client_config));

        Self {
            probe_requests,
            shutdown,
            metrics,
            relay_map,
            #[cfg(not(wasm_browser))]
            quic_client,
            #[cfg(not(wasm_browser))]
            dns_resolver,
            #[cfg(not(wasm_browser))]
            tls_config: opts.tls_config,
            protocols,
            #[cfg(not(wasm_browser))]
            user_config: opts.user_config,
            tasks: JoinSet::new(),
            #[cfg(not(wasm_browser))]
            qad_observed_tx,
            #[cfg(wasm_browser)]
            _qad_observed_tx,
            qad_observed_rx,
            #[cfg(not(wasm_browser))]
            qad_conns: super::qad::QadConns::default(),
            cancel_https: CancellationToken::new(),
            #[cfg(not(wasm_browser))]
            cancel_captive_portal: CancellationToken::new(),
            current: Report::default(),
            history: ReportHistory::default(),
            report_out,
            cycle: None,
        }
    }

    /// Runs the actor until the shutdown token is cancelled.
    ///
    /// On shutdown, dropping `self` drops the [`JoinSet`] and the QAD
    /// connections, aborting every task the actor owns.
    pub(super) async fn run(mut self) {
        loop {
            let report_deadline =
                sleep_until_opt(self.cycle.as_ref().and_then(|c| c.report_deadline));
            let abort_deadline =
                sleep_until_opt(self.cycle.as_ref().and_then(|c| c.abort_deadline));
            n0_future::pin!(report_deadline);
            n0_future::pin!(abort_deadline);

            tokio::select! {
                biased;

                _ = self.shutdown.cancelled() => break,

                _ = self.probe_requests.notify.notified() => {
                    if let Some(req) = self.probe_requests.take() {
                        self.handle_request(req);
                    }
                }

                // A new QAD address observation. In the browser the sender is
                // never modified, so `changed()` stays pending and this branch
                // never fires.
                Ok(()) = self.qad_observed_rx.changed() => {
                    #[cfg(not(wasm_browser))]
                    self.handle_qad_observations();
                }

                Some(joined) = self.tasks.join_next() => {
                    match joined {
                        Ok(output) => self.handle_output(output),
                        // A panicked task yields no result; taking it from the
                        // set already dropped it from the outstanding count,
                        // which is all the cycle needs. (Aborted tasks live in
                        // a dropped JoinSet and are never yielded here.)
                        Err(err) if err.is_panic() => error!("probe task panicked: {err:#}"),
                        Err(_) => {}
                    }
                    self.advance();
                }

                _ = &mut report_deadline => self.on_report_deadline(),
                _ = &mut abort_deadline => self.on_abort_deadline(),
            }
        }
    }

    /// Handles a probe request: defer it, restart the cycle, or start one.
    fn handle_request(&mut self, req: ProbeRequest) {
        if self.relay_map.is_empty() {
            debug!("skipping net_report, empty RelayMap");
            return;
        }

        if let Some(cycle) = &mut self.cycle {
            match req.scope {
                ProbeScope::Refresh => {
                    // Defer: run right after the current cycle finishes so
                    // the trigger is not lost (the old DirectAddrUpdateState
                    // remembered this via `want_update`). Only `Refresh`
                    // requests are deferred, so the remembered scope stays
                    // `Refresh`; just take the latest interface state.
                    match &mut cycle.rerun {
                        Some(pending) => pending.if_state = req.if_state,
                        None => cycle.rerun = Some(req),
                    }
                    debug!("deferring probe request until current cycle finishes");
                    return;
                }
                // Full: abort the current cycle and start fresh.
                ProbeScope::Full => self.abort_cycle(),
            }
        }

        self.start_cycle(req);
    }

    /// Aborts the current cycle and clears its transient state.
    ///
    /// Dropping the `JoinSet` discards the probe tasks' results, and a fresh
    /// observation channel drops the last observation, so nothing leaks into
    /// the next cycle. Only a `Full` restart does this, and a `Full` restart
    /// also closes the open QAD connections, so no observer task is left
    /// running without an owner.
    fn abort_cycle(&mut self) {
        self.tasks = JoinSet::new();
        #[cfg(not(wasm_browser))]
        {
            let (tx, rx) = watch::channel(QadObserved::default());
            self.qad_observed_tx = tx;
            self.qad_observed_rx = rx;
        }
        self.cycle = None;
    }

    /// Starts a new probe cycle.
    fn start_cycle(&mut self, req: ProbeRequest) {
        let ProbeRequest {
            if_state,
            scope: request_scope,
        } = req;
        let now = Instant::now();
        let scope = self.history.scope_for(request_scope, now);

        debug!(?request_scope, ?scope, "starting probe cycle");

        if scope == ProbeScope::Full {
            #[cfg(not(wasm_browser))]
            self.qad_conns.clear();
            self.history.last = None;
            self.history.next_full = false;
            self.history.last_full = now;
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        // Start the report from scratch. spawn_qad_probes copies the last
        // address from each still-open QAD connection back in.
        self.current = Report::default();
        self.cancel_https = CancellationToken::new();

        #[cfg(not(wasm_browser))]
        let (qad_v4, qad_v6) = self.spawn_qad_probes(&if_state);
        #[cfg(wasm_browser)]
        let (qad_v4, qad_v6) = (0usize, 0usize);
        let qad = QadState::new(qad_v4, qad_v6);
        self.spawn_https_probes();
        #[cfg(not(wasm_browser))]
        if scope == ProbeScope::Full && self.user_config.captive_portal_check {
            self.spawn_captive_portal();
        }

        self.cycle = Some(ProbeCycle {
            started: now,
            qad,
            published: false,
            rerun: None,
            report_deadline: Some(now + FIRST_REPORT_TIMEOUT),
            abort_deadline: Some(now + ABORT_TIMEOUT),
        });

        // A cycle can start with no probes at all: every family already has
        // an open connection and HTTPS is off. It is already complete, so
        // finalize now to still update history and the preferred relay.
        self.advance();
    }

    /// Applies one [`ProbeOutput`] to the report and drives the cycle forward.
    fn handle_output(&mut self, output: ProbeOutput) {
        match output {
            #[cfg(not(wasm_browser))]
            ProbeOutput::Qad(family, result) => {
                if let Some(c) = &mut self.cycle {
                    c.qad.record_result(family, &result);
                }
                match result {
                    ProbeResult::Ok((probe_report, conn)) => {
                        debug!(?family, ?probe_report, "QAD probe completed");
                        // Accumulate: the first result sets the global
                        // address; a second result from a different relay
                        // decides mapping-varies-by-destination.
                        self.current.apply_qad_result(family, &probe_report);
                        if self.qad_conns.slot(family).is_none() {
                            // First result for this family: keep this
                            // connection open, but let the other probes run
                            // so a second result can decide mapping-varies.
                            *self.qad_conns.slot_mut(family) = Some(conn);
                        } else {
                            // Second result: mapping-varies is decided, so
                            // stop the family's remaining probes and drop
                            // this connection.
                            conn.conn
                                .close(QUIC_ADDR_DISC_CLOSE_CODE, QUIC_ADDR_DISC_CLOSE_REASON);
                            self.qad_conns.cancel(family).cancel();
                        }
                        // UDP works, so skip captive portal detection.
                        self.cancel_captive_portal.cancel();
                    }
                    ProbeResult::Err(e) => debug!(?family, "QAD probe failed: {e:#}"),
                    ProbeResult::Timeout => debug!(?family, "QAD probe timed out"),
                    ProbeResult::Cancelled => {}
                }
                self.publish();
            }
            ProbeOutput::Https(result) => {
                match result {
                    ProbeResult::Ok(probe_report) => {
                        debug!(?probe_report, "HTTPS probe completed");
                        self.current.apply_https_result(&probe_report);
                        if self.have_all_relay_latencies() {
                            self.cancel_https.cancel();
                        }
                    }
                    ProbeResult::Err(e) => debug!("HTTPS probe failed: {e:#}"),
                    ProbeResult::Timeout => debug!("HTTPS probe timed out"),
                    ProbeResult::Cancelled => {}
                }
                self.publish();
            }
            #[cfg(not(wasm_browser))]
            ProbeOutput::CaptivePortal(result) => {
                match result {
                    ProbeResult::Ok(found) => {
                        debug!(found, "captive portal check completed");
                        self.current.captive_portal = Some(found);
                    }
                    ProbeResult::Err(e) => debug!("captive portal check failed: {e:#}"),
                    ProbeResult::Timeout => debug!("captive portal check timed out"),
                    // Cancelled is expected: a successful QAD cancels this check.
                    ProbeResult::Cancelled => {}
                }
                self.publish();
            }
        }
    }

    /// Applies the latest address observation for each family.
    ///
    /// Called after the `qad_observed` watch channel signals a change. A
    /// single change can carry a new report for either or both families;
    /// re-applying an unchanged one is a cheap no-op, so both slots are
    /// applied unconditionally.
    #[cfg(not(wasm_browser))]
    fn handle_qad_observations(&mut self) {
        let observed = self.qad_observed_rx.borrow_and_update().clone();
        for family in [AddrFamily::V4, AddrFamily::V6] {
            if let Some(obs) = observed.get(family) {
                self.handle_qad_observation(family, obs.clone());
            }
        }
    }

    /// Applies one family's latest address observation.
    ///
    /// Runs outside any cycle, for as long as the connection stays open.
    #[cfg(not(wasm_browser))]
    fn handle_qad_observation(&mut self, family: AddrFamily, obs: QadProbeReport) {
        // Take observations only from the connection we kept for this family.
        // A probe we dropped may still send one last observation before its
        // task ends; ignore it.
        let is_current = self
            .qad_conns
            .slot(family)
            .is_some_and(|c| *c.relay_url() == obs.relay_url);
        if is_current {
            trace!(?family, ?obs, "QAD address observation");
            if let Some(conn) = self.qad_conns.slot_mut(family) {
                conn.probe_report = obs.clone();
            }
            self.current.apply_qad_observation(family, &obs);
            self.publish();
        }
    }

    /// Publishes the current report, unless a guard holds it back.
    ///
    /// Two guards apply. An empty report is never published, since it would
    /// overwrite addresses a caller has already seen. And the first report of
    /// a cycle waits until every family the cycle probed has a result, so a
    /// caller does not briefly see an IPv4-only report just before the IPv6
    /// address arrives.
    fn publish(&mut self) {
        if !self.current.has_data() {
            return;
        }
        if let Some(c) = &self.cycle
            && !c.published
            && !c.qad.all_determined()
        {
            return;
        }
        if let Some(c) = &mut self.cycle {
            c.published = true;
        }
        self.report_out.set(Some(self.current.clone())).ok();
    }

    /// Finalizes the cycle once no probe tasks remain outstanding.
    fn advance(&mut self) {
        if self.cycle.is_some() && self.tasks.is_empty() {
            self.finish_cycle();
        }
    }

    /// Finalizes the cycle and runs any request deferred during it.
    ///
    /// Commits the report to history, selects the preferred relay, emits the
    /// final report, then applies a `Refresh` request that arrived mid-cycle.
    fn finish_cycle(&mut self) {
        let Some(cycle) = self.cycle.take() else {
            return;
        };
        self.history.record(&mut self.current);
        // Emit the final report, now stamped with the preferred relay. This
        // often repeats the last incremental value; `Watchable::set` only
        // notifies watchers on change, so an identical final emit is a no-op.
        // Keep the last good report rather than overwriting it with an empty
        // one when a cycle discovered nothing.
        if self.current.has_data() {
            self.report_out.set(Some(self.current.clone())).ok();
        }
        debug!(
            report = ?self.current,
            duration = ?cycle.started.elapsed(),
            "net_report cycle complete",
        );
        if let Some(rerun) = cycle.rerun {
            self.handle_request(rerun);
        }
    }

    /// Publishes the current report when the first-report deadline fires.
    ///
    /// Emits what we have now, even if some probed families have not answered
    /// yet.
    fn on_report_deadline(&mut self) {
        debug!("report deadline fired");
        if let Some(c) = &mut self.cycle {
            c.report_deadline = None;
            c.published = true;
        }
        self.publish();
    }

    /// Finalizes the cycle when the abort deadline fires.
    ///
    /// Stops any remaining probes and finalizes with whatever we have.
    fn on_abort_deadline(&mut self) {
        debug!("abort deadline fired, finalizing cycle");
        // Dropping the tasks aborts the remaining probes; their results are
        // discarded rather than collected.
        self.tasks = JoinSet::new();
        self.finish_cycle();
    }

    /// Returns `true` when every relay has at least one latency sample.
    ///
    /// Used to cancel remaining HTTPS probes once coverage is complete.
    fn have_all_relay_latencies(&self) -> bool {
        let seen: BTreeSet<_> = self
            .current
            .relay_latency
            .iter()
            .map(|(_, url, _)| url)
            .collect();
        seen.len() >= self.relay_map.len()
    }

    /// Starts a QAD probe for each family that needs one.
    ///
    /// Returns how many probes it started per family, as `(v4, v6)`. A family
    /// needs a probe only when it has no open connection.
    #[cfg(not(wasm_browser))]
    fn spawn_qad_probes(&mut self, if_state: &IfState) -> (usize, usize) {
        let Some(quic_client) = self.quic_client.clone() else {
            return (0, 0);
        };

        // Drops any QAD connection that has closed, then copies the last address
        // of each still-open connection into the working report.
        for family in [AddrFamily::V4, AddrFamily::V6] {
            if let Some(conn) = self.qad_conns.slot(family)
                && let Some(reason) = conn.conn.close_reason()
            {
                trace!(?family, url = ?conn.relay_url(), "QAD conn closed: {reason}");
                self.qad_conns.slot_mut(family).take();
            }
            if let Some(probe_report) = self.qad_conns.current(family) {
                self.current.apply_qad_observation(family, &probe_report);
            }
        }
        self.qad_conns.reset_cancels();

        let need_v4 = self.qad_conns.slot(AddrFamily::V4).is_none() && if_state.have_v4;
        let need_v6 = self.qad_conns.slot(AddrFamily::V6).is_none() && if_state.have_v6;

        const MAX_RELAYS: usize = 5;
        let relays: Vec<_> = self
            .relay_map
            .relays::<Vec<_>>()
            .into_iter()
            .take(MAX_RELAYS)
            .collect();
        let stagger = self.user_config.qad_stagger;

        // One probe per (relay, needed family). Stagger successive probes by an
        // increasing delay so they do not all fire at once.
        let mut spawned_v4 = 0u32;
        let mut spawned_v6 = 0u32;
        for relay in &relays {
            if need_v4 {
                let delay = stagger * (spawned_v4 + spawned_v6);
                self.spawn_qad_probe(AddrFamily::V4, relay.clone(), quic_client.clone(), delay);
                spawned_v4 += 1;
            }
            if need_v6 {
                let delay = stagger * (spawned_v4 + spawned_v6);
                self.spawn_qad_probe(AddrFamily::V6, relay.clone(), quic_client.clone(), delay);
                spawned_v6 += 1;
            }
        }

        (spawned_v4 as usize, spawned_v6 as usize)
    }

    /// Spawns a single QAD probe for `family` against `relay`, after `delay`.
    #[cfg(not(wasm_browser))]
    fn spawn_qad_probe(
        &mut self,
        family: AddrFamily,
        relay: Arc<iroh_relay::RelayConfig>,
        quic_client: iroh_relay::quic::QuicClient,
        delay: Duration,
    ) {
        self.spawn_probe_task(
            info_span!("QAD", ?family, relay_url=%relay.url),
            self.qad_conns.cancel(family).child_token(),
            delay,
            QAD_PROBE_TIMEOUT,
            super::qad::run_probe(
                family,
                relay,
                quic_client,
                self.dns_resolver.clone(),
                self.shutdown.child_token(),
                self.qad_observed_tx.clone(),
            ),
            move |result| ProbeOutput::Qad(family, result),
        );
    }

    /// Spawns HTTPS latency probes according to the current [`ProbePlan`].
    fn spawn_https_probes(&mut self) {
        let plan = match self.history.last {
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

    /// Spawns a single HTTPS latency probe to `relay`, after `delay`.
    fn spawn_https_probe(&mut self, delay: Duration, relay: Arc<iroh_relay::RelayConfig>) {
        self.spawn_probe_task(
            info_span!("HTTPS", relay_url=%relay.url),
            self.cancel_https.child_token(),
            delay,
            HTTPS_PROBE_TIMEOUT,
            super::https::run_probe(
                #[cfg(not(wasm_browser))]
                self.dns_resolver.clone(),
                relay.url.clone(),
                #[cfg(not(wasm_browser))]
                self.tls_config.clone(),
            ),
            ProbeOutput::Https,
        );
    }

    /// Spawns the captive portal detection check.
    ///
    /// Delayed by [`CAPTIVE_PORTAL_DELAY`] to give QAD probes time to succeed
    /// first, and cancelled if QAD confirms UDP connectivity.
    #[cfg(not(wasm_browser))]
    fn spawn_captive_portal(&mut self) {
        self.cancel_captive_portal = CancellationToken::new();
        let preferred = self
            .history
            .last
            .as_ref()
            .and_then(|r| r.preferred_relay.clone());
        self.spawn_probe_task(
            info_span!("captive-portal"),
            self.cancel_captive_portal.child_token(),
            CAPTIVE_PORTAL_DELAY,
            CAPTIVE_PORTAL_TIMEOUT,
            super::captive_portal::check(
                self.dns_resolver.clone(),
                self.relay_map.clone(),
                preferred,
                self.tls_config.clone(),
            ),
            ProbeOutput::CaptivePortal,
        );
    }

    /// Spawns a probe task into the actor's [`JoinSet`].
    ///
    /// The task waits out `delay`, runs `work` with a `timeout`, and can be
    /// aborted at any point through `cancel`. However the probe ends, its
    /// result becomes a [`ProbeResult`]; `to_output` maps it into the
    /// [`ProbeOutput`] the task returns, which the actor collects via
    /// `join_next`. The delay sits outside the timeout, so a staggered probe
    /// still gets its full timeout once it starts.
    fn spawn_probe_task<T: MaybeSend, E: MaybeSend>(
        &mut self,
        span: Span,
        cancel: CancellationToken,
        delay: Duration,
        timeout: Duration,
        work: impl 'static + MaybeSend + Future<Output = Result<T, E>>,
        to_output: impl 'static + MaybeSend + FnOnce(ProbeResult<T, E>) -> ProbeOutput,
    ) {
        self.tasks.spawn(
            async move {
                let result = cancel
                    .run_until_cancelled(async move {
                        if !delay.is_zero() {
                            time::sleep(delay).await;
                        }
                        time::timeout(timeout, work).await
                    })
                    .await;
                let result = match result {
                    Some(Ok(Ok(value))) => ProbeResult::Ok(value),
                    Some(Ok(Err(err))) => ProbeResult::Err(err),
                    Some(Err(_elapsed)) => ProbeResult::Timeout,
                    None => ProbeResult::Cancelled,
                };
                to_output(result)
            }
            .instrument(span),
        );
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::time::Duration;

    use iroh_base::RelayUrl;
    use n0_error::Result;

    use super::*;
    use crate::net_report::probes::Probe;

    #[test]
    fn test_qad_gate() {
        // Nothing being probed: the gate never blocks.
        assert!(QadState::default().all_determined());

        // A probed family blocks until it is determined.
        let mut qad = QadState::default();
        qad.v4.probing = true;
        assert!(!qad.all_determined());
        qad.v4.determined = true;
        assert!(qad.all_determined());

        // Both probed: both must be determined.
        let mut qad = QadState::default();
        qad.v4.probing = true;
        qad.v6.probing = true;
        qad.v4.determined = true;
        assert!(!qad.all_determined());
        qad.v6.determined = true;
        assert!(qad.all_determined());

        // A family that is not being probed does not block, even if another
        // probed family has determined.
        let mut qad = QadState::default();
        qad.v6.probing = true;
        qad.v4.determined = true;
        assert!(!qad.all_determined());
        qad.v6.determined = true;
        assert!(qad.all_determined());
    }

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
