//! The actor that probes the relays and publishes the [`Outputs`].
//!
//! [`NetReportActor`] runs in the background for as long as the endpoint is
//! alive. It learns about the network in three ways:
//!
//! - QAD (QUIC Address Discovery) opens a QUIC connection to a relay. The
//!   relay reports the public address it sees us coming from, and the round
//!   trip measures our latency to that relay.
//! - An HTTPS probe measures latency to a relay with a plain GET request. It
//!   finds no address, but it still works on networks that block QUIC.
//! - The captive portal check looks for a network that intercepts HTTP.
//!
//! The actor is a single loop that waits for these events:
//!
//! - The network interfaces changed.
//! - The relay map changed.
//! - The relay transport's connection to the home relay changed.
//! - A probe finished.
//! - A kept QAD connection reported an address or closed.
//! - A timer fired.
//!
//! Probes are futures the loop polls itself, and kept QAD connections are
//! streams it polls itself, so the actor spawns no tasks and owns everything
//! it runs. Dropping a probe or a connection stops it.
//!
//! QAD connections are long-lived, and that shapes the rest. For each address
//! family the actor races a probe to several relays and keeps the connection
//! that answers first. A second answer decides whether our address varies by
//! destination, and then the actor stops the others. The kept connection
//! stays open, and the relay reports a change of our address on it within a
//! keep-alive interval. When a kept connection closes, the actor runs a
//! refresh to replace it.
//!
//! A probe cycle is a round of probing. A [`ProbeScope::Full`] cycle starts
//! from nothing: a major network change and a change of the relay map run
//! one, and so does the periodic full cycle. Everything else runs a
//! [`ProbeScope::Refresh`] that keeps what still works. The actor publishes a
//! public address as soon as a relay reports it. It decides the home relay
//! twice per cycle: early, once two relays have answered and the current home
//! relay with them, or at [`Timing::first_report_timeout`] when they are slow,
//! and again when the cycle ends. Only completed failures can disqualify an
//! existing home relay; a connected relay transport vouches for it.
//!
//! [`Timing::first_report_timeout`]: super::timing::Timing::first_report_timeout

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    net::SocketAddr,
    panic::AssertUnwindSafe,
    sync::Arc,
    task::Poll,
};

use iroh_base::RelayUrl;
use iroh_relay::{RelayConfig, RelayMap};
use n0_future::{
    FutureExt, FuturesUnordered, StreamExt,
    boxed::BoxFuture,
    future,
    time::{self, Duration, Instant},
};
use n0_watcher::Watcher;
use rand::RngExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info_span, trace};

#[cfg(any(test, feature = "unstable-net-report"))]
use super::Report;
use super::{
    Message, Metrics, Options, Outputs, RelayStatus,
    https::{self, HttpsProbeReport},
    interfaces::Interfaces,
    outputs::{PublicAddr, PublicAddrs},
    qad::{AddrFamily, PerFamily, QadConn, QadConnEvent, QadProbeReport},
    report::{Probe, RelayLatencies},
};
#[cfg(not(wasm_browser))]
use super::{captive_portal, qad, timing::CAPTIVE_PORTAL_TIMEOUT};

/// The maximum number of relays a cycle probes with QAD per family.
const MAX_QAD_RELAYS: usize = 5;

/// The minimum age of a kept QAD connection whose close starts a refresh.
///
/// A younger connection that closes leaves its family to the next cycle.
pub(super) const MIN_QAD_CONN_AGE: Duration = Duration::from_secs(5);

/// The share of the refresh interval added at random to each refresh.
const REFRESH_JITTER: f64 = 0.3;

/// How much of the probe set a cycle runs.
///
/// The variants order `Refresh < Full` so that merging two pending triggers
/// can just take the more urgent one with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeScope {
    /// Keeps the open QAD connections and probes only the missing families.
    ///
    /// It also re-picks the home relay. It measures HTTPS latency when the
    /// last cycle found nothing or the home relay transport is disconnected,
    /// and it skips the captive portal check.
    Refresh,
    /// Closes the open QAD connections and runs every probe from scratch.
    ///
    /// This is what a real network change calls for. Once the debounce has
    /// passed, a `Full` trigger aborts a running cycle.
    Full,
}

/// What a probe established, preserving the difference between failure and cancellation.
#[derive(Debug)]
enum ProbeResult<T> {
    Success(T),
    Failed,
    Inconclusive,
}

/// The final result of one probe of a cycle.
enum ProbeOutput {
    /// A QAD probe finished, with the connection to keep on success.
    Qad(AddrFamily, RelayUrl, ProbeResult<(QadProbeReport, QadConn)>),
    /// An HTTPS latency probe finished.
    Https(RelayUrl, ProbeResult<HttpsProbeReport>),
    /// The captive portal check finished.
    CaptivePortal(ProbeResult<bool>),
}

/// Returns the next update from a kept QAD connection.
fn next_qad_event(
    conns: &mut PerFamily<Option<QadConn>>,
) -> impl Future<Output = (AddrFamily, QadConnEvent)> + '_ {
    future::poll_fn(|cx| {
        for family in AddrFamily::ALL {
            if let Some(conn) = &mut conns[family]
                && let Poll::Ready(Some(event)) = conn.poll_next(cx)
            {
                return Poll::Ready((family, event));
            }
        }
        Poll::Pending
    })
}

/// Returns the next probe result of the running cycle.
///
/// Yields `None` without a cycle or once its probes are done, which disables
/// the `select!` branch for that iteration.
async fn next_probe_output(cycle: &mut Option<ProbeCycle>) -> Option<ProbeOutput> {
    match cycle {
        Some(cycle) if !cycle.probes.is_empty() => cycle.probes.next().await,
        _ => None,
    }
}

/// Runs a probe after `delay`, under `timeout`, until `cancel` fires.
///
/// Errors and timeouts establish failure. Cancellation and panics do not
/// establish reachability. It logs failures in the caller's span. The delay sits
/// outside the timeout, so a staggered probe still gets its full timeout once
/// it starts. The actor polls probes itself, so catching a panic here keeps a
/// bug in one probe from stopping the actor.
async fn guarded<T, E: fmt::Display>(
    cancel: CancellationToken,
    delay: Duration,
    timeout: Duration,
    work: impl Future<Output = Result<T, E>>,
) -> ProbeResult<T> {
    let result = cancel
        .run_until_cancelled(async {
            if !delay.is_zero() {
                time::sleep(delay).await;
            }
            time::timeout(timeout, AssertUnwindSafe(work).catch_unwind()).await
        })
        .await;
    match result {
        Some(Ok(Ok(Ok(value)))) => ProbeResult::Success(value),
        Some(Ok(Ok(Err(err)))) => {
            debug!(err = %format_args!("{err:#}"), "probe failed");
            ProbeResult::Failed
        }
        Some(Ok(Err(_panic))) => {
            error!("probe panicked");
            ProbeResult::Inconclusive
        }
        Some(Err(_elapsed)) => {
            debug!("probe timed out");
            ProbeResult::Failed
        }
        None => ProbeResult::Inconclusive,
    }
}

/// Returns `interval` plus a random share of up to [`REFRESH_JITTER`] of it.
fn jittered(interval: Duration) -> Duration {
    interval + interval.mul_f64(rand::rng().random_range(0.0..=REFRESH_JITTER))
}

/// Our public address in one family, as far as we know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    /// The address and port the relays see us coming from.
    addr: SocketAddr,
    /// Whether the address differs per destination, `None` while undecided.
    varies: Option<bool>,
}

impl Known {
    /// Returns what we know after a kept connection reported `addr`.
    ///
    /// A change on a single connection means our address changed, for
    /// example because the NAT rebound. It does not decide whether the
    /// address varies by destination, so the verdict stays.
    fn observe(known: Option<Self>, addr: SocketAddr) -> Self {
        Self {
            addr,
            varies: known.and_then(|k| k.varies),
        }
    }

    /// Returns the published form of the address, if it is of type `A`.
    fn public_addr<A>(
        self,
        matching: impl FnOnce(SocketAddr) -> Option<A>,
    ) -> Option<PublicAddr<A>> {
        Some(PublicAddr {
            addr: matching(self.addr)?,
            varies_by_dest: self.varies == Some(true),
        })
    }
}

/// How far the running cycle got with one address family.
///
/// The family's [`Known`] address stays what the last cycle established.
/// [`Progress::view`] and [`Progress::settle`] combine the two into what to
/// publish while the cycle runs, and what remains when it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Progress {
    /// A connection kept from an earlier cycle vouches for the family.
    ///
    /// The cycle does not probe it, and the connection keeps the known
    /// address current.
    Kept,
    /// No relay has answered for the family in this cycle.
    #[default]
    Waiting,
    /// One relay answered with this address.
    One(SocketAddr),
    /// At least two relays answered, so the cycle decided the verdict.
    Decided {
        /// The address of the first answer.
        addr: SocketAddr,
        /// Whether any later answer saw a different address.
        varies: bool,
    },
}

impl Progress {
    /// Returns the progress after another relay answered with `addr`.
    fn answer(self, addr: SocketAddr) -> Self {
        match self {
            Self::Kept | Self::Waiting => Self::One(addr),
            Self::One(first) => Self::Decided {
                addr: first,
                varies: first != addr,
            },
            Self::Decided {
                addr: first,
                varies,
            } => Self::Decided {
                addr: first,
                varies: varies || first != addr,
            },
        }
    }

    /// Returns the progress after a connection kept in this cycle saw `addr`.
    fn observe(self, addr: SocketAddr) -> Self {
        match self {
            Self::One(_) => Self::One(addr),
            Self::Decided { varies, .. } => Self::Decided { addr, varies },
            other => other,
        }
    }

    /// Returns what to publish for the family while the cycle runs.
    ///
    /// The known address stays until the cycle learns a new one. A known
    /// verdict carries over only to the same address.
    fn view(self, known: Option<Known>) -> Option<Known> {
        match self {
            Self::Kept | Self::Waiting => known,
            Self::One(addr) => Some(Known {
                addr,
                varies: known.filter(|k| k.addr == addr).and_then(|k| k.varies),
            }),
            Self::Decided { addr, varies } => Some(Known {
                addr,
                varies: Some(varies),
            }),
        }
    }

    /// Returns what we know about the family once the cycle ended.
    ///
    /// Like [`Self::view`], except that a family no relay answered for loses
    /// its address: nothing confirmed it.
    fn settle(self, known: Option<Known>) -> Option<Known> {
        match self {
            Self::Waiting => None,
            _ => self.view(known),
        }
    }
}

/// Where a home relay decision looks for candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidates {
    /// Only relays the cycle measured.
    ///
    /// A cycle that heard from no relay, for example while we are offline,
    /// then keeps the current home relay.
    Measured,
    /// Relays the cycle measured, or else relays with a latency of the last
    /// five minutes.
    ///
    /// Used when the relay transport could not dial the home relay. That
    /// happens between cycles, when the cycle may not have measured another
    /// relay.
    Recent,
}

/// How the current home relay compares at the end of a cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CurrentHome {
    /// The cycle measured its latency.
    Measured,
    /// No fresh result establishes reachability, for example after cancellation.
    ///
    /// Its latency of the last five minutes remains the hysteresis baseline.
    Unknown,
    /// Completed probes failed while its transport was disconnected, the
    /// relay transport failed to dial it, or it left the relay map.
    Unreachable,
}

/// Latencies of recent cycles, for picking the home relay.
#[derive(Debug, Default)]
struct History {
    /// Latencies of the cycles of the last five minutes, by end time.
    prev: BTreeMap<Instant, RelayLatencies>,
    /// Start of the last `Full` cycle, or `None` before the first one.
    last_full: Option<Instant>,
}

impl History {
    /// Maximum age of recorded latencies considered for relay selection.
    const MAX_AGE: Duration = Duration::from_secs(5 * 60);

    /// Records the latencies of a finished cycle.
    fn record(&mut self, latencies: &RelayLatencies, now: Instant) {
        self.prev
            .retain(|t, _| now.duration_since(*t) <= Self::MAX_AGE);
        self.prev.insert(now, latencies.clone());
    }

    /// Returns whether the last finished cycle measured no latency at all.
    fn last_was_empty(&self) -> bool {
        self.prev
            .last_key_value()
            .is_none_or(|(_, latencies)| latencies.is_empty())
    }

    /// Picks the home relay among the relays in `latencies`.
    ///
    /// The candidate is the relay in `relay_map` with the best latency across
    /// the last five minutes. It replaces the current home relay only when it
    /// is at least 33% faster, or when the current one is
    /// [`CurrentHome::Unreachable`]. An unreachable home relay is no
    /// candidate. Returns `None`, which keeps the current home relay, when
    /// there is no candidate.
    fn select_home_relay(
        &self,
        latencies: &RelayLatencies,
        current: Option<(&RelayUrl, CurrentHome)>,
        candidates: Candidates,
        relay_map: &RelayMap,
        now: Instant,
    ) -> Option<RelayUrl> {
        // Best latency per relay over the last five minutes.
        let mut best_recent = RelayLatencies::default();
        for (t, prev) in self.prev.iter() {
            if now.duration_since(*t) <= Self::MAX_AGE {
                best_recent.merge(prev);
            }
        }
        best_recent.merge(latencies);

        let unreachable = current
            .filter(|(_, status)| *status == CurrentHome::Unreachable)
            .map(|(url, _)| url);
        let best_of = |set: &RelayLatencies| {
            set.iter()
                .map(|(_, url, _)| url)
                .filter(|url| relay_map.contains(url) && Some(*url) != unreachable)
                .filter_map(|url| Some((url.clone(), best_recent.get(url)?)))
                .min_by_key(|(_, latency)| *latency)
        };
        let (best_url, best_latency) = match candidates {
            Candidates::Measured => best_of(latencies),
            Candidates::Recent => best_of(latencies).or_else(|| best_of(&best_recent)),
        }?;
        let Some((current, status)) = current else {
            return Some(best_url);
        };
        let current_latency = match status {
            CurrentHome::Measured => latencies.get(current),
            CurrentHome::Unknown => best_recent.get(current),
            CurrentHome::Unreachable => None,
        };

        // Hysteresis: don't switch if the new relay isn't much better.
        if let Some(current_latency) = current_latency
            && !current_latency.is_zero()
            && best_latency > current_latency / 3 * 2
        {
            return Some(current.clone());
        }
        Some(best_url)
    }

    /// Decides the scope of the next cycle.
    ///
    /// A `Full` trigger always yields a `Full` cycle. A `Refresh` trigger is
    /// promoted to `Full` on the first cycle, once `full_cycle_interval` has
    /// elapsed, or when we are behind a captive portal without UDP.
    fn scope_for(
        &self,
        trigger: ProbeScope,
        now: Instant,
        full_cycle_interval: Duration,
        captive_without_udp: bool,
    ) -> ProbeScope {
        let full = trigger == ProbeScope::Full
            || self
                .last_full
                .is_none_or(|t| now.duration_since(t) > full_cycle_interval)
            || captive_without_udp;
        if full {
            ProbeScope::Full
        } else {
            ProbeScope::Refresh
        }
    }
}

/// The probe cycle in flight.
///
/// Owns the cycle's probes and their cancellation tokens, so dropping the
/// cycle stops everything it started.
struct ProbeCycle {
    /// The probes still running. The cycle is done when this is empty.
    probes: FuturesUnordered<BoxFuture<ProbeOutput>>,
    /// The latest time for the early home relay decision.
    ///
    /// `None` once the cycle made it. The cycle decides early, as soon as two relays have answered and the
    /// current home relay has answered if the cycle probes it. It decides once
    /// more when it ends, with complete results.
    decide_at: Option<Instant>,
    /// When the cycle stops its remaining probes and ends.
    deadline: Instant,
    /// The relays this cycle probes for latency.
    probed: BTreeSet<RelayUrl>,
    /// The relays that answered a probe of this cycle.
    ///
    /// A kept QAD connection does not count: it may be dead without knowing
    /// it yet.
    answered: BTreeSet<RelayUrl>,
    /// Relays whose probes actually failed or timed out, rather than being cancelled.
    failed: BTreeSet<RelayUrl>,
    /// Cancels the remaining HTTPS probes to each relay.
    ///
    /// A relay's token fires once the relay has a latency sample from any
    /// probe.
    https_cancel: BTreeMap<RelayUrl, CancellationToken>,
    /// How far the cycle got with each address family.
    progress: PerFamily<Progress>,
    /// Cancels the remaining QAD probes of a family once two have answered.
    qad_cancel: PerFamily<CancellationToken>,
    /// Cancels the captive portal check once a QAD probe confirms UDP works.
    captive_portal_cancel: CancellationToken,
}

impl ProbeCycle {
    /// Cancels the remaining HTTPS probes to `relay_url`.
    fn cancel_https(&mut self, relay_url: &RelayUrl) {
        if let Some(cancel) = self.https_cancel.remove(relay_url) {
            cancel.cancel();
        }
    }
}

/// Probes the relays and publishes the [`Outputs`].
///
/// See the [module documentation](self) for an overview.
pub(super) struct NetReportActor {
    /// The network interfaces, which trigger cycles when they change.
    interfaces: Interfaces,
    /// Changes the actor cannot observe itself.
    messages: mpsc::UnboundedReceiver<Message>,
    /// Cancelled to stop the actor and drop everything it owns.
    shutdown: CancellationToken,
    /// Shared metrics counters.
    metrics: Arc<Metrics>,
    /// What the probes run with, and how.
    opts: Options,

    /// The cycle to start once the debounce allows, if any.
    pending: Option<ProbeScope>,
    /// When the last cycle started, for the request debounce.
    last_cycle_start: Option<Instant>,
    /// No cycle starts before this instant, set by a network change.
    not_before: Option<Instant>,
    /// When the next periodic refresh is due.
    next_refresh: Instant,
    /// Whether the actor changed home relay without fresh evidence of connectivity.
    ///
    /// Set after transport-driven failover or a cycle decision using only cached readings.
    ///
    /// It does so at most once until fresh connectivity evidence arrives. When
    /// we go offline no relay can be dialed, and acting on every failure would
    /// rotate the home relay.
    failed_over: bool,

    /// The QAD connection kept for each family, reused across cycles.
    qad_conns: PerFamily<Option<QadConn>>,
    /// The cycle in flight, or `None` when idle.
    cycle: Option<ProbeCycle>,

    /// Our public address per family, as the last cycle established it.
    known: PerFamily<Option<Known>>,
    /// The latencies measured since the current or last cycle started.
    latencies: RelayLatencies,
    /// Whether the last check found a captive portal.
    captive_portal: Option<bool>,
    /// Latencies of recent cycles.
    history: History,

    /// Where the actor publishes what it learned.
    outputs: Outputs,
}

impl NetReportActor {
    /// Creates the actor from its dependencies and [`Options`].
    pub(super) fn new(
        opts: Options,
        interfaces: Interfaces,
        messages: mpsc::UnboundedReceiver<Message>,
        outputs: Outputs,
        metrics: Arc<Metrics>,
        shutdown: CancellationToken,
    ) -> Self {
        interfaces.publish_initial(&outputs.network_state);
        Self {
            interfaces,
            messages,
            shutdown,
            metrics,
            opts,
            // Probe right away on startup.
            pending: Some(ProbeScope::Full),
            last_cycle_start: None,
            not_before: None,
            next_refresh: Instant::now(),
            failed_over: false,
            qad_conns: PerFamily::default(),
            cycle: None,
            known: PerFamily::default(),
            latencies: RelayLatencies::default(),
            captive_portal: None,
            history: History::default(),
            outputs,
        }
    }

    /// Runs the actor until the shutdown token is cancelled.
    ///
    /// On shutdown, dropping `self` drops the cycle and the kept QAD
    /// connections, which stops every probe.
    pub(super) async fn run(mut self) {
        let mut interfaces_closed = false;
        let mut relay_status_closed = false;
        self.maybe_start(Instant::now());
        loop {
            let timer = time::sleep_until(self.next_deadline());
            n0_future::pin!(timer);

            tokio::select! {
                biased;

                _ = self.shutdown.cancelled() => break,
                change = self.interfaces.updated(), if !interfaces_closed => match change {
                    Ok(is_major) => self.on_network_change(is_major),
                    Err(_) => interfaces_closed = true,
                },
                Some(message) = self.messages.recv() => match message {
                    Message::RelaysChanged => {
                        debug!("relay map changed");
                        self.trigger(ProbeScope::Full);
                    }
                    Message::NetworkChange => self.interfaces.network_change().await,
                    #[cfg(all(test, with_crypto_provider))]
                    Message::ForceNetworkChange(is_major) => self.on_network_change(is_major),
                },
                status = self.opts.relay_status.updated(), if !relay_status_closed => match status {
                    Ok(status) => self.on_relay_status(status),
                    Err(_) => relay_status_closed = true,
                },
                Some(output) = next_probe_output(&mut self.cycle) => self.on_probe_output(output),
                event = next_qad_event(&mut self.qad_conns) => self.on_qad_event(event),
                _ = &mut timer => self.on_timer(Instant::now()),
            }
        }
    }

    /// Publishes a network change and waits for a usable route before notifying QUIC.
    fn on_network_change(&mut self, is_major: bool) {
        #[cfg(not(wasm_browser))]
        if is_major {
            self.opts.dns_resolver.reset();
        }
        self.interfaces
            .publish_change(is_major, &self.outputs.network_state);
        // The socket rebinds on the same change. Wait out the debounce, so
        // the probes go out on the new sockets.
        self.not_before = Some(Instant::now() + self.opts.timing.request_debounce);
        self.trigger(if is_major {
            ProbeScope::Full
        } else {
            ProbeScope::Refresh
        });
    }

    /// Handles a change of the relay transport's home relay connection.
    ///
    /// When the relay transport could not dial the home relay, the home relay
    /// is unreachable, and the actor decides without it right away. It does
    /// so once until fresh evidence of connectivity arrives.
    fn on_relay_status(&mut self, status: Option<RelayStatus>) {
        let Some(status) = status else {
            return;
        };
        if Some(status.url()) != self.outputs.home_relay.get().as_ref() {
            return;
        }
        if status.is_connected() {
            self.failed_over = false;
            return;
        }
        if self.relay_unreachable(status.url()) {
            debug!(relay_url = %status.url(), "home relay unreachable, deciding without it");
            if self.decide_home_relay(self.cycle.as_ref(), Candidates::Recent) {
                self.failed_over = true;
                self.publish();
            }
        }
    }

    /// Returns whether the relay transport is connected to `url`.
    fn relay_connected(&self, url: &RelayUrl) -> bool {
        self.opts
            .relay_status
            .peek()
            .as_ref()
            .is_some_and(|s| s.url() == url && s.is_connected())
    }

    /// Returns whether the relay transport failed to dial `url` just now.
    fn relay_unreachable(&self, url: &RelayUrl) -> bool {
        self.opts
            .relay_status
            .peek()
            .as_ref()
            .is_some_and(|s| s.url() == url && !s.is_connected() && s.dial_failed())
    }

    /// Asks for a cycle of `scope`, merged with any cycle already pending.
    fn trigger(&mut self, scope: ProbeScope) {
        self.pending = Some(self.pending.map_or(scope, |p| p.max(scope)));
        self.maybe_start(Instant::now());
    }

    /// Returns the earliest instant at which [`Self::on_timer`] has work.
    fn next_deadline(&self) -> Instant {
        // A pending cycle waits for the debounce, unless it waits for the
        // running cycle to end.
        let debounce = self
            .pending
            .filter(|&scope| self.cycle.is_none() || scope == ProbeScope::Full)
            .and_then(|_| self.start_allowed_at());
        let cycle = self.cycle.as_ref();
        [
            debounce,
            self.interfaces.next_deadline(),
            cycle.and_then(|c| c.decide_at),
            cycle.map(|c| c.deadline),
        ]
        .into_iter()
        .flatten()
        .fold(self.next_refresh, Instant::min)
    }

    /// Returns when a pending cycle may start, or `None` if it may start now.
    ///
    /// That is once the request debounce after the last cycle start has
    /// passed, and the debounce after the last network change.
    fn start_allowed_at(&self) -> Option<Instant> {
        let debounce = self
            .last_cycle_start
            .map(|t| t + self.opts.timing.request_debounce);
        debounce.max(self.not_before)
    }

    /// Handles every deadline that has passed by `now`.
    fn on_timer(&mut self, now: Instant) {
        self.interfaces.on_timer(now, &self.outputs.network_state);
        if self
            .cycle
            .as_ref()
            .and_then(|c| c.decide_at)
            .is_some_and(|t| t <= now)
        {
            debug!("first report deadline passed, deciding the home relay");
            self.decide_home_relay_early(true);
        }
        if self.cycle.as_ref().is_some_and(|c| c.deadline <= now) {
            debug!("cycle timeout passed, ending cycle");
            self.finish_cycle(now);
        }
        if self.next_refresh <= now {
            self.next_refresh = now + jittered(self.opts.timing.refresh_interval);
            self.pending = Some(self.pending.unwrap_or(ProbeScope::Refresh));
        }
        self.maybe_start(now);
    }

    /// Starts the pending cycle, if it may start now.
    ///
    /// A pending cycle waits for the request debounce. After that a `Full`
    /// cycle aborts a running cycle, while a `Refresh` waits until the running
    /// cycle ends.
    fn maybe_start(&mut self, now: Instant) {
        let Some(scope) = self.pending else {
            return;
        };
        if self.start_allowed_at().is_some_and(|t| now < t) {
            return;
        }
        if self.cycle.is_some() {
            if scope == ProbeScope::Refresh {
                trace!("deferring refresh until the running cycle ends");
                return;
            }
            debug!("aborting running cycle");
            self.cycle = None;
        }
        self.pending = None;
        self.start_cycle(scope, now);
    }

    /// Starts a new probe cycle.
    fn start_cycle(&mut self, trigger: ProbeScope, now: Instant) {
        self.last_cycle_start = Some(now);
        self.not_before = None;
        self.next_refresh = now + jittered(self.opts.timing.refresh_interval);
        if self.opts.relay_map.is_empty() {
            debug!("empty relay map, clearing net_report state");
            self.clear();
            return;
        }

        let has_udp = AddrFamily::ALL.into_iter().any(|f| self.known[f].is_some());
        let scope = self.history.scope_for(
            trigger,
            now,
            self.opts.timing.full_cycle_interval,
            !has_udp && self.captive_portal == Some(true),
        );
        debug!(?trigger, ?scope, "starting probe cycle");
        if scope == ProbeScope::Full {
            self.close_qad_conns();
            self.captive_portal = None;
            self.history.last_full = Some(now);
            self.metrics.reports_full.inc();
        }
        self.metrics.reports.inc();

        // Measure latencies from scratch, starting with the kept QAD
        // connections. Drop a connection that closed before we handled its
        // close event, so the cycle probes its family. A `Full` cycle forgets
        // a family whose interface is gone.
        self.latencies = RelayLatencies::default();
        let mut progress = PerFamily::<Progress>::default();
        for family in AddrFamily::ALL {
            if self.qad_conns[family]
                .as_ref()
                .is_some_and(QadConn::is_closed)
            {
                self.qad_conns[family] = None;
            }
            if scope == ProbeScope::Full && !self.interfaces.has_family(family) {
                self.known[family] = None;
            }
            if let Some(report) = self.qad_conns[family]
                .as_ref()
                .and_then(QadConn::current_report)
            {
                progress[family] = Progress::Kept;
                self.known[family] = Some(Known::observe(self.known[family], report.addr));
                self.latencies
                    .update_relay(report.relay_url, report.latency, family.probe());
            }
        }

        let mut cycle = ProbeCycle {
            probes: FuturesUnordered::new(),
            decide_at: Some(now + self.opts.timing.first_report_timeout),
            deadline: now + self.opts.timing.cycle_timeout,
            probed: BTreeSet::new(),
            answered: BTreeSet::new(),
            failed: BTreeSet::new(),
            https_cancel: BTreeMap::new(),
            progress,
            qad_cancel: PerFamily::default(),
            captive_portal_cancel: CancellationToken::new(),
        };
        #[cfg(not(wasm_browser))]
        {
            self.add_qad_probes(&mut cycle);
            if scope == ProbeScope::Full && self.opts.config.captive_portal_check {
                self.add_captive_portal_check(&mut cycle);
            }
        }
        // A full cycle measures every relay over HTTPS, and so does a cycle
        // after one that measured nothing. A refresh only checks the home
        // relay, and only when the relay transport has no healthy connection
        // to it. A kept QAD connection does not vouch for it: it may be dead
        // without knowing it yet.
        let https_relays = if scope == ProbeScope::Full || self.history.last_was_empty() {
            self.opts.relay_map.relays()
        } else {
            self.outputs
                .home_relay
                .get()
                .filter(|url| !self.relay_connected(url))
                .and_then(|url| self.opts.relay_map.get(&url))
                .into_iter()
                .collect()
        };
        self.add_https_probes(&mut cycle, https_relays);

        let done = cycle.probes.is_empty();
        self.cycle = Some(cycle);
        self.publish();
        // A cycle can start with no probes at all: every family has a kept
        // connection and HTTPS is not due. It is complete right away.
        if done {
            self.finish_cycle(now);
        }
    }

    /// Forgets everything and clears the outputs, for an empty relay map.
    fn clear(&mut self) {
        self.cycle = None;
        self.close_qad_conns();
        self.known = PerFamily::default();
        self.latencies = RelayLatencies::default();
        self.captive_portal = None;
        self.history = History::default();
        self.outputs.public_addrs.set(PublicAddrs::default()).ok();
        #[cfg(any(test, feature = "unstable-net-report"))]
        self.outputs.report.set(None).ok();
    }

    /// Applies one probe result.
    fn on_probe_output(&mut self, output: ProbeOutput) {
        let Some(cycle) = &mut self.cycle else {
            return;
        };
        match output {
            ProbeOutput::Qad(family, _, ProbeResult::Success((report, conn))) => {
                debug!(?family, ?report, "QAD probe completed");
                cycle.cancel_https(&report.relay_url);
                // UDP works, so skip captive portal detection.
                cycle.captive_portal_cancel.cancel();
                cycle.answered.insert(report.relay_url.clone());
                self.failed_over = false;
                let progress = &mut cycle.progress[family];
                *progress = progress.answer(report.addr);
                if let Progress::Decided { varies: true, .. } = progress {
                    debug!(?family, "public address varies by destination");
                }
                self.latencies
                    .update_relay(report.relay_url, report.latency, family.probe());
                if self.qad_conns[family].is_none() {
                    // Keep this connection, and let the other probes run so a
                    // second answer can decide mapping-varies. The address may
                    // have changed since the probe returned.
                    if let Some(fresh) = conn.current_report() {
                        *progress = progress.observe(fresh.addr);
                    }
                    self.qad_conns[family] = Some(conn);
                } else {
                    // The second answer decided mapping-varies, so stop the
                    // family's remaining probes and drop this connection.
                    conn.close();
                    cycle.qad_cancel[family].cancel();
                }
            }
            ProbeOutput::Https(_, ProbeResult::Success(report)) => {
                debug!(?report, "HTTPS probe completed");
                cycle.cancel_https(&report.relay_url);
                cycle.answered.insert(report.relay_url.clone());
                self.failed_over = false;
                self.latencies
                    .update_relay(report.relay_url, report.latency, Probe::Https);
            }
            ProbeOutput::CaptivePortal(ProbeResult::Success(found)) => {
                debug!(found, "captive portal check completed");
                self.captive_portal = Some(found);
            }
            ProbeOutput::Qad(_, url, ProbeResult::Failed)
            | ProbeOutput::Https(url, ProbeResult::Failed) => {
                cycle.failed.insert(url);
            }
            // Cancellation, a panic, or a failed captive portal check tells us nothing about a relay.
            _ => {}
        }
        let done = cycle.probes.is_empty();
        self.decide_home_relay_early(false);
        self.publish();
        if done {
            self.finish_cycle(Instant::now());
        }
    }

    /// Records the current address and latency of a kept QAD connection.
    ///
    /// A connection kept in the running cycle updates the cycle's progress.
    /// One kept from an earlier cycle updates the known address directly.
    fn on_qad_observation(&mut self, family: AddrFamily, report: &QadProbeReport) {
        self.failed_over = false;
        self.latencies
            .update_relay(report.relay_url.clone(), report.latency, family.probe());
        match self.cycle.as_mut().map(|c| &mut c.progress[family]) {
            Some(progress @ (Progress::One(_) | Progress::Decided { .. })) => {
                *progress = progress.observe(report.addr);
            }
            _ => self.known[family] = Some(Known::observe(self.known[family], report.addr)),
        }
    }

    /// Applies one update from a kept QAD connection.
    fn on_qad_event(&mut self, (family, event): (AddrFamily, QadConnEvent)) {
        match event {
            QadConnEvent::Observed(report) => {
                trace!(?family, ?report, "QAD address observation");
                self.on_qad_observation(family, &report);
                self.publish();
            }
            QadConnEvent::Closed => {
                let Some(conn) = self.qad_conns[family].take() else {
                    return;
                };
                let relay_url = conn.relay_url();
                // A relay that closes connections right away would otherwise
                // make us probe again and again.
                if conn.age() < MIN_QAD_CONN_AGE {
                    debug!(?family, %relay_url, "kept QAD connection closed early");
                } else {
                    debug!(?family, %relay_url, "kept QAD connection closed, refreshing");
                    self.trigger(ProbeScope::Refresh);
                }
            }
        }
    }

    /// Decides the home relay early, if the cycle has enough answers.
    ///
    /// That is once two relays have answered (or the only one, with a single
    /// relay), and the current home relay has answered if the cycle probes
    /// it. When `deadline_passed`, the cycle decides with what it has.
    fn decide_home_relay_early(&mut self, deadline_passed: bool) {
        let Some(cycle) = &self.cycle else {
            return;
        };
        if cycle.decide_at.is_none() {
            return;
        }
        let home_pending = self
            .outputs
            .home_relay
            .get()
            .is_some_and(|url| cycle.probed.contains(&url) && !cycle.answered.contains(&url));
        let enough = cycle.answered.len() >= 2.min(self.opts.relay_map.len());
        if !deadline_passed && (home_pending || !enough) {
            return;
        }
        let changed = self.decide_home_relay(Some(cycle), Candidates::Measured);
        self.failed_over |= changed && cycle.answered.is_empty();
        if let Some(cycle) = &mut self.cycle {
            cycle.decide_at = None;
        }
    }

    /// Picks the home relay with what `cycle` learned so far.
    ///
    /// Without a cycle, it decides with the latencies of the last one.
    fn decide_home_relay(&self, cycle: Option<&ProbeCycle>, candidates: Candidates) -> bool {
        let current = self.outputs.home_relay.get();
        // Apply the offline guard to cycle decisions as well as transport failures.
        // A relay removed from the map must still be replaced.
        if self.failed_over
            && current
                .as_ref()
                .is_some_and(|url| self.opts.relay_map.contains(url))
        {
            return false;
        }
        let current = current.as_ref().map(|url| {
            let status = if !self.opts.relay_map.contains(url) || self.relay_unreachable(url) {
                CurrentHome::Unreachable
            } else if cycle.is_some_and(|c| c.answered.contains(url)) {
                CurrentHome::Measured
            } else if !self.relay_connected(url)
                && cycle.is_some_and(|c| c.probes.is_empty() && c.failed.contains(url))
            {
                CurrentHome::Unreachable
            } else {
                CurrentHome::Unknown
            };
            (url, status)
        });
        let selected = self.history.select_home_relay(
            &self.latencies,
            current,
            candidates,
            &self.opts.relay_map,
            Instant::now(),
        );
        self.set_home_relay(selected)
    }

    /// Publishes `selected` as home relay and returns whether it changed.
    fn set_home_relay(&self, selected: Option<RelayUrl>) -> bool {
        if selected.is_some() && selected != self.outputs.home_relay.get() {
            debug!(home_relay = ?selected, "home relay selected");
            self.outputs.home_relay.set(selected).ok();
            true
        } else {
            false
        }
    }

    /// Publishes the public addresses and the debug report.
    ///
    /// Watchers only see a value that changed.
    fn publish(&mut self) {
        let [v4, v6] = AddrFamily::ALL.map(|f| match &self.cycle {
            Some(cycle) => cycle.progress[f].view(self.known[f]),
            None => self.known[f],
        });
        let public_addrs = PublicAddrs {
            v4: v4.and_then(|k| {
                k.public_addr(|addr| match addr {
                    SocketAddr::V4(addr) => Some(addr),
                    SocketAddr::V6(_) => None,
                })
            }),
            v6: v6.and_then(|k| {
                k.public_addr(|addr| match addr {
                    SocketAddr::V6(addr) => Some(addr),
                    SocketAddr::V4(_) => None,
                })
            }),
        };
        self.outputs.public_addrs.set(public_addrs).ok();

        #[cfg(any(test, feature = "unstable-net-report"))]
        {
            let report = Report {
                udp_v4: public_addrs.v4.is_some(),
                udp_v6: public_addrs.v6.is_some(),
                mapping_varies_by_dest_ipv4: v4.and_then(|k| k.varies),
                mapping_varies_by_dest_ipv6: v6.and_then(|k| k.varies),
                preferred_relay: self.outputs.home_relay.get(),
                relay_latency: self.latencies.clone(),
                global_v4: public_addrs.v4.map(|a| a.addr),
                global_v6: public_addrs.v6.map(|a| a.addr),
                captive_portal: self.captive_portal,
            };
            // Stay `None` until there is something to report.
            if report.has_data() || self.outputs.report.get().is_some() {
                self.outputs.report.set(Some(report)).ok();
            }
        }
    }

    /// Ends the running cycle.
    ///
    /// Drops the cycle's remaining probes, drops what the cycle could not
    /// confirm, picks the home relay, and records the latencies. Then starts a
    /// cycle that waited for this one.
    fn finish_cycle(&mut self, now: Instant) {
        let Some(mut cycle) = self.cycle.take() else {
            return;
        };
        // Stop unfinished probes; only failures already collected count as evidence.
        cycle.probes = FuturesUnordered::new();
        for family in AddrFamily::ALL {
            let progress = cycle.progress[family];
            if progress == Progress::Waiting && self.known[family].is_some() {
                debug!(?family, "dropping public address the cycle did not confirm");
            }
            self.known[family] = progress.settle(self.known[family]);
        }
        let changed = self.decide_home_relay(Some(&cycle), Candidates::Measured);
        self.failed_over |= changed && cycle.answered.is_empty();
        self.history.record(&self.latencies, now);
        self.publish();
        debug!(
            latencies = ?self.latencies,
            duration = ?self.last_cycle_start.map(|t| now.duration_since(t)),
            "net_report cycle complete",
        );
        self.maybe_start(now);
    }

    /// Closes and drops the kept QAD connections.
    fn close_qad_conns(&mut self) {
        for family in AddrFamily::ALL {
            if let Some(conn) = self.qad_conns[family].take() {
                conn.close();
            }
        }
    }

    /// Adds a QAD probe for each relay and each family that needs one.
    ///
    /// A family needs probes when it has no kept connection, its interface is
    /// up, and the options enable it.
    #[cfg(not(wasm_browser))]
    fn add_qad_probes(&self, cycle: &mut ProbeCycle) {
        let Some(quic_client) = &self.opts.quic_client else {
            return;
        };
        let needed: Vec<AddrFamily> = AddrFamily::ALL
            .into_iter()
            .filter(|&family| {
                self.qad_conns[family].is_none()
                    && self.interfaces.has_family(family)
                    && (family == AddrFamily::V4 || self.opts.qad_ipv6)
            })
            .collect();

        // One probe per (relay, needed family). Stagger successive probes by
        // an increasing delay so they do not all start at once.
        let stagger = self.opts.config.qad_stagger;
        let mut index = 0u32;
        for relay in self
            .opts
            .relay_map
            .relays::<Vec<_>>()
            .into_iter()
            .take(MAX_QAD_RELAYS)
        {
            for &family in &needed {
                cycle.probed.insert(relay.url.clone());
                let work = qad::run_probe(
                    family,
                    relay.clone(),
                    quic_client.clone(),
                    self.opts.dns_resolver.clone(),
                );
                let probe = guarded(
                    cycle.qad_cancel[family].clone(),
                    stagger * index,
                    self.opts.timing.probe_timeout,
                    work,
                );
                let span = info_span!("QAD", ?family, relay_url = %relay.url);
                let relay_url = relay.url.clone();
                cycle.probes.push(Box::pin(
                    async move { ProbeOutput::Qad(family, relay_url, probe.await) }
                        .instrument(span),
                ));
                index += 1;
            }
        }
    }

    /// Adds HTTPS latency probes to `relays`, three per relay.
    // TODO: On a QUIC-blocked network HTTPS is the only latency source, yet a
    // Refresh only checks the home relay. Between Full cycles a faster relay
    // cannot take over on such networks. Revisit if that turns out to matter.
    fn add_https_probes(&self, cycle: &mut ProbeCycle, relays: Vec<Arc<RelayConfig>>) {
        if !self.opts.config.https_probes {
            return;
        }
        for relay in relays {
            cycle.probed.insert(relay.url.clone());
            let cancel = cycle
                .https_cancel
                .entry(relay.url.clone())
                .or_default()
                .clone();
            for delay in https::probe_delays() {
                let work = https::run_probe(
                    #[cfg(not(wasm_browser))]
                    self.opts.dns_resolver.clone(),
                    relay.url.clone(),
                    #[cfg(not(wasm_browser))]
                    self.opts.tls_config.clone(),
                    #[cfg(not(wasm_browser))]
                    self.opts.proxy_url.clone(),
                );
                let probe = guarded(cancel.clone(), delay, self.opts.timing.probe_timeout, work);
                let span = info_span!("HTTPS", relay_url = %relay.url);
                let relay_url = relay.url.clone();
                cycle.probes.push(Box::pin(
                    async move { ProbeOutput::Https(relay_url, probe.await) }.instrument(span),
                ));
            }
        }
    }

    /// Adds the captive portal check.
    ///
    /// Delayed by [`Timing::captive_portal_delay`] to give QAD probes time to
    /// succeed first, and cancelled if QAD confirms UDP connectivity.
    ///
    /// [`Timing::captive_portal_delay`]: super::timing::Timing::captive_portal_delay
    #[cfg(not(wasm_browser))]
    fn add_captive_portal_check(&self, cycle: &mut ProbeCycle) {
        let work = captive_portal::check(
            self.opts.dns_resolver.clone(),
            self.opts.relay_map.clone(),
            self.outputs.home_relay.get(),
            self.opts.tls_config.clone(),
            self.opts.proxy_url.clone(),
        );
        let probe = guarded(
            cycle.captive_portal_cancel.clone(),
            self.opts.timing.captive_portal_delay,
            CAPTIVE_PORTAL_TIMEOUT,
            work,
        );
        cycle.probes.push(Box::pin(
            async move { ProbeOutput::CaptivePortal(probe.await) }
                .instrument(info_span!("captive-portal")),
        ));
    }
}

#[cfg(all(test, with_crypto_provider))]
mod tests {
    use std::time::Duration;

    use iroh_base::RelayUrl;
    use n0_error::Result;

    use super::*;
    use crate::net_report::{report::Probe, timing::Timing};

    /// Returns a made-up relay URL with number `i`.
    fn relay_url(i: u16) -> RelayUrl {
        format!("http://{i}.com").parse().unwrap()
    }

    /// Returns a relay map with the made-up relays 1 to 3.
    fn relay_map() -> RelayMap {
        RelayMap::from_iter((1..=3).map(|i| RelayConfig::from(relay_url(i))))
    }

    /// Builds QAD IPv4 latencies from `("d<relay number>", seconds)` pairs.
    fn latencies(a: impl IntoIterator<Item = (&'static str, u64)>) -> RelayLatencies {
        let mut latencies = RelayLatencies::default();
        for (s, d) in a {
            assert!(s.starts_with('d'), "invalid relay server key");
            let id: u16 = s[1..].parse().unwrap();
            latencies.update_relay(relay_url(id), Duration::from_secs(d), Probe::QadIpv4);
        }
        latencies
    }

    /// Checks the home relay selection across a sequence of cycles.
    ///
    /// Each case runs steps of `(seconds later, [(relay, latency secs)])` and
    /// checks the number of recorded cycles and the resulting home relay.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_history_and_home_relay() -> Result {
        type Step = (u64, &'static [(u16, u64)]);
        let cases: [(&str, &[Step], usize, u16); 7] = [
            ("first_reading", &[(0, &[(1, 2), (2, 3)][..])][..], 1, 1),
            (
                "with_two",
                &[(0, &[(1, 2), (2, 3)][..]), (1, &[(1, 4), (2, 3)][..])][..],
                2,
                1,
            ),
            (
                "but_now_d1_gone",
                &[
                    (0, &[(1, 2), (2, 3)][..]),
                    (1, &[(1, 4), (2, 3)][..]),
                    (2, &[(2, 3)][..]),
                ][..],
                3,
                2,
            ),
            (
                "d1_is_back",
                &[
                    (0, &[(1, 2), (2, 3)][..]),
                    (1, &[(1, 4), (2, 3)][..]),
                    (2, &[(2, 3)][..]),
                    (3, &[(1, 4), (2, 3)][..]),
                ][..],
                4,
                1,
            ),
            (
                "things_clean_up",
                &[
                    (0, &[(1, 1), (2, 2)][..]),
                    (1, &[(1, 1), (2, 2)][..]),
                    (2, &[(1, 1), (2, 2)][..]),
                    (3, &[(1, 1), (2, 2)][..]),
                    (10 * 60, &[(3, 3)][..]),
                ][..],
                1,
                3,
            ),
            (
                "preferred_relay_hysteresis_no_switch",
                &[(0, &[(1, 4), (2, 5)][..]), (1, &[(1, 4), (2, 3)][..])][..],
                2,
                1,
            ),
            (
                "preferred_relay_hysteresis_do_switch",
                &[(0, &[(1, 4), (2, 5)][..]), (1, &[(1, 4), (2, 1)][..])][..],
                2,
                2,
            ),
        ];

        for (name, steps, want_prev_len, want_relay) in cases {
            println!("test: {name}");
            let mut history = History::default();
            let map = relay_map();
            let mut home_relay = None;
            for &(after, relays) in steps {
                tokio::time::advance(Duration::from_secs(after)).await;
                let mut latencies = RelayLatencies::default();
                for &(relay, secs) in relays {
                    latencies.update_relay(
                        relay_url(relay),
                        Duration::from_secs(secs),
                        Probe::QadIpv4,
                    );
                }
                let now = Instant::now();
                // Each step is a cycle that probed every relay.
                let current = home_relay.as_ref().map(|url| {
                    let status = if latencies.get(url).is_some() {
                        CurrentHome::Measured
                    } else {
                        CurrentHome::Unreachable
                    };
                    (url, status)
                });
                home_relay =
                    history.select_home_relay(&latencies, current, Candidates::Measured, &map, now);
                history.record(&latencies, now);
            }
            assert_eq!(history.prev.len(), want_prev_len, "{name}: prev length");
            assert_eq!(
                home_relay,
                Some(relay_url(want_relay)),
                "{name}: home relay"
            );
        }

        Ok(())
    }

    /// Checks how the status of the current home relay affects the choice.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_current_home_status() {
        let mut history = History::default();
        let now = Instant::now();
        history.record(&latencies([("d1", 30), ("d2", 28)]), now);
        let d1 = relay_url(1);
        let relays = relay_map();
        let select = |latencies: RelayLatencies, status| {
            history.select_home_relay(
                &latencies,
                Some((&d1, status)),
                Candidates::Recent,
                &relays,
                now,
            )
        };

        // Measured: hysteresis keeps d1, since 28s is not 33% faster than 30s.
        assert_eq!(
            select(latencies([("d1", 30), ("d2", 28)]), CurrentHome::Measured),
            Some(relay_url(1))
        );
        // Unprobed: the recent latency of d1 stands in.
        assert_eq!(
            select(latencies([("d2", 28)]), CurrentHome::Unknown),
            Some(relay_url(1))
        );
        // Unprobed, but a much faster relay still wins.
        assert_eq!(
            select(latencies([("d2", 10)]), CurrentHome::Unknown),
            Some(relay_url(2))
        );
        // Unreachable: switch to the best relay we have.
        assert_eq!(
            select(latencies([("d2", 28)]), CurrentHome::Unreachable),
            Some(relay_url(2))
        );
        // Unreachable, and the cycle measured no other relay: the relays of
        // the last five minutes are the candidates.
        assert_eq!(
            select(latencies([("d1", 30)]), CurrentHome::Unreachable),
            Some(relay_url(2))
        );
        // A cycle decision only looks at what the cycle measured. With
        // nothing else measured, for example offline, it keeps d1.
        assert_eq!(
            history.select_home_relay(
                &latencies([("d1", 30)]),
                Some((&d1, CurrentHome::Unreachable)),
                Candidates::Measured,
                &relays,
                now
            ),
            None
        );
        // A relay that left the relay map is no candidate.
        let relays = RelayMap::from_iter([RelayConfig::from(relay_url(1))]);
        assert_eq!(
            history.select_home_relay(
                &latencies([("d1", 30)]),
                Some((&d1, CurrentHome::Unreachable)),
                Candidates::Recent,
                &relays,
                now
            ),
            None
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn test_scope_for() {
        let interval = Timing::default().full_cycle_interval;
        let mut history = History::default();
        let now = Instant::now();
        let scope = |h: &History, trigger, at, captive| h.scope_for(trigger, at, interval, captive);
        assert_eq!(
            scope(&history, ProbeScope::Refresh, now, false),
            ProbeScope::Full,
            "first cycle is full"
        );

        history.last_full = Some(now);
        assert_eq!(
            scope(&history, ProbeScope::Refresh, now, false),
            ProbeScope::Refresh
        );
        assert_eq!(
            scope(&history, ProbeScope::Full, now, false),
            ProbeScope::Full
        );
        assert_eq!(
            scope(
                &history,
                ProbeScope::Refresh,
                now + interval + Duration::from_secs(1),
                false
            ),
            ProbeScope::Full,
            "full after the interval"
        );
        assert_eq!(
            scope(&history, ProbeScope::Refresh, now, true),
            ProbeScope::Full,
            "full behind a captive portal without UDP"
        );
    }

    #[test]
    fn test_jittered() {
        let interval = Duration::from_secs(20);
        for _ in 0..100 {
            let d = jittered(interval);
            assert!(d >= interval && d <= Duration::from_secs(26), "{d:?}");
        }
    }

    #[cfg(not(wasm_browser))]
    #[test]
    fn test_progress_answer() {
        let a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2000".parse().unwrap();

        assert_eq!(Progress::Waiting.answer(a), Progress::One(a));
        assert_eq!(
            Progress::One(a).answer(a),
            Progress::Decided {
                addr: a,
                varies: false
            }
        );
        assert_eq!(
            Progress::One(a).answer(b),
            Progress::Decided {
                addr: a,
                varies: true
            }
        );
        // Once an answer differed, later matching answers do not undo it.
        assert_eq!(
            Progress::One(a).answer(b).answer(a),
            Progress::Decided {
                addr: a,
                varies: true
            }
        );
        // An observation replaces the address but keeps the verdict.
        assert_eq!(Progress::One(a).observe(b), Progress::One(b));
        assert_eq!(Progress::Waiting.observe(b), Progress::Waiting);
    }

    #[test]
    fn test_progress_view_and_settle() {
        let a: SocketAddr = "1.1.1.1:1000".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2000".parse().unwrap();
        let known = Some(Known {
            addr: a,
            varies: Some(true),
        });
        let k = |addr, varies| Some(Known { addr, varies });

        // (progress, what is published while the cycle runs, what remains after)
        let cases = [
            (Progress::Kept, known, known),
            (Progress::Waiting, known, None),
            // The same address keeps its verdict, a new one starts undecided.
            (Progress::One(a), known, known),
            (Progress::One(b), k(b, None), k(b, None)),
            (
                Progress::Decided {
                    addr: b,
                    varies: false,
                },
                k(b, Some(false)),
                k(b, Some(false)),
            ),
        ];
        for (progress, view, settled) in cases {
            assert_eq!(progress.view(known), view, "view of {progress:?}");
            assert_eq!(progress.settle(known), settled, "settle of {progress:?}");
        }
        assert_eq!(Progress::Waiting.view(None), None);
        assert_eq!(Progress::One(a).view(None), k(a, None));
    }
    /// An actor driven directly by tests, with three relays and a known home.
    fn test_actor() -> (NetReportActor, n0_watcher::Watchable<Option<RelayStatus>>) {
        let status = n0_watcher::Watchable::new(None);
        let interfaces = n0_watcher::Watchable::new(netwatch::netmon::State::fake());
        let (_sender, receiver) = mpsc::unbounded_channel();
        let opts = Options {
            config: crate::net_report::NetReportConfig::minimal(),
            timing: Timing::default(),
            relay_map: relay_map(),
            relay_status: status.watch(),
            quic_client: None,
            qad_ipv6: false,
            dns_resolver: crate::dns::DnsResolver::new(),
            tls_config: iroh_relay::tls::make_dangerous_client_config(),
            proxy_url: None,
        };
        let outputs = Outputs::default();
        outputs.home_relay.set(Some(relay_url(1))).unwrap();
        let mut actor = NetReportActor::new(
            opts,
            Interfaces::from_watcher(interfaces.watch()),
            receiver,
            outputs,
            Arc::new(Metrics::default()),
            CancellationToken::new(),
        );
        actor.pending = None;
        actor.history.record(
            &latencies([("d1", 10), ("d2", 11), ("d3", 12)]),
            Instant::now(),
        );
        (actor, status)
    }

    fn test_cycle() -> ProbeCycle {
        ProbeCycle {
            probes: FuturesUnordered::new(),
            decide_at: Some(Instant::now()),
            deadline: Instant::now(),
            probed: BTreeSet::from([relay_url(1), relay_url(2), relay_url(3)]),
            answered: BTreeSet::new(),
            failed: BTreeSet::new(),
            https_cancel: BTreeMap::new(),
            progress: PerFamily::default(),
            qad_cancel: PerFamily::default(),
            captive_portal_cancel: CancellationToken::new(),
        }
    }

    #[tokio::test]
    async fn test_home_relay_requires_failure_evidence() {
        for connected in [false, true] {
            for failed in [false, true] {
                let (mut actor, status) = test_actor();
                if connected {
                    status
                        .set(Some(RelayStatus::new(
                            relay_url(1),
                            crate::socket::transports::RelayConnectionState::Connected,
                        )))
                        .unwrap();
                    actor.opts.relay_status.get();
                }
                actor.latencies = latencies([("d2", 11), ("d3", 12)]);
                let mut cycle = test_cycle();
                cycle.answered.extend([relay_url(2), relay_url(3)]);
                if failed {
                    cycle.failed.insert(relay_url(1));
                }
                // The first-report deadline does not turn a pending probe into a failure.
                cycle.probes.push(Box::pin(std::future::pending()));
                actor.cycle = Some(cycle);
                actor.decide_home_relay_early(true);
                assert_eq!(
                    actor.outputs.home_relay.get(),
                    Some(relay_url(1)),
                    "pending probe, connected={connected}, failed={failed}"
                );
                // Finishing with a cancelled home probe must preserve hysteresis.
                // An actually failed probe can evict it only if the transport is not connected.
                actor.finish_cycle(Instant::now());
                let expected = if failed && !connected { 2 } else { 1 };
                assert_eq!(
                    actor.outputs.home_relay.get(),
                    Some(relay_url(expected)),
                    "finished cycle, connected={connected}, failed={failed}"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_probe_cancellation_is_not_failure() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let result = guarded(
            cancel,
            Duration::ZERO,
            Duration::from_secs(1),
            std::future::pending::<Result<HttpsProbeReport, &'static str>>(),
        )
        .await;
        assert!(matches!(result, ProbeResult::Inconclusive));

        let (mut actor, _) = test_actor();
        actor.latencies = latencies([("d2", 11), ("d3", 12)]);
        actor.cycle = Some(test_cycle());
        actor.on_probe_output(ProbeOutput::Https(relay_url(1), result));
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(1)));

        let result = guarded(
            CancellationToken::new(),
            Duration::ZERO,
            Duration::from_secs(1),
            async { Err::<HttpsProbeReport, _>("unreachable") },
        )
        .await;
        actor.cycle = Some(test_cycle());
        actor.on_probe_output(ProbeOutput::Https(relay_url(1), result));
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
    }

    #[tokio::test(start_paused = true)]
    async fn test_probe_timeout_and_panic_evidence() {
        let result = guarded(
            CancellationToken::new(),
            Duration::ZERO,
            Duration::from_secs(1),
            std::future::pending::<Result<(), &'static str>>(),
        )
        .await;
        assert!(matches!(result, ProbeResult::Failed));
        let result = guarded(
            CancellationToken::new(),
            Duration::ZERO,
            Duration::from_secs(1),
            async {
                panic!("broken probe");
                #[allow(unreachable_code)]
                Ok::<(), &'static str>(())
            },
        )
        .await;
        assert!(matches!(result, ProbeResult::Inconclusive));
    }

    #[tokio::test]
    async fn test_cached_latency_does_not_rearm_offline_failover() {
        let (mut actor, _) = test_actor();
        actor.failed_over = true;
        actor.latencies = latencies([("d1", 10)]);
        let mut cycle = test_cycle();
        cycle.progress[AddrFamily::V4] = Progress::Kept;
        actor.cycle = Some(cycle);
        actor.finish_cycle(Instant::now());
        assert!(actor.failed_over);
        // A genuine success recovers immediately, even while other probes still run.
        let mut cycle = test_cycle();
        cycle.probes.push(Box::pin(std::future::pending()));
        actor.cycle = Some(cycle);
        actor.on_probe_output(ProbeOutput::Https(
            relay_url(2),
            ProbeResult::Success(HttpsProbeReport {
                relay_url: relay_url(2),
                latency: Duration::from_secs(11),
            }),
        ));
        assert!(!actor.failed_over);
        actor.failed_over = true;
        actor.on_qad_observation(
            AddrFamily::V4,
            &QadProbeReport {
                relay_url: relay_url(2),
                latency: Duration::from_secs(11),
                addr: "192.0.2.1:1234".parse().unwrap(),
            },
        );
        assert!(!actor.failed_over);
    }

    #[tokio::test]
    async fn test_failover_publishes_report_and_stops_until_recovery() {
        let (mut actor, status) = test_actor();
        actor.latencies = latencies([("d1", 10), ("d2", 11), ("d3", 12)]);
        actor.publish();
        let fail = |actor: &mut NetReportActor, relay| {
            let failure = RelayStatus::failed_dial_for_test(relay_url(relay));
            status.set(Some(failure.clone())).unwrap();
            actor.opts.relay_status.get();
            actor.on_relay_status(Some(failure));
        };
        fail(&mut actor, 1);
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
        assert!(actor.failed_over);
        assert_eq!(
            actor.outputs.report.get().unwrap().preferred_relay,
            Some(relay_url(2))
        );
        fail(&mut actor, 2);
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
        // A refresh retaining the failed old relay's QAD reading cannot undo the guard.
        actor.latencies = latencies([("d1", 10)]);
        let mut cycle = test_cycle();
        cycle.failed.insert(relay_url(2));
        cycle.progress[AddrFamily::V4] = Progress::Kept;
        actor.cycle = Some(cycle);
        actor.finish_cycle(Instant::now());
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
        assert!(actor.failed_over);

        let connected = RelayStatus::new(
            relay_url(2),
            crate::socket::transports::RelayConnectionState::Connected,
        );
        status.set(Some(connected.clone())).unwrap();
        actor.opts.relay_status.get();
        actor.on_relay_status(Some(connected));
        assert!(!actor.failed_over);
        fail(&mut actor, 2);
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(1)));
        assert_eq!(
            actor.outputs.report.get().unwrap().preferred_relay,
            Some(relay_url(1))
        );
    }

    #[tokio::test]
    async fn test_unsuccessful_failover_does_not_latch() {
        let (mut actor, status) = test_actor();
        actor.history = History::default();
        let failure = RelayStatus::failed_dial_for_test(relay_url(1));
        status.set(Some(failure.clone())).unwrap();
        actor.opts.relay_status.get();
        actor.on_relay_status(Some(failure));
        assert!(!actor.failed_over);
    }

    #[tokio::test]
    async fn test_portal_result_initializes_report() {
        for found in [false, true] {
            let (mut actor, _) = test_actor();
            actor.cycle = Some(test_cycle());
            actor.on_probe_output(ProbeOutput::CaptivePortal(ProbeResult::Success(found)));
            assert_eq!(
                actor.outputs.report.get().unwrap().captive_portal,
                Some(found)
            );
        }
    }
    #[tokio::test]
    async fn test_offline_guard_allows_replacing_removed_home() {
        let (mut actor, _) = test_actor();
        actor.failed_over = true;
        actor.opts.relay_map = RelayMap::from(RelayConfig::from(relay_url(2)));
        assert!(actor.decide_home_relay(None, Candidates::Recent));
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
    }
    #[tokio::test]
    async fn test_failed_cycles_do_not_rotate_cached_relays() {
        let (mut actor, _) = test_actor();
        actor.latencies = latencies([("d2", 11), ("d3", 12)]);
        let mut cycle = test_cycle();
        cycle.failed.insert(relay_url(1));
        actor.cycle = Some(cycle);
        actor.finish_cycle(Instant::now());
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
        assert!(actor.failed_over);

        let mut cycle = test_cycle();
        cycle.failed.insert(relay_url(2));
        actor.cycle = Some(cycle);
        actor.finish_cycle(Instant::now());
        assert_eq!(actor.outputs.home_relay.get(), Some(relay_url(2)));
    }
}
