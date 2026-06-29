//! Smoothed round-trip-time tracking used to order nameservers fastest-first.

use std::{sync::Mutex, time::Instant};

use n0_future::time::Duration;

/// EWMA weight for folding a new RTT sample into a nameserver's smoothed RTT.
const SRTT_ALPHA: f64 = 0.3;
/// Neutral smoothed-RTT baseline (microseconds) for a never-probed nameserver,
/// and the value the estimate decays toward. Measured-fast servers sit below it
/// and are preferred; failed servers sit above it and are demoted. Decaying
/// toward this (rather than toward zero) keeps a measured-fast server ahead of
/// an idle or recovering one instead of the other way round.
const SRTT_BASELINE_MICROS: f64 = 50_000.0;
/// Penalty added to a nameserver's smoothed RTT on a failed attempt, in
/// microseconds. Large enough to demote it below currently-healthy servers.
const SRTT_FAILURE_PENALTY_MICROS: f64 = 150_000.0;
/// Upper bound on a nameserver's smoothed RTT, in microseconds.
const SRTT_MAX_MICROS: f64 = 5_000_000.0;
/// Time constant (seconds) of the read-time decay of the smoothed RTT toward
/// the baseline, so demoted servers recover and idle estimates lapse to neutral.
const SRTT_DECAY_SECS: f64 = 180.0;

/// Smoothed round-trip time estimate for one nameserver.
///
/// Used to order nameservers fastest-first and to demote ones that fail. A
/// read-time exponential decay pulls the estimate back toward zero so that a
/// demoted server eventually gets re-probed, and a once-fast server that has
/// gone away does not stay preferred forever.
#[derive(Debug)]
struct Srtt {
    /// Smoothed estimate in microseconds, as of `updated`.
    micros: f64,
    /// When `micros` was last written.
    updated: Instant,
}

impl Srtt {
    fn new() -> Self {
        Self {
            micros: SRTT_BASELINE_MICROS,
            updated: Instant::now(),
        }
    }

    /// The decayed estimate at `now`, used for ordering. Relaxes toward
    /// [`SRTT_BASELINE_MICROS`] as the estimate ages.
    fn decayed(&self, now: Instant) -> f64 {
        let dt = now.saturating_duration_since(self.updated).as_secs_f64();
        SRTT_BASELINE_MICROS + (self.micros - SRTT_BASELINE_MICROS) * (-dt / SRTT_DECAY_SECS).exp()
    }

    /// Folds a successful round-trip time into the estimate.
    fn record_success(&mut self, rtt: Duration, now: Instant) {
        let sample = rtt.as_micros() as f64;
        let base = self.decayed(now);
        self.micros = (SRTT_ALPHA * sample + (1.0 - SRTT_ALPHA) * base).min(SRTT_MAX_MICROS);
        self.updated = now;
    }

    /// Penalizes the estimate after a failed attempt.
    fn record_failure(&mut self, now: Instant) {
        let base = self.decayed(now);
        self.micros = (base + SRTT_FAILURE_PENALTY_MICROS).min(SRTT_MAX_MICROS);
        self.updated = now;
    }
}

/// Smoothed-RTT estimates for a fixed set of nameservers, indexed in parallel
/// to the resolver's nameserver list.
///
/// Behind a single mutex so the resolver can read and update health from
/// concurrent queries without threading a lock through the call sites.
#[derive(Debug)]
pub(super) struct RttMap {
    entries: Mutex<Vec<Srtt>>,
}

impl RttMap {
    /// Creates a map with `len` nameservers, each at the neutral baseline.
    pub(super) fn new(len: usize) -> Self {
        Self {
            entries: Mutex::new((0..len).map(|_| Srtt::new()).collect()),
        }
    }

    /// Returns the decayed smoothed RTT for nameserver `idx`, used for ordering.
    pub(super) fn get_decayed(&self, idx: usize) -> f64 {
        self.entries.lock().expect("poisoned")[idx].decayed(Instant::now())
    }

    /// Folds a successful round-trip time for nameserver `idx` into its estimate.
    pub(super) fn record_success(&self, idx: usize, rtt: Duration) {
        self.entries.lock().expect("poisoned")[idx].record_success(rtt, Instant::now());
    }

    /// Penalizes nameserver `idx` after a failed attempt.
    pub(super) fn record_failure(&self, idx: usize) {
        self.entries.lock().expect("poisoned")[idx].record_failure(Instant::now());
    }
}
