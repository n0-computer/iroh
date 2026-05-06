//! Pluggable path selection.
//!
//! [`PathSelector`] decides which path is the preferred one to use among the candidates
//! known to a remote endpoint.  The default implementation is [`BiasedRttPathSelector`],
//! which preserves iroh's historical "lowest biased RTT wins, with stickiness against
//! flapping" behaviour.

// The `pub` items here are re-exported only behind `unstable-custom-transports`; the
// `pub(crate)` items (the default selector and its bias config) are used directly by
// tests and by `RemoteStateActor`.  Some configuration knobs (`with_rtt_disadvantage`,
// `with_bias`) are reachable only from `cfg(test)` callers, so allow `dead_code`
// unconditionally to avoid noise in non-test builds.
#![allow(dead_code)]
#![cfg_attr(not(feature = "unstable-custom-transports"), allow(unreachable_pub))]

use std::{fmt::Debug, sync::Arc, time::Duration};

use rustc_hash::FxHashMap;

use super::{
    remote_map::PathSelectionContext,
    transports::{Addr, AddrKind},
};

/// Implementations of this trait decide which path is the preferred one to use among the
/// candidate paths known to a remote endpoint.
///
/// The default selector sorts by biased RTT and is sticky to avoid flapping.  Most users
/// do not need to provide their own selector.
///
/// # Aggregation across connections
///
/// One iroh remote endpoint can have multiple QUIC connections active at the same time
/// (e.g. during reconnect or when a protocol opens several connections in parallel).
/// Each connection carries its own per-path stats — RTT, congestion window, loss
/// counters, etc.  As a result [`PathSelectionContext::paths`] may yield the **same
/// address more than once**, with different [`PathStats`] each time.
///
/// Selector implementations are responsible for choosing how to aggregate those samples
/// into a per-address ranking.  The default selector takes the minimum RTT.  A selector
/// that ranks on a different signal (e.g. `pacing_rate`, `cwnd`, packet loss) may want a
/// different aggregation — there is no single "right" answer at the framework level.
///
/// # Stability against flapping
///
/// Selectors are called repeatedly as path stats update.  RTT (and other signals) jitter
/// in real networks; a selector that picks "lowest RTT wins, no questions asked" will
/// flap between candidates that happen to be within noise.  Use [`PathSelectionContext::current`]
/// and a hysteresis threshold (e.g. "only switch if the new biased RTT is at least 5ms
/// better than the current one") to avoid this.  Note that hysteresis only against
/// `current` still leaves the choice *among* equally-good non-current candidates greedy
/// — if that matters for your algorithm, apply a within-noise tie-break (cwnd, MTU, …)
/// before comparing to `current`.
pub trait PathSelector: Send + Sync + Debug + 'static {
    /// Picks a path among the candidates known for a remote endpoint.
    ///
    /// Build the result by starting from [`PathSelection::default`] and calling
    /// [`PathSelection::add`] for each path the selector wants active.  Today only the
    /// first added path is used; future iroh releases may support multiple selected
    /// paths concurrently, at which point further added paths will be respected.
    ///
    /// Returning an empty [`PathSelection`] keeps the current selection unchanged.
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection;
}

/// The set of paths a [`PathSelector`] has chosen.
///
/// Today this holds at most one path; future iroh releases will support multi-path
/// selection.  Build via [`PathSelection::default`] + [`PathSelection::add`] so selector
/// code that wants to nominate multiple paths can already be written today (additional
/// paths are dropped with a warning until multi-path support lands).
#[derive(Debug, Clone, Default)]
pub struct PathSelection {
    // Today: at most one path.  Future: a `SmallVec<[Addr; 1]>` (or similar) so the
    // single-path case remains zero-allocation while multi-path becomes possible.
    inner: Option<Addr>,
}

impl PathSelection {
    /// Adds a path to the selection.
    ///
    /// Today the selection holds at most one path: the first call wins, subsequent
    /// calls log a warning and are ignored.  When multi-path selection ships, all
    /// added paths will be respected and the warning will go away.
    pub fn add(&mut self, addr: &Addr) {
        if self.inner.is_some() {
            tracing::warn!(
                ?addr,
                "PathSelection already contains a path; ignoring additional path \
                 (multi-path selection is not yet supported)"
            );
            return;
        }
        self.inner = Some(addr.clone());
    }

    /// The primary path: the one data should be sent on.
    ///
    /// Returns `None` when nothing has been added.
    pub fn primary(&self) -> Option<&Addr> {
        self.inner.as_ref()
    }

    /// All paths in this selection (today: 0 or 1).
    pub fn iter(&self) -> impl Iterator<Item = &Addr> + '_ {
        self.inner.iter()
    }
}

/// Whether a transport is a primary path or a backup.
///
/// Primary paths are used preferentially.  Backup paths are only used when no primary
/// path is available.  This is independent of the QUIC `PathStatus`; today the only
/// transport classified as backup is the relay transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum TransportType {
    /// A primary path: used whenever available.
    Primary = 0,
    /// A backup path: only used when no primary path is available.
    Backup = 1,
}

/// Bias configuration for a single transport kind.
///
/// Used by [`BiasedRttPathSelector`] to bias path selection per address kind.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use iroh::endpoint::transports::TransportBias;
///
/// // A primary transport with 100ms RTT advantage (will be preferred).
/// let bias = TransportBias::primary().with_rtt_advantage(Duration::from_millis(100));
///
/// // A primary transport with 50ms RTT disadvantage (will be less preferred).
/// let bias = TransportBias::primary().with_rtt_disadvantage(Duration::from_millis(50));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TransportBias {
    transport_type: TransportType,
    /// RTT bias in nanoseconds.  Negative values make this transport more preferred.
    rtt_bias: i128,
}

impl TransportBias {
    /// Creates a primary transport bias with no RTT advantage.
    pub(crate) fn primary() -> Self {
        Self {
            transport_type: TransportType::Primary,
            rtt_bias: 0,
        }
    }

    /// Creates a backup transport bias with no RTT advantage.
    pub(crate) fn backup() -> Self {
        Self {
            transport_type: TransportType::Backup,
            rtt_bias: 0,
        }
    }

    /// Adds an RTT advantage to this transport, making it more preferred.
    pub(crate) fn with_rtt_advantage(mut self, advantage: Duration) -> Self {
        self.rtt_bias -= advantage.as_nanos() as i128;
        self
    }

    /// Adds an RTT disadvantage to this transport, making it less preferred.
    pub(crate) fn with_rtt_disadvantage(mut self, disadvantage: Duration) -> Self {
        self.rtt_bias += disadvantage.as_nanos() as i128;
        self
    }
}

/// How much do we prefer IPv6 over IPv4 by default.
const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Stickiness threshold for biased RTT comparisons.  Switching to a same-tier path only
/// happens when its biased RTT is at least this much better than the current path's.
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// The default [`PathSelector`] used by iroh.
///
/// Sorts paths by `(transport_type, biased_rtt)` (primary tier wins, then lowest biased
/// RTT).  Within the same tier, switching only happens once a candidate's biased RTT is
/// at least 50ms better than the currently-selected path — this avoids flapping under
/// jitter.  Across tiers, switching is immediate.
///
/// The biases are configured per [`AddrKind`].  Defaults: IPv4 and IPv6 are primary
/// (IPv6 has a 3ms RTT advantage), Relay is backup, custom transports are primary with
/// no advantage.
#[derive(Debug, Clone)]
pub(crate) struct BiasedRttPathSelector {
    biases: Arc<FxHashMap<AddrKind, TransportBias>>,
}

impl Default for BiasedRttPathSelector {
    fn default() -> Self {
        let mut map = FxHashMap::default();
        map.insert(AddrKind::IpV4, TransportBias::primary());
        map.insert(
            AddrKind::IpV6,
            TransportBias::primary().with_rtt_advantage(IPV6_RTT_ADVANTAGE),
        );
        map.insert(AddrKind::Relay, TransportBias::backup());
        Self {
            biases: Arc::new(map),
        }
    }
}

impl BiasedRttPathSelector {
    /// Creates a new [`BiasedRttPathSelector`] with the default biases.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns a new selector with the given bias added or updated for `kind`.
    pub(crate) fn with_bias(self, kind: AddrKind, bias: TransportBias) -> Self {
        let mut map = (*self.biases).clone();
        map.insert(kind, bias);
        Self {
            biases: Arc::new(map),
        }
    }

    /// Looks up the bias for an address.  Defaults to primary with no RTT bias.
    fn bias_for(&self, addr: &Addr) -> TransportBias {
        self.biases
            .get(&addr.addr_kind())
            .copied()
            .unwrap_or_else(TransportBias::primary)
    }

    /// Computes the sort key for a path: lower is better.
    fn sort_key(&self, addr: &Addr, rtt: Duration) -> (TransportType, i128) {
        let bias = self.bias_for(addr);
        let biased_rtt = rtt.as_nanos() as i128 + bias.rtt_bias;
        (bias.transport_type, biased_rtt)
    }
}

impl PathSelector for BiasedRttPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        // Single pass: track the best candidate by sort key, and the best (lowest)
        // sort key seen for the currently-selected address.  When the same address
        // appears multiple times (one path per connection), `min` over `sort_key`
        // naturally picks the lowest-RTT instance — no separate aggregation needed.
        let current = ctx.current();
        let mut best: Option<(&Addr, (TransportType, i128))> = None;
        let mut current_key: Option<(TransportType, i128)> = None;

        for psd in ctx.paths() {
            let addr = psd.addr();
            // Skip paths whose stats can't be read (e.g. closed concurrently with select).
            let Some(stats) = psd.stats() else {
                continue;
            };
            let key = self.sort_key(addr, stats.rtt);

            if Some(addr) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best.is_none_or(|(_, b)| key < b) {
                best = Some((addr, key));
            }
        }

        let mut selection = PathSelection::default();
        let Some((best_addr, (best_tier, best_biased))) = best else {
            return selection;
        };

        // If we have no current path or no data for it, switch to the best.
        let Some((current_tier, current_biased)) = current_key else {
            selection.add(best_addr);
            return selection;
        };

        if current_tier != best_tier {
            // Always switch across tiers (e.g. relay -> primary).
            selection.add(best_addr);
        } else if best_biased + RTT_SWITCHING_MIN.as_nanos() as i128 <= current_biased {
            // For the same tier, only switch when biased RTT is meaningfully better.
            selection.add(best_addr);
        }
        selection
    }
}

// Note: unit tests for `BiasedRttPathSelector::select` lived here previously, driving the
// algorithm with synthetic (addr, rtt) pairs.  The new `PathSelectionContext` walks live
// `noq::Connection`s lazily, so the algorithm is now exercised by the integration tests in
// `test_utils::test_transport` (`test_custom_transport_only`,
// `test_custom_transport_wins_over_ip`, `test_ip_wins_over_custom`,
// `test_custom_transport_wins_over_relay`) which use real connections end-to-end.
