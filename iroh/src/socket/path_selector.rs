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

use super::transports::{Addr, AddrKind};
use crate::endpoint::quic::PathStats;

/// Implementations of this trait decide which path is the preferred one to use among the
/// candidate paths known to a remote endpoint.
///
/// The default selector ([`BiasedRttPathSelector`]) sorts by biased RTT and is sticky to
/// avoid flapping.  Most users do not need to provide their own selector.
pub trait PathSelector: Send + Sync + Debug + 'static {
    /// Picks a path among the candidates known for a remote endpoint.
    ///
    /// Returns `Some(addr)` to make `addr` the new selected path.  Returning `Some` with
    /// the same address as `state.current()` is a no-op.  Returning `None` keeps the
    /// current selection unchanged.
    fn select(&self, state: &PathSelectionContext<'_>) -> Option<Addr>;
}

/// State of the endpoint relevant for path selection.
///
/// Constructed by the endpoint and passed to [`PathSelector::select`].  Borrows from
/// the endpoint's internal data.
#[derive(Debug)]
pub struct PathSelectionContext<'a> {
    current: Option<&'a Addr>,
    paths: &'a [(&'a Addr, PathStats)],
}

impl<'a> PathSelectionContext<'a> {
    /// Constructs a [`PathSelectionContext`].  Used by the framework and by tests.
    pub(crate) fn new(current: Option<&'a Addr>, paths: &'a [(&'a Addr, PathStats)]) -> Self {
        Self { current, paths }
    }

    /// The path currently considered the preferred path to the remote endpoint, if any.
    pub fn current(&self) -> Option<&'a Addr> {
        self.current
    }

    /// Iterator over candidate paths.
    ///
    /// The same address may appear more than once when it is a path on multiple
    /// connections to the remote.  Selectors that care should aggregate as appropriate.
    pub fn paths(&self) -> impl Iterator<Item = PathSelectionData<'a>> + '_ {
        self.paths
            .iter()
            .map(|(addr, stats)| PathSelectionData { addr, stats })
    }
}

/// Data the selector sees about one candidate path.
///
/// This currently provides the path statistics (RTT, loss, etc.) but may be
/// extended in the future with other data.
#[derive(Debug)]
pub struct PathSelectionData<'a> {
    addr: &'a Addr,
    stats: &'a PathStats,
}

impl<'a> PathSelectionData<'a> {
    /// The address of the candidate path.
    pub fn addr(&self) -> &'a Addr {
        self.addr
    }

    /// QUIC path statistics: rtt, cwnd, loss, mtu, etc.
    pub fn stats(&self) -> &'a PathStats {
        self.stats
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
    fn select(&self, state: &PathSelectionContext<'_>) -> Option<Addr> {
        // Single pass: track the best candidate by sort key, and the best (lowest)
        // sort key seen for the currently-selected address.  When the same address
        // appears multiple times (one path per connection), `min` over `sort_key`
        // naturally picks the lowest-RTT instance — no separate aggregation needed.
        let current = state.current();
        let mut best: Option<(&Addr, (TransportType, i128))> = None;
        let mut current_key: Option<(TransportType, i128)> = None;

        for psd in state.paths() {
            let addr = psd.addr();
            let key = self.sort_key(addr, psd.stats().rtt);

            if Some(addr) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best.is_none_or(|(_, b)| key < b) {
                best = Some((addr, key));
            }
        }

        let (best_addr, (best_tier, best_biased)) = best?;

        // If we have no current path or no data for it, switch to the best.
        let Some((current_tier, current_biased)) = current_key else {
            return Some(best_addr.clone());
        };

        if current_tier != best_tier {
            // Always switch across tiers (e.g. relay -> primary).
            Some(best_addr.clone())
        } else if best_biased + RTT_SWITCHING_MIN.as_nanos() as i128 <= current_biased {
            // For the same tier, only switch when biased RTT is meaningfully better.
            Some(best_addr.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use iroh_base::{EndpointId, RelayUrl};

    use super::*;

    fn v4(port: u16) -> Addr {
        Addr::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))
    }

    fn v6(port: u16) -> Addr {
        Addr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        )))
    }

    fn relay(port: u16) -> Addr {
        let url = format!("https://relay{port}.iroh.computer")
            .parse::<RelayUrl>()
            .unwrap();
        Addr::Relay(url, EndpointId::from_bytes(&[0u8; 32]).unwrap())
    }

    fn stats(rtt_ms: u64) -> PathStats {
        let mut s = PathStats::default();
        s.rtt = Duration::from_millis(rtt_ms);
        s
    }

    /// Run the default selector against a slice of (addr, rtt_ms) pairs and an optional current.
    fn select(paths: &[(Addr, u64)], current: Option<&Addr>) -> Option<Addr> {
        let buf: Vec<(&Addr, PathStats)> = paths
            .iter()
            .map(|(addr, rtt_ms)| (addr, stats(*rtt_ms)))
            .collect();
        let state = PathSelectionContext::new(current, &buf);
        BiasedRttPathSelector::default().select(&state)
    }

    #[test]
    fn ipv6_wins_over_ipv4_within_bias() {
        // Equal RTTs: IPv6 wins (3ms bias).
        let paths = [(v4(1), 10), (v6(1), 10)];
        let chosen = select(&paths, None).unwrap();
        assert!(matches!(chosen, Addr::Ip(SocketAddr::V6(_))));

        // IPv6 2ms slower, still within 3ms bias: IPv6 wins.
        let paths = [(v4(1), 10), (v6(1), 12)];
        let chosen = select(&paths, None).unwrap();
        assert!(matches!(chosen, Addr::Ip(SocketAddr::V6(_))));

        // IPv6 10ms slower, exceeds 3ms bias: IPv4 wins.
        let paths = [(v4(1), 10), (v6(1), 20)];
        let chosen = select(&paths, None).unwrap();
        assert!(matches!(chosen, Addr::Ip(SocketAddr::V4(_))));
    }

    #[test]
    fn primary_wins_over_backup_regardless_of_rtt() {
        // High-RTT primary still wins over low-RTT backup.
        let paths = [(v4(1), 100), (relay(1), 10)];
        let chosen = select(&paths, None).unwrap();
        assert!(chosen.is_ip());

        let paths = [(v4(1), 1000), (relay(1), 1)];
        let chosen = select(&paths, None).unwrap();
        assert!(chosen.is_ip());
    }

    #[test]
    fn same_tier_only_switches_with_significant_rtt_diff() {
        let current = v4(1);

        // 2ms better < 5ms threshold: keep current.
        let paths = [(v4(1), 20), (v4(2), 18)];
        assert!(select(&paths, Some(&current)).is_none());

        // 4ms better < 5ms threshold: keep current.
        let paths = [(v4(1), 20), (v4(2), 16)];
        assert!(select(&paths, Some(&current)).is_none());

        // Exactly 5ms better == threshold: switch.
        let paths = [(v4(1), 20), (v4(2), 15)];
        assert_eq!(select(&paths, Some(&current)).unwrap(), v4(2));

        // 6ms better > threshold: switch.
        let paths = [(v4(1), 20), (v4(2), 14)];
        assert_eq!(select(&paths, Some(&current)).unwrap(), v4(2));
    }

    #[test]
    fn no_current_path_selects_best() {
        let paths = [(v4(1), 20), (v4(2), 10)];
        assert_eq!(select(&paths, None).unwrap(), v4(2));
    }

    #[test]
    fn empty_paths_returns_none() {
        assert!(select(&[], None).is_none());
        assert!(select(&[], Some(&v4(1))).is_none());
    }
}
