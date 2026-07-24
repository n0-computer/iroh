//! Default [`PathSelector`] implementation.
//!
//! [`BiasedRttPathSelector`] preserves iroh's historical "lowest biased RTT wins, with
//! stickiness against flapping" behaviour and is what's installed when no custom
//! selector is provided.

use std::{sync::Arc, time::Duration};

use rustc_hash::FxHashMap;
use tracing::trace;

use super::{
    remote_map::{PathSelection, PathSelectionContext, PathSelectionData, PathSelector},
    transports::AddrKind,
};
use crate::socket::transports::FourTuple;

/// How much do we prefer IPv6 over IPv4 by default.
const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Stickiness threshold for biased RTT comparisons.  Switching to a same-tier path only
/// happens when its biased RTT is at least this much better than the current path's.
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// Whether a transport is a primary path or a backup.
///
/// Primary paths are used preferentially.  Backup paths are only used when no primary
/// path is available.  This is independent of the QUIC `PathStatus`; today the only
/// transport classified as backup is the relay transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TransportType {
    /// A primary path: used whenever available.
    Primary,
    /// A backup path: only used when no primary path is available.
    Backup,
}

/// Bias configuration for a single transport kind.
///
/// Used by [`BiasedRttPathSelector`] to bias path selection per address kind.
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
    fn backup() -> Self {
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
    #[cfg(all(test, feature = "unstable-custom-transports"))]
    pub(crate) fn with_rtt_disadvantage(mut self, disadvantage: Duration) -> Self {
        self.rtt_bias += disadvantage.as_nanos() as i128;
        self
    }
}

/// The default [`PathSelector`] used by iroh.
///
/// Sorts paths by `(transport_type, biased_rtt)` (primary tier wins, then lowest biased
/// RTT).  Within the same tier, switching only happens once a candidate's biased RTT is
/// at least 5ms better than the currently-selected path — this avoids flapping under
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
    /// Returns a new selector with the given bias added or updated for `kind`.
    #[cfg(all(test, feature = "unstable-custom-transports"))]
    pub(crate) fn with_bias(self, kind: AddrKind, bias: TransportBias) -> Self {
        let mut map = (*self.biases).clone();
        map.insert(kind, bias);
        Self {
            biases: Arc::new(map),
        }
    }

    /// Looks up the bias for an address.  Defaults to primary with no RTT bias.
    fn bias_for(&self, addr: &FourTuple) -> TransportBias {
        self.biases
            .get(&addr.addr_kind())
            .copied()
            .unwrap_or_else(TransportBias::primary)
    }

    /// Computes the sort key for a path: lower is better.
    fn sort_key(&self, addr: &FourTuple, rtt: Duration) -> (TransportType, i128) {
        let bias = self.bias_for(addr);
        let biased_rtt = (rtt.as_nanos() as i128).saturating_add(bias.rtt_bias);
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
        let mut best: Option<(PathSelectionData<'_>, (TransportType, i128))> = None;
        let mut current_key: Option<(TransportType, i128)> = None;

        trace!("dumping path RTTs");
        for psd in ctx.paths() {
            let network_path = psd.network_path();
            // Skip paths whose stats can't be read (e.g. closed concurrently with select).
            let Some(stats) = psd.stats() else {
                continue;
            };
            // A suspect path stopped acknowledging data; its stale RTT would
            // otherwise keep winning against live but slower paths.
            if stats.suspect {
                trace!(%network_path, "skipping suspect path");
                continue;
            }
            let rtt = stats.rtt;
            trace!(%network_path, ?rtt);
            let key = self.sort_key(network_path, rtt);

            if Some(network_path) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best.as_ref().is_none_or(|(_, b)| key < *b) {
                best = Some((psd, key));
            }
        }

        let mut selection = PathSelection::none();
        let Some((best_psd, (best_tier, best_biased))) = best else {
            return selection;
        };

        // If we have no current path or no data for it, switch to the best.
        let Some((current_tier, current_biased)) = current_key else {
            selection.set(&best_psd);
            return selection;
        };

        if current_tier != best_tier {
            // Always switch across tiers (e.g. relay -> primary).
            selection.set(&best_psd);
        } else if best_biased + RTT_SWITCHING_MIN.as_nanos() as i128 <= current_biased {
            // For the same tier, only switch when biased RTT is meaningfully better.
            selection.set(&best_psd);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use iroh_base::{EndpointId, RelayUrl};
    use noq::PathStats;

    use super::*;
    use crate::socket::{
        remote_map::{PathSelectionContext, PathSelectionData},
        transports::{self, Addr},
    };

    fn v4(port: u16) -> transports::FourTuple {
        transports::FourTuple::from_remote(Addr::Ip(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            port,
        ))))
    }

    fn v6(port: u16) -> transports::FourTuple {
        transports::FourTuple::from_remote(Addr::Ip(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            port,
            0,
            0,
        ))))
    }

    fn relay(port: u16) -> transports::FourTuple {
        let url = format!("https://relay{port}.iroh.computer")
            .parse::<RelayUrl>()
            .unwrap();
        transports::FourTuple::from_remote(Addr::Relay(
            url,
            EndpointId::from_bytes(&[0u8; 32]).unwrap(),
        ))
    }

    fn psd(addr: &transports::FourTuple, rtt_ms: u64) -> PathSelectionData<'_> {
        // PathStats is #[non_exhaustive], so build via Default + field assignment.
        let mut stats = PathStats::default();
        stats.rtt = Duration::from_millis(rtt_ms);
        PathSelectionData::for_test(addr, Some(stats))
    }

    /// Runs [`BiasedRttPathSelector::default`] against the given paths and current
    /// selection, returning the selector's primary pick (cloned, for easier asserts).
    fn select_with_default(
        current: Option<&transports::FourTuple>,
        paths: Vec<PathSelectionData<'_>>,
    ) -> Option<transports::FourTuple> {
        let ctx = PathSelectionContext::for_test(current, paths);
        BiasedRttPathSelector::default()
            .select(&ctx)
            .selected()
            .cloned()
    }

    #[test]
    fn ipv6_wins_over_ipv4_within_bias() {
        let v4 = v4(1);
        let v6 = v6(1);

        // Equal RTTs: IPv6 wins because of the bias advantage.
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 10)]);
        assert_eq!(chosen.as_ref(), Some(&v6));

        // IPv6 still wins when 2ms slower (within the 3ms bias).
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 12)]);
        assert_eq!(chosen.as_ref(), Some(&v6));

        // IPv4 wins when IPv6 is 10ms slower (exceeds 3ms bias).
        let chosen = select_with_default(None, vec![psd(&v4, 10), psd(&v6, 20)]);
        assert_eq!(chosen.as_ref(), Some(&v4));
    }

    #[test]
    fn primary_wins_over_backup_regardless_of_rtt() {
        let v4 = v4(1);
        let relay = relay(1);

        // Primary tier beats backup tier even when the backup has a much lower RTT.
        let chosen = select_with_default(None, vec![psd(&v4, 100), psd(&relay, 10)]);
        assert!(matches!(
            chosen.as_ref().map(|t| t.remote()),
            Some(Addr::Ip(_))
        ));

        // Even more extreme: 1000ms primary still wins over 1ms backup.
        let chosen = select_with_default(None, vec![psd(&v4, 1000), psd(&relay, 1)]);
        assert!(matches!(
            chosen.as_ref().map(|t| t.remote()),
            Some(Addr::Ip(_))
        ));
    }

    #[test]
    fn same_tier_only_switches_with_significant_rtt_diff() {
        let v4_1 = v4(1);
        let v4_2 = v4(2);

        // 2ms diff < 5ms threshold → keep current (no switch, primary() == None).
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 18)]);
        assert_eq!(chosen, None);

        // 4ms diff < 5ms → keep current.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 16)]);
        assert_eq!(chosen, None);

        // 5ms diff hits the threshold (the condition is `<=`) → switch.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 15)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));

        // 6ms diff > 5ms → switch.
        let chosen = select_with_default(Some(&v4_1), vec![psd(&v4_1, 20), psd(&v4_2, 14)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));
    }

    #[test]
    fn no_current_path_selects_best() {
        let v4_1 = v4(1);
        let v4_2 = v4(2);
        let chosen = select_with_default(None, vec![psd(&v4_1, 20), psd(&v4_2, 10)]);
        assert_eq!(chosen.as_ref(), Some(&v4_2));
    }

    #[test]
    fn empty_paths_returns_none() {
        // No current, no candidates: nothing to pick.
        assert_eq!(select_with_default(None, vec![]), None);

        // Current is set but there are no candidates: keep current (primary() == None).
        let v4 = v4(1);
        assert_eq!(select_with_default(Some(&v4), vec![]), None);
    }
}
