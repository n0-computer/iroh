//! Default [`PathSelector`] implementation.
//!
//! [`BiasedRttPathSelector`] preserves iroh's historical "lowest biased RTT wins, with
//! stickiness against flapping" behaviour and is what's installed when no custom
//! selector is provided.

#![allow(dead_code)]

use std::{sync::Arc, time::Duration};

use rustc_hash::FxHashMap;

use super::{
    remote_map::{PathSelection, PathSelectionContext, PathSelector},
    transports::{Addr, AddrKind},
};

/// Whether a transport is a primary path or a backup.
///
/// Primary paths are used preferentially.  Backup paths are only used when no primary
/// path is available.  This is independent of the QUIC `PathStatus`; today the only
/// transport classified as backup is the relay transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TransportType {
    /// A primary path: used whenever available.
    Primary = 0,
    /// A backup path: only used when no primary path is available.
    Backup = 1,
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
