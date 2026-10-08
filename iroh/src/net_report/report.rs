//! The debug network report and per-relay latency bookkeeping.

use std::{collections::BTreeMap, time::Duration};

#[cfg(any(test, feature = "unstable-net-report"))]
use std::{
    fmt,
    net::{SocketAddrV4, SocketAddrV6},
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};

/// Snapshot of what the net report knows about the network.
///
/// This is a debug view, published through `Endpoint::net_report`. The net
/// report assembles it from its state whenever that state changes.
#[cfg(any(test, feature = "unstable-net-report"))]
#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
#[non_exhaustive]
pub struct Report {
    /// Whether a QAD IPv4 round trip succeeded.
    pub udp_v4: bool,
    /// Whether a QAD IPv6 round trip succeeded.
    pub udp_v6: bool,
    /// Whether the observed public IPv4 address differs across relay servers.
    ///
    /// `None` until at least two relays have reported.
    pub mapping_varies_by_dest_ipv4: Option<bool>,
    /// Whether the observed public IPv6 address differs across relay servers.
    ///
    /// `None` until at least two relays have reported.
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// The relay with the lowest recent latency, chosen with hysteresis.
    ///
    /// `None` until at least one latency measurement exists.
    pub preferred_relay: Option<RelayUrl>,
    /// Best observed latency to each relay, keyed by relay URL.
    pub relay_latency: RelayLatencies,
    /// Public IPv4 address and port as observed by relay servers.
    pub global_v4: Option<SocketAddrV4>,
    /// Public IPv6 address and port as observed by relay servers.
    pub global_v6: Option<SocketAddrV6>,
    /// Whether a captive portal was detected.
    ///
    /// `None` if the check was skipped, cancelled, or has not yet completed.
    pub captive_portal: Option<bool>,
}

#[cfg(any(test, feature = "unstable-net-report"))]
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

#[cfg(any(test, feature = "unstable-net-report"))]
impl Report {
    /// Returns `true` if any probe indicates UDP is working.
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn has_udp(&self) -> bool {
        self.udp_v4 || self.udp_v6
    }

    /// Returns whether the reported public address differs across servers.
    #[cfg_attr(
        not(feature = "unstable-net-report"),
        allow(unreachable_pub, dead_code)
    )]
    pub fn mapping_varies_by_dest(&self) -> Option<bool> {
        match (
            self.mapping_varies_by_dest_ipv4,
            self.mapping_varies_by_dest_ipv6,
        ) {
            (Some(v4), Some(v6)) => Some(v4 || v6),
            (None, Some(v6)) => Some(v6),
            (Some(v4), None) => Some(v4),
            (None, None) => None,
        }
    }

    /// Returns `true` if the report carries meaningful probe data.
    ///
    /// Used to wait for the first observation before initializing the report.
    pub(super) fn has_data(&self) -> bool {
        self.global_v4.is_some()
            || self.global_v6.is_some()
            || self.has_udp()
            || !self.relay_latency.is_empty()
            || self.captive_portal.is_some()
    }
}

/// The protocol used to time a relay's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Display)]
#[repr(u8)]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
#[non_exhaustive]
pub enum Probe {
    /// An HTTPS latency probe.
    Https,
    /// A QUIC address discovery probe over IPv4.
    QadIpv4,
    /// A QUIC address discovery probe over IPv6.
    QadIpv6,
}

/// Best observed latency to each relay, bucketed by probe type.
///
/// Keeps separate maps for QAD IPv4, QAD IPv6, and HTTPS. Latency lookups
/// return the minimum across all three maps for a given relay, so a relay
/// reachable by any probe type compares on its fastest path.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
pub struct RelayLatencies {
    /// Best QAD IPv4 latency per relay.
    ipv4: BTreeMap<RelayUrl, Duration>,
    /// Best QAD IPv6 latency per relay.
    ipv6: BTreeMap<RelayUrl, Duration>,
    /// Best HTTPS latency per relay.
    https: BTreeMap<RelayUrl, Duration>,
}

impl RelayLatencies {
    /// Updates a relay's latency, if it is faster than before.
    pub(super) fn update_relay(&mut self, url: RelayUrl, latency: Duration, probe: Probe) {
        let list = match probe {
            Probe::Https => &mut self.https,
            Probe::QadIpv4 => &mut self.ipv4,
            Probe::QadIpv6 => &mut self.ipv6,
        };
        let old_latency = list.entry(url).or_insert(latency);
        *old_latency = (*old_latency).min(latency);
    }

    /// Merges another [`RelayLatencies`] into this one, keeping the best of each.
    pub(super) fn merge(&mut self, other: &RelayLatencies) {
        for (probe, url, latency) in other.iter() {
            self.update_relay(url.clone(), latency, probe);
        }
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .map(|(url, l)| (Probe::Https, url, *l))
            .chain(self.ipv4.iter().map(|(url, l)| (Probe::QadIpv4, url, *l)))
            .chain(self.ipv6.iter().map(|(url, l)| (Probe::QadIpv6, url, *l)))
    }

    /// Returns `true` if no relay has any latency recorded.
    pub(super) fn is_empty(&self) -> bool {
        self.iter().next().is_none()
    }

    /// Returns the lowest latency to `url` across probe types.
    pub(super) fn get(&self, url: &RelayUrl) -> Option<Duration> {
        [&self.https, &self.ipv4, &self.ipv6]
            .into_iter()
            .filter_map(|latencies| latencies.get(url))
            .copied()
            .min()
    }
}
