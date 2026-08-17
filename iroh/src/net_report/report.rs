//! The network [`Report`] and its per-relay latency bookkeeping.

use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

#[cfg(not(wasm_browser))]
use super::qad::{AddrFamily, QadProbeReport};
use super::{https::HttpsProbeReport, probes::Probe};

/// Snapshot of the host's network conditions as determined by probe results.
///
/// Populated incrementally during a probe cycle and published via the
/// report watcher. Fields start at their `Default` values and are filled
/// in as individual probes complete.
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

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl Report {
    /// Returns `true` if any probe indicates UDP is working.
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn has_udp(&self) -> bool {
        self.udp_v4 || self.udp_v6
    }

    /// Returns whether the reported public address differs across servers.
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
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
    /// Used to avoid publishing an empty report over a previous one.
    pub(super) fn has_data(&self) -> bool {
        self.global_v4.is_some()
            || self.global_v6.is_some()
            || self.has_udp()
            || !self.relay_latency.is_empty()
    }

    /// Incorporates an HTTPS probe result into the report's relay latencies.
    pub(super) fn apply_https_result(&mut self, probe_report: &HttpsProbeReport) {
        self.relay_latency.update_relay(
            probe_report.relay_url.clone(),
            probe_report.latency,
            Probe::Https,
        );
    }

    /// Applies a QAD probe result for `family`.
    ///
    /// Records the address, and decides mapping-varies-by-destination once a
    /// second relay has answered.
    #[cfg(not(wasm_browser))]
    pub(super) fn apply_qad_result(&mut self, family: AddrFamily, probe_report: &QadProbeReport) {
        match family {
            AddrFamily::V4 => self.apply_qad_result_v4(probe_report),
            AddrFamily::V6 => self.apply_qad_result_v6(probe_report),
        }
    }

    /// Applies an address seen on the open QAD connection for `family`.
    ///
    /// Unlike a probe result this only replaces the address; it never decides
    /// mapping-varies, because a change on a single open connection is a
    /// genuine address change rather than a per-destination difference.
    #[cfg(not(wasm_browser))]
    pub(super) fn apply_qad_observation(
        &mut self,
        family: AddrFamily,
        probe_report: &QadProbeReport,
    ) {
        match family {
            AddrFamily::V4 => self.apply_qad_observation_v4(probe_report),
            AddrFamily::V6 => self.apply_qad_observation_v6(probe_report),
        }
    }

    /// Incorporates a QAD IPv4 probe result into the report.
    ///
    /// Updates relay latencies, sets `udp_v4` to true, and records or
    /// compares the observed global IPv4 address. When multiple relays
    /// report different addresses, `mapping_varies_by_dest_ipv4` is set.
    #[cfg(not(wasm_browser))]
    fn apply_qad_result_v4(&mut self, probe_report: &QadProbeReport) {
        self.relay_latency.update_relay(
            probe_report.relay_url.clone(),
            probe_report.latency,
            Probe::QadIpv4,
        );
        let SocketAddr::V4(ipp) = probe_report.addr else {
            warn!("received IPv6 address from IPv4 QAD: {}", probe_report.addr);
            return;
        };

        self.udp_v4 = true;

        if let Some(global) = self.global_v4 {
            if global == ipp {
                if self.mapping_varies_by_dest_ipv4.is_none() {
                    self.mapping_varies_by_dest_ipv4 = Some(false);
                }
            } else {
                self.mapping_varies_by_dest_ipv4 = Some(true);
                warn!("IPv4 address detected by QAD varies by destination");
            }
        } else {
            self.global_v4 = Some(ipp);
        }
        trace!(?self.global_v4, ?self.mapping_varies_by_dest_ipv4, %ipp, "stored report");
    }

    /// Incorporates a QAD IPv6 probe result into the report.
    ///
    /// Updates relay latencies, sets `udp_v6` to true, and records or
    /// compares the observed global IPv6 address. When multiple relays
    /// report different addresses, `mapping_varies_by_dest_ipv6` is set.
    #[cfg(not(wasm_browser))]
    fn apply_qad_result_v6(&mut self, probe_report: &QadProbeReport) {
        self.relay_latency.update_relay(
            probe_report.relay_url.clone(),
            probe_report.latency,
            Probe::QadIpv6,
        );
        let SocketAddr::V6(ipp) = probe_report.addr else {
            warn!("received IPv4 address from IPv6 QAD: {}", probe_report.addr);
            return;
        };

        self.udp_v6 = true;
        if let Some(global) = self.global_v6 {
            if global == ipp {
                if self.mapping_varies_by_dest_ipv6.is_none() {
                    self.mapping_varies_by_dest_ipv6 = Some(false);
                }
            } else {
                self.mapping_varies_by_dest_ipv6 = Some(true);
                warn!("IPv6 address detected by QAD varies by destination");
            }
        } else {
            self.global_v6 = Some(ipp);
        }
        trace!(?self.global_v6, ?self.mapping_varies_by_dest_ipv6, %ipp, "stored report");
    }

    /// Records a QAD IPv4 address seen on the open connection.
    ///
    /// Unlike [`apply_qad_result_v4`](Self::apply_qad_result_v4), this does
    /// no mapping-varies-by-destination detection. A changed address on a
    /// single open connection means our address really changed, for example
    /// because the NAT rebound, not that it depends on the destination, so
    /// the new address just replaces the old one.
    #[cfg(not(wasm_browser))]
    fn apply_qad_observation_v4(&mut self, probe_report: &QadProbeReport) {
        self.relay_latency.update_relay(
            probe_report.relay_url.clone(),
            probe_report.latency,
            Probe::QadIpv4,
        );
        let SocketAddr::V4(ipp) = probe_report.addr else {
            warn!("received IPv6 address from IPv4 QAD: {}", probe_report.addr);
            return;
        };
        self.udp_v4 = true;
        self.global_v4 = Some(ipp);
    }

    /// Records a QAD IPv6 address seen on the open connection.
    ///
    /// See [`apply_qad_observation_v4`](Self::apply_qad_observation_v4).
    #[cfg(not(wasm_browser))]
    fn apply_qad_observation_v6(&mut self, probe_report: &QadProbeReport) {
        self.relay_latency.update_relay(
            probe_report.relay_url.clone(),
            probe_report.latency,
            Probe::QadIpv6,
        );
        let SocketAddr::V6(ipp) = probe_report.addr else {
            warn!("received IPv4 address from IPv6 QAD: {}", probe_report.addr);
            return;
        };
        self.udp_v6 = true;
        self.global_v6 = Some(ipp);
    }
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
    #[cfg(not(wasm_browser))]
    ipv4: BTreeMap<RelayUrl, Duration>,
    /// Best QAD IPv6 latency per relay.
    #[cfg(not(wasm_browser))]
    ipv6: BTreeMap<RelayUrl, Duration>,
    /// Best HTTPS latency per relay.
    https: BTreeMap<RelayUrl, Duration>,
}

impl RelayLatencies {
    /// Updates a relay's latency, if it is faster than before.
    pub(super) fn update_relay(&mut self, url: RelayUrl, latency: Duration, probe: Probe) {
        let list = match probe {
            Probe::Https => &mut self.https,
            #[cfg(not(wasm_browser))]
            Probe::QadIpv4 => &mut self.ipv4,
            #[cfg(not(wasm_browser))]
            Probe::QadIpv6 => &mut self.ipv6,
        };
        let old_latency = list.entry(url).or_insert(latency);
        if latency < *old_latency {
            *old_latency = latency;
        }
    }

    /// Merges another [`RelayLatencies`] into this one.
    ///
    /// For each relay the latency is updated using [`RelayLatencies::update_relay`].
    pub(super) fn merge(&mut self, other: &RelayLatencies) {
        for (url, latency) in other.https.iter() {
            self.update_relay(url.clone(), *latency, Probe::Https);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv4.iter() {
            self.update_relay(url.clone(), *latency, Probe::QadIpv4);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv6.iter() {
            self.update_relay(url.clone(), *latency, Probe::QadIpv6);
        }
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(not(wasm_browser))]
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .map(|(url, l)| (Probe::Https, url, *l))
            .chain(self.ipv4.iter().map(|(url, l)| (Probe::QadIpv4, url, *l)))
            .chain(self.ipv6.iter().map(|(url, l)| (Probe::QadIpv6, url, *l)))
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(wasm_browser)]
    #[cfg_attr(not(feature = "unstable-net-report"), allow(unreachable_pub))]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https.iter().map(|(k, v)| (Probe::Https, k, *v))
    }

    /// Returns `true` if no relay has any latency recorded.
    #[cfg(not(wasm_browser))]
    pub(super) fn is_empty(&self) -> bool {
        self.https.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    /// Returns `true` if no relay has any latency recorded.
    #[cfg(wasm_browser)]
    pub(super) fn is_empty(&self) -> bool {
        self.https.is_empty()
    }

    /// Returns the lowest latency across records.
    pub(super) fn get(&self, url: &RelayUrl) -> Option<Duration> {
        let mut list = Vec::with_capacity(3);
        if let Some(val) = self.https.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv4.get(url) {
            list.push(*val);
        }
        #[cfg(not(wasm_browser))]
        if let Some(val) = self.ipv6.get(url) {
            list.push(*val);
        }
        list.into_iter().min()
    }
}

#[cfg(all(test, not(wasm_browser)))]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::*;

    fn qad_v4(addr: SocketAddrV4) -> QadProbeReport {
        QadProbeReport {
            relay_url: "http://relay.example".parse().unwrap(),
            latency: Duration::from_millis(10),
            addr: SocketAddr::V4(addr),
        }
    }

    #[test]
    fn test_apply_qad_result_needs_two_results_for_mapping_varies() {
        let a = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1000);
        let b = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 2000);

        // A single result sets the address but leaves mapping-varies undecided.
        let mut r = Report::default();
        r.apply_qad_result_v4(&qad_v4(a));
        assert_eq!(r.global_v4, Some(a));
        assert_eq!(r.mapping_varies_by_dest_ipv4, None);

        // A matching second result decides "does not vary".
        r.apply_qad_result_v4(&qad_v4(a));
        assert_eq!(r.mapping_varies_by_dest_ipv4, Some(false));

        // A differing second result decides "varies by destination" and keeps
        // the first address as the global one.
        let mut r = Report::default();
        r.apply_qad_result_v4(&qad_v4(a));
        r.apply_qad_result_v4(&qad_v4(b));
        assert_eq!(r.global_v4, Some(a));
        assert_eq!(r.mapping_varies_by_dest_ipv4, Some(true));
    }

    #[test]
    fn test_apply_qad_observation_replaces_address() {
        let a = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 1000);
        let b = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 2000);

        let mut r = Report::default();
        r.apply_qad_result_v4(&qad_v4(a));

        // An address seen on the open connection replaces the old one (our
        // address changed) without flagging mapping-varies.
        r.apply_qad_observation_v4(&qad_v4(b));
        assert_eq!(r.global_v4, Some(b));
        assert_eq!(r.mapping_varies_by_dest_ipv4, None);
    }
}
