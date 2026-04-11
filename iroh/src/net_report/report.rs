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
use super::qad::QadProbeReport;
use super::{https::HttpsProbeReport, probes::Probe};

/// Snapshot of the host's network conditions as determined by probe results.
///
/// Populated incrementally during a probe cycle and published via the
/// report watcher. Fields start at their `Default` values and are filled
/// in as individual probes complete.
#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Whether a QAD IPv4 round trip succeeded.
    pub udp_v4: bool,
    /// Whether a QAD IPv6 round trip succeeded.
    pub udp_v6: bool,
    /// Whether the observed public IPv4 address differs across relay servers.
    /// `None` until at least two relays have reported.
    pub mapping_varies_by_dest_ipv4: Option<bool>,
    /// Whether the observed public IPv6 address differs across relay servers.
    /// `None` until at least two relays have reported.
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// The relay with the lowest recent latency, chosen with hysteresis.
    /// `None` until at least one latency measurement exists.
    pub preferred_relay: Option<RelayUrl>,
    /// Best observed latency to each relay, keyed by relay URL.
    pub relay_latency: RelayLatencies,
    /// Public IPv4 address and port as observed by relay servers.
    pub global_v4: Option<SocketAddrV4>,
    /// Public IPv6 address and port as observed by relay servers.
    pub global_v6: Option<SocketAddrV6>,
    /// Whether a captive portal was detected. `None` if the check was
    /// skipped, cancelled, or has not yet completed.
    pub captive_portal: Option<bool>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

impl Report {
    /// Do we have any indication that UDP is working?
    pub fn has_udp(&self) -> bool {
        self.udp_v4 || self.udp_v6
    }

    /// Whether the reported public address differs when probing different servers.
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

    /// Incorporates an HTTPS probe result into the report's relay latencies.
    pub(super) fn update_https(&mut self, report: &HttpsProbeReport) {
        self.relay_latency
            .update_relay(report.relay.clone(), report.latency, Probe::Https);
    }

    /// Incorporates a QAD IPv4 probe result into the report.
    ///
    /// Updates relay latencies, sets `udp_v4` to true, and records or
    /// compares the observed global IPv4 address. When multiple relays
    /// report different addresses, `mapping_varies_by_dest_ipv4` is set.
    #[cfg(not(wasm_browser))]
    pub(super) fn update_qad_v4(&mut self, report: &QadProbeReport) {
        self.relay_latency
            .update_relay(report.relay.clone(), report.latency, Probe::QadIpv4);
        let SocketAddr::V4(ipp) = report.addr else {
            warn!("received IPv6 address from IPv4 QAD: {}", report.addr);
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
    pub(super) fn update_qad_v6(&mut self, report: &QadProbeReport) {
        self.relay_latency
            .update_relay(report.relay.clone(), report.latency, Probe::QadIpv6);
        let SocketAddr::V6(ipp) = report.addr else {
            warn!("received IPv4 address from IPv6 QAD: {}", report.addr);
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
}

/// Best observed latency to each relay, bucketed by probe type.
///
/// Keeps separate maps for IPv4, IPv6, and HTTPS so the caller can
/// reason about per-protocol reachability. The [`get`](Self::get) method
/// returns the minimum across all protocol maps for a given relay.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
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
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .map(|(url, l)| (Probe::Https, url, *l))
            .chain(self.ipv4.iter().map(|(url, l)| (Probe::QadIpv4, url, *l)))
            .chain(self.ipv6.iter().map(|(url, l)| (Probe::QadIpv6, url, *l)))
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(wasm_browser)]
    pub fn iter(&self) -> impl Iterator<Item = (Probe, &'_ RelayUrl, Duration)> + '_ {
        self.https.iter().map(|(k, v)| (Probe::Https, k, *v))
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn is_empty(&self) -> bool {
        self.https.is_empty() && self.ipv4.is_empty() && self.ipv6.is_empty()
    }

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
