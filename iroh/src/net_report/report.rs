use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};
use tracing::{trace, warn};

use super::{ProbeReport, probes::Probe};

/// A net_report report.
#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Report {
    /// A QAD IPv4 round trip completed.
    pub udp_v4: bool,
    /// A QAD IPv6 round trip completed.
    pub udp_v6: bool,
    /// Whether the reported public address differs when probing different servers (on IPv4).
    pub mapping_varies_by_dest_ipv4: Option<bool>,
    /// Whether the reported public address differs when probing different servers (on IPv6).
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// Probe indicating the presence of port mapping protocols on the LAN.
    /// `None` for unknown
    pub preferred_relay: Option<RelayUrl>,
    /// keyed by relay Url
    pub relay_latency: RelayLatencies,
    /// ip:port of global IPv4
    pub global_v4: Option<SocketAddrV4>,
    /// `[ip]:port` of global IPv6
    pub global_v6: Option<SocketAddrV6>,
    /// CaptivePortal is set when we think there's a captive portal that is
    /// intercepting HTTP traffic.
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

    /// Updates a net_report [`Report`] with a new [`ProbeReport`].
    pub(super) fn update(&mut self, report: &ProbeReport) {
        match report {
            ProbeReport::Https(report) => {
                self.relay_latency
                    .update_relay(report.relay.clone(), report.latency, Probe::Https);
            }
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv4(report) => {
                self.relay_latency.update_relay(
                    report.relay.clone(),
                    report.latency,
                    Probe::QadIpv4,
                );
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
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv6(report) => {
                self.relay_latency.update_relay(
                    report.relay.clone(),
                    report.latency,
                    Probe::QadIpv6,
                );
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
    }
}

/// Latencies per relay endpoint.
#[derive(Debug, Default, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct RelayLatencies {
    #[cfg(not(wasm_browser))]
    ipv4: BTreeMap<RelayUrl, Duration>,
    #[cfg(not(wasm_browser))]
    ipv6: BTreeMap<RelayUrl, Duration>,
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
