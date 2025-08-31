use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{ProbeReport, probes::Probe};

/// A net_report report.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct Report {
    /// A QAD IPv4 round trip completed.
    pub udp_v4: bool,
    /// A QAD IPv6 round trip completed.
    pub udp_v6: bool,
    /// Whether the reported public address differs when probing different servers (on IPv4).
    pub mapping_varies_by_dest_ipv4: Option<bool>,
    /// Whether the reported public address differs when probing different servers (on IPv6).
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// Whether the reported public port differs when probing different destination ports (on IPv4).
    pub mapping_varies_by_dest_port_ipv4: Option<bool>,
    /// Whether the reported public port differs when probing different destination ports (on IPv6).
    pub mapping_varies_by_dest_port_ipv6: Option<bool>,
    /// Whether hairpinning (sending to own external address) works for IPv4.
    pub hairpinning_ipv4: Option<bool>,
    /// Whether hairpinning (sending to own external address) works for IPv6.
    pub hairpinning_ipv6: Option<bool>,
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

    // Internal tracking for port mapping variation detection
    /// Tracks IPv4 public ports seen from different destination ports (dest_port -> public_port)
    ipv4_port_mappings: BTreeMap<u16, u16>,
    /// Tracks IPv6 public ports seen from different destination ports (dest_port -> public_port)
    ipv6_port_mappings: BTreeMap<u16, u16>,
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

    /// Whether the reported public port differs when probing different destination ports.
    pub fn mapping_varies_by_dest_port(&self) -> Option<bool> {
        match (
            self.mapping_varies_by_dest_port_ipv4,
            self.mapping_varies_by_dest_port_ipv6,
        ) {
            (Some(v4), Some(v6)) => Some(v4 || v6),
            (None, Some(v6)) => Some(v6),
            (Some(v4), None) => Some(v4),
            (None, None) => None,
        }
    }

    /// Whether hairpinning (sending to own external address) works.
    pub fn hairpinning(&self) -> Option<bool> {
        match (self.hairpinning_ipv4, self.hairpinning_ipv6) {
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
                    .update_relay(report.node.clone(), report.latency, Probe::Https);
            }
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv4(report) => {
                self.relay_latency.update_relay(
                    report.node.clone(),
                    report.latency,
                    Probe::QadIpv4,
                );
                let SocketAddr::V4(ipp) = report.addr else {
                    warn!("received IPv6 address from IPv4 QAD: {}", report.addr);
                    return;
                };

                self.udp_v4 = true;

                tracing::debug!(?self.global_v4, ?self.mapping_varies_by_dest_ipv4, %ipp,"got");
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

                let public_port = ipp.port();
                let dest_port = report.dest_port;

                if let Some(&existing_public_port) = self.ipv4_port_mappings.get(&dest_port) {
                    if existing_public_port != public_port {
                        self.mapping_varies_by_dest_port_ipv4 = Some(true);
                        warn!(
                            "IPv4 public port varies by destination port: dest {} -> public {} (was {})",
                            dest_port, public_port, existing_public_port
                        );
                    } else if self.mapping_varies_by_dest_port_ipv4.is_none() {
                        let has_different_mappings = self
                            .ipv4_port_mappings
                            .values()
                            .any(|&port| port != public_port);
                        self.mapping_varies_by_dest_port_ipv4 = Some(has_different_mappings);
                    }
                } else {
                    self.ipv4_port_mappings.insert(dest_port, public_port);

                    if self.ipv4_port_mappings.len() > 1 {
                        let has_different_mappings = self
                            .ipv4_port_mappings
                            .values()
                            .any(|&port| port != public_port);
                        if has_different_mappings {
                            self.mapping_varies_by_dest_port_ipv4 = Some(true);
                        } else if self.mapping_varies_by_dest_port_ipv4.is_none() {
                            self.mapping_varies_by_dest_port_ipv4 = Some(false);
                        }
                    }
                }

                if let Some(hairpinning_result) = report.hairpinning_works {
                    self.hairpinning_ipv4 = Some(hairpinning_result);
                }
            }
            #[cfg(not(wasm_browser))]
            ProbeReport::QadIpv6(report) => {
                self.relay_latency.update_relay(
                    report.node.clone(),
                    report.latency,
                    Probe::QadIpv6,
                );
                let SocketAddr::V6(ipp) = report.addr else {
                    warn!("received IPv4 address from IPv6 QAD: {}", report.addr);
                    return;
                };

                self.udp_v6 = true;
                tracing::debug!(?self.global_v6, ?self.mapping_varies_by_dest_ipv6, %ipp,"got");
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

                let public_port = ipp.port();
                let dest_port = report.dest_port;

                if let Some(&existing_public_port) = self.ipv6_port_mappings.get(&dest_port) {
                    if existing_public_port != public_port {
                        self.mapping_varies_by_dest_port_ipv6 = Some(true);
                        warn!(
                            "IPv6 public port varies by destination port: dest {} -> public {} (was {})",
                            dest_port, public_port, existing_public_port
                        );
                    } else if self.mapping_varies_by_dest_port_ipv6.is_none() {
                        let has_different_mappings = self
                            .ipv6_port_mappings
                            .values()
                            .any(|&port| port != public_port);
                        self.mapping_varies_by_dest_port_ipv6 = Some(has_different_mappings);
                    }
                } else {
                    self.ipv6_port_mappings.insert(dest_port, public_port);

                    if self.ipv6_port_mappings.len() > 1 {
                        let has_different_mappings = self
                            .ipv6_port_mappings
                            .values()
                            .any(|&port| port != public_port);
                        if has_different_mappings {
                            self.mapping_varies_by_dest_port_ipv6 = Some(true);
                        } else if self.mapping_varies_by_dest_port_ipv6.is_none() {
                            self.mapping_varies_by_dest_port_ipv6 = Some(false);
                        }
                    }
                }

                if let Some(hairpinning_result) = report.hairpinning_works {
                    self.hairpinning_ipv6 = Some(hairpinning_result);
                }
            }
        }
    }
}

/// Latencies per relay node.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq, Clone)]
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
            Probe::QadIpv4 | Probe::QadIpv4PortVariation => &mut self.ipv4,
            #[cfg(not(wasm_browser))]
            Probe::QadIpv6 | Probe::QadIpv6PortVariation => &mut self.ipv6,
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
    pub fn iter(&self) -> impl Iterator<Item = (&'_ RelayUrl, Duration)> + '_ {
        self.https
            .iter()
            .chain(self.ipv4.iter())
            .chain(self.ipv6.iter())
            .map(|(k, v)| (k, *v))
    }

    /// Returns an iterator over all the relays and their latencies.
    #[cfg(wasm_browser)]
    pub fn iter(&self) -> impl Iterator<Item = (&'_ RelayUrl, Duration)> + '_ {
        self.https.iter().map(|(k, v)| (k, *v))
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

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use iroh_base::RelayUrl;

    use super::*;
    use crate::net_report::reportgen::{ProbeReport, QadProbeReport};

    #[test]
    fn test_port_mapping_variation_detection_ipv4() {
        let mut report = Report::default();
        let relay_url = RelayUrl::from(url::Url::parse("https://relay.example.com").unwrap());

        // Test Case 1: Same public port for different destination ports -> false
        let probe_port_7842 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(50),
            addr: "203.0.113.42:54321".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: None,
        });

        let probe_port_7843 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(52),
            addr: "203.0.113.42:54321".parse::<SocketAddr>().unwrap(), // Same public port
            dest_port: 7843,
            hairpinning_works: None,
        });

        report.update(&probe_port_7842);
        assert_eq!(
            report.mapping_varies_by_dest_port_ipv4, None,
            "Should be None with only one probe"
        );

        report.update(&probe_port_7843);
        assert_eq!(
            report.mapping_varies_by_dest_port_ipv4,
            Some(false),
            "Should be false when public ports are the same"
        );

        // Test Case 2: Different public port for third destination port -> true
        let probe_port_7844 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(48),
            addr: "203.0.113.42:54322".parse::<SocketAddr>().unwrap(), // Different public port
            dest_port: 7844,
            hairpinning_works: None,
        });

        report.update(&probe_port_7844);
        assert_eq!(
            report.mapping_varies_by_dest_port_ipv4,
            Some(true),
            "Should be true when public ports vary"
        );

        // Verify the mappings are tracked correctly
        assert_eq!(report.ipv4_port_mappings.get(&7842), Some(&54321));
        assert_eq!(report.ipv4_port_mappings.get(&7843), Some(&54321));
        assert_eq!(report.ipv4_port_mappings.get(&7844), Some(&54322));
    }

    #[test]
    fn test_port_mapping_variation_detection_ipv6() {
        let mut report = Report::default();
        let relay_url = RelayUrl::from(url::Url::parse("https://relay.example.com").unwrap());

        // Test IPv6 with port mapping variation
        let probe_v6_7842 = ProbeReport::QadIpv6(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(45),
            addr: "[2001:db8::1]:54321".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: None,
        });

        let probe_v6_7843 = ProbeReport::QadIpv6(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(47),
            addr: "[2001:db8::1]:54399".parse::<SocketAddr>().unwrap(), // Different public port
            dest_port: 7843,
            hairpinning_works: None,
        });

        report.update(&probe_v6_7842);
        assert_eq!(report.mapping_varies_by_dest_port_ipv6, None);

        report.update(&probe_v6_7843);
        assert_eq!(
            report.mapping_varies_by_dest_port_ipv6,
            Some(true),
            "Should detect IPv6 port variation"
        );

        // Verify IPv6 mappings
        assert_eq!(report.ipv6_port_mappings.get(&7842), Some(&54321));
        assert_eq!(report.ipv6_port_mappings.get(&7843), Some(&54399));
    }

    #[test]
    fn test_port_mapping_same_dest_port_different_public_ports() {
        let mut report = Report::default();
        let relay_url = RelayUrl::from(url::Url::parse("https://relay.example.com").unwrap());

        // Test same destination port reporting different public ports (unstable NAT)
        let probe1 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(50),
            addr: "203.0.113.42:54321".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: None,
        });

        let probe2 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(52),
            addr: "203.0.113.42:54322".parse::<SocketAddr>().unwrap(), // Different public port for same dest port
            dest_port: 7842,
            hairpinning_works: None,
        });

        report.update(&probe1);
        assert_eq!(report.mapping_varies_by_dest_port_ipv4, None);

        report.update(&probe2);
        assert_eq!(
            report.mapping_varies_by_dest_port_ipv4,
            Some(true),
            "Should detect unstable mapping for same dest port"
        );
    }

    #[test]
    fn test_hairpinning_detection() {
        let mut report = Report::default();
        let relay_url = RelayUrl::from(url::Url::parse("https://relay.example.com").unwrap());

        // Test hairpinning works
        let probe_hairpin_works = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(50),
            addr: "203.0.113.42:54321".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: Some(true),
        });

        report.update(&probe_hairpin_works);
        assert_eq!(report.hairpinning_ipv4, Some(true));

        // Test hairpinning doesn't work (should override previous value)
        let probe_hairpin_fails = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(55),
            addr: "203.0.113.42:54322".parse::<SocketAddr>().unwrap(),
            dest_port: 7843,
            hairpinning_works: Some(false),
        });

        report.update(&probe_hairpin_fails);
        assert_eq!(
            report.hairpinning_ipv4,
            Some(false),
            "Should update hairpinning result"
        );
    }

    #[test]
    fn test_combined_functionality() {
        let mut report = Report::default();
        let relay_url = RelayUrl::from(url::Url::parse("https://relay.example.com").unwrap());

        // Test that the combined helper functions work correctly
        let probe1 = ProbeReport::QadIpv4(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(50),
            addr: "203.0.113.42:54321".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: Some(true),
        });

        let probe2 = ProbeReport::QadIpv6(QadProbeReport {
            node: relay_url.clone(),
            latency: Duration::from_millis(45),
            addr: "[2001:db8::1]:54399".parse::<SocketAddr>().unwrap(),
            dest_port: 7842,
            hairpinning_works: Some(false),
        });

        report.update(&probe1);
        report.update(&probe2);

        // Test the combined helper functions
        assert_eq!(
            report.mapping_varies_by_dest_port(),
            None,
            "Should be None when only one dest port tested per IP version"
        );
        assert_eq!(
            report.hairpinning(),
            Some(true),
            "Should be true if any IP version supports hairpinning"
        );
    }
}
