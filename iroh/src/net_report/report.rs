use std::{
    collections::BTreeMap,
    fmt,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use iroh_base::RelayUrl;
use tracing::warn;

use super::{reportgen::ProbeProto, ProbeReport};

/// A net_report report.
///
/// Can be obtained by calling [`Client::get_report`].
#[derive(Default, Debug, PartialEq, Eq, Clone)]
pub struct Report {
    /// A UDP STUN round trip completed.
    pub udp: bool,
    /// An IPv6 round trip completed.
    pub ipv6: bool,
    /// An IPv4 round trip completed.
    pub ipv4: bool,
    /// An IPv6 packet was able to be sent
    pub ipv6_can_send: bool,
    /// an IPv4 packet was able to be sent
    pub ipv4_can_send: bool,
    /// could bind a socket to ::1
    pub os_has_ipv6: bool,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv4).
    pub mapping_varies_by_dest_ip: Option<bool>,
    /// Whether STUN results depend on which STUN server you're talking to (on IPv6).
    ///
    /// Note that we don't really expect this to happen and are merely logging this if
    /// detecting rather than using it.  For now.
    pub mapping_varies_by_dest_ipv6: Option<bool>,
    /// Probe indicating the presence of port mapping protocols on the LAN.
    pub portmap_probe: Option<portmapper::ProbeOutput>,
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
    /// Updates a net_report [`Report`] with a new [`ProbeReport`].
    pub(super) fn update(&mut self, probe_report: &ProbeReport) {
        let relay_node = probe_report.probe.node();
        if let Some(latency) = probe_report.latency {
            self.relay_latency.update_relay(
                relay_node.url.clone(),
                latency,
                probe_report.probe.proto(),
            );

            #[cfg(not(wasm_browser))]
            if matches!(
                probe_report.probe.proto(),
                ProbeProto::QadIpv4 | ProbeProto::QadIpv6
            ) {
                self.udp = true;

                match probe_report.addr {
                    Some(SocketAddr::V4(ipp)) => {
                        self.ipv4 = true;
                        if self.global_v4.is_none() {
                            self.global_v4 = Some(ipp);
                        } else if self.global_v4 != Some(ipp) {
                            self.mapping_varies_by_dest_ip = Some(true);
                        } else if self.mapping_varies_by_dest_ip.is_none() {
                            self.mapping_varies_by_dest_ip = Some(false);
                        }
                    }
                    Some(SocketAddr::V6(ipp)) => {
                        self.ipv6 = true;
                        if self.global_v6.is_none() {
                            self.global_v6 = Some(ipp);
                        } else if self.global_v6 != Some(ipp) {
                            self.mapping_varies_by_dest_ipv6 = Some(true);
                            warn!("IPv6 Address detected by STUN varies by destination");
                        } else if self.mapping_varies_by_dest_ipv6.is_none() {
                            self.mapping_varies_by_dest_ipv6 = Some(false);
                        }
                    }
                    None => {
                        // If we are here we had a relay server latency reported from a STUN probe.
                        // Thus we must have a reported address.
                        debug_assert!(probe_report.addr.is_some());
                    }
                }
            }
        }
        self.ipv4_can_send |= probe_report.ipv4_can_send;
        self.ipv6_can_send |= probe_report.ipv6_can_send;
    }
}

/// Latencies per relay node.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct RelayLatencies {
    #[cfg(not(wasm_browser))]
    ipv4: BTreeMap<RelayUrl, Duration>,
    #[cfg(not(wasm_browser))]
    ipv6: BTreeMap<RelayUrl, Duration>,
    https: BTreeMap<RelayUrl, Duration>,
}

impl RelayLatencies {
    /// Updates a relay's latency, if it is faster than before.
    pub(super) fn update_relay(&mut self, url: RelayUrl, latency: Duration, probe: ProbeProto) {
        let list = match probe {
            ProbeProto::Https => &mut self.https,
            #[cfg(not(wasm_browser))]
            ProbeProto::QadIpv4 => &mut self.ipv4,
            #[cfg(not(wasm_browser))]
            ProbeProto::QadIpv6 => &mut self.ipv6,
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
            self.update_relay(url.clone(), *latency, ProbeProto::Https);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv4.iter() {
            self.update_relay(url.clone(), *latency, ProbeProto::QadIpv4);
        }
        #[cfg(not(wasm_browser))]
        for (url, latency) in other.ipv6.iter() {
            self.update_relay(url.clone(), *latency, ProbeProto::QadIpv6);
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

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.https.len() + self.ipv4.len() + self.ipv6.len()
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

    #[cfg(not(wasm_browser))]
    pub(super) fn ipv4(&self) -> &BTreeMap<RelayUrl, Duration> {
        &self.ipv4
    }

    #[cfg(not(wasm_browser))]
    pub(super) fn ipv6(&self) -> &BTreeMap<RelayUrl, Duration> {
        &self.ipv6
    }
}
