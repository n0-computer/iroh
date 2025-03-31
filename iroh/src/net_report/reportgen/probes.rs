//! The relay probes.
//!
//! All the probes try and establish the latency to the relay servers.  Preferably the STUN
//! probes work and we also learn about our public IP addresses and ports.  But fallback
//! probes for HTTPS and ICMP exist as well.

use std::{collections::BTreeSet, fmt, sync::Arc};

use anyhow::{ensure, Result};
use iroh_base::RelayUrl;
use iroh_relay::{RelayMap, RelayNode};
use n0_future::time::Duration;
#[cfg(not(wasm_browser))]
use netwatch::interfaces;

use crate::net_report::Report;

/// The retransmit interval used when net_report first runs.
///
/// We have no past context to work with, and we want answers relatively quickly, so it's
/// biased slightly more aggressive than [`DEFAULT_ACTIVE_RETRANSMIT_DELAY`]. A few extra
/// packets at startup is fine.
const DEFAULT_INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

/// The retransmit interval used when a previous report exists but is missing latency.
///
/// When in an active steady-state, i.e. a previous report exists, we use the latency of the
/// previous report to determine the retransmit interval.  However when this previous relay
/// latency is missing this default is used.
///
/// This is a somewhat conservative guess because if we have no data, likely the relay node
/// is very far away and we have no data because we timed out the last time we probed it.
const DEFAULT_ACTIVE_RETRANSMIT_DELAY: Duration = Duration::from_millis(200);

/// The extra time to add to retransmits if a previous report exists.
///
/// When in an active steady-state, i.e. a previous report exists, we add this delay
/// multiplied with the attempt to probe retries to give later attempts increasingly more
/// time.
const ACTIVE_RETRANSMIT_EXTRA_DELAY: Duration = Duration::from_millis(50);

/// The number of fastest relays to periodically re-query during incremental net_report
/// reports. (During a full report, all relay servers are scanned.)
const NUM_INCREMENTAL_RELAYS: usize = 3;

/// The protocol used to time a node's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Display)]
#[repr(u8)]
pub enum ProbeProto {
    /// STUN IPv4
    #[cfg(not(wasm_browser))]
    StunIpv4,
    /// STUN IPv6
    #[cfg(not(wasm_browser))]
    StunIpv6,
    /// HTTPS
    Https,
    /// ICMP IPv4
    #[cfg(not(wasm_browser))]
    IcmpV4,
    /// ICMP IPv6
    #[cfg(not(wasm_browser))]
    IcmpV6,
    /// QUIC Address Discovery Ipv4
    #[cfg(not(wasm_browser))]
    QuicIpv4,
    /// QUIC Address Discovery Ipv6
    #[cfg(not(wasm_browser))]
    QuicIpv6,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, derive_more::Display)]
pub(super) enum Probe {
    #[display("STUN Ipv4 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    StunIpv4 {
        /// When the probe is started, relative to the time that `get_report` is called.
        /// One probe in each `ProbePlan` should have a delay of 0. Non-zero values
        /// are for retries on UDP loss or timeout.
        delay: Duration,

        /// The relay server to send this probe to.
        node: Arc<RelayNode>,
    },
    #[display("STUN Ipv6 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    StunIpv6 {
        delay: Duration,
        node: Arc<RelayNode>,
    },
    #[display("HTTPS after {delay:?} to {node}")]
    Https {
        delay: Duration,
        node: Arc<RelayNode>,
    },
    #[display("ICMPv4 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    IcmpV4 {
        delay: Duration,
        node: Arc<RelayNode>,
    },
    #[display("ICMPv6 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    IcmpV6 {
        delay: Duration,
        node: Arc<RelayNode>,
    },
    #[display("QAD Ipv4 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    QuicIpv4 {
        delay: Duration,
        node: Arc<RelayNode>,
    },
    #[display("QAD Ipv6 after {delay:?} to {node}")]
    #[cfg(not(wasm_browser))]
    QuicIpv6 {
        delay: Duration,
        node: Arc<RelayNode>,
    },
}

impl Probe {
    pub(super) fn delay(&self) -> Duration {
        match self {
            #[cfg(not(wasm_browser))]
            Probe::StunIpv4 { delay, .. }
            | Probe::StunIpv6 { delay, .. }
            | Probe::Https { delay, .. }
            | Probe::IcmpV4 { delay, .. }
            | Probe::IcmpV6 { delay, .. }
            | Probe::QuicIpv4 { delay, .. }
            | Probe::QuicIpv6 { delay, .. } => *delay,
            #[cfg(wasm_browser)]
            Probe::Https { delay, .. } => *delay,
        }
    }

    pub(super) fn proto(&self) -> ProbeProto {
        match self {
            #[cfg(not(wasm_browser))]
            Probe::StunIpv4 { .. } => ProbeProto::StunIpv4,
            #[cfg(not(wasm_browser))]
            Probe::StunIpv6 { .. } => ProbeProto::StunIpv6,
            Probe::Https { .. } => ProbeProto::Https,
            #[cfg(not(wasm_browser))]
            Probe::IcmpV4 { .. } => ProbeProto::IcmpV4,
            #[cfg(not(wasm_browser))]
            Probe::IcmpV6 { .. } => ProbeProto::IcmpV6,
            #[cfg(not(wasm_browser))]
            Probe::QuicIpv4 { .. } => ProbeProto::QuicIpv4,
            #[cfg(not(wasm_browser))]
            Probe::QuicIpv6 { .. } => ProbeProto::QuicIpv6,
        }
    }

    pub(super) fn node(&self) -> &Arc<RelayNode> {
        match self {
            #[cfg(not(wasm_browser))]
            Probe::StunIpv4 { node, .. }
            | Probe::StunIpv6 { node, .. }
            | Probe::Https { node, .. }
            | Probe::IcmpV4 { node, .. }
            | Probe::IcmpV6 { node, .. }
            | Probe::QuicIpv4 { node, .. }
            | Probe::QuicIpv6 { node, .. } => node,
            #[cfg(wasm_browser)]
            Probe::Https { node, .. } => node,
        }
    }
}

/// A probe set is a sequence of similar [`Probe`]s with delays between them.
///
/// The probes are to the same Relayer and of the same [`ProbeProto`] but will have different
/// delays.  The delays are effectively retries, though they do not wait for the previous
/// probe to be finished.  The first successful probe will cancel all other probes in the
/// set.
///
/// This is a lot of type-safety by convention.  It would be so much nicer to have this
/// compile-time checked but that introduces a giant mess of generics and traits and
/// associated exploding types.
///
/// A [`ProbeSet`] implements [`IntoIterator`] similar to how [`Vec`] does.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ProbeSet {
    /// The [`ProbeProto`] all the probes in this set have.
    proto: ProbeProto,
    /// The probes in the set.
    probes: Vec<Probe>,
}

impl ProbeSet {
    fn new(proto: ProbeProto) -> Self {
        Self {
            probes: Vec::new(),
            proto,
        }
    }

    fn push(&mut self, probe: Probe) -> Result<()> {
        ensure!(probe.proto() == self.proto, "mismatching probe proto");
        self.probes.push(probe);
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }
}

impl<'a> IntoIterator for &'a ProbeSet {
    type Item = &'a Probe;

    type IntoIter = std::slice::Iter<'a, Probe>;

    fn into_iter(self) -> Self::IntoIter {
        self.probes.iter()
    }
}

impl fmt::Display for ProbeSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, r#"ProbeSet("{}") {{"#, self.proto)?;
        for probe in self.probes.iter() {
            writeln!(f, "        {probe},")?;
        }
        writeln!(f, "}}")
    }
}

/// A probe plan.
///
/// A probe plan contains a number of [`ProbeSet`]s containing probes to be executed.
/// Generally the first probe of of a set which completes aborts the remaining probes of a
/// set.  Sometimes a failing probe can also abort the remaining probes of a set.
///
/// The [`reportgen`] actor will also abort all the remaining [`ProbeSet`]s once it has
/// sufficient information for a report.
///
/// [`reportgen`]: crate::reportgen
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProbePlan {
    set: BTreeSet<ProbeSet>,
    protocols: BTreeSet<ProbeProto>,
}

impl ProbePlan {
    /// Creates an initial probe plan.
    #[cfg(not(wasm_browser))]
    pub(super) fn initial(
        relay_map: &RelayMap,
        protocols: &BTreeSet<ProbeProto>,
        if_state: &interfaces::State,
    ) -> Self {
        let mut plan = Self {
            set: BTreeSet::new(),
            protocols: protocols.clone(),
        };

        // The first time we need add probes after the STUN we record this delay, so that
        // further relay server can reuse this delay.
        let mut max_high_prio_delay: Option<Duration> = None;

        for relay_node in relay_map.nodes() {
            let mut stun_ipv4_probes = ProbeSet::new(ProbeProto::StunIpv4);
            let mut stun_ipv6_probes = ProbeSet::new(ProbeProto::StunIpv6);
            let mut quic_ipv4_probes = ProbeSet::new(ProbeProto::QuicIpv4);
            let mut quic_ipv6_probes = ProbeSet::new(ProbeProto::QuicIpv6);

            for attempt in 0..3 {
                let delay = DEFAULT_INITIAL_RETRANSMIT * attempt as u32;

                if if_state.have_v4 {
                    stun_ipv4_probes
                        .push(Probe::StunIpv4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding StunIpv4 probe to a StunIpv4 probe set");
                    quic_ipv4_probes
                        .push(Probe::QuicIpv4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding QuicIpv4 probe to a QuicIpv4 probe set");
                }
                if if_state.have_v6 {
                    stun_ipv6_probes
                        .push(Probe::StunIpv6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding StunIpv6 probe to a StunIpv6 probe set");
                    quic_ipv6_probes
                        .push(Probe::QuicIpv6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding QuicIpv6 probe to a QuicAddrIpv6 probe set");
                }
            }
            plan.add_if_enabled(stun_ipv4_probes);
            plan.add_if_enabled(stun_ipv6_probes);
            plan.add_if_enabled(quic_ipv4_probes);
            plan.add_if_enabled(quic_ipv6_probes);

            // The HTTP and ICMP probes only start after the STUN probes have had a chance.
            let mut https_probes = ProbeSet::new(ProbeProto::Https);
            let mut icmp_v4_probes = ProbeSet::new(ProbeProto::IcmpV4);
            let mut icmp_v6_probes = ProbeSet::new(ProbeProto::IcmpV6);

            for attempt in 0..3 {
                let mut start = *max_high_prio_delay.get_or_insert_with(|| plan.max_delay());
                // if there are high priority probes, ensure there is a buffer between
                // the highest probe delay and the next probes we create
                // if there are no high priority probes, we don't need a buffer
                if plan.has_priority_probes() {
                    start += DEFAULT_INITIAL_RETRANSMIT;
                }
                let delay = start + DEFAULT_INITIAL_RETRANSMIT * attempt as u32;
                https_probes
                    .push(Probe::Https {
                        delay,
                        node: relay_node.clone(),
                    })
                    .expect("adding Https probe to a Https probe set");
                if if_state.have_v4 {
                    icmp_v4_probes
                        .push(Probe::IcmpV4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding Icmp probe to an Icmp probe set");
                }
                if if_state.have_v6 {
                    icmp_v6_probes
                        .push(Probe::IcmpV6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding IcmpIpv6 probe to and IcmpIpv6 probe set");
                }
            }

            plan.add_if_enabled(https_probes);
            plan.add_if_enabled(icmp_v4_probes);
            plan.add_if_enabled(icmp_v6_probes);
        }
        plan
    }

    /// Creates an initial probe plan for browsers.
    ///
    /// Here, we essentially only run HTTPS probes without any delays waiting for STUN.
    #[cfg(wasm_browser)]
    pub(super) fn initial(relay_map: &RelayMap, protocols: &BTreeSet<ProbeProto>) -> Self {
        let mut plan = Self {
            set: BTreeSet::new(),
            protocols: protocols.clone(),
        };

        for relay_node in relay_map.nodes() {
            let mut https_probes = ProbeSet::new(ProbeProto::Https);

            for attempt in 0u32..3 {
                let delay = DEFAULT_INITIAL_RETRANSMIT * attempt;
                https_probes
                    .push(Probe::Https {
                        delay,
                        node: relay_node.clone(),
                    })
                    .expect("adding Https probe to a Https probe set");
            }

            plan.add_if_enabled(https_probes);
        }
        plan
    }

    /// Creates a follow up probe plan using a previous net_report report in browsers.
    ///
    /// This will only schedule HTTPS probes.
    #[cfg(not(wasm_browser))]
    pub(super) fn with_last_report(
        relay_map: &RelayMap,
        last_report: &Report,
        protocols: &BTreeSet<ProbeProto>,
        if_state: &interfaces::State,
    ) -> Self {
        if last_report.relay_latency.is_empty() {
            return Self::initial(relay_map, protocols, if_state);
        }
        let mut plan = Self {
            set: Default::default(),
            protocols: protocols.clone(),
        };

        // The first time we need add probes after the STUN we record this delay, so that
        // further relay servers can reuse this delay.
        let mut max_stun_delay: Option<Duration> = None;

        let had_stun_ipv4 = !last_report.relay_v4_latency.is_empty();
        let had_stun_ipv6 = !last_report.relay_v6_latency.is_empty();
        let had_both = if_state.have_v6 && had_stun_ipv4 && had_stun_ipv6;
        let sorted_relays = sort_relays(relay_map, last_report);
        for (ri, (url, relay_node)) in sorted_relays.into_iter().enumerate() {
            if ri == NUM_INCREMENTAL_RELAYS {
                break;
            }
            let mut do4 = if_state.have_v4;
            let mut do6 = if_state.have_v6;

            // By default, each node only gets one STUN packet sent,
            // except the fastest two from the previous round.
            let mut attempts = 1;
            let is_fastest_two = ri < 2;

            if is_fastest_two {
                attempts = 2;
            } else if had_both {
                // For dual stack machines, make the 3rd & slower nodes alternate between
                // IPv4 and IPv6 for STUN and ICMP probes.
                if ri % 2 == 0 {
                    (do4, do6) = (true, false);
                } else {
                    (do4, do6) = (false, true);
                }
            }
            if !is_fastest_two && !had_stun_ipv6 {
                do6 = false;
            }
            if Some(url) == last_report.preferred_relay.as_ref() {
                // But if we already had a relay home, try extra hard to
                // make sure it's there so we don't flip flop around.
                attempts = 4;
            }
            let retransmit_delay = last_report
                .relay_latency
                .get(url)
                .map(|l| l * 120 / 100) // increases latency by 20%, why?
                .unwrap_or(DEFAULT_ACTIVE_RETRANSMIT_DELAY);

            let mut stun_ipv4_probes = ProbeSet::new(ProbeProto::StunIpv4);
            let mut stun_ipv6_probes = ProbeSet::new(ProbeProto::StunIpv6);
            let mut quic_ipv4_probes = ProbeSet::new(ProbeProto::QuicIpv4);
            let mut quic_ipv6_probes = ProbeSet::new(ProbeProto::QuicIpv6);

            for attempt in 0..attempts {
                let delay = (retransmit_delay * attempt as u32)
                    + (ACTIVE_RETRANSMIT_EXTRA_DELAY * attempt as u32);
                if do4 {
                    stun_ipv4_probes
                        .push(Probe::StunIpv4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("Pushing StunIpv4 Probe to StunIpv4 ProbeSet");
                    quic_ipv4_probes
                        .push(Probe::QuicIpv4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding QuicIpv4 probe to a QuicAddrIpv4 probe set");
                }
                if do6 {
                    stun_ipv6_probes
                        .push(Probe::StunIpv6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("Pushing StunIpv6 Probe to StunIpv6 ProbeSet");
                    quic_ipv6_probes
                        .push(Probe::QuicIpv6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("adding QuicIpv6 probe to a QuicAddrIpv6 probe set");
                }
            }
            plan.add_if_enabled(stun_ipv4_probes);
            plan.add_if_enabled(stun_ipv6_probes);
            plan.add_if_enabled(quic_ipv4_probes);
            plan.add_if_enabled(quic_ipv6_probes);

            // The HTTP and ICMP probes only start after the STUN probes have had a chance.
            let mut https_probes = ProbeSet::new(ProbeProto::Https);
            let mut icmp_v4_probes = ProbeSet::new(ProbeProto::IcmpV4);
            let mut icmp_v6_probes = ProbeSet::new(ProbeProto::IcmpV6);
            let start = *max_stun_delay.get_or_insert_with(|| plan.max_delay());
            for attempt in 0..attempts {
                let delay = start
                    + (retransmit_delay * attempt as u32)
                    + (ACTIVE_RETRANSMIT_EXTRA_DELAY * (attempt as u32 + 1));
                https_probes
                    .push(Probe::Https {
                        delay,
                        node: relay_node.clone(),
                    })
                    .expect("Pushing Https Probe to an Https ProbeSet");
                if do4 {
                    icmp_v4_probes
                        .push(Probe::IcmpV4 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("Pushing IcmpV4 Probe to an Icmp ProbeSet");
                }
                if do6 {
                    icmp_v6_probes
                        .push(Probe::IcmpV6 {
                            delay,
                            node: relay_node.clone(),
                        })
                        .expect("Pusying IcmpV6 Probe to an IcmpV6 ProbeSet");
                }
            }

            plan.add_if_enabled(https_probes);
            plan.add_if_enabled(icmp_v4_probes);
            plan.add_if_enabled(icmp_v6_probes);
        }
        plan
    }

    #[cfg(wasm_browser)]
    pub(super) fn with_last_report(
        relay_map: &RelayMap,
        last_report: &Report,
        protocols: &BTreeSet<ProbeProto>,
    ) -> Self {
        if last_report.relay_latency.is_empty() {
            return Self::initial(relay_map, protocols);
        }
        let mut plan = Self {
            set: Default::default(),
            protocols: protocols.clone(),
        };

        let sorted_relays = sort_relays(relay_map, last_report);
        for (ri, (url, relay_node)) in sorted_relays.into_iter().enumerate() {
            if ri == NUM_INCREMENTAL_RELAYS {
                break;
            }

            // By default, each node only gets one probe sent,
            let mut attempts: u32 = 1;
            // except the fastest two from the previous round.
            if ri < 2 {
                attempts = 2;
            }
            if Some(url) == last_report.preferred_relay.as_ref() {
                // But if we already had a relay home, try extra hard to
                // make sure it's there so we don't flip flop around.
                attempts = 4;
            }
            let retransmit_delay = last_report
                .relay_latency
                .get(url)
                .map(|l| l * 120 / 100) // increases latency by 20%, why?
                .unwrap_or(DEFAULT_ACTIVE_RETRANSMIT_DELAY);

            let mut https_probes = ProbeSet::new(ProbeProto::Https);
            for attempt in 0..attempts {
                let delay =
                    (retransmit_delay * attempt) + (ACTIVE_RETRANSMIT_EXTRA_DELAY * (attempt + 1));
                https_probes
                    .push(Probe::Https {
                        delay,
                        node: relay_node.clone(),
                    })
                    .expect("Pushing Https Probe to an Https ProbeSet");
            }

            plan.add_if_enabled(https_probes);
        }
        plan
    }

    /// Returns an iterator over the [`ProbeSet`]s in this plan.
    pub(super) fn iter(&self) -> impl Iterator<Item = &ProbeSet> {
        self.set.iter()
    }

    /// Adds a [`ProbeSet`] if it contains probes and the protocol indicated in
    /// the [`ProbeSet] matches a protocol in our set of [`ProbeProto`]s.
    fn add_if_enabled(&mut self, set: ProbeSet) {
        if !set.is_empty() && self.protocols.contains(&set.proto) {
            self.set.insert(set);
        }
    }

    /// Returns the delay of the last probe in the probe plan.
    fn max_delay(&self) -> Duration {
        self.set
            .iter()
            .flatten()
            .map(|probe| probe.delay())
            .max()
            .unwrap_or_default()
    }

    /// Stun & Quic probes are "priority" probes
    fn has_priority_probes(&self) -> bool {
        #[cfg(not(wasm_browser))]
        for probe in &self.set {
            if matches!(
                probe.proto,
                ProbeProto::StunIpv4
                    | ProbeProto::StunIpv6
                    | ProbeProto::QuicIpv4
                    | ProbeProto::QuicIpv6
            ) {
                return true;
            }
        }
        false
    }
}

impl fmt::Display for ProbePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProbePlan {{")?;
        for probe_set in self.set.iter() {
            writeln!(f, r#"    ProbeSet("{}") {{"#, probe_set.proto)?;
            for probe in probe_set.probes.iter() {
                writeln!(f, "        {probe},")?;
            }
            writeln!(f, "    }}")?;
        }
        writeln!(f, "}}")
    }
}

impl FromIterator<ProbeSet> for ProbePlan {
    fn from_iter<T: IntoIterator<Item = ProbeSet>>(iter: T) -> Self {
        Self {
            set: iter.into_iter().collect(),
            protocols: BTreeSet::new(),
        }
    }
}

/// Sorts the nodes in the [`RelayMap`] from fastest to slowest.
///
/// This uses the latencies from the last report to determine the order. Relay Nodes with no
/// data are at the end.
fn sort_relays<'a>(
    relay_map: &'a RelayMap,
    last_report: &Report,
) -> Vec<(&'a RelayUrl, &'a Arc<RelayNode>)> {
    let mut prev: Vec<_> = relay_map.nodes().collect();
    prev.sort_by(|a, b| {
        let latencies_a = last_report.relay_latency.get(&a.url);
        let latencies_b = last_report.relay_latency.get(&b.url);
        match (latencies_a, latencies_b) {
            (Some(_), None) => {
                // Non-zero sorts before zero.
                std::cmp::Ordering::Less
            }
            (None, Some(_)) => {
                // Zero can't sort before anything else.
                std::cmp::Ordering::Greater
            }
            (None, None) => {
                // For both empty latencies sort by relay_id.
                a.url.cmp(&b.url)
            }
            (Some(_), Some(_)) => match latencies_a.cmp(&latencies_b) {
                std::cmp::Ordering::Equal => a.url.cmp(&b.url),
                x => x,
            },
        }
    });

    prev.into_iter().map(|n| (&n.url, n)).collect()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use tracing_test::traced_test;

    use super::*;
    use crate::net_report::{test_utils, RelayLatencies};

    /// Shorthand which declares a new ProbeSet.
    ///
    /// `$kind`: The `ProbeProto`.
    /// `$node`: Expression which will be an `Arc<RelayNode>`.
    /// `$delays`: A `Vec` of the delays for this probe.
    macro_rules! probeset {
        (proto: ProbeProto::$kind:ident, relay: $node:expr, delays: $delays:expr,) => {
            ProbeSet {
                proto: ProbeProto::$kind,
                probes: $delays
                    .iter()
                    .map(|delay| Probe::$kind {
                        delay: *delay,
                        node: $node,
                    })
                    .collect(),
            }
        };
    }

    fn default_protocols() -> BTreeSet<ProbeProto> {
        BTreeSet::from([
            ProbeProto::StunIpv4,
            ProbeProto::StunIpv6,
            ProbeProto::QuicIpv4,
            ProbeProto::QuicIpv6,
            ProbeProto::IcmpV4,
            ProbeProto::IcmpV6,
            ProbeProto::Https,
        ])
    }

    #[tokio::test]
    async fn test_initial_probeplan() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_node_1 = relay_map.nodes().next().unwrap();
        let relay_node_2 = relay_map.nodes().nth(1).unwrap();
        let if_state = interfaces::State::fake();
        let plan = ProbePlan::initial(&relay_map, &default_protocols(), &if_state);

        let mut expected_plan: ProbePlan = [
            probeset! {
                proto: ProbeProto::StunIpv4,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::StunIpv6,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::QuicIpv4,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::QuicIpv6,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::Https,
                relay: relay_node_1.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: ProbeProto::IcmpV4,
                relay: relay_node_1.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: ProbeProto::IcmpV6,
                relay: relay_node_1.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: ProbeProto::StunIpv4,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::StunIpv6,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::QuicIpv4,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::QuicIpv6,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::Https,
                relay: relay_node_2.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: ProbeProto::IcmpV4,
                relay: relay_node_2.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: ProbeProto::IcmpV6,
                relay: relay_node_2.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
        ]
        .into_iter()
        .collect();
        expected_plan.protocols = default_protocols();

        println!("expected:");
        println!("{expected_plan}");
        println!("actual:");
        println!("{plan}");
        // The readable error:
        assert_eq!(plan.to_string(), expected_plan.to_string());
        // Just in case there's a bug in the Display impl:
        assert_eq!(plan, expected_plan);
    }

    #[tokio::test]
    async fn test_initial_probeplan_some_protocols() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_node_1 = relay_map.nodes().next().unwrap();
        let relay_node_2 = relay_map.nodes().nth(1).unwrap();
        let if_state = interfaces::State::fake();
        let plan = ProbePlan::initial(
            &relay_map,
            &BTreeSet::from([ProbeProto::Https, ProbeProto::IcmpV4, ProbeProto::IcmpV6]),
            &if_state,
        );

        let mut expected_plan: ProbePlan = [
            probeset! {
                proto: ProbeProto::Https,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::IcmpV4,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::IcmpV6,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::Https,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::IcmpV4,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: ProbeProto::IcmpV6,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
        ]
        .into_iter()
        .collect();
        expected_plan.protocols =
            BTreeSet::from([ProbeProto::Https, ProbeProto::IcmpV4, ProbeProto::IcmpV6]);

        println!("expected:");
        println!("{expected_plan}");
        println!("actual:");
        println!("{plan}");
        // The readable error:
        assert_eq!(plan.to_string(), expected_plan.to_string());
        // Just in case there's a bug in the Display impl:
        assert_eq!(plan, expected_plan);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_plan_with_report() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_node_1 = relay_map.nodes().next().unwrap().clone();
        let relay_node_2 = relay_map.nodes().nth(1).unwrap().clone();
        let if_state = interfaces::State::fake();

        for i in 0..10 {
            println!("round {}", i);
            let mut latencies = RelayLatencies::new();
            latencies.update_relay(relay_node_1.url.clone(), Duration::from_millis(2));
            latencies.update_relay(relay_node_2.url.clone(), Duration::from_millis(2));
            let last_report = Report {
                udp: true,
                ipv6: true,
                ipv4: true,
                ipv6_can_send: true,
                ipv4_can_send: true,
                os_has_ipv6: true,
                icmpv4: None,
                icmpv6: None,
                mapping_varies_by_dest_ip: Some(false),
                mapping_varies_by_dest_ipv6: Some(false),
                hair_pinning: Some(true),
                portmap_probe: None,
                preferred_relay: Some(relay_node_1.url.clone()),
                relay_latency: latencies.clone(),
                relay_v4_latency: latencies.clone(),
                relay_v6_latency: latencies.clone(),
                global_v4: None,
                global_v6: None,
                captive_portal: None,
            };
            let plan = ProbePlan::with_last_report(
                &relay_map,
                &last_report,
                &default_protocols(),
                &if_state,
            );
            let mut expected_plan: ProbePlan = [
                probeset! {
                    proto: ProbeProto::StunIpv4,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: ProbeProto::StunIpv6,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: ProbeProto::QuicIpv4,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: ProbeProto::QuicIpv6,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: ProbeProto::Https,
                    relay: relay_node_1.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600),
                             Duration::from_micros(312_000),
                             Duration::from_micros(364_400)],
                },
                probeset! {
                    proto: ProbeProto::IcmpV4,
                    relay: relay_node_1.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600),
                             Duration::from_micros(312_000),
                             Duration::from_micros(364_400)],
                },
                probeset! {
                    proto: ProbeProto::IcmpV6,
                    relay: relay_node_1.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600),
                             Duration::from_micros(312_000),
                             Duration::from_micros(364_400)],
                },
                probeset! {
                    proto: ProbeProto::StunIpv4,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: ProbeProto::StunIpv6,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: ProbeProto::QuicIpv4,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: ProbeProto::QuicIpv6,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: ProbeProto::Https,
                    relay: relay_node_2.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600)],
                },
                probeset! {
                    proto: ProbeProto::IcmpV4,
                    relay: relay_node_2.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600)],
                },
                probeset! {
                    proto: ProbeProto::IcmpV6,
                    relay: relay_node_2.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600)],
                },
            ]
            .into_iter()
            .collect();
            expected_plan.protocols = default_protocols();

            println!("{} round", i);
            println!("expected:");
            println!("{expected_plan}");
            println!("actual:");
            println!("{plan}");
            // The readable error:
            assert_eq!(plan.to_string(), expected_plan.to_string(), "{}", i);
            // Just in case there's a bug in the Display impl:
            assert_eq!(plan, expected_plan, "{}", i);
        }
    }

    fn create_last_report(
        url_1: &RelayUrl,
        latency_1: Option<Duration>,
        url_2: &RelayUrl,
        latency_2: Option<Duration>,
    ) -> Report {
        let mut latencies = RelayLatencies::new();
        if let Some(latency_1) = latency_1 {
            latencies.update_relay(url_1.clone(), latency_1);
        }
        if let Some(latency_2) = latency_2 {
            latencies.update_relay(url_2.clone(), latency_2);
        }
        Report {
            udp: true,
            ipv6: true,
            ipv4: true,
            ipv6_can_send: true,
            ipv4_can_send: true,
            os_has_ipv6: true,
            icmpv4: None,
            icmpv6: None,
            mapping_varies_by_dest_ip: Some(false),
            mapping_varies_by_dest_ipv6: Some(false),
            hair_pinning: Some(true),
            portmap_probe: None,
            preferred_relay: Some(url_1.clone()),
            relay_latency: latencies.clone(),
            relay_v4_latency: latencies.clone(),
            relay_v6_latency: latencies.clone(),
            global_v4: None,
            global_v6: None,
            captive_portal: None,
        }
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_sort_two_latencies() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let r1 = relay_map.nodes().next().unwrap();
        let r2 = relay_map.nodes().nth(1).unwrap();
        let last_report = create_last_report(
            &r1.url,
            Some(Duration::from_millis(1)),
            &r2.url,
            Some(Duration::from_millis(2)),
        );
        let sorted: Vec<_> = sort_relays(&relay_map, &last_report)
            .iter()
            .map(|(url, _reg)| *url)
            .collect();
        assert_eq!(sorted, vec![&r1.url, &r2.url]);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_sort_equal_latencies() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let r1 = relay_map.nodes().next().unwrap();
        let r2 = relay_map.nodes().nth(1).unwrap();
        let last_report = create_last_report(
            &r1.url,
            Some(Duration::from_millis(2)),
            &r2.url,
            Some(Duration::from_millis(2)),
        );
        let sorted: Vec<_> = sort_relays(&relay_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![&r1.url, &r2.url]);
    }

    #[tokio::test]
    async fn test_relay_sort_missing_latency() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let r1 = relay_map.nodes().next().unwrap();
        let r2 = relay_map.nodes().nth(1).unwrap();

        let last_report =
            create_last_report(&r1.url, None, &r2.url, Some(Duration::from_millis(2)));
        let sorted: Vec<_> = sort_relays(&relay_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![&r2.url, &r1.url]);

        let last_report =
            create_last_report(&r1.url, Some(Duration::from_millis(2)), &r2.url, None);
        let sorted: Vec<_> = sort_relays(&relay_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![&r1.url, &r2.url]);
    }

    #[tokio::test]
    #[traced_test]
    async fn test_relay_sort_no_latency() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let r1 = relay_map.nodes().next().unwrap();
        let r2 = relay_map.nodes().nth(1).unwrap();

        let last_report = create_last_report(&r1.url, None, &r2.url, None);
        let sorted: Vec<_> = sort_relays(&relay_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        // sorted by relay url only
        assert_eq!(sorted, vec![&r1.url, &r2.url]);
    }
}
