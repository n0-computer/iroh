//! The relay probes.
//!
//! All the probes try and establish the latency to the relay servers.  Preferably the STUN
//! probes work and we also learn about our public IP addresses and ports.  But fallback
//! probes for HTTPS and ICMP exist as well.

use std::{collections::BTreeSet, fmt, sync::Arc};

use iroh_base::RelayUrl;
use iroh_relay::{RelayMap, RelayNode};
use n0_future::time::Duration;
use snafu::Snafu;

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
pub enum Probe {
    /// HTTPS
    Https,
    /// QUIC Address Discovery Ipv4
    #[cfg(not(wasm_browser))]
    QadIpv4,
    /// QUIC Address Discovery Ipv6
    #[cfg(not(wasm_browser))]
    QadIpv6,
}

impl Probe {
    #[cfg(not(wasm_browser))]
    pub(super) fn is_udp(&self) -> bool {
        matches!(self, Self::QadIpv4 | Self::QadIpv6)
    }

    #[cfg(wasm_browser)]
    pub(super) fn is_udp(&self) -> bool {
        false
    }
}

/// A probe set is a sequence of similar [`Probe`]s with delays between them.
///
/// The probes are to the same Relayer and of the same [`Probe`] but will have different
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
    /// The [`Probe`] all the probes in this set have.
    proto: Probe,
    /// The data in the set.
    probes: Vec<(Duration, Arc<RelayNode>)>,
}

#[derive(Debug, Snafu)]
#[snafu(display("Mismatching probe"))]
struct PushError;

impl ProbeSet {
    fn new(proto: Probe) -> Self {
        Self {
            probes: Vec::new(),
            proto,
        }
    }

    pub(super) fn proto(&self) -> Probe {
        self.proto
    }

    fn push(&mut self, delay: Duration, node: Arc<RelayNode>) {
        self.probes.push((delay, node));
    }

    fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    fn delays(&self) -> impl Iterator<Item = &Duration> {
        self.probes.iter().map(|(d, _)| d)
    }

    pub(super) fn params(&self) -> impl Iterator<Item = &(Duration, Arc<RelayNode>)> {
        self.probes.iter()
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
/// [`reportgen`]: crate::net_report::reportgen
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct ProbePlan {
    set: BTreeSet<ProbeSet>,
}

impl ProbePlan {
    /// Creates an initial probe plan.
    #[cfg(not(wasm_browser))]
    pub(super) fn initial(
        relay_map: &RelayMap,
        protocols: &BTreeSet<Probe>,
        if_state: &super::IfStateDetails,
    ) -> Self {
        let mut plan = Self {
            set: Default::default(),
        };

        // The first time we need add probes after the STUN we record this delay, so that
        // further relay server can reuse this delay.
        let mut max_high_prio_delay: Option<Duration> = None;

        for relay_node in relay_map.nodes() {
            let mut quic_ipv4_probes = ProbeSet::new(Probe::QadIpv4);
            let mut quic_ipv6_probes = ProbeSet::new(Probe::QadIpv6);

            for attempt in 0..3 {
                let delay = DEFAULT_INITIAL_RETRANSMIT * attempt as u32;

                if if_state.have_v4 {
                    quic_ipv4_probes.push(delay, relay_node.clone());
                }
                if if_state.have_v6 {
                    quic_ipv6_probes.push(delay, relay_node.clone());
                }
            }
            // plan.add_if_enabled(protocols, quic_ipv4_probes);
            // plan.add_if_enabled(protocols, quic_ipv6_probes);

            // The HTTP probes only start after the QAD probes have had a chance.
            let mut https_probes = ProbeSet::new(Probe::Https);

            for attempt in 0..3 {
                let mut start = *max_high_prio_delay.get_or_insert_with(|| plan.max_delay());
                // if there are high priority probes, ensure there is a buffer between
                // the highest probe delay and the next probes we create
                // if there are no high priority probes, we don't need a buffer
                if plan.has_priority_probes() {
                    start += DEFAULT_INITIAL_RETRANSMIT;
                }
                let delay = start + DEFAULT_INITIAL_RETRANSMIT * attempt as u32;
                https_probes.push(delay, relay_node.clone());
            }

            plan.add_if_enabled(protocols, https_probes);
        }
        plan
    }

    /// Creates an initial probe plan for browsers.
    ///
    /// Here, we essentially only run HTTPS probes without any delays waiting for STUN.
    #[cfg(wasm_browser)]
    pub(super) fn initial(relay_map: &RelayMap, protocols: &BTreeSet<Probe>) -> Self {
        let mut plan = Self {
            set: Default::default(),
        };

        for relay_node in relay_map.nodes() {
            let mut https_probes = ProbeSet::new(Probe::Https);

            for attempt in 0u32..3 {
                let delay = DEFAULT_INITIAL_RETRANSMIT * attempt;
                https_probes.push(delay, relay_node.clone());
            }

            plan.add_if_enabled(protocols, https_probes);
        }
        plan
    }

    /// Creates a follow up probe plan using a previous net_report report in browsers.
    ///
    /// This will only schedule HTTPS probes.
    pub(super) fn with_last_report(
        relay_map: &RelayMap,
        last_report: &Report,
        protocols: &BTreeSet<Probe>,
        if_state: &super::IfStateDetails,
    ) -> Self {
        if last_report.relay_latency.is_empty() {
            return Self::initial(relay_map, protocols, if_state);
        }
        Self::default()
    }

    /// Returns an iterator over the [`ProbeSet`]s in this plan.
    pub(super) fn iter(&self) -> impl Iterator<Item = &ProbeSet> {
        self.set.iter()
    }

    /// Adds a [`ProbeSet`] if it contains probes and the protocol indicated in
    /// the [`ProbeSet] matches a protocol in our set of [`Probe`]s.
    fn add_if_enabled(&mut self, protocols: &BTreeSet<Probe>, set: ProbeSet) {
        if !set.is_empty() && protocols.contains(&set.proto) {
            self.set.insert(set);
        }
    }

    /// Returns the delay of the last probe in the probe plan.
    fn max_delay(&self) -> Duration {
        self.set
            .iter()
            .flat_map(|probe_set| probe_set.delays())
            .max()
            .copied()
            .unwrap_or_default()
    }

    /// Any UDP based probes are "priority" probes
    fn has_priority_probes(&self) -> bool {
        self.set.iter().any(|p| p.proto.is_udp())
    }
}

impl fmt::Display for ProbePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProbePlan {{")?;
        for probe_set in self.set.iter() {
            writeln!(f, r#"    ProbeSet("{}") {{"#, probe_set.proto)?;
            for (delay, node) in probe_set.probes.iter() {
                writeln!(f, "        {delay:?} to {node},")?;
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
    use crate::net_report::{reportgen::IfStateDetails, test_utils, RelayLatencies};

    /// Shorthand which declares a new ProbeSet.
    ///
    /// `$kind`: The `Probe`.
    /// `$node`: Expression which will be an `Arc<RelayNode>`.
    /// `$delays`: A `Vec` of the delays for this probe.
    macro_rules! probeset {
        (proto: Probe::$kind:ident, relay: $node:expr, delays: $delays:expr,) => {
            ProbeSet {
                proto: Probe::$kind,
                probes: $delays.iter().map(|delay| (*delay, $node)).collect(),
            }
        };
    }

    fn default_protocols() -> BTreeSet<Probe> {
        BTreeSet::from([Probe::QadIpv4, Probe::QadIpv6, Probe::Https])
    }

    #[tokio::test]
    async fn test_initial_probeplan() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_node_1 = relay_map.nodes().next().unwrap();
        let relay_node_2 = relay_map.nodes().nth(1).unwrap();
        let if_state = IfStateDetails::fake();
        let plan = ProbePlan::initial(&relay_map, &default_protocols(), &if_state);

        let expected_plan: ProbePlan = [
            probeset! {
                proto: Probe::QadIpv4,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: Probe::QadIpv6,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: Probe::Https,
                relay: relay_node_1.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
            probeset! {
                proto: Probe::QadIpv4,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: Probe::QadIpv6,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: Probe::Https,
                relay: relay_node_2.clone(),
                delays: [Duration::from_millis(300),
                         Duration::from_millis(400),
                         Duration::from_millis(500)],
            },
        ]
        .into_iter()
        .collect();

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
        let if_state = IfStateDetails::fake();
        let plan = ProbePlan::initial(&relay_map, &BTreeSet::from([Probe::Https]), &if_state);

        let expected_plan: ProbePlan = [
            probeset! {
                proto: Probe::Https,
                relay: relay_node_1.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
            probeset! {
                proto: Probe::Https,
                relay: relay_node_2.clone(),
                delays: [Duration::ZERO,
                         Duration::from_millis(100),
                         Duration::from_millis(200)],
            },
        ]
        .into_iter()
        .collect();

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
        let if_state = IfStateDetails::fake();

        for i in 0..10 {
            println!("round {}", i);
            let mut latencies = RelayLatencies::default();
            latencies.update_relay(
                relay_node_1.url.clone(),
                Duration::from_millis(2),
                Probe::QadIpv4,
            );
            latencies.update_relay(
                relay_node_2.url.clone(),
                Duration::from_millis(2),
                Probe::QadIpv4,
            );
            let last_report = Report {
                udp_v6: true,
                udp_v4: true,
                mapping_varies_by_dest_ipv4: Some(false),
                mapping_varies_by_dest_ipv6: Some(false),
                preferred_relay: Some(relay_node_1.url.clone()),
                relay_latency: latencies.clone(),
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
            let expected_plan: ProbePlan = [
                probeset! {
                    proto: Probe::QadIpv4,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: Probe::QadIpv6,
                    relay: relay_node_1.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400),
                             Duration::from_micros(104_800),
                             Duration::from_micros(157_200)],
                },
                probeset! {
                    proto: Probe::Https,
                    relay: relay_node_1.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600),
                             Duration::from_micros(312_000),
                             Duration::from_micros(364_400)],
                },
                probeset! {
                    proto: Probe::QadIpv4,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: Probe::QadIpv6,
                    relay: relay_node_2.clone(),
                    delays: [Duration::ZERO,
                             Duration::from_micros(52_400)],
                },
                probeset! {
                    proto: Probe::Https,
                    relay: relay_node_2.clone(),
                    delays: [Duration::from_micros(207_200),
                             Duration::from_micros(259_600)],
                },
            ]
            .into_iter()
            .collect();

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
        let mut latencies = RelayLatencies::default();
        if let Some(latency_1) = latency_1 {
            latencies.update_relay(url_1.clone(), latency_1, Probe::QadIpv4);
        }
        if let Some(latency_2) = latency_2 {
            latencies.update_relay(url_2.clone(), latency_2, Probe::QadIpv4);
        }
        Report {
            udp_v6: true,
            udp_v4: true,
            mapping_varies_by_dest_ipv4: Some(false),
            mapping_varies_by_dest_ipv6: Some(false),
            preferred_relay: Some(url_1.clone()),
            relay_latency: latencies,
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
