//! The relay probes.
//!
//! All the probes try and establish the latency to the relay servers.  Preferably the STUN
//! probes work and we also learn about our public IP addresses and ports.  But fallback
//! probes for HTTPS and ICMP exist as well.

use std::{collections::BTreeSet, fmt, sync::Arc};

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
    /// Creates an initial probe plan
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
    ) -> Self {
        if last_report.relay_latency.is_empty() {
            return Self::initial(relay_map, protocols);
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

#[cfg(test)]
mod tests {
    use iroh_base::RelayUrl;
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
        let plan = ProbePlan::initial(&relay_map, &default_protocols());

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
        let plan = ProbePlan::initial(&relay_map, &BTreeSet::from([Probe::Https]));

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
            let plan = ProbePlan::with_last_report(&relay_map, &last_report, &default_protocols());
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
}
