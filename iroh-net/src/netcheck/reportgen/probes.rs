//! The DERP probes.
//!
//! All the probes try and establish the latency to the DERP servers.  Preferably the STUN
//! probes work and we also learn about our public IP addresses and ports.  But fallback
//! probes for HTTPS and ICMP exist as well.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use anyhow::{ensure, Result};
use tokio::time::Duration;
use url::Url;

use crate::derp::{DerpMap, DerpNode};
use crate::net::interfaces;
use crate::netcheck::Report;

/// The retransmit interval used when netcheck first runs.
///
/// We have no past context to work with, and we want answers relatively quickly, so it's
/// biased slightly more aggressive than [`DEFAULT_ACTIVE_RETRANSMIT_DELAY`]. A few extra
/// packets at startup is fine.
const DEFAULT_INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

/// The retransmit interval used when a previous report exists but is missing latency.
///
/// When in an active steady-state, i.e. a previous report exists, we use the latency of the
/// previous report to determine the retransmit interval.  However when this previous region
/// latency is missing this default is used.
///
/// This is a somewhat conservative guess because if we have no data, likely the DERP node
/// is very far away and we have no data because we timed out the last time we probed it.
const DEFAULT_ACTIVE_RETRANSMIT_DELAY: Duration = Duration::from_millis(200);

/// The extra time to add to retransmits if a previous report exists.
///
/// When in an active steady-state, i.e. a previous report exists, we add this delay
/// multiplied with the attempt to probe retries to give later attempts increasingly more
/// time.
const ACTIVE_RETRANSMIT_EXTRA_DELAY: Duration = Duration::from_millis(50);

/// The number of fastest regions to periodically re-query during incremental netcheck
/// reports. (During a full report, all regions are scanned.)
const NUM_INCREMENTAL_REGIONS: usize = 3;

/// The protocol used to time a node's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, derive_more::Display)]
#[repr(u8)]
pub(super) enum ProbeProto {
    /// STUN IPv4
    StunIpv4,
    /// STUN IPv6
    StunIpv6,
    /// HTTPS
    Https,
    /// ICMP
    Icmp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, derive_more::Display)]
pub(super) enum Probe {
    #[display("Ipv4 after {delay:?} to {node}")]
    StunIpv4 {
        /// When the probe is started, relative to the time that `get_report` is called.
        /// One probe in each `ProbePlan` should have a delay of 0. Non-zero values
        /// are for retries on UDP loss or timeout.
        delay: Duration,

        /// The DERP server to send this probe to.
        node: Arc<DerpNode>,
    },
    #[display("Ipv6 after {delay:?} to {node}")]
    StunIpv6 {
        delay: Duration,
        node: Arc<DerpNode>,
    },
    // TODO: Probably can remove DerpRegion since the DerpNode already contains the region
    // ID which can then be looked up in the DerpMap.  But Https isn't even implemented
    // right now so leave it.
    #[display("Https after {delay:?} to {node}")]
    Https {
        delay: Duration,
        node: Arc<DerpNode>,
    },
    #[display("Icmp after {delay:?} to {node}")]
    Icmp {
        delay: Duration,
        node: Arc<DerpNode>,
    },
}

impl Probe {
    pub(super) fn delay(&self) -> Duration {
        match self {
            Probe::StunIpv4 { delay, .. }
            | Probe::StunIpv6 { delay, .. }
            | Probe::Https { delay, .. }
            | Probe::Icmp { delay, .. } => *delay,
        }
    }

    pub(super) fn proto(&self) -> ProbeProto {
        match self {
            Probe::StunIpv4 { .. } => ProbeProto::StunIpv4,
            Probe::StunIpv6 { .. } => ProbeProto::StunIpv6,
            Probe::Https { .. } => ProbeProto::Https,
            Probe::Icmp { .. } => ProbeProto::Icmp,
        }
    }

    pub(super) fn node(&self) -> &Arc<DerpNode> {
        match self {
            Probe::StunIpv4 { node, .. }
            | Probe::StunIpv6 { node, .. }
            | Probe::Https { node, .. }
            | Probe::Icmp { node, .. } => node,
        }
    }
}

/// A probe set is a sequence of similar [`Probe`]s with delays between them.
///
/// The probes are to the same region and of the same [`ProbeProto`] but will have different
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
/// [`reportgen`]: crate::netcheck::reportgen
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ProbePlan(BTreeSet<ProbeSet>);

impl ProbePlan {
    /// Creates an initial probe plan.
    pub(super) fn initial(derp_map: &DerpMap, if_state: &interfaces::State) -> Self {
        let mut plan = Self(BTreeSet::new());

        for (_url, derp_node) in derp_map.nodes() {
            let mut stun_ipv4_probes = ProbeSet::new(ProbeProto::StunIpv4);
            let mut stun_ipv6_probes = ProbeSet::new(ProbeProto::StunIpv6);

            for attempt in 0..3 {
                let delay = DEFAULT_INITIAL_RETRANSMIT * attempt as u32;

                if if_state.have_v4 {
                    stun_ipv4_probes
                        .push(Probe::StunIpv4 {
                            delay,
                            node: derp_node.clone(),
                        })
                        .expect("adding StunIpv4 probe to a StunIpv4 probe set");
                }
                if if_state.have_v6 {
                    stun_ipv6_probes
                        .push(Probe::StunIpv6 {
                            delay,
                            node: derp_node.clone(),
                        })
                        .expect("adding StunIpv6 probe to a StunIpv6 probe set");
                }
            }
            plan.add(stun_ipv4_probes);
            plan.add(stun_ipv6_probes);

            // The HTTP and ICMP probes only start after the STUN probes have had a chance.
            let mut https_probes = ProbeSet::new(ProbeProto::Https);
            let mut icmp_probes = ProbeSet::new(ProbeProto::Icmp);
            for attempt in 0..3 {
                let start = plan.max_delay() + DEFAULT_INITIAL_RETRANSMIT;
                let delay = start + DEFAULT_INITIAL_RETRANSMIT * attempt as u32;

                https_probes
                    .push(Probe::Https {
                        delay,
                        node: derp_node.clone(),
                    })
                    .expect("adding Https probe to a Https probe set");

                icmp_probes
                    .push(Probe::Icmp {
                        delay,
                        node: derp_node.clone(),
                    })
                    .expect("adding Icmp probe to an Icmp probe set");
            }
            plan.add(https_probes);
            plan.add(icmp_probes);
        }
        plan
    }

    /// Creates a follow up probe plan using a previous netcheck report.
    pub(super) fn with_last_report(
        derp_map: &DerpMap,
        if_state: &interfaces::State,
        last_report: &Report,
    ) -> Self {
        if last_report.region_latency.is_empty() {
            return Self::initial(derp_map, if_state);
        }
        let mut plan = Self(Default::default());

        let had_stun_ipv4 = !last_report.region_v4_latency.is_empty();
        let had_stun_ipv6 = !last_report.region_v6_latency.is_empty();
        let had_both = if_state.have_v6 && had_stun_ipv4 && had_stun_ipv6;
        let sorted_regions = sort_regions(derp_map, last_report);
        for (ri, (url, derp_node)) in sorted_regions.into_iter().enumerate() {
            if ri == NUM_INCREMENTAL_REGIONS {
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
                // IPv4 and IPv6 STUN probes.
                if ri % 2 == 0 {
                    (do4, do6) = (true, false);
                } else {
                    (do4, do6) = (false, true);
                }
            }
            if !is_fastest_two && !had_stun_ipv6 {
                do6 = false;
            }
            if Some(url) == last_report.preferred_derp.as_ref() {
                // But if we already had a DERP home, try extra hard to
                // make sure it's there so we don't flip flop around.
                attempts = 4;
            }
            let retransmit_delay = last_report
                .region_latency
                .get(url)
                .map(|l| l * 120 / 100) // increases latency by 20%, why?
                .unwrap_or(DEFAULT_ACTIVE_RETRANSMIT_DELAY);

            let mut stun_ipv4_probes = ProbeSet::new(ProbeProto::StunIpv4);
            let mut stun_ipv6_probes = ProbeSet::new(ProbeProto::StunIpv6);

            for attempt in 0..attempts {
                let delay = (retransmit_delay * attempt as u32)
                    + (ACTIVE_RETRANSMIT_EXTRA_DELAY * attempt as u32);
                if do4 {
                    stun_ipv4_probes
                        .push(Probe::StunIpv4 {
                            delay,
                            node: derp_node.clone(),
                        })
                        .expect("Pushing StunIpv4 Probe to StunIpv4 ProbeSet");
                }
                if do6 {
                    stun_ipv6_probes
                        .push(Probe::StunIpv6 {
                            delay,
                            node: derp_node.clone(),
                        })
                        .expect("Pushing StunIpv6 Probe to StunIpv6 ProbeSet");
                }
            }
            plan.add(stun_ipv4_probes);
            plan.add(stun_ipv6_probes);

            // The HTTP and ICMP probes only start after the STUN probes have had a chance.
            let mut https_probes = ProbeSet::new(ProbeProto::Https);
            let mut icmp_probes = ProbeSet::new(ProbeProto::Icmp);
            let start = plan.max_delay();
            for attempt in 0..attempts {
                let delay = start
                    + (retransmit_delay * attempt as u32)
                    + (ACTIVE_RETRANSMIT_EXTRA_DELAY * (attempt as u32 + 1));
                https_probes
                    .push(Probe::Https {
                        delay,
                        node: derp_node.clone(),
                    })
                    .expect("Pushing Https Probe to an Https ProbeSet");

                icmp_probes
                    .push(Probe::Icmp {
                        delay,
                        node: derp_node.clone(),
                    })
                    .expect("Pushing Icmp Probe to an Icmp ProbeSet");
            }
            plan.add(https_probes);
            plan.add(icmp_probes);
        }
        plan
    }

    /// Returns an iterator over the [`ProbeSet`]s in this plan.
    pub(super) fn iter(&self) -> impl Iterator<Item = &ProbeSet> {
        self.0.iter()
    }

    pub(super) fn has_icmp_probes(&self) -> bool {
        for probe_set in self.iter() {
            if probe_set.proto == ProbeProto::Icmp {
                return true;
            }
        }
        false
    }

    /// Adds a [`ProbeSet`] if it contains probes.
    fn add(&mut self, set: ProbeSet) {
        if !set.is_empty() {
            self.0.insert(set);
        }
    }

    /// Returns the delay of the last probe in the probe plan.
    fn max_delay(&self) -> Duration {
        self.0
            .iter()
            .flatten()
            .map(|probe| probe.delay())
            .max()
            .unwrap_or_default()
    }
}

impl fmt::Display for ProbePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProbePlan {{")?;
        for probe_set in self.0.iter() {
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
        Self(iter.into_iter().collect())
    }
}

/// Sorts the nodes in the [`DerpMap`] from fastest to slowest.
///
/// This uses the latencies from the last report to determine the order.  Regions with no
/// data are at the end.
fn sort_regions<'a>(
    derp_map: &'a DerpMap,
    last_report: &Report,
) -> Vec<(&'a Url, &'a Arc<DerpNode>)> {
    let mut prev: Vec<_> = derp_map.nodes().collect();
    prev.sort_by(|(a_url, _a), (b_url, _b)| {
        let latencies_a = last_report.region_latency.get(a_url);
        let latencies_b = last_report.region_latency.get(b_url);
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
                // For both empty latencies sort by region_id.
                a_url.cmp(&b_url)
            }
            (Some(_), Some(_)) => match latencies_a.cmp(&latencies_b) {
                std::cmp::Ordering::Equal => a_url.cmp(&b_url),
                x => x,
            },
        }
    });

    prev
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::defaults::default_derp_map;
    use crate::net::interfaces;
    use crate::netcheck::RegionLatencies;

    use super::*;

    #[tokio::test]
    async fn test_initial_probeplan() {
        let derp_map = default_derp_map();
        let derp_node_1 = derp_map.nodes().nth(0).unwrap().1;
        let derp_node_2 = derp_map.nodes().nth(1).unwrap().1;
        let if_state = interfaces::State::fake();
        let plan = ProbePlan::initial(&derp_map, &if_state);

        let expected_plan: ProbePlan = [
            ProbeSet {
                proto: ProbeProto::StunIpv4,
                probes: vec![
                    Probe::StunIpv4 {
                        delay: Duration::ZERO,
                        node: derp_node_1.clone(),
                    },
                    Probe::StunIpv4 {
                        delay: Duration::from_millis(100),
                        node: derp_node_1.clone(),
                    },
                    Probe::StunIpv4 {
                        delay: Duration::from_millis(200),
                        node: derp_node_1.clone(),
                    },
                ],
            },
            ProbeSet {
                proto: ProbeProto::Https,
                probes: vec![
                    Probe::Https {
                        delay: Duration::from_millis(300),
                        node: derp_node_1.clone(),
                    },
                    Probe::Https {
                        delay: Duration::from_millis(400),
                        node: derp_node_1.clone(),
                    },
                    Probe::Https {
                        delay: Duration::from_millis(500),
                        node: derp_node_1.clone(),
                    },
                ],
            },
            ProbeSet {
                proto: ProbeProto::Icmp,
                probes: vec![
                    Probe::Icmp {
                        delay: Duration::from_millis(300),
                        node: derp_node_1.clone(),
                    },
                    Probe::Icmp {
                        delay: Duration::from_millis(400),
                        node: derp_node_1.clone(),
                    },
                    Probe::Icmp {
                        delay: Duration::from_millis(500),
                        node: derp_node_1.clone(),
                    },
                ],
            },
            ProbeSet {
                proto: ProbeProto::StunIpv4,
                probes: vec![
                    Probe::StunIpv4 {
                        delay: Duration::ZERO,
                        node: derp_node_2.clone(),
                    },
                    Probe::StunIpv4 {
                        delay: Duration::from_millis(100),
                        node: derp_node_2.clone(),
                    },
                    Probe::StunIpv4 {
                        delay: Duration::from_millis(200),
                        node: derp_node_2.clone(),
                    },
                ],
            },
            ProbeSet {
                proto: ProbeProto::Https,
                probes: vec![
                    Probe::Https {
                        delay: Duration::from_millis(600),
                        node: derp_node_2.clone(),
                    },
                    Probe::Https {
                        delay: Duration::from_millis(700),
                        node: derp_node_2.clone(),
                    },
                    Probe::Https {
                        delay: Duration::from_millis(800),
                        node: derp_node_2.clone(),
                    },
                ],
            },
            ProbeSet {
                proto: ProbeProto::Icmp,
                probes: vec![
                    Probe::Icmp {
                        delay: Duration::from_millis(600),
                        node: derp_node_2.clone(),
                    },
                    Probe::Icmp {
                        delay: Duration::from_millis(700),
                        node: derp_node_2.clone(),
                    },
                    Probe::Icmp {
                        delay: Duration::from_millis(800),
                        node: derp_node_2.clone(),
                    },
                ],
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
    async fn test_plan_with_report() {
        for i in 0..10 {
            println!("round {}", i);
            let derp_map = default_derp_map();
            let (u1, derp_node_1) = derp_map.nodes().nth(0).unwrap();
            let (u2, derp_node_2) = derp_map.nodes().nth(1).unwrap();
            let if_state = interfaces::State::fake();
            let mut latencies = RegionLatencies::new();
            latencies.update_region(u1.clone(), Duration::from_millis(2));
            latencies.update_region(u2.clone(), Duration::from_millis(2));
            let last_report = Report {
                udp: true,
                ipv6: true,
                ipv4: true,
                ipv6_can_send: true,
                ipv4_can_send: true,
                os_has_ipv6: true,
                icmpv4: true,
                mapping_varies_by_dest_ip: Some(false),
                hair_pinning: Some(true),
                portmap_probe: None,
                preferred_derp: Some(u1.clone()),
                region_latency: latencies.clone(),
                region_v4_latency: latencies.clone(),
                region_v6_latency: latencies.clone(),
                global_v4: None,
                global_v6: None,
                captive_portal: None,
            };
            let plan = ProbePlan::with_last_report(&derp_map, &if_state, &last_report);
            let expected_plan: ProbePlan = [
                ProbeSet {
                    proto: ProbeProto::StunIpv4,
                    probes: vec![
                        Probe::StunIpv4 {
                            delay: Duration::ZERO,
                            node: derp_node_1.clone(),
                        },
                        Probe::StunIpv4 {
                            delay: Duration::from_micros(52_400),
                            node: derp_node_1.clone(),
                        },
                        Probe::StunIpv4 {
                            delay: Duration::from_micros(104_800),
                            node: derp_node_1.clone(),
                        },
                        Probe::StunIpv4 {
                            delay: Duration::from_micros(157_200),
                            node: derp_node_1.clone(),
                        },
                    ],
                },
                ProbeSet {
                    proto: ProbeProto::Https,
                    probes: vec![
                        Probe::Https {
                            delay: Duration::from_micros(207_200),
                            node: derp_node_1.clone(),
                        },
                        Probe::Https {
                            delay: Duration::from_micros(259_600),
                            node: derp_node_1.clone(),
                        },
                        Probe::Https {
                            delay: Duration::from_micros(312_000),
                            node: derp_node_1.clone(),
                        },
                        Probe::Https {
                            delay: Duration::from_micros(364_400),
                            node: derp_node_1.clone(),
                        },
                    ],
                },
                ProbeSet {
                    proto: ProbeProto::Icmp,
                    probes: vec![
                        Probe::Icmp {
                            delay: Duration::from_micros(207_200),
                            node: derp_node_1.clone(),
                        },
                        Probe::Icmp {
                            delay: Duration::from_micros(259_600),
                            node: derp_node_1.clone(),
                        },
                        Probe::Icmp {
                            delay: Duration::from_micros(312_000),
                            node: derp_node_1.clone(),
                        },
                        Probe::Icmp {
                            delay: Duration::from_micros(364_400),
                            node: derp_node_1.clone(),
                        },
                    ],
                },
                ProbeSet {
                    proto: ProbeProto::StunIpv4,
                    probes: vec![
                        Probe::StunIpv4 {
                            delay: Duration::ZERO,
                            node: derp_node_2.clone(),
                        },
                        Probe::StunIpv4 {
                            delay: Duration::from_micros(52_400),
                            node: derp_node_2.clone(),
                        },
                    ],
                },
                ProbeSet {
                    proto: ProbeProto::Https,
                    probes: vec![
                        Probe::Https {
                            delay: Duration::from_micros(414_400),
                            node: derp_node_2.clone(),
                        },
                        Probe::Https {
                            delay: Duration::from_micros(466_800),
                            node: derp_node_2.clone(),
                        },
                    ],
                },
                ProbeSet {
                    proto: ProbeProto::Icmp,
                    probes: vec![
                        Probe::Icmp {
                            delay: Duration::from_micros(414_400),
                            node: derp_node_2.clone(),
                        },
                        Probe::Icmp {
                            delay: Duration::from_micros(466_800),
                            node: derp_node_2.clone(),
                        },
                    ],
                },
            ]
            .into_iter()
            .collect();

            println!("{} round", i);
            println!("expected:");
            println!("{expected_plan}");
            println!("actual:");
            println!("{plan}");
            // Just in case there's a bug in the Display impl:
            assert_eq!(plan, expected_plan, "{}", i);

            // The readable error:
            assert_eq!(plan.to_string(), expected_plan.to_string(), "{}", i);
        }
    }

    fn create_last_report(
        url_1: &Url,
        latency_1: Option<Duration>,
        url_2: &Url,
        latency_2: Option<Duration>,
    ) -> Report {
        let mut latencies = RegionLatencies::new();
        if let Some(latency_1) = latency_1 {
            latencies.update_region(url_1.clone(), latency_1);
        }
        if let Some(latency_2) = latency_2 {
            latencies.update_region(url_2.clone(), latency_2);
        }
        Report {
            udp: true,
            ipv6: true,
            ipv4: true,
            ipv6_can_send: true,
            ipv4_can_send: true,
            os_has_ipv6: true,
            icmpv4: true,
            mapping_varies_by_dest_ip: Some(false),
            hair_pinning: Some(true),
            portmap_probe: None,
            preferred_derp: Some(url_1.clone()),
            region_latency: latencies.clone(),
            region_v4_latency: latencies.clone(),
            region_v6_latency: latencies.clone(),
            global_v4: None,
            global_v6: None,
            captive_portal: None,
        }
    }

    #[test]
    fn test_derp_region_sort_two_latencies() {
        let derp_map = default_derp_map();
        let r1 = derp_map.nodes().nth(0).unwrap();
        let r2 = derp_map.nodes().nth(1).unwrap();
        let last_report = create_last_report(
            r1.0,
            Some(Duration::from_millis(1)),
            r2.0,
            Some(Duration::from_millis(2)),
        );
        let sorted: Vec<_> = sort_regions(&derp_map, &last_report)
            .iter()
            .map(|(url, _reg)| *url)
            .collect();
        assert_eq!(sorted, vec![r1.0, r2.0]);
    }

    #[test]
    fn test_derp_region_sort_equal_latencies() {
        let derp_map = default_derp_map();
        let r1 = derp_map.nodes().nth(0).unwrap();
        let r2 = derp_map.nodes().nth(1).unwrap();
        let last_report = create_last_report(
            r1.0,
            Some(Duration::from_millis(2)),
            r2.0,
            Some(Duration::from_millis(2)),
        );
        let sorted: Vec<_> = sort_regions(&derp_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![r1.0, r2.0]);
    }

    #[test]
    fn test_derp_region_sort_missing_latency() {
        let derp_map = default_derp_map();
        let r1 = derp_map.nodes().nth(0).unwrap();
        let r2 = derp_map.nodes().nth(1).unwrap();

        let last_report = create_last_report(r1.0, None, r2.0, Some(Duration::from_millis(2)));
        let sorted: Vec<_> = sort_regions(&derp_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![r2.0, r1.0]);

        let last_report = create_last_report(r1.0, Some(Duration::from_millis(2)), r2.0, None);
        let sorted: Vec<_> = sort_regions(&derp_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        assert_eq!(sorted, vec![r1.0, r2.0]);
    }

    #[test]
    fn test_derp_region_sort_no_latency() {
        let derp_map = default_derp_map();
        let r1 = derp_map.nodes().nth(0).unwrap();
        let r2 = derp_map.nodes().nth(1).unwrap();

        let last_report = create_last_report(r1.0, None, r2.0, None);
        let sorted: Vec<_> = sort_regions(&derp_map, &last_report)
            .iter()
            .map(|(url, _)| *url)
            .collect();
        // sorted by region id only
        assert_eq!(sorted, vec![r1.0, r2.0]);
    }
}
