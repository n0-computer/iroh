//! The relay probes.
//!
//! All the probes try and establish the latency to the relay servers.  Preferably the QAD
//! probes work and we also learn about our public IP addresses and ports.  But fallback
//! probes for HTTPS exist as well.

use std::{collections::BTreeSet, fmt, sync::Arc};

use iroh_relay::{RelayConfig, RelayMap};
use n0_future::time::Duration;

use crate::net_report::Report;

/// The retransmit interval used.
const DEFAULT_INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

/// The delay before starting HTTPS probes.
const HTTPS_OFFSET: Duration = Duration::from_millis(200);

/// The protocol used to time an endpoint's latency.
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
    probes: Vec<(Duration, Arc<RelayConfig>)>,
}

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

    fn push(&mut self, delay: Duration, endpoint: Arc<RelayConfig>) {
        self.probes.push((delay, endpoint));
    }

    fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub(super) fn params(&self) -> impl Iterator<Item = &(Duration, Arc<RelayConfig>)> {
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
        let mut plan = Self::default();

        for relay in relay_map.relays::<Vec<_>>() {
            let mut https_probes = ProbeSet::new(Probe::Https);

            for attempt in 0u32..3 {
                let delay = HTTPS_OFFSET + DEFAULT_INITIAL_RETRANSMIT * attempt;
                https_probes.push(delay, relay.clone());
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

        // TODO: is this good?
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
}

impl fmt::Display for ProbePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "ProbePlan {{")?;
        for probe_set in self.set.iter() {
            writeln!(f, r#"    ProbeSet("{}") {{"#, probe_set.proto)?;
            for (delay, endpoint) in probe_set.probes.iter() {
                writeln!(f, "        {delay:?} to {endpoint},")?;
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
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::net_report::test_utils;

    /// Shorthand which declares a new ProbeSet.
    ///
    /// `$kind`: The `Probe`.
    /// `$endpoint`: Expression which will be an `Arc<RelayConfig>`.
    /// `$delays`: A `Vec` of the delays for this probe.
    macro_rules! probeset {
        (proto: Probe::$kind:ident, relay: $endpoint:expr, delays: $delays:expr,) => {
            ProbeSet {
                proto: Probe::$kind,
                probes: $delays.iter().map(|delay| (*delay, $endpoint)).collect(),
            }
        };
    }

    fn default_protocols() -> BTreeSet<Probe> {
        BTreeSet::from([Probe::QadIpv4, Probe::QadIpv6, Probe::Https])
    }

    #[tokio::test]
    async fn test_initial_probeplan() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_1 = &relay_map.relays::<Vec<_>>()[0];
        let relay_2 = &relay_map.relays::<Vec<_>>()[1];
        let plan = ProbePlan::initial(&relay_map, &default_protocols());

        let expected_plan: ProbePlan = [
            probeset! {
                proto: Probe::Https,
                relay: relay_1.clone(),
                delays: [
                    Duration::from_millis(200),
                    Duration::from_millis(300),
                    Duration::from_millis(400)
                ],
            },
            probeset! {
                proto: Probe::Https,
                relay: relay_2.clone(),
                delays: [
                    Duration::from_millis(200),
                    Duration::from_millis(300),
                    Duration::from_millis(400)
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
    async fn test_initial_probeplan_some_protocols() {
        let (_servers, relay_map) = test_utils::relay_map(2).await;
        let relay_1 = &relay_map.relays::<Vec<_>>()[0];
        let relay_2 = &relay_map.relays::<Vec<_>>()[1];
        let plan = ProbePlan::initial(&relay_map, &BTreeSet::from([Probe::Https]));

        let expected_plan: ProbePlan = [
            probeset! {
                proto: Probe::Https,
                relay: relay_1.clone(),
                delays: [Duration::from_millis(200),
                         Duration::from_millis(300),
                         Duration::from_millis(400)],
            },
            probeset! {
                proto: Probe::Https,
                relay: relay_2.clone(),
                delays: [Duration::from_millis(200),
                         Duration::from_millis(300),
                         Duration::from_millis(400)],
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
}
