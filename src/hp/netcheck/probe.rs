use std::{collections::HashMap, ops::Deref, time::Duration};

use crate::{
    hp::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6},
    net::interfaces,
};

use super::Report;

/// The number of fastest regions to periodically re-query during incremental netcheck
/// reports. (During a full report, all regions are scanned.)
const NUM_INCREMENTAL_REGIONS: usize = 3;

/// The retransmit interval we use for STUN probes when we're in steady state (not in start-up),
/// but don't have previous latency information for a DERP node. This is a somewhat conservative
/// guess because if we have no data, likely the DERP node is very far away and we have no
/// data because we timed out the last time we probed it.
const DEFAULT_ACTIVE_RETRANSMIT_TIME: Duration = Duration::from_millis(200);

/// The retransmit interval used when netcheck first runs. We have no past context to work with,
/// and we want answers relatively quickly, so it's biased slightly more aggressive than
/// [`DEFAULT_ACTIVE_RETRANSMIT_TIME`]. A few extra packets at startup is fine.
const DEFAULT_INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

/// The protocol used to time a node's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProbeProto {
    /// STUN IPv4
    Ipv4,
    /// STUN IPv6
    Ipv6,
    /// HTTPS
    Https,
}

#[derive(Debug, Clone)]
pub enum Probe {
    Ipv4 {
        /// When the probe is started, relative to the time that `get_report` is called.
        /// One probe in each `ProbePlan` should have a delay of 0. Non-zero values
        /// are for retries on UDP loss or timeout.
        delay: Duration,

        /// The name of the node name. DERP node names are globally
        /// unique so there's no region ID.
        node: String,
    },
    Ipv6 {
        delay: Duration,
        node: String,
    },
    Https {
        delay: Duration,
        node: String,
        region: DerpRegion,
    },
}

impl Probe {
    pub fn delay(&self) -> &Duration {
        match self {
            Probe::Ipv4 { delay, .. } | Probe::Ipv6 { delay, .. } | Probe::Https { delay, .. } => {
                delay
            }
        }
    }

    pub fn proto(&self) -> ProbeProto {
        match self {
            Probe::Ipv4 { .. } => ProbeProto::Ipv4,
            Probe::Ipv6 { .. } => ProbeProto::Ipv6,
            Probe::Https { .. } => ProbeProto::Https,
        }
    }

    pub fn node(&self) -> &str {
        match self {
            Probe::Ipv4 { node, .. } => node,
            Probe::Ipv6 { node, .. } => node,
            Probe::Https { node, .. } => node,
        }
    }
}

/// Describes a set of node probes to run.
/// The map key is a descriptive name, only used for tests.
///
/// The values are logically an unordered set of tests to run concurrently.
/// In practice there's some order to them based on their delay fields,
/// but multiple probes can have the same delay time or be running concurrently
/// both within and between sets.
///
/// A set of probes is done once either one of the probes completes, or
/// the next probe to run wouldn't yield any new information not
/// already discovered by any previous probe in any set.
#[derive(Debug, Default, Clone)]
pub struct ProbePlan(HashMap<String, Vec<Probe>>);

impl ProbePlan {
    pub fn has_https_probes(&self) -> bool {
        self.keys().any(|k| k.ends_with("https"))
    }
    /// Generates the probe plan for a `DerpMap`, given the most recent report and
    /// whether IPv6 is configured on an interface.
    pub fn new(dm: &DerpMap, if_state: &interfaces::State, last: Option<&Report>) -> ProbePlan {
        if last.is_none() || last.unwrap().region_latency.is_empty() {
            return Self::new_initial(dm, if_state);
        }
        let last = last.unwrap();
        let have6if = if_state.have_v6;
        let have4if = if_state.have_v4;
        let mut plan = ProbePlan::default();

        let had4 = !last.region_v4_latency.is_empty();
        let had6 = !last.region_v6_latency.is_empty();
        let had_both = have6if && had4 && had6;
        for (ri, reg) in sort_regions(dm, last).into_iter().enumerate() {
            if ri == NUM_INCREMENTAL_REGIONS {
                break;
            }
            let mut do4 = have4if;
            let mut do6 = have6if;
            let dohttps = !have4if && !have6if;

            // By default, each node only gets one STUN packet sent,
            // except the fastest two from the previous round.
            let mut tries = 1;
            let is_fastest_two = ri < 2;

            if is_fastest_two {
                tries = 2;
            } else if had_both {
                // For dual stack machines, make the 3rd & slower nodes alternate between.
                if ri % 2 == 0 {
                    (do4, do6) = (true, false);
                } else {
                    (do4, do6) = (false, true);
                }
            }
            if !is_fastest_two && !had6 {
                do6 = false;
            }

            if reg.region_id == last.preferred_derp {
                // But if we already had a DERP home, try extra hard to
                // make sure it's there so we don't flip flop around.
                tries = 4;
            }

            let mut p4 = Vec::new();
            let mut p6 = Vec::new();
            let mut https = Vec::new();

            for tr in 0..tries {
                if reg.nodes.is_empty() {
                    // Shouldn't be possible.
                    continue;
                }
                if tr != 0 && !had6 {
                    do6 = false;
                }
                let n = &reg.nodes[tr % reg.nodes.len()];
                let mut prev_latency = last.region_latency[&reg.region_id] * 120 / 100;
                if prev_latency.is_zero() {
                    prev_latency = DEFAULT_ACTIVE_RETRANSMIT_TIME;
                }
                let mut delay = prev_latency * tr as u32;
                if tr > 1 {
                    delay += Duration::from_millis(50) * tr as u32;
                }
                if do4 {
                    p4.push(Probe::Ipv4 {
                        delay,
                        node: n.name.clone(),
                    });
                }
                if do6 {
                    p6.push(Probe::Ipv6 {
                        delay,
                        node: n.name.clone(),
                    });
                }
                if dohttps {
                    https.push(Probe::Https {
                        delay,
                        region: reg.clone(),
                        node: n.name.clone(),
                    });
                }
            }
            if !p4.is_empty() {
                plan.0.insert(format!("region-{}-v4", reg.region_id), p4);
            }
            if !p6.is_empty() {
                plan.0.insert(format!("region-{}-v6", reg.region_id), p6);
            }
            if !https.is_empty() {
                plan.0
                    .insert(format!("region-{}-https", reg.region_id), https);
            }
        }
        plan
    }

    fn new_initial(dm: &DerpMap, if_state: &interfaces::State) -> ProbePlan {
        let mut plan = ProbePlan::default();

        for reg in dm.regions.values() {
            let mut p4 = Vec::new();
            let mut p6 = Vec::new();
            let mut https = Vec::new();

            for tr in 0..3 {
                let n = &reg.nodes[tr % reg.nodes.len()];
                let delay = DEFAULT_INITIAL_RETRANSMIT * tr as u32;
                let have_v4 = if_state.have_v4 && node_might4(n);
                let have_v6 = if_state.have_v6 && node_might6(n);
                if have_v4 {
                    p4.push(Probe::Ipv4 {
                        delay,
                        node: n.name.clone(),
                    });
                }
                if have_v6 {
                    p6.push(Probe::Ipv6 {
                        delay,
                        node: n.name.clone(),
                    })
                }
                if region_has_derp_node(reg) || (!have_v6 && !have_v4) {
                    https.push(Probe::Https {
                        delay,
                        region: reg.clone(),
                        node: n.name.clone(),
                    });
                }
            }
            if !p4.is_empty() {
                plan.0.insert(format!("region-{}-v4", reg.region_id), p4);
            }
            if !p6.is_empty() {
                plan.0.insert(format!("region-{}-v6", reg.region_id), p6);
            }
            if !https.is_empty() {
                plan.0
                    .insert(format!("region-{}-https", reg.region_id), https);
            }
        }
        plan
    }
}

impl Deref for ProbePlan {
    type Target = HashMap<String, Vec<Probe>>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Returns the regions of dm first sorted from fastest to slowest (based on the 'last' report),
/// end in regions that have no data.
fn sort_regions<'a>(dm: &'a DerpMap, last: &Report) -> Vec<&'a DerpRegion> {
    let mut prev: Vec<_> = dm.regions.values().filter(|r| !r.avoid).collect();
    prev.sort_by(|a, b| {
        let da = last.region_latency.get(&a.region_id);
        let db = last.region_latency.get(&b.region_id);
        if db.is_none() && da.is_some() {
            // Non-zero sorts before zero.
            return std::cmp::Ordering::Greater;
        }
        if da.is_none() {
            // Zero can't sort before anything else.
            return std::cmp::Ordering::Less;
        }
        da.cmp(&db)
    });

    prev
}

/// Reports whether n might reply to STUN over IPv6 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might6(n: &DerpNode) -> bool {
    match n.ipv6 {
        UseIpv6::None => true,
        UseIpv6::Disabled => false,
        UseIpv6::Some(_) => true,
    }
}

/// Reports whether n might reply to STUN over IPv4 based on
/// its config alone, without DNS lookups. It only returns false if
/// it's not explicitly disabled.
fn node_might4(n: &DerpNode) -> bool {
    match n.ipv4 {
        UseIpv4::None => true,
        UseIpv4::Disabled => false,
        UseIpv4::Some(_) => true,
    }
}

fn region_has_derp_node(r: &DerpRegion) -> bool {
    for n in &r.nodes {
        if !n.stun_only {
            return true;
        }
    }

    false
}
