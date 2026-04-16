//! Detection of the local NAT's port-allocation pattern.
//!
//! iroh runs QAD probes against multiple relays and keeps every observed
//! external address in [`crate::NetReport::qad_v4_observations`] /
//! `qad_v6_observations`. Feeding that list into [`NatPattern::classify`]
//! produces a classification, and [`NatPattern::expand_candidates`] turns
//! the pattern into a predicted port set to advertise to peers.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// A single QAD probe observation used for NAT pattern classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// External address the QAD server saw.
    pub observed: SocketAddr,
}

/// The detected port-allocation pattern of the local NAT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatPattern {
    /// Not enough observations to classify (need at least 3).
    Unknown,
    /// Port preservation: every probe saw the same external port.
    ///
    /// When `external_port == bound_port` this is a port-preserving NAT (or
    /// no NAT at all). When the two differ the NAT is still
    /// endpoint-independent but shifts the port.
    Preservation {
        /// Port the local socket is bound to.
        bound_port: u16,
        /// External port observed from every QAD probe.
        external_port: u16,
    },
    /// Monotone allocation: observed ports differ by a constant step.
    ///
    /// The peer can predict the next allocation as `last_port + delta`.
    Incremental {
        /// Highest port observed so far.
        last_port: u16,
        /// Constant step between successive allocations.
        delta: u16,
        /// Whether all observations preserved the parity of the bound port
        /// (RFC 4787 REQ-4).
        parity_preserving: bool,
    },
    /// Port-block allocation: observations fall inside a contiguous block.
    ///
    /// Typical of CGN vendors (Fortinet, Juniper, F5) where each subscriber
    /// gets a fixed block of ports within which allocations are effectively
    /// random.
    PortBlock {
        /// Lowest port in the inferred block.
        block_base: u16,
        /// Number of ports in the block (always a power of two).
        block_size: u16,
        /// First port observed in the cycle, used as the spiral centre when
        /// expanding candidates.
        first_observed: u16,
    },
    /// Random allocation across a wide range; no useful prediction.
    Random,
}

/// Configuration controlling pattern detection and candidate expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatPatternConfig {
    /// Master enable switch.
    pub enabled: bool,
    /// Upper bound on the number of candidates emitted for
    /// [`NatPattern::PortBlock`].
    ///
    /// Set to zero to disable PBA-specific expansion without disabling
    /// [`NatPattern::Incremental`] prediction.
    pub pba_candidate_cap: usize,
    /// Half-width of the candidate window emitted for
    /// [`NatPattern::Incremental`]. The total emitted is approximately
    /// `2 * incremental_window + 1` before parity filtering.
    pub incremental_window: u16,
}

impl Default for NatPatternConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            pba_candidate_cap: 128,
            incremental_window: 4,
        }
    }
}

/// Lower bound on observation count; fewer than this yields
/// [`NatPattern::Unknown`].
const MIN_OBSERVATIONS: usize = 3;
/// Spread at or below this is classified as [`NatPattern::Incremental`] or
/// [`NatPattern::Preservation`] rather than [`NatPattern::PortBlock`].
const INCREMENTAL_MAX_SPREAD: u16 = 31;
/// Spread above this is [`NatPattern::Random`].
const PORT_BLOCK_MAX_SPREAD: u16 = 2047;

impl NatPattern {
    /// Classify the local NAT from a set of QAD observations.
    ///
    /// `bound_port` is the local port the probes originated from; it is used
    /// to detect port preservation and parity behaviour.
    pub fn classify(observations: &[Observation], bound_port: u16) -> Self {
        if observations.len() < MIN_OBSERVATIONS {
            return Self::Unknown;
        }
        let ports: Vec<u16> = observations.iter().map(|o| o.observed.port()).collect();

        if ports.iter().all(|p| *p == ports[0]) {
            return Self::Preservation {
                bound_port,
                external_port: ports[0],
            };
        }

        if let Some(delta) = detect_constant_delta(&ports) {
            let last_port = ports.iter().copied().max().unwrap_or(0);
            let parity_preserving = ports.iter().all(|p| (p & 1) == (bound_port & 1));
            return Self::Incremental {
                last_port,
                delta,
                parity_preserving,
            };
        }

        let (Some(min), Some(max)) = (ports.iter().copied().min(), ports.iter().copied().max())
        else {
            return Self::Unknown;
        };
        let spread = max - min;

        if spread <= INCREMENTAL_MAX_SPREAD {
            // Narrow non-monotone spread: treat as a small block.
            let block_size = (spread + 1).next_power_of_two();
            let block_base = min & !(block_size.saturating_sub(1));
            return Self::PortBlock {
                block_base,
                block_size,
                first_observed: observations[0].observed.port(),
            };
        }
        if spread <= PORT_BLOCK_MAX_SPREAD {
            let block_size = (spread + 1).next_power_of_two();
            let block_base = min & !(block_size.saturating_sub(1));
            return Self::PortBlock {
                block_base,
                block_size,
                first_observed: observations[0].observed.port(),
            };
        }

        Self::Random
    }

    /// Produce the predicted external-port candidate set for this pattern.
    ///
    /// The output respects `config.pba_candidate_cap` and
    /// `config.incremental_window`, and is parity-filtered for
    /// [`NatPattern::Incremental`] patterns where the NAT appears to
    /// preserve parity.
    pub fn expand_candidates(&self, config: &NatPatternConfig) -> Vec<u16> {
        if !config.enabled {
            return Vec::new();
        }
        match self {
            Self::Unknown | Self::Random => Vec::new(),
            Self::Preservation { external_port, .. } => vec![*external_port],
            Self::Incremental {
                last_port,
                delta,
                parity_preserving,
            } => {
                let window = config.incremental_window;
                let mut out = Vec::with_capacity(2 * window as usize + 1);
                for k in 1..=(window + 1) {
                    out.push(last_port.saturating_add(delta.saturating_mul(k)));
                }
                for k in 1..=window {
                    out.push(last_port.saturating_sub(delta.saturating_mul(k)));
                }
                if *parity_preserving {
                    let parity = last_port & 1;
                    out.retain(|p| (p & 1) == parity);
                }
                out.sort_unstable();
                out.dedup();
                out
            }
            Self::PortBlock {
                block_base,
                block_size,
                first_observed,
            } => {
                let cap = config.pba_candidate_cap.min(*block_size as usize);
                if cap == 0 {
                    return Vec::new();
                }
                let base = *block_base;
                let end = base.saturating_add(*block_size);
                let mut out = Vec::with_capacity(cap);
                out.push(*first_observed);
                for k in 1..*block_size {
                    let up = first_observed.saturating_add(k);
                    if up < end && !out.contains(&up) {
                        out.push(up);
                        if out.len() >= cap {
                            break;
                        }
                    }
                    if let Some(down) = first_observed.checked_sub(k)
                        && down >= base
                        && !out.contains(&down)
                    {
                        out.push(down);
                        if out.len() >= cap {
                            break;
                        }
                    }
                }
                out
            }
        }
    }
}

impl std::fmt::Display for NatPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Preservation { .. } => write!(f, "preservation"),
            Self::Incremental { .. } => write!(f, "incremental"),
            Self::PortBlock { .. } => write!(f, "port-block"),
            Self::Random => write!(f, "random"),
        }
    }
}

fn detect_constant_delta(ports: &[u16]) -> Option<u16> {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() < 2 {
        return None;
    }
    let deltas: Vec<u16> = sorted.windows(2).map(|w| w[1] - w[0]).collect();
    let first = *deltas.first()?;
    if first == 0 || first > 32 {
        return None;
    }
    deltas.iter().all(|d| *d == first).then_some(first)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn obs(port: u16) -> Observation {
        Observation {
            observed: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), port),
        }
    }

    #[test]
    fn unknown_when_too_few_observations() {
        let pattern = NatPattern::classify(&[obs(1), obs(2)], 42);
        assert_eq!(pattern, NatPattern::Unknown);
    }

    #[test]
    fn preservation_when_all_ports_equal() {
        let pattern = NatPattern::classify(&[obs(5000), obs(5000), obs(5000)], 5000);
        assert_eq!(
            pattern,
            NatPattern::Preservation {
                bound_port: 5000,
                external_port: 5000
            }
        );
    }

    #[test]
    fn preservation_with_port_shift() {
        let pattern = NatPattern::classify(&[obs(49200), obs(49200), obs(49200)], 12345);
        assert_eq!(
            pattern,
            NatPattern::Preservation {
                bound_port: 12345,
                external_port: 49200
            }
        );
    }

    #[test]
    fn incremental_delta_one() {
        let pattern = NatPattern::classify(&[obs(40001), obs(40002), obs(40003)], 40001);
        assert_eq!(
            pattern,
            NatPattern::Incremental {
                last_port: 40003,
                delta: 1,
                parity_preserving: false,
            }
        );
    }

    #[test]
    fn incremental_parity_preserving() {
        let pattern = NatPattern::classify(&[obs(40002), obs(40004), obs(40006)], 40000);
        assert_eq!(
            pattern,
            NatPattern::Incremental {
                last_port: 40006,
                delta: 2,
                parity_preserving: true,
            }
        );
    }

    #[test]
    fn port_block_for_narrow_non_monotone_spread() {
        let pattern = NatPattern::classify(&[obs(44100), obs(44500), obs(44200)], 12345);
        let NatPattern::PortBlock {
            block_base,
            block_size,
            first_observed,
        } = pattern
        else {
            panic!("expected PortBlock, got {pattern:?}");
        };
        assert_eq!(first_observed, 44100);
        assert!(block_size.is_power_of_two());
        assert!(block_base <= 44100);
        assert!(block_base + block_size > 44500);
    }

    #[test]
    fn random_for_wide_spread() {
        let pattern = NatPattern::classify(&[obs(3000), obs(51000), obs(22000)], 12345);
        assert_eq!(pattern, NatPattern::Random);
    }

    #[test]
    fn expand_preservation() {
        let pattern = NatPattern::Preservation {
            bound_port: 100,
            external_port: 200,
        };
        assert_eq!(
            pattern.expand_candidates(&NatPatternConfig::default()),
            vec![200]
        );
    }

    #[test]
    fn expand_incremental_applies_parity() {
        let pattern = NatPattern::Incremental {
            last_port: 100,
            delta: 2,
            parity_preserving: true,
        };
        let out = pattern.expand_candidates(&NatPatternConfig::default());
        assert!(out.iter().all(|p| p % 2 == 0), "all candidates must be even");
    }

    #[test]
    fn expand_incremental_window_controls_size() {
        let pattern = NatPattern::Incremental {
            last_port: 1000,
            delta: 1,
            parity_preserving: false,
        };
        let narrow = pattern.expand_candidates(&NatPatternConfig {
            incremental_window: 1,
            ..Default::default()
        });
        let wide = pattern.expand_candidates(&NatPatternConfig {
            incremental_window: 16,
            ..Default::default()
        });
        assert!(narrow.len() < wide.len());
    }

    #[test]
    fn expand_port_block_respects_cap_and_bounds() {
        let pattern = NatPattern::PortBlock {
            block_base: 1024,
            block_size: 1024,
            first_observed: 1500,
        };
        let cap = 128;
        let out = pattern.expand_candidates(&NatPatternConfig {
            pba_candidate_cap: cap,
            ..Default::default()
        });
        assert_eq!(out.len(), cap);
        assert_eq!(out[0], 1500, "first candidate is observed port");
        assert!(
            out.iter().all(|p| (1024..2048).contains(p)),
            "all candidates stay within the block"
        );
    }

    #[test]
    fn expand_port_block_cap_zero_emits_nothing() {
        let pattern = NatPattern::PortBlock {
            block_base: 1024,
            block_size: 1024,
            first_observed: 1500,
        };
        let out = pattern.expand_candidates(&NatPatternConfig {
            pba_candidate_cap: 0,
            ..Default::default()
        });
        assert!(out.is_empty());
    }

    #[test]
    fn expand_disabled_emits_nothing() {
        let pattern = NatPattern::Incremental {
            last_port: 100,
            delta: 1,
            parity_preserving: false,
        };
        let out = pattern.expand_candidates(&NatPatternConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(out.is_empty());
    }

    #[test]
    fn expand_random_and_unknown_emit_nothing() {
        let cfg = NatPatternConfig::default();
        assert!(NatPattern::Random.expand_candidates(&cfg).is_empty());
        assert!(NatPattern::Unknown.expand_candidates(&cfg).is_empty());
    }
}
