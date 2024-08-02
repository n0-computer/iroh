//! Path state for UDP addresses of a single peer node.
//!
//! This started as simply moving the [`NodeState`]'s `direct_addresses` and `best_addr`
//! into one place together.  The aim is for external places to not directly interact with
//! the inside and instead only notifies this struct of state changes to each path.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;
use tracing::warn;

use crate::disco::SendAddr;

use super::best_addr::{self, BestAddr};
use super::node_state::{PathState, PongReply};
use super::IpPort;

#[derive(Debug)]
pub(super) enum UdpSendAddr {
    Valid(SocketAddr),
    Outdated(SocketAddr),
    Unconfirmed(SocketAddr),
    None,
}

/// The UDP paths for a single node.
///
/// Paths are identified by the [`IpPort`] of their UDP address.
///
/// Initially this collects two structs directly from the [`NodeState`] into one place,
/// leaving the APIs and astractions the same.  The goal is that this slowly migrates
/// directly interacting with this data into only receiving [`PathState`] updates.  This
/// will consolidate the logic of direct path selection and make this simpler to reason
/// about.  However doing that all at once is too large a refactor.
///
/// [`NodeState`]: super::node_state::NodeState
#[derive(Debug, Default)]
pub(super) struct NodeUdpPaths {
    /// The state for each of this node's direct paths.
    pub(super) paths: BTreeMap<IpPort, PathState>,
    /// Best UDP path currently selected.
    pub(super) best_addr: BestAddr,
    /// If we had to choose a path because we had no `best_addr` it is stored here.
    chosen_candidate: Option<IpPort>,
}

impl NodeUdpPaths {
    pub(super) fn new() -> Self {
        Default::default()
    }

    #[cfg(test)]
    pub(super) fn from_parts(paths: BTreeMap<IpPort, PathState>, best_addr: BestAddr) -> Self {
        Self {
            paths,
            best_addr,
            chosen_candidate: None,
        }
    }

    /// Returns the current UDP address to send on.
    ///
    /// TODO: The goal here is for this to simply return the already known send address, so
    /// it should be `&self` and not `&mut self`.  This is only possible once the state from
    /// [`NodeUdpPaths`] is no longer modified from outside.
    pub(super) fn send_addr(&mut self, now: Instant, have_ipv6: bool) -> UdpSendAddr {
        self.assign_best_addr_from_candidates_if_empty();
        match self.best_addr.state(now) {
            best_addr::State::Valid(addr) => UdpSendAddr::Valid(addr.addr),
            best_addr::State::Outdated(addr) => UdpSendAddr::Outdated(addr.addr),
            best_addr::State::Empty => {
                // No direct connection has been used before.  If we know of any possible
                // candidate addresses, randomlly try to use one.  This path is most
                // effective when folks use a NodeAddr with exactly one direct address which
                // they know to work, effectively like using a traditional socket or quic
                // endpoint.
                let addr = self
                    .chosen_candidate
                    .and_then(|ipp| self.paths.get(&ipp))
                    .and_then(|path| path.udp_addr())
                    .filter(|addr| addr.is_ipv4() || have_ipv6)
                    .or_else(|| {
                        // Look for a new candidate in all the known paths.  This may look
                        // like a RNG use on the hot-path but this is normally invoked at
                        // most most once at startup.
                        let addr = self
                            .paths
                            .values()
                            .filter_map(|path| path.udp_addr())
                            .filter(|addr| addr.is_ipv4() || have_ipv6)
                            .choose(&mut rand::thread_rng());
                        self.chosen_candidate = addr.as_ref().map(|addr| IpPort::from(*addr));
                        addr
                    });
                match addr {
                    Some(addr) => UdpSendAddr::Unconfirmed(addr),
                    None => UdpSendAddr::None,
                }
            }
        }
    }

    /// Fixup best_adrr from candidates.
    ///
    /// If somehow we end up in a state where we failed to set a best_addr, while we do have
    /// valid candidates, this will chose a candidate and set best_addr again.  Most likely
    /// this is a bug elsewhere though.
    fn assign_best_addr_from_candidates_if_empty(&mut self) {
        if !self.best_addr.is_empty() {
            return;
        }

        // The highest acceptable latency for an endpoint path.  If the latency is higher
        // then this the path will be ignored.
        const MAX_LATENCY: Duration = Duration::from_secs(60 * 60);
        let best_pong = self.paths.iter().fold(None, |best_pong, (ipp, state)| {
            let best_latency = best_pong
                .map(|p: &PongReply| p.latency)
                .unwrap_or(MAX_LATENCY);
            match state.recent_pong() {
                // This pong is better if it has a lower latency, or if it has the same
                // latency but on an IPv6 path.
                Some(pong)
                    if pong.latency < best_latency
                        || (pong.latency == best_latency && ipp.ip().is_ipv6()) =>
                {
                    Some(pong)
                }
                _ => best_pong,
            }
        });

        // If we found a candidate, set to best addr
        if let Some(pong) = best_pong {
            if let SendAddr::Udp(addr) = pong.from {
                warn!(%addr, "No best_addr was set, choose candidate with lowest latency");
                self.best_addr.insert_if_better_or_reconfirm(
                    addr,
                    pong.latency,
                    best_addr::Source::BestCandidate,
                    pong.pong_at,
                )
            }
        }
    }
}
