//! Path state for UDP addresses of a single peer node.
//!
//! This started as simply moving the [`NodeState`]'s `direct_addresses` and `best_addr`
//! into one place together.  The aim is for external places to not directly interact with
//! the inside and instead only notifies this struct of state changes to each path.
//!
//! [`NodeState`]: super::node_state::NodeState
use std::{collections::BTreeMap, net::SocketAddr};

use n0_future::time::Instant;
use tracing::{event, Level};

use super::{path_state::PathState, IpPort};

/// The address on which to send datagrams over UDP.
///
/// The [`MagicSock`] sends packets to zero or one UDP address, depending on the known paths
/// to the remote node.  This conveys the UDP address to send on from the [`NodeUdpPaths`]
/// to the [`NodeState`].
///
/// [`NodeUdpPaths`] contains all the UDP path states, while [`NodeState`] has to decide the
/// bigger picture including the relay server.
///
/// See [`NodeUdpPaths::send_addr`].
///
/// [`MagicSock`]: crate::magicsock::MagicSock
/// [`NodeState`]: super::node_state::NodeState
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpSendAddr {
    /// The UDP address can be relied on to deliver data to the remote node.
    ///
    /// This means this path is usable with a reasonable latency and can be fully trusted to
    /// transport payload data to the remote node.
    Valid(SocketAddr),
    /// The UDP address is highly likely to work, but has not been used for a while.
    ///
    /// The path should be usable but has not carried DISCO or payload data for a little too
    /// long.  It is best to also use a backup, i.e. relay, path if possible.
    Outdated(SocketAddr),
    /// The UDP address is not known to work, but it might.
    ///
    /// We know this UDP address belongs to the remote node, but we do not know if the path
    /// already works or may need holepunching before it will start to work.  It might even
    /// never work.  It is still useful to send to this together with backup path,
    /// i.e. relay, in case the path works: if the path does not need holepunching it might
    /// be much faster.  And if there is no relay path at all it might be the only way to
    /// establish a connection.
    Unconfirmed(SocketAddr),
    /// No known UDP path exists to the remote node.
    #[default]
    None,
}

impl UdpSendAddr {
    pub fn get_addr(&self) -> Option<SocketAddr> {
        match self {
            UdpSendAddr::Valid(addr)
            | UdpSendAddr::Outdated(addr)
            | UdpSendAddr::Unconfirmed(addr) => Some(*addr),
            UdpSendAddr::None => None,
        }
    }
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
    /// The current address we use to send on.
    ///
    /// This is *almost* the same as going through `paths` and finding
    /// the best one, except that this is
    /// 1. Not updated in `send_addr`, but instead when there's changes to `paths`, so that `send_addr` can take `&self`.
    /// 2. Slightly sticky: It only changes when
    ///   - the current send addr is not a validated path anymore or
    ///   - we received a pong with lower latency.
    pub(super) best: UdpSendAddr,
    /// The current best address to send on from all IPv4 addresses we have available.
    ///
    /// Follows the same logic as `best` above, but doesn't include any IPv6 addresses.
    pub(super) best_ipv4: UdpSendAddr,
}

impl NodeUdpPaths {
    pub(super) fn new() -> Self {
        Default::default()
    }

    #[cfg(test)]
    pub(super) fn from_parts(paths: BTreeMap<IpPort, PathState>, best: UdpSendAddr) -> Self {
        Self {
            paths,
            best_ipv4: best, // we only use ipv4 addrs in tests
            best,
        }
    }

    /// Returns the current UDP address to send on.
    pub(super) fn send_addr(&self, have_ipv6: bool) -> &UdpSendAddr {
        if !have_ipv6 {
            return &self.best_ipv4;
        }
        &self.best
    }

    /// Changes the current best address(es) to ones chosen as described in [`Self::best_addr`] docs.
    ///
    /// Returns whether one of the best addresses had to change.
    ///
    /// This should be called any time that `paths` is modified.
    pub(super) fn update_to_best_addr(&mut self, now: Instant) -> bool {
        let best_ipv4 = self.best_addr(false, now);
        let best = self.best_addr(true, now);
        let mut changed = false;
        if best_ipv4 != self.best_ipv4 {
            event!(
                target: "iroh::_events::udp::best_ipv4",
                Level::DEBUG,
                ?best_ipv4,
            );
            changed = true;
        }
        if best != self.best {
            event!(
                target: "iroh::_events::udp::best",
                Level::DEBUG,
                ?best,
            );
            changed = true;
        }
        self.best_ipv4 = best_ipv4;
        self.best = best;
        changed
    }

    pub(super) fn best_addr(&self, have_ipv6: bool, now: Instant) -> UdpSendAddr {
        let Some((ipp, path)) = self
            .paths
            .iter()
            .filter(|(ipp, _)| have_ipv6 || ipp.ip.is_ipv4())
            .max_by_key(|(ipp, path)| {
                // We find the best by sorting on a key of type (Option<ReverseOrd<Duration>>, Option<ReverseOrd<Duration>>, bool)
                // where the first is set to Some(ReverseOrd(latency)) iff path.is_valid(now) and
                // the second is set to Some(ReverseOrd(latency)) if path.is_outdated(now) and
                // the third is set to whether the ipp is ipv6.
                // This makes max_by_key sort for the lowest valid latency first, then sort for
                // the lowest outdated latency second, and if latencies are equal, it'll sort IPv6 paths first.
                let is_ipv6 = ipp.ip.is_ipv6();
                if let Some(latency) = path.validity.latency_if_valid(now) {
                    (Some(ReverseOrd(latency)), None, is_ipv6)
                } else if let Some(latency) = path.validity.latency_if_outdated(now) {
                    (None, Some(ReverseOrd(latency)), is_ipv6)
                } else {
                    (None, None, is_ipv6)
                }
            })
        else {
            return UdpSendAddr::None;
        };

        if path.validity.is_valid(now) {
            UdpSendAddr::Valid((*ipp).into())
        } else if path.validity.is_outdated(now) {
            UdpSendAddr::Outdated((*ipp).into())
        } else {
            UdpSendAddr::Unconfirmed((*ipp).into())
        }
    }
}

#[derive(PartialEq, Eq)]
struct ReverseOrd<N: PartialOrd + Ord + PartialEq + Eq>(N);

impl<N: PartialOrd + Ord + PartialEq + Eq> Ord for ReverseOrd<N> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

impl<N: PartialOrd + Ord + PartialEq + Eq> PartialOrd for ReverseOrd<N> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0
            .partial_cmp(&other.0)
            .map(std::cmp::Ordering::reverse)
    }
}
