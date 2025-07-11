//! The state kept for each network path to a remote node.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};

use iroh_base::NodeId;
use n0_future::time::{Duration, Instant};

use super::{
    node_state::{ControlMsg, SESSION_ACTIVE_TIMEOUT},
    IpPort, Source,
};
use crate::disco::SendAddr;

/// State about a particular path to another [`NodeState`].
///
/// This state is used for both the relay path and any direct UDP paths.
///
/// [`NodeState`]: super::node_state::NodeState
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PathState {
    /// The node for which this path exists.
    node_id: NodeId,
    /// The path this applies for.
    path: SendAddr,

    /// The time this endpoint was last advertised via a call-me-maybe DISCO message.
    pub(super) call_me_maybe_time: Option<Instant>,

    /// When the last payload data was **received** via this path.
    ///
    /// This excludes DISCO messages.
    pub(super) last_payload_msg: Option<Instant>,
    /// Sources is a map of [`Source`]s to [`Instant`]s, keeping track of all the ways we have
    /// learned about this path
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size of
    /// the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
}

impl PathState {
    pub(super) fn new(node_id: NodeId, path: SendAddr, source: Source, now: Instant) -> Self {
        let mut sources = HashMap::new();
        sources.insert(source, now);
        Self {
            node_id,
            path,
            call_me_maybe_time: None,
            last_payload_msg: None,
            sources,
        }
    }

    pub(super) fn udp_addr(&self) -> Option<SocketAddr> {
        match self.path {
            SendAddr::Udp(addr) => Some(addr),
            SendAddr::Relay(_) => None,
        }
    }

    pub(super) fn with_last_payload(
        node_id: NodeId,
        path: SendAddr,
        source: Source,
        now: Instant,
    ) -> Self {
        let mut sources = HashMap::new();
        sources.insert(source, now);
        PathState {
            node_id,
            path,
            call_me_maybe_time: None,
            last_payload_msg: Some(now),
            sources,
        }
    }

    /// Check whether this path is considered active.
    ///
    /// Active means the path has received payload messages within the last
    /// [`SESSION_ACTIVE_TIMEOUT`].
    ///
    /// Note that a path might be alive but not active if it's contactable but not in
    /// use.
    pub(super) fn is_active(&self) -> bool {
        self.last_payload_msg
            .as_ref()
            .map(|instant| instant.elapsed() <= SESSION_ACTIVE_TIMEOUT)
            .unwrap_or(false)
    }

    /// Reports the last instant this path was considered alive.
    ///
    /// Alive means the path is considered in use by the remote endpoint.  Either because we
    /// received a payload message, a DISCO message (ping, pong) or it was advertised in a
    /// call-me-maybe message.
    ///
    /// This is the most recent instant between:
    /// - when last pong was received.
    /// - when this path was last advertised in a received CallMeMaybe message.
    /// - When the last payload transmission occurred.
    /// - when the last ping from them was received.
    pub(super) fn last_alive(&self) -> Option<Instant> {
        self.last_payload_msg
            .as_ref()
            .into_iter()
            .chain(self.call_me_maybe_time.as_ref())
            .max()
            .copied()
    }

    /// The last control or DISCO message **about** this path.
    ///
    /// This is the most recent instant among:
    /// - when this path was last advertised in a received CallMeMaybe message.
    /// - when the last ping from them was received.
    ///
    /// Returns the time elapsed since the last control message, and the type of control message.
    pub(super) fn last_control_msg(&self, now: Instant) -> Option<(Duration, ControlMsg)> {
        // get every control message and assign it its kind
        let last_call_me_maybe = self
            .call_me_maybe_time
            .as_ref()
            .map(|call_me| (*call_me, ControlMsg::CallMeMaybe));

        last_call_me_maybe
            .into_iter()
            .max_by_key(|(instant, _kind)| *instant)
            .map(|(instant, kind)| (now.duration_since(instant), kind))
    }

    pub(super) fn add_source(&mut self, source: Source, now: Instant) {
        self.sources.insert(source, now);
    }

    pub(super) fn clear(&mut self) {
        self.call_me_maybe_time = None;
    }

    fn summary(&self, mut w: impl std::fmt::Write) -> std::fmt::Result {
        write!(w, "{{ ")?;
        if self.is_active() {
            write!(w, "active ")?;
        }
        if let Some(last_source) = self.sources.iter().max_by_key(|&(_, instant)| instant) {
            write!(
                w,
                "last-source: {}({:?} ago)",
                last_source.0,
                last_source.1.elapsed()
            )?;
        }
        write!(w, "}}")
    }
}

// TODO: Make an `EndpointPaths` struct and do things nicely.
pub(super) fn summarize_node_paths(paths: &BTreeMap<IpPort, PathState>) -> String {
    use std::fmt::Write;

    let mut w = String::new();
    write!(&mut w, "[").ok();
    for (i, (ipp, state)) in paths.iter().enumerate() {
        if i > 0 {
            write!(&mut w, ", ").ok();
        }
        write!(&mut w, "{ipp}").ok();
        state.summary(&mut w).ok();
    }
    write!(&mut w, "]").ok();
    w
}
