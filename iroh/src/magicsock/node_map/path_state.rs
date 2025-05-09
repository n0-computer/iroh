//! The state kept for each network path to a remote node.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};

use iroh_base::NodeId;
use iroh_relay::protos::stun;
use n0_future::time::{Duration, Instant};
use tracing::{debug, event, Level};

use super::{
    node_state::{ControlMsg, PongReply, SESSION_ACTIVE_TIMEOUT},
    IpPort, PingRole, Source,
};
use crate::{disco::SendAddr, magicsock::HEARTBEAT_INTERVAL};

/// The minimum time between pings to an endpoint.
///
/// Except in the case of CallMeMaybe frames resetting the counter, as the first pings
/// likely didn't through the firewall.
const DISCO_PING_INTERVAL: Duration = Duration::from_secs(5);

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
    /// The last (outgoing) ping time.
    pub(super) last_ping: Option<Instant>,

    /// If non-zero, means that this was an endpoint that we learned about at runtime (from an
    /// incoming ping). If so, we keep the time updated and use it to discard old candidates.
    // NOTE: tx_id Originally added in tailscale due to <https://github.com/tailscale/tailscale/issues/7078>.
    last_got_ping: Option<(Instant, stun::TransactionId)>,

    /// The time this endpoint was last advertised via a call-me-maybe DISCO message.
    pub(super) call_me_maybe_time: Option<Instant>,

    /// The most recent [`PongReply`].
    ///
    /// Previous replies are cleared when they are no longer relevant to determine whether
    /// this path can still be used to reach the remote node.
    pub(super) recent_pong: Option<PongReply>,
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
            last_ping: None,
            last_got_ping: None,
            call_me_maybe_time: None,
            recent_pong: None,
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
            last_ping: None,
            last_got_ping: None,
            call_me_maybe_time: None,
            recent_pong: None,
            last_payload_msg: Some(now),
            sources,
        }
    }

    pub(super) fn with_ping(
        node_id: NodeId,
        path: SendAddr,
        tx_id: stun::TransactionId,
        source: Source,
        now: Instant,
    ) -> Self {
        let mut new = PathState::new(node_id, path, source, now);
        new.handle_ping(tx_id, now);
        new
    }

    pub(super) fn add_pong_reply(&mut self, r: PongReply) {
        if let SendAddr::Udp(ref path) = self.path {
            if self.recent_pong.is_none() {
                event!(
                    target: "iroh::_events::holepunched",
                    Level::DEBUG,
                    remote_node = %self.node_id.fmt_short(),
                    path = ?path,
                    direction = "outgoing",
                );
            }
        }
        self.recent_pong = Some(r);
    }

    #[cfg(test)]
    pub(super) fn with_pong_reply(node_id: NodeId, r: PongReply) -> Self {
        PathState {
            node_id,
            path: r.from.clone(),
            last_ping: None,
            last_got_ping: None,
            call_me_maybe_time: None,
            recent_pong: Some(r),
            last_payload_msg: None,
            sources: HashMap::new(),
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

    /// Returns the instant the last incoming ping was received.
    pub(super) fn last_incoming_ping(&self) -> Option<&Instant> {
        self.last_got_ping.as_ref().map(|(time, _tx_id)| time)
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
        self.recent_pong
            .as_ref()
            .map(|pong| &pong.pong_at)
            .into_iter()
            .chain(self.last_payload_msg.as_ref())
            .chain(self.call_me_maybe_time.as_ref())
            .chain(self.last_incoming_ping())
            .max()
            .copied()
    }

    /// The last control or DISCO message **about** this path.
    ///
    /// This is the most recent instant among:
    /// - when last pong was received.
    /// - when this path was last advertised in a received CallMeMaybe message.
    /// - when the last ping from them was received.
    ///
    /// Returns the time elapsed since the last control message, and the type of control message.
    pub(super) fn last_control_msg(&self, now: Instant) -> Option<(Duration, ControlMsg)> {
        // get every control message and assign it its kind
        let last_pong = self
            .recent_pong
            .as_ref()
            .map(|pong| (pong.pong_at, ControlMsg::Pong));
        let last_call_me_maybe = self
            .call_me_maybe_time
            .as_ref()
            .map(|call_me| (*call_me, ControlMsg::CallMeMaybe));
        let last_ping = self
            .last_incoming_ping()
            .map(|ping| (*ping, ControlMsg::Ping));

        last_pong
            .into_iter()
            .chain(last_call_me_maybe)
            .chain(last_ping)
            .max_by_key(|(instant, _kind)| *instant)
            .map(|(instant, kind)| (now.duration_since(instant), kind))
    }

    /// Returns the latency from the most recent pong, if available.
    pub(super) fn latency(&self) -> Option<Duration> {
        self.recent_pong.as_ref().map(|p| p.latency)
    }

    pub(super) fn needs_ping(&self, now: &Instant) -> bool {
        match self.last_ping {
            None => true,
            Some(last_ping) => {
                let elapsed = now.duration_since(last_ping);

                // TODO: remove!
                // This logs "ping is too new" for each send whenever the endpoint does *not* need
                // a ping. Pretty sure this is not a useful log, but maybe there was a reason?
                // if !needs_ping {
                //     debug!("ping is too new: {}ms", elapsed.as_millis());
                // }
                elapsed > DISCO_PING_INTERVAL
            }
        }
    }

    pub(super) fn handle_ping(&mut self, tx_id: stun::TransactionId, now: Instant) -> PingRole {
        if Some(&tx_id) == self.last_got_ping.as_ref().map(|(_t, tx_id)| tx_id) {
            PingRole::Duplicate
        } else {
            let prev = self.last_got_ping.replace((now, tx_id));
            let heartbeat_deadline = HEARTBEAT_INTERVAL + (HEARTBEAT_INTERVAL / 2);
            match prev {
                Some((prev_time, _tx)) if now.duration_since(prev_time) <= heartbeat_deadline => {
                    PingRole::LikelyHeartbeat
                }
                Some((prev_time, _tx)) => {
                    debug!(
                        elapsed = ?now.duration_since(prev_time),
                        "heartbeat missed, reactivating",
                    );
                    PingRole::Activate
                }
                None => {
                    if let SendAddr::Udp(ref addr) = self.path {
                        event!(
                            target: "iroh::_events::holepunched",
                            Level::DEBUG,
                            remote_node = %self.node_id.fmt_short(),
                            path = ?addr,
                            direction = "incoming",
                        );
                    }
                    PingRole::Activate
                }
            }
        }
    }

    pub(super) fn add_source(&mut self, source: Source, now: Instant) {
        self.sources.insert(source, now);
    }

    pub(super) fn clear(&mut self) {
        self.last_ping = None;
        self.last_got_ping = None;
        self.call_me_maybe_time = None;
        self.recent_pong = None;
    }

    fn summary(&self, mut w: impl std::fmt::Write) -> std::fmt::Result {
        write!(w, "{{ ")?;
        if self.is_active() {
            write!(w, "active ")?;
        }
        if let Some(ref pong) = self.recent_pong {
            write!(w, "pong-received({:?} ago) ", pong.pong_at.elapsed())?;
        }
        if let Some(when) = self.last_incoming_ping() {
            write!(w, "ping-received({:?} ago) ", when.elapsed())?;
        }
        if let Some(ref when) = self.last_ping {
            write!(w, "ping-sent({:?} ago) ", when.elapsed())?;
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
