//! The protocol state of the `iroh-gossip` protocol.

use std::{
    collections::{hash_map, HashMap, HashSet},
    fmt,
    str::FromStr,
    time::{Duration, Instant},
};

use anyhow::anyhow;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::proto::{topic, Config, PeerAddress};
use iroh_metrics::{inc, inc_by};

use super::PeerData;
use crate::metrics::Metrics;

/// The identifier for a topic
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Ord, PartialOrd, Deserialize)]
pub struct TopicId([u8; 32]);

impl TopicId {
    /// Create a new `TopicId` from a byte array.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TopicId {
    /// Returns a byte slice of this [`TopicId`].
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for TopicId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for TopicId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl From<blake3::Hash> for TopicId {
    fn from(value: blake3::Hash) -> Self {
        Self(value.into())
    }
}

impl fmt::Display for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}
impl fmt::Debug for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}…{}", &text[..5], &text[(text.len() - 2)..])
    }
}

impl FromStr for TopicId {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())?
            .try_into()
            .map_err(|_| anyhow!("Failed to parse topic: must be 32 bytes "))?;
        Ok(TopicId::from_bytes(bytes))
    }
}

/// Protocol wire message
///
/// This is the wire frame of the `iroh-gossip` protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<PA> {
    topic: TopicId,
    message: topic::Message<PA>,
}

impl<PA> Message<PA> {
    /// Get the kind of this message
    pub fn kind(&self) -> MessageKind {
        self.message.kind()
    }
}

/// Whether this is a control or data message
pub enum MessageKind {
    /// A data message and its payload size.
    Data,
    /// A control message.
    Control,
}

impl<PA: Serialize> Message<PA> {
    /// Get the encoded size of this message
    pub fn size(&self) -> postcard::Result<usize> {
        postcard::experimental::serialized_size(&self)
    }
}

/// A timer to be registered into the runtime
///
/// As the implementation of the protocol is an IO-less state machine, registering timers does not
/// happen within the protocol implementation. Instead, these `Timer` structs are emitted as
/// [`OutEvent`]s. The implementor must register the timer in its runtime to be emitted on the specified [`Instant`],
/// and once triggered inject an [`InEvent::TimerExpired`] into the protocol state.
#[derive(Clone, Debug)]
pub struct Timer<PA> {
    topic: TopicId,
    timer: topic::Timer<PA>,
}

/// Input event to the protocol state.
#[derive(Clone, Debug)]
pub enum InEvent<PA> {
    /// Message received from the network.
    RecvMessage(PA, Message<PA>),
    /// Execute a command from the application.
    Command(TopicId, topic::Command<PA>),
    /// Trigger a previously scheduled timer.
    TimerExpired(Timer<PA>),
    /// Peer disconnected on the network level.
    PeerDisconnected(PA),
    /// Update the opaque peer data about yourself.
    UpdatePeerData(PeerData),
}

/// Output event from the protocol state.
#[derive(Debug, Clone)]
pub enum OutEvent<PA> {
    /// Send a message on the network
    SendMessage(PA, Message<PA>),
    /// Emit an event to the application.
    EmitEvent(TopicId, topic::Event<PA>),
    /// Schedule a timer. The runtime is responsible for sending an [InEvent::TimerExpired]
    /// after the duration.
    ScheduleTimer(Duration, Timer<PA>),
    /// Close the connection to a peer on the network level.
    DisconnectPeer(PA),
    /// Updated peer data
    PeerData(PA, PeerData),
}

type ConnsMap<PA> = HashMap<PA, HashSet<TopicId>>;
type Outbox<PA> = Vec<OutEvent<PA>>;

enum InEventMapped<PA> {
    All(topic::InEvent<PA>),
    TopicEvent(TopicId, topic::InEvent<PA>),
}

impl<PA> From<InEvent<PA>> for InEventMapped<PA> {
    fn from(event: InEvent<PA>) -> InEventMapped<PA> {
        match event {
            InEvent::RecvMessage(from, Message { topic, message }) => {
                Self::TopicEvent(topic, topic::InEvent::RecvMessage(from, message))
            }
            InEvent::Command(topic, command) => {
                Self::TopicEvent(topic, topic::InEvent::Command(command))
            }
            InEvent::TimerExpired(Timer { topic, timer }) => {
                Self::TopicEvent(topic, topic::InEvent::TimerExpired(timer))
            }
            InEvent::PeerDisconnected(peer) => Self::All(topic::InEvent::PeerDisconnected(peer)),
            InEvent::UpdatePeerData(data) => Self::All(topic::InEvent::UpdatePeerData(data)),
        }
    }
}

/// The state of the `iroh-gossip` protocol.
///
/// The implementation works as an IO-less state machine. The implementor injects events through
/// [`Self::handle`], which returns an iterator of [`OutEvent`]s to be processed.
///
/// This struct contains a map of [`topic::State`] for each topic that was joined. It mostly acts as
/// a forwarder of [`InEvent`]s to matching topic state. Each topic's state is completely
/// independent; thus the actual protocol logic lives with [`topic::State`].
#[derive(Debug)]
pub struct State<PA, R> {
    me: PA,
    me_data: PeerData,
    config: Config,
    rng: R,
    states: HashMap<TopicId, topic::State<PA, R>>,
    outbox: Outbox<PA>,
    conns: ConnsMap<PA>,
}

impl<PA: PeerAddress, R: Rng + Clone> State<PA, R> {
    /// Create a new protocol state instance.
    ///
    /// `me` is the [`PeerAddress`] of the local node, `peer_data` is the initial [`PeerData`]
    /// (which can be updated over time).
    /// For the protocol to perform as recommended in the papers, the [`Config`] should be
    /// identical for all nodes in the network.
    pub fn new(me: PA, me_data: PeerData, config: Config, rng: R) -> Self {
        Self {
            me,
            me_data,
            config,
            rng,
            states: Default::default(),
            outbox: Default::default(),
            conns: Default::default(),
        }
    }

    /// Get a reference to the node's [`PeerAddress`]
    pub fn me(&self) -> &PA {
        &self.me
    }

    /// Get a reference to the protocol state for a topic.
    pub fn state(&self, topic: &TopicId) -> Option<&topic::State<PA, R>> {
        self.states.get(topic)
    }

    /// Get a reference to the protocol state for a topic.
    #[cfg(test)]
    pub fn state_mut(&mut self, topic: &TopicId) -> Option<&mut topic::State<PA, R>> {
        self.states.get_mut(topic)
    }

    /// Get an iterator of all joined topics.
    pub fn topics(&self) -> impl Iterator<Item = &TopicId> {
        self.states.keys()
    }

    /// Get an iterator for the states of all joined topics.
    pub fn states(&self) -> impl Iterator<Item = (&TopicId, &topic::State<PA, R>)> {
        self.states.iter()
    }

    /// Check if a topic has any active (connected) peers.
    pub fn has_active_peers(&self, topic: &TopicId) -> bool {
        self.state(topic)
            .map(|s| s.has_active_peers())
            .unwrap_or(false)
    }

    /// Handle an [`InEvent`]
    ///
    /// This returns an iterator of [`OutEvent`]s that must be processed.
    pub fn handle(
        &mut self,
        event: InEvent<PA>,
        now: Instant,
    ) -> impl Iterator<Item = OutEvent<PA>> + '_ {
        track_in_event(&event);

        let event: InEventMapped<PA> = event.into();

        // todo: add command to leave a topic
        match event {
            InEventMapped::TopicEvent(topic, event) => {
                // when receiving messages, update our conn map to take note that this topic state may want
                // to keep this connection
                // TODO: this is a lot of hashmap lookups, maybe there's ways to optimize?
                if let topic::InEvent::RecvMessage(from, _message) = &event {
                    self.conns.entry(*from).or_default().insert(topic);
                }
                // when receiving a join command, initialize state if it doesn't exist
                if let topic::InEvent::Command(topic::Command::Join(_peer)) = &event {
                    if let hash_map::Entry::Vacant(e) = self.states.entry(topic) {
                        e.insert(topic::State::with_rng(
                            self.me,
                            self.me_data.clone(),
                            self.config.clone(),
                            self.rng.clone(),
                        ));
                    }
                }

                // when receiving a quit command, note this and drop the topic state after
                // processing this last event
                let quit = matches!(event, topic::InEvent::Command(topic::Command::Quit));

                if let hash_map::Entry::Vacant(e) = self.states.entry(topic) {
                    e.insert(topic::State::with_rng(
                        self.me,
                        self.me_data.clone(),
                        self.config.clone(),
                        self.rng.clone(),
                    ));
                }

                // pass the event to the state handler
                if let Some(state) = self.states.get_mut(&topic) {
                    let out = state.handle(event, now);
                    for event in out {
                        handle_out_event(topic, event, &mut self.conns, &mut self.outbox);
                    }
                }

                if quit {
                    self.states.remove(&topic);
                }
            }
            // when a peer disconnected on the network level, forward event to all states
            InEventMapped::All(event) => {
                if let topic::InEvent::UpdatePeerData(data) = &event {
                    self.me_data = data.clone();
                }
                for (topic, state) in self.states.iter_mut() {
                    let out = state.handle(event.clone(), now);
                    for event in out {
                        handle_out_event(*topic, event, &mut self.conns, &mut self.outbox);
                    }
                }
            }
        }

        // track metrics
        track_out_events(&self.outbox);

        self.outbox.drain(..)
    }
}

fn handle_out_event<PA: PeerAddress>(
    topic: TopicId,
    event: topic::OutEvent<PA>,
    conns: &mut ConnsMap<PA>,
    outbox: &mut Outbox<PA>,
) {
    match event {
        topic::OutEvent::SendMessage(to, message) => {
            outbox.push(OutEvent::SendMessage(to, Message { topic, message }))
        }
        topic::OutEvent::EmitEvent(event) => outbox.push(OutEvent::EmitEvent(topic, event)),
        topic::OutEvent::ScheduleTimer(delay, timer) => {
            outbox.push(OutEvent::ScheduleTimer(delay, Timer { topic, timer }))
        }
        topic::OutEvent::DisconnectPeer(peer) => {
            let empty = conns
                .get_mut(&peer)
                .map(|list| list.remove(&topic) && list.is_empty())
                .unwrap_or(false);
            if empty {
                conns.remove(&peer);
                outbox.push(OutEvent::DisconnectPeer(peer));
            }
        }
        topic::OutEvent::PeerData(peer, data) => outbox.push(OutEvent::PeerData(peer, data)),
    }
}

fn track_out_events<PA: Serialize>(events: &[OutEvent<PA>]) {
    for event in events {
        match event {
            OutEvent::SendMessage(_to, message) => match message.kind() {
                MessageKind::Data => {
                    inc!(Metrics, msgs_data_sent);
                    inc_by!(
                        Metrics,
                        msgs_data_sent_size,
                        message.size().unwrap_or(0) as u64
                    );
                }
                MessageKind::Control => {
                    inc!(Metrics, msgs_ctrl_sent);
                    inc_by!(
                        Metrics,
                        msgs_ctrl_sent_size,
                        message.size().unwrap_or(0) as u64
                    );
                }
            },
            OutEvent::EmitEvent(_topic, event) => match event {
                super::Event::NeighborUp(_peer) => inc!(Metrics, neighbor_up),
                super::Event::NeighborDown(_peer) => inc!(Metrics, neighbor_down),
                _ => {}
            },
            _ => {}
        }
    }
}

fn track_in_event<PA: Serialize>(event: &InEvent<PA>) {
    match event {
        InEvent::RecvMessage(_from, message) => match message.kind() {
            MessageKind::Data => {
                inc!(Metrics, msgs_data_recv);
                inc_by!(
                    Metrics,
                    msgs_data_recv_size,
                    message.size().unwrap_or(0) as u64
                );
            }
            MessageKind::Control => {
                inc!(Metrics, msgs_ctrl_recv);
                inc_by!(
                    Metrics,
                    msgs_ctrl_recv_size,
                    message.size().unwrap_or(0) as u64
                );
            }
        },
        _ => {}
    }
}
