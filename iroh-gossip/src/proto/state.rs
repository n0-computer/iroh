use std::{
    collections::{hash_map, HashMap, HashSet},
    fmt,
    time::{Duration, Instant},
};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::proto::{topic, Config, PeerAddress};

use super::PeerData;

#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Ord, PartialOrd, Deserialize)]
pub struct TopicId([u8; 32]);

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<PA> {
    topic: TopicId,
    message: topic::Message<PA>,
}

#[derive(Clone, Debug)]
pub struct Timer<PA> {
    topic: TopicId,
    timer: topic::Timer<PA>,
}

/// Input event to the state handler.
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

    pub fn endpoint(&self) -> &PA {
        &self.me
    }

    pub fn state(&self, topic: &TopicId) -> Option<&topic::State<PA, R>> {
        self.states.get(topic)
    }

    pub fn state_mut(&mut self, topic: &TopicId) -> Option<&mut topic::State<PA, R>> {
        self.states.get_mut(topic)
    }

    pub fn has_active_peers(&self, topic: &TopicId) -> bool {
        self.state(topic)
            .map(|s| s.has_active_peers())
            .unwrap_or(false)
    }

    pub fn handle(
        &mut self,
        event: InEvent<PA>,
        now: Instant,
    ) -> impl Iterator<Item = OutEvent<PA>> + '_ {
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
