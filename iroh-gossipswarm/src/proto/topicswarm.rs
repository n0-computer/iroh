use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use rand::Rng;
use serde::{Deserialize, Serialize};

use super::gossipswarm::{self, Command};
use super::{Config, PeerAddress};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Ord, PartialOrd, Deserialize)]
pub struct TopicId([u8; 32]);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Message<PA> {
    topic: TopicId,
    message: gossipswarm::Message<PA>,
}

#[derive(Clone, Debug)]
pub struct Timer<PA> {
    topic: TopicId,
    timer: gossipswarm::Timer<PA>,
}

/// Input event to the state handler.
#[derive(Clone, Debug)]
pub enum InEvent<PA> {
    /// Message received from the network.
    RecvMessage(PA, Message<PA>),
    /// Execute a command from the application.
    Command(TopicId, Command<PA>),
    /// Trigger a previously scheduled timer.
    TimerExpired(Timer<PA>),
    /// Peer disconnected on the network level.
    PeerDisconnected(PA),
}

#[derive(Debug, Clone)]
pub enum OutEvent<PA> {
    /// Send a message on the network
    SendMessage(PA, Message<PA>),
    /// Emit an event to the application.
    EmitEvent(TopicId, gossipswarm::Event<PA>),
    /// Schedule a timer. The runtime is responsible for sending an [InEvent::TimerExpired]
    /// after the duration.
    ScheduleTimer(Duration, Timer<PA>),
    /// Close the connection to a peer on the network level.
    DisconnectPeer(PA),
}

type ConnsMap<PA> = HashMap<PA, HashSet<TopicId>>;
type Outbox<PA> = Vec<OutEvent<PA>>;

enum InEventMapped<PA> {
    PeerDisconnected(PA),
    TopicEvent(TopicId, gossipswarm::InEvent<PA>),
}

impl<PA> From<InEvent<PA>> for InEventMapped<PA> {
    fn from(event: InEvent<PA>) -> InEventMapped<PA> {
        match event {
            InEvent::RecvMessage(from, Message { topic, message }) => {
                Self::TopicEvent(topic, gossipswarm::InEvent::RecvMessage(from, message))
            }
            InEvent::Command(topic, command) => {
                Self::TopicEvent(topic, gossipswarm::InEvent::Command(command))
            }
            InEvent::TimerExpired(Timer { topic, timer }) => {
                Self::TopicEvent(topic, gossipswarm::InEvent::TimerExpired(timer))
            }
            InEvent::PeerDisconnected(peer) => Self::PeerDisconnected(peer),
        }
    }
}

pub struct TopicSwarm<PA, R> {
    me: PA,
    config: Config,
    rng: R,
    states: HashMap<TopicId, gossipswarm::State<PA, R>>,
    outbox: Outbox<PA>,
    conns: ConnsMap<PA>,
}

impl<PA: PeerAddress, R: Rng + Clone> TopicSwarm<PA, R> {
    pub fn new(me: PA, config: Config, rng: R) -> Self {
        Self {
            me,
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

    pub fn state(&self, topic: &TopicId) -> Option<&gossipswarm::State<PA, R>> {
        self.states.get(topic)
    }

    pub fn state_mut(&mut self, topic: &TopicId) -> Option<&mut gossipswarm::State<PA, R>> {
        self.states.get_mut(topic)
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
                if let gossipswarm::InEvent::RecvMessage(from, _message) = &event {
                    self.conns.entry(*from).or_default().insert(topic);
                }
                // when receiving a join command, initialize state if it doesn't exist
                if let gossipswarm::InEvent::Command(gossipswarm::Command::Join(_peer)) = event {
                    if !self.states.contains_key(&topic) {
                        self.states.insert(
                            topic,
                            gossipswarm::State::with_rng(
                                self.me,
                                self.config.clone(),
                                self.rng.clone(),
                            ),
                        );
                    }
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
            InEventMapped::PeerDisconnected(peer) => {
                for (topic, state) in self.states.iter_mut() {
                    let out = state.handle(gossipswarm::InEvent::PeerDisconnected(peer), now);
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
    event: gossipswarm::OutEvent<PA>,
    conns: &mut ConnsMap<PA>,
    outbox: &mut Outbox<PA>,
) {
    match event {
        gossipswarm::OutEvent::SendMessage(to, message) => {
            outbox.push(OutEvent::SendMessage(to, Message { topic, message }))
        }
        gossipswarm::OutEvent::EmitEvent(event) => outbox.push(OutEvent::EmitEvent(topic, event)),
        gossipswarm::OutEvent::ScheduleTimer(delay, timer) => {
            outbox.push(OutEvent::ScheduleTimer(delay, Timer { topic, timer }))
        }
        gossipswarm::OutEvent::DisconnectPeer(peer) => {
            let empty = conns
                .get_mut(&peer)
                .map(|list| list.remove(&topic) && list.is_empty())
                .unwrap_or(false);
            if empty {
                conns.remove(&peer);
                outbox.push(OutEvent::DisconnectPeer(peer));
            }
        }
    }
}
