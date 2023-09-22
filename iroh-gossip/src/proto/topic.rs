//! This module contains the implementation of the gossiping protocol for an individual topic

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bytes::Bytes;
use derive_more::From;
use rand::Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use super::plumtree::{self, GossipEvent, InEvent as GossipIn, Scope};
use super::{
    hyparview::{self, InEvent as SwarmIn},
    state::MessageKind,
};
use super::{PeerData, PeerIdentity};

/// Input event to the topic state handler.
#[derive(Clone, Debug)]
pub enum InEvent<PI> {
    /// Message received from the network.
    RecvMessage(PI, Message<PI>),
    /// Execute a command from the application.
    Command(Command<PI>),
    /// Trigger a previously scheduled timer.
    TimerExpired(Timer<PI>),
    /// Peer disconnected on the network level.
    PeerDisconnected(PI),
    /// Update the opaque peer data about yourself.
    UpdatePeerData(PeerData),
}

/// An output event from the state handler.
#[derive(Debug, PartialEq, Eq)]
pub enum OutEvent<PI> {
    /// Send a message on the network
    SendMessage(PI, Message<PI>),
    /// Emit an event to the application.
    EmitEvent(Event<PI>),
    /// Schedule a timer. The runtime is responsible for sending an [InEvent::TimerExpired]
    /// after the duration.
    ScheduleTimer(Duration, Timer<PI>),
    /// Close the connection to a peer on the network level.
    DisconnectPeer(PI),
    /// Emitted when new [`PeerData`] was received for a peer.
    PeerData(PI, PeerData),
}

impl<PI> From<hyparview::OutEvent<PI>> for OutEvent<PI> {
    fn from(event: hyparview::OutEvent<PI>) -> Self {
        use hyparview::OutEvent::*;
        match event {
            SendMessage(to, message) => Self::SendMessage(to, message.into()),
            ScheduleTimer(delay, timer) => Self::ScheduleTimer(delay, timer.into()),
            DisconnectPeer(peer) => Self::DisconnectPeer(peer),
            EmitEvent(event) => Self::EmitEvent(event.into()),
            PeerData(peer, data) => Self::PeerData(peer, data),
        }
    }
}

impl<PI> From<plumtree::OutEvent<PI>> for OutEvent<PI> {
    fn from(event: plumtree::OutEvent<PI>) -> Self {
        use plumtree::OutEvent::*;
        match event {
            SendMessage(to, message) => Self::SendMessage(to, message.into()),
            ScheduleTimer(delay, timer) => Self::ScheduleTimer(delay, timer.into()),
            EmitEvent(event) => Self::EmitEvent(event.into()),
        }
    }
}

/// A trait for a concrete type to push `OutEvent`s to.
///
/// The implementation is generic over this trait, which allows the upper layer to supply a
/// container of their choice for `OutEvent`s emitted from the protocol state.
pub trait IO<PI: Clone> {
    /// Push an event in the IO container
    fn push(&mut self, event: impl Into<OutEvent<PI>>);

    /// Push all events from an iterator into the IO container
    fn push_from_iter(&mut self, iter: impl IntoIterator<Item = impl Into<OutEvent<PI>>>) {
        for event in iter.into_iter() {
            self.push(event);
        }
    }
}

/// A protocol message for a particular topic
#[derive(From, Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message<PI> {
    /// A message of the swarm membership layer
    Swarm(hyparview::Message<PI>),
    /// A message of the gossip broadcast layer
    Gossip(plumtree::Message),
}

impl<PI> Message<PI> {
    /// Get the kind of this message
    pub fn kind(&self) -> MessageKind {
        match self {
            Message::Swarm(_) => MessageKind::Control,
            Message::Gossip(message) => match message {
                plumtree::Message::Gossip(_) => MessageKind::Data,
                _ => MessageKind::Control,
            },
        }
    }
}

/// An event to be emitted to the application for a particular topic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Event<PI> {
    /// We have a new, direct neighbor in the swarm membership layer for this topic
    NeighborUp(PI),
    /// We dropped direct neighbor in the swarm membership layer for this topic
    NeighborDown(PI),
    /// A gossip message was received for this topic
    Received(GossipEvent<PI>),
}

impl<PI> From<hyparview::Event<PI>> for Event<PI> {
    fn from(value: hyparview::Event<PI>) -> Self {
        match value {
            hyparview::Event::NeighborUp(peer) => Self::NeighborUp(peer),
            hyparview::Event::NeighborDown(peer) => Self::NeighborDown(peer),
        }
    }
}

impl<PI> From<plumtree::Event<PI>> for Event<PI> {
    fn from(value: plumtree::Event<PI>) -> Self {
        match value {
            plumtree::Event::Received(event) => Self::Received(event),
        }
    }
}

/// A timer to be registered for a particular topic.
///
/// This should be treated as an opaque value by the implementer and, once emitted, simply returned
/// to the protocol through [`InEvent::TimerExpired`].
#[derive(Clone, From, Debug, PartialEq, Eq)]
pub enum Timer<PI> {
    /// A timer for the swarm layer
    Swarm(hyparview::Timer<PI>),
    /// A timer for the gossip layer
    Gossip(plumtree::Timer),
}

/// A command to the protocol state for a particular topic.
#[derive(Clone, derive_more::Debug)]
pub enum Command<PI> {
    /// Join this topic and connect to peers.
    ///
    /// If the list of peers is empty, will prepare the state and accept incoming join requests,
    /// but only become operational after the first join request by another peer.
    Join(Vec<PI>),
    /// Broadcast a message for this topic.
    Broadcast(#[debug("<{}b>", _0.len())] Bytes, Scope),
    /// Leave this topic and drop all state.
    Quit,
}

impl<PI: Clone> IO<PI> for VecDeque<OutEvent<PI>> {
    fn push(&mut self, event: impl Into<OutEvent<PI>>) {
        self.push_back(event.into())
    }
}
/// Protocol configuration
#[derive(Clone, Default, Debug)]
pub struct Config {
    /// Configuration for the swarm membership layer
    pub membership: hyparview::Config,
    /// Configuration for the gossip broadcast layer
    pub broadcast: plumtree::Config,
}

/// The topic state maintains the swarm membership and broadcast tree for a particular topic.
#[derive(Debug)]
pub struct State<PI, R> {
    me: PI,
    pub(crate) swarm: hyparview::State<PI, R>,
    pub(crate) gossip: plumtree::State<PI>,
    outbox: VecDeque<OutEvent<PI>>,
    stats: Stats,
}

impl<PI: PeerIdentity> State<PI, rand::rngs::StdRng> {
    /// Initialize the local state with the default random number generator.
    pub fn new(me: PI, me_data: Option<PeerData>, config: Config) -> Self {
        Self::with_rng(me, me_data, config, rand::rngs::StdRng::from_entropy())
    }
}

impl<PI, R> State<PI, R> {
    /// The address of your local endpoint.
    pub fn endpoint(&self) -> &PI {
        &self.me
    }
}

impl<PI: PeerIdentity, R: Rng> State<PI, R> {
    /// Initialize the local state with a custom random number generator.
    pub fn with_rng(me: PI, me_data: Option<PeerData>, config: Config, rng: R) -> Self {
        Self {
            swarm: hyparview::State::new(me, me_data, config.membership, rng),
            gossip: plumtree::State::new(me, config.broadcast),
            me,
            outbox: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    /// Handle an incoming event.
    ///
    /// Returns an iterator of outgoing events that must be processed by the application.
    pub fn handle(
        &mut self,
        event: InEvent<PI>,
        now: Instant,
    ) -> impl Iterator<Item = OutEvent<PI>> + '_ {
        let io = &mut self.outbox;
        // Process the event, store out events in outbox.
        match event {
            InEvent::Command(command) => match command {
                Command::Join(peers) => {
                    for peer in peers {
                        self.swarm.handle(SwarmIn::RequestJoin(peer), now, io);
                    }
                }
                Command::Broadcast(data, scope) => {
                    self.gossip
                        .handle(GossipIn::Broadcast(data, scope), now, io)
                }
                Command::Quit => self.swarm.handle(SwarmIn::Quit, now, io),
            },
            InEvent::RecvMessage(from, message) => {
                self.stats.messages_received += 1;
                match message {
                    Message::Swarm(message) => {
                        self.swarm
                            .handle(SwarmIn::RecvMessage(from, message), now, io)
                    }
                    Message::Gossip(message) => {
                        self.gossip
                            .handle(GossipIn::RecvMessage(from, message), now, io)
                    }
                }
            }
            InEvent::TimerExpired(timer) => match timer {
                Timer::Swarm(timer) => self.swarm.handle(SwarmIn::TimerExpired(timer), now, io),
                Timer::Gossip(timer) => self.gossip.handle(GossipIn::TimerExpired(timer), now, io),
            },
            InEvent::PeerDisconnected(peer) => {
                self.swarm.handle(SwarmIn::PeerDisconnected(peer), now, io);
                self.gossip.handle(GossipIn::NeighborDown(peer), now, io);
            }
            InEvent::UpdatePeerData(data) => {
                self.swarm.handle(SwarmIn::UpdatePeerData(data), now, io)
            }
        }

        // Forward NeigborUp and NeighborDown events from hyparview to plumtree
        let mut io = VecDeque::new();
        for event in self.outbox.iter() {
            match event {
                OutEvent::EmitEvent(Event::NeighborUp(peer)) => {
                    self.gossip
                        .handle(GossipIn::NeighborUp(*peer), now, &mut io)
                }
                OutEvent::EmitEvent(Event::NeighborDown(peer)) => {
                    self.gossip
                        .handle(GossipIn::NeighborDown(*peer), now, &mut io)
                }
                _ => {}
            }
        }
        // Note that this is a no-op because plumtree::handle(NeighborUp | NeighborDown)
        // above does not emit any OutEvents.
        self.outbox.extend(io.drain(..));

        // Update sent message counter
        self.stats.messages_sent += self
            .outbox
            .iter()
            .filter(|event| matches!(event, OutEvent::SendMessage(_, _)))
            .count();

        self.outbox.drain(..)
    }

    /// Get stats on how many messages were sent and received
    ///
    /// TODO: Remove/replace with metrics?
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Get statistics for the gossip broadcast state
    ///
    /// TODO: Remove/replace with metrics?
    pub fn gossip_stats(&self) -> &plumtree::Stats {
        self.gossip.stats()
    }

    /// Check if this topic has any active (connected) peers.
    pub fn has_active_peers(&self) -> bool {
        !self.swarm.active_view.is_empty()
    }
}

/// Statistics for the protocol state of a topic
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Number of messages sent
    pub messages_sent: usize,
    /// Number of messages received
    pub messages_received: usize,
}
