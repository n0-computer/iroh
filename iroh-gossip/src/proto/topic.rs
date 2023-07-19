//! This module contains the implementation of the gossiping protocol for an individual topic

use std::{
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};

use bytes::Bytes;
use derive_more::From;
use rand::Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use super::hyparview::{self, InEvent as SwarmIn};
use super::plumtree::{self, InEvent as GossipIn};
use super::{PeerAddress, PeerData};

/// Input event to the topic state handler.
#[derive(Clone, Debug)]
pub enum InEvent<PA> {
    /// Message received from the network.
    RecvMessage(PA, Message<PA>),
    /// Execute a command from the application.
    Command(Command<PA>),
    /// Trigger a previously scheduled timer.
    TimerExpired(Timer<PA>),
    /// Peer disconnected on the network level.
    PeerDisconnected(PA),
    /// Update the opaque peer data about yourself.
    UpdatePeerData(PeerData),
}

/// An output event from the state handler.
#[derive(Debug)]
pub enum OutEvent<PA> {
    /// Send a message on the network
    SendMessage(PA, Message<PA>),
    /// Emit an event to the application.
    EmitEvent(Event<PA>),
    /// Schedule a timer. The runtime is responsible for sending an [InEvent::TimerExpired]
    /// after the duration.
    ScheduleTimer(Duration, Timer<PA>),
    /// Close the connection to a peer on the network level.
    DisconnectPeer(PA),
    /// Emitted when new [`PeerData`] was received for a peer.
    PeerData(PA, PeerData),
}

impl<PA> From<hyparview::OutEvent<PA>> for OutEvent<PA> {
    fn from(event: hyparview::OutEvent<PA>) -> Self {
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

impl<PA> From<plumtree::OutEvent<PA>> for OutEvent<PA> {
    fn from(event: plumtree::OutEvent<PA>) -> Self {
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
pub trait IO<PA: Clone> {
    /// Store the event in the message container
    fn push(&mut self, event: impl Into<OutEvent<PA>>);
}

/// A protocol message for a particular topic
#[derive(From, Debug, Serialize, Deserialize, Clone)]
pub enum Message<PA> {
    /// A message of the swarm membership layer
    Swarm(hyparview::Message<PA>),
    /// A message of the gossip broadcast layer
    Gossip(plumtree::Message),
}

/// An event to be emitted to the application for a particular topic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Event<PA> {
    /// We have a new, direct neighbor in the swarm membership layer for this topic
    NeighborUp(PA),
    /// We dropped direct neighbor in the swarm membership layer for this topic
    NeighborDown(PA),
    /// A gossip message was received for this topic
    Received(Bytes),
}
impl<PA: fmt::Debug> fmt::Debug for Event<PA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Received(msg) => write!(f, "Received(<{}>)", msg.len()),
            Self::NeighborUp(peer) => write!(f, "NeighborUp({peer:?})"),
            Self::NeighborDown(peer) => write!(f, "NeighborDown({peer:?})"),
        }
    }
}

impl<PA> From<hyparview::Event<PA>> for Event<PA> {
    fn from(value: hyparview::Event<PA>) -> Self {
        match value {
            hyparview::Event::NeighborUp(peer) => Self::NeighborUp(peer),
            hyparview::Event::NeighborDown(peer) => Self::NeighborDown(peer),
        }
    }
}

impl<PA> From<plumtree::Event> for Event<PA> {
    fn from(value: plumtree::Event) -> Self {
        match value {
            plumtree::Event::Received(peer) => Self::Received(peer),
        }
    }
}

/// A timer to be registered for a particular topic.
///
/// This should be treated an an opaque value by the implementor and, once emitted, simply returned
/// to the protocol through [`InEvent::TimerExpired`].
#[derive(Clone, From, Debug)]
pub enum Timer<PA> {
    /// A timer for the swarm layer
    Swarm(hyparview::Timer<PA>),
    /// A timer for the gossip layer
    Gossip(plumtree::Timer),
}

/// A command to the protocol state for a particular topic.
#[derive(Clone)]
pub enum Command<PA> {
    /// Join a peer for this topic
    Join(PA),
    /// Broadcast a message for this topic
    Broadcast(Bytes),
}

impl<PA: fmt::Debug> fmt::Debug for Command<PA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Join(peer) => write!(f, "Join({peer:?})"),
            Self::Broadcast(msg) => write!(f, "Broadcast(<{}>)", msg.len()),
        }
    }
}

impl<PA: Clone> IO<PA> for VecDeque<OutEvent<PA>> {
    fn push(&mut self, event: impl Into<OutEvent<PA>>) {
        self.push_back(event.into())
    }
}

/// Protocol configuration
#[derive(Clone, Default)]
pub struct Config {
    /// Configuration for the swarm membership layer
    pub membership: hyparview::Config,
    /// Configuration for the gossip broadcast layer
    pub broadcast: plumtree::Config,
}

/// The topic state maintains the swarm membership and broadcast tree for a particular topic.
#[derive(Debug)]
pub struct State<PA, R> {
    me: PA,
    pub(crate) swarm: hyparview::State<PA, R>,
    pub(crate) gossip: plumtree::State<PA>,
    outbox: VecDeque<OutEvent<PA>>,
    stats: Stats,
}

impl<PA: PeerAddress> State<PA, rand::rngs::StdRng> {
    /// Initialize the local state with the default random number generator.
    pub fn new(me: PA, me_data: PeerData, config: Config) -> Self {
        Self::with_rng(me, me_data, config, rand::rngs::StdRng::from_entropy())
    }
}

impl<PA, R> State<PA, R> {
    /// The address of your local endpoint.
    pub fn endpoint(&self) -> &PA {
        &self.me
    }
}

impl<PA: PeerAddress, R: Rng> State<PA, R> {
    /// Initialize the local state with a custom random number generator.
    pub fn with_rng(me: PA, me_data: PeerData, config: Config, rng: R) -> Self {
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
        event: InEvent<PA>,
        now: Instant,
    ) -> impl Iterator<Item = OutEvent<PA>> + '_ {
        let io = &mut self.outbox;
        // Process the event, store out events in outbox.
        match event {
            InEvent::Command(command) => match command {
                Command::Join(peer) => self.swarm.handle(SwarmIn::RequestJoin(peer), now, io),
                Command::Broadcast(data) => self.gossip.handle(GossipIn::Broadcast(data), io),
            },
            InEvent::RecvMessage(from, message) => {
                self.stats.messages_received += 1;
                match message {
                    Message::Swarm(message) => {
                        self.swarm
                            .handle(SwarmIn::RecvMessage(from, message), now, io)
                    }
                    Message::Gossip(message) => {
                        self.gossip.handle(GossipIn::RecvMessage(from, message), io)
                    }
                }
            }
            InEvent::TimerExpired(timer) => match timer {
                Timer::Swarm(timer) => self.swarm.handle(SwarmIn::TimerExpired(timer), now, io),
                Timer::Gossip(timer) => self.gossip.handle(GossipIn::TimerExpired(timer), io),
            },
            InEvent::PeerDisconnected(peer) => {
                self.swarm.handle(SwarmIn::PeerDisconnected(peer), now, io);
                self.gossip.handle(GossipIn::PeerDisconnected(peer), io);
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
                    self.gossip.handle(GossipIn::NeighborUp(*peer), &mut io)
                }
                OutEvent::EmitEvent(Event::NeighborDown(peer)) => {
                    self.gossip.handle(GossipIn::NeighborDown(*peer), &mut io)
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

    /// Get statistics for the gossip broacast state
    ///
    /// TODO: Remove/replace with metrics?
    pub fn gossip_stats(&self) -> &plumtree::Stats {
        &self.gossip.stats()
    }

    /// Check if this topic has any active (connected) peers.
    pub fn has_active_peers(&self) -> bool {
        !self.swarm.active_view.is_empty()
    }
}

/// Statistics for the protocol state of a topic
#[derive(Clone, Debug, Default)]
pub struct Stats {
    /// Number of messges sent
    pub messages_sent: usize,
    /// Number of messages received
    pub messages_received: usize,
}

#[cfg(test)]
mod test {
    use std::{env, time::Instant};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::{Command, Config, Event, State};
    use crate::proto::tests::{
        assert_synchronous_active, report_round_distribution, sort, Network, Simulator,
        SimulatorConfig,
    };

    fn setup_logging() {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();
    }

    #[test]
    fn hyparview_smoke() {
        setup_logging();
        // Create a network with 4 nodes and active_view_capacity 2
        let mut config = Config::default();
        config.membership.active_view_capacity = 2;
        let mut network = Network::new(Instant::now());
        for i in 0..4 {
            network.push(State::new(i, Default::default(), config.clone()));
        }

        // Do some joins between nodes 0,1,2
        network.command(0, Command::Join(1));
        network.command(0, Command::Join(2));
        network.command(1, Command::Join(2));
        network.ticks(10);

        // Confirm emitted events
        let actual = network.events_sorted();
        let expected = sort(vec![
            (0, Event::NeighborUp(1)),
            (0, Event::NeighborUp(2)),
            (1, Event::NeighborUp(2)),
            (1, Event::NeighborUp(0)),
            (2, Event::NeighborUp(0)),
            (2, Event::NeighborUp(1)),
        ]);
        assert_eq!(actual, expected);

        // Confirm active connections
        assert_eq!(network.conns(), vec![(0, 1), (0, 2), (1, 2)]);

        // Now let node 3 join node 0.
        // Node 0 is full, so it will disconnect from either node 1 or node 2.
        network.command(3, Command::Join(0));
        network.ticks(8);

        // Confirm emitted events. There's two options because whether node 0 disconnects from
        // node 1 or node 2 is random.
        let actual = network.events_sorted();
        eprintln!("actual {actual:?}");
        let expected1 = sort(vec![
            (3, Event::NeighborUp(0)),
            (0, Event::NeighborUp(3)),
            (0, Event::NeighborDown(1)),
            (1, Event::NeighborDown(0)),
        ]);
        let expected2 = sort(vec![
            (3, Event::NeighborUp(0)),
            (0, Event::NeighborUp(3)),
            (0, Event::NeighborDown(2)),
            (2, Event::NeighborDown(0)),
        ]);
        assert!((actual == expected1) || (actual == expected2));

        // Confirm active connections.
        if actual == expected1 {
            assert_eq!(network.conns(), vec![(0, 2), (0, 3), (1, 2)]);
        } else {
            assert_eq!(network.conns(), vec![(0, 1), (0, 3), (1, 2)]);
        }
        assert!(assert_synchronous_active(&network));
    }

    #[test]
    fn plumtree_smoke() {
        setup_logging();
        let config = Config::default();
        let mut network = Network::new(Instant::now());
        let broadcast_ticks = 12;
        let join_ticks = 12;
        // build a network with 6 nodes
        for i in 0..6 {
            network.push(State::new(i, Default::default(), config.clone()));
        }

        // connect nodes 1 and 2 to node 0
        (1..3).for_each(|i| network.command(i, Command::Join(0)));
        // connect nodes 4 and 5 to node 3
        (4..6).for_each(|i| network.command(i, Command::Join(3)));
        // run ticks and drain events
        network.ticks(join_ticks);
        let _ = network.events();
        assert!(assert_synchronous_active(&network));

        // now broadcast a first message
        network.command(1, Command::Broadcast(b"hi1".to_vec().into()));
        network.ticks(broadcast_ticks);
        let events = network.events();
        let received = events.filter(|x| matches!(x, (_, Event::Received(_))));
        // message should be received by two other nodes
        assert_eq!(received.count(), 2);
        assert!(assert_synchronous_active(&network));

        // now connect the two sections of the swarm
        network.command(2, Command::Join(5));
        network.ticks(join_ticks);
        let _ = network.events();
        report_round_distribution(&network);

        // now broadcast again
        network.command(1, Command::Broadcast(b"hi2".to_vec().into()));
        network.ticks(broadcast_ticks);
        let events = network.events();
        let received = events.filter(|x| matches!(x, (_, Event::Received(_))));
        // message should be received by all 5 other nodes
        assert_eq!(received.count(), 5);
        assert!(assert_synchronous_active(&network));
        report_round_distribution(&network);
    }

    fn read_var(name: &str, default: usize) -> usize {
        env::var(name)
            .unwrap_or_else(|_| default.to_string())
            .parse()
            .unwrap()
    }

    #[test]
    fn big_multiple_sender() {
        setup_logging();
        let mut gossip_config = Config::default();
        gossip_config.broadcast.optimization_threshold = (read_var("OPTIM", 7) as u16).into();
        let config = SimulatorConfig {
            peers_count: read_var("PEERS", 100),
            ..Default::default()
        };
        let rounds = read_var("ROUNDS", 10);
        let mut simulator = Simulator::new(config, gossip_config);
        simulator.init();
        simulator.bootstrap();
        for i in 0..rounds {
            let from = i + 1;
            let message = format!("m{i}").into_bytes().into();
            simulator.gossip_round(from, message)
        }
        simulator.report_round_sums();
    }

    #[test]
    fn big_single_sender() {
        setup_logging();
        let mut gossip_config = Config::default();
        gossip_config.broadcast.optimization_threshold = (read_var("OPTIM", 7) as u16).into();
        let config = SimulatorConfig {
            peers_count: read_var("PEERS", 100),
            ..Default::default()
        };
        let rounds = read_var("ROUNDS", 10);
        let mut simulator = Simulator::new(config, gossip_config);
        simulator.init();
        simulator.bootstrap();
        for i in 0..rounds {
            let from = 2;
            let message = format!("m{i}").into_bytes().into();
            simulator.gossip_round(from, message)
        }
        simulator.report_round_sums();
    }
}
