use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use bytes::Bytes;
use derive_more::From;
use rand::Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use super::hyparview::{self, InEvent as SwarmIn};
use super::plumtree::{self, InEvent as GossipIn};
use super::PeerAddress;

/// Input event to the state handler.
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
}

impl<PA> From<hyparview::OutEvent<PA>> for OutEvent<PA> {
    fn from(event: hyparview::OutEvent<PA>) -> Self {
        use hyparview::OutEvent::*;
        match event {
            SendMessage(to, message) => Self::SendMessage(to, message.into()),
            ScheduleTimer(delay, timer) => Self::ScheduleTimer(delay, timer.into()),
            DisconnectPeer(peer) => Self::DisconnectPeer(peer),
            EmitEvent(event) => Self::EmitEvent(event.into()),
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

pub trait IO<PA: Clone> {
    fn push(&mut self, event: impl Into<OutEvent<PA>>);
}

#[derive(From, Debug, Serialize, Deserialize, Clone)]
pub enum Message<PA> {
    Swarm(hyparview::Message<PA>),
    Gossip(plumtree::Message),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Event<PA> {
    NeighborUp(PA),
    NeighborDown(PA),
    Received(Bytes),
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

#[derive(Clone, From, Debug)]
pub enum Timer<PA> {
    Swarm(hyparview::Timer<PA>),
    Gossip(plumtree::Timer),
}

#[derive(Clone, Debug)]
pub enum Command<PA> {
    Join(PA),
    Broadcast(Bytes),
}

impl<PA: Clone> IO<PA> for VecDeque<OutEvent<PA>> {
    fn push(&mut self, event: impl Into<OutEvent<PA>>) {
        self.push_back(event.into())
    }
}

#[derive(Clone, Default)]
pub struct Config {
    pub membership: hyparview::Config,
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
    pub fn new(me: PA, config: Config) -> Self {
        Self::with_rng(me, config, rand::rngs::StdRng::from_entropy())
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
    pub fn with_rng(me: PA, config: Config, rng: R) -> Self {
        Self {
            swarm: hyparview::State::new(me, config.membership, rng),
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

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn has_active_peers(&self) -> bool {
        !self.swarm.active_view.is_empty()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub messages_sent: usize,
    pub messages_received: usize,
}

#[cfg(test)]
mod test {
    use std::{
        collections::{BTreeMap, HashMap, HashSet, VecDeque},
        env,
        time::{Duration, Instant},
    };

    use bytes::Bytes;
    use rand::Rng;
    use rand_core::SeedableRng;
    use tracing::{debug, warn};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::{Command, Config, Event, InEvent, OutEvent, PeerAddress, State, Timer};
    use crate::proto::util::TimerMap;

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
            network.push(State::new(i, config.clone()));
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
            network.push(State::new(i, config.clone()));
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

    fn report_round_distribution<PA: PeerAddress, R: Rng>(network: &Network<PA, R>) {
        let mut eager_distrib: BTreeMap<usize, usize> = BTreeMap::new();
        let mut lazy_distrib: BTreeMap<usize, usize> = BTreeMap::new();
        let mut active_distrib: BTreeMap<usize, usize> = BTreeMap::new();
        let mut passive_distrib: BTreeMap<usize, usize> = BTreeMap::new();
        let mut payload_recv = 0;
        let mut control_recv = 0;
        for state in network.peers.iter() {
            let stats = state.gossip.stats();
            *eager_distrib
                .entry(state.gossip.eager_push_peers.len())
                .or_default() += 1;
            *lazy_distrib
                .entry(state.gossip.lazy_push_peers.len())
                .or_default() += 1;
            *active_distrib
                .entry(state.swarm.active_view().count())
                .or_default() += 1;
            *passive_distrib
                .entry(state.swarm.passive_view().count())
                .or_default() += 1;
            payload_recv += stats.payload_messages_received;
            control_recv += stats.control_messages_received;
        }
        // eprintln!("distributions {round_distrib:?}");
        eprintln!("payload_recv {payload_recv} control_recv {control_recv}");
        eprintln!("eager_distrib {eager_distrib:?}");
        eprintln!("lazy_distrib {lazy_distrib:?}");
        eprintln!("active_distrib {active_distrib:?}");
        eprintln!("passive_distrib {passive_distrib:?}");
    }

    const TICK_DURATION: Duration = Duration::from_millis(10);
    const DEFAULT_LATENCY: Duration = TICK_DURATION.saturating_mul(3);

    /// Test network implementation.
    /// Stores events in VecDeques and processes on ticks.
    /// Timers are checked after each tick. The local time is increased with TICK_DURATION before
    /// each tick.
    /// Note: Panics when sending to an unknown peer.
    struct Network<PA, R> {
        start: Instant,
        time: Instant,
        tick_duration: Duration,
        inqueues: Vec<VecDeque<InEvent<PA>>>,
        peers: Vec<State<PA, R>>,
        peers_by_address: HashMap<PA, usize>,
        conns: HashSet<ConnId<PA>>,
        events: VecDeque<(PA, Event<PA>)>,
        timers: TimerMap<(usize, Timer<PA>)>,
        transport: TimerMap<(usize, InEvent<PA>)>,
        latencies: HashMap<ConnId<PA>, Duration>,
    }
    impl<PA, R> Network<PA, R> {
        pub fn new(time: Instant) -> Self {
            Self {
                start: time,
                time,
                tick_duration: TICK_DURATION,
                inqueues: Default::default(),
                peers: Default::default(),
                peers_by_address: Default::default(),
                conns: Default::default(),
                events: Default::default(),
                timers: TimerMap::new(),
                transport: TimerMap::new(),
                latencies: HashMap::new(),
            }
        }
    }

    fn push_back<PA: Eq + std::hash::Hash>(
        inqueues: &mut [VecDeque<InEvent<PA>>],
        peer_pos: usize,
        event: InEvent<PA>,
    ) {
        inqueues.get_mut(peer_pos).unwrap().push_back(event);
    }

    impl<PA: PeerAddress + Ord, R: Rng> Network<PA, R> {
        pub fn push(&mut self, peer: State<PA, R>) {
            let idx = self.inqueues.len();
            self.inqueues.push(VecDeque::new());
            self.peers_by_address.insert(*peer.endpoint(), idx);
            self.peers.push(peer);
        }

        pub fn events(&mut self) -> impl Iterator<Item = (PA, Event<PA>)> + '_ {
            self.events.drain(..)
        }

        pub fn events_sorted(&mut self) -> Vec<(PA, Event<PA>)> {
            sort(self.events().collect())
        }

        pub fn conns(&self) -> Vec<(PA, PA)> {
            sort(self.conns.iter().cloned().map(Into::into).collect())
        }

        pub fn command(&mut self, peer: PA, command: Command<PA>) {
            debug!(?peer, "~~ COMMAND {command:?}");
            let idx = *self.peers_by_address.get(&peer).unwrap();
            push_back(&mut self.inqueues, idx, InEvent::Command(command));
        }

        pub fn ticks(&mut self, n: usize) {
            (0..n).for_each(|_| self.tick())
        }

        pub fn get_tick(&self) -> u32 {
            ((self.time - self.start) / self.tick_duration.as_millis() as u32).as_millis() as u32
        }

        pub fn tick(&mut self) {
            self.time += self.tick_duration;

            // process timers
            for (_time, (idx, timer)) in self.timers.drain_until(&self.time) {
                push_back(&mut self.inqueues, idx, InEvent::TimerExpired(timer));
            }

            // move messages
            for (_time, (peer, event)) in self.transport.drain_until(&self.time) {
                push_back(&mut self.inqueues, peer, event);
            }

            // process inqueues: let peer handle all incoming events
            let mut messages_sent = 0;
            for (idx, queue) in self.inqueues.iter_mut().enumerate() {
                let state = self.peers.get_mut(idx).unwrap();
                let peer = *state.endpoint();
                while let Some(event) = queue.pop_front() {
                    if let InEvent::RecvMessage(from, _message) = &event {
                        self.conns.insert((*from, peer).into());
                    }
                    debug!(peer = ?peer, "IN  {event:?}");
                    let out = state.handle(event, self.time);
                    for event in out {
                        debug!(peer = ?peer, "OUT {event:?}");
                        match event {
                            OutEvent::SendMessage(to, message) => {
                                let to_idx = *self.peers_by_address.get(&to).unwrap();
                                let latency = latency_between(&mut self.latencies, &peer, &to);
                                self.transport.insert(
                                    self.time + latency,
                                    (to_idx, InEvent::RecvMessage(peer, message)),
                                );
                                messages_sent += 1;
                            }
                            OutEvent::ScheduleTimer(latency, timer) => {
                                self.timers.insert(self.time + latency, (idx, timer));
                            }
                            OutEvent::DisconnectPeer(to) => {
                                debug!(peer = ?peer, other = ?to, "disconnect");
                                let to_idx = *self.peers_by_address.get(&to).unwrap();
                                let latency = latency_between(&mut self.latencies, &peer, &to)
                                    + Duration::from_nanos(1);
                                if self.conns.remove(&(peer, to).into()) {
                                    self.transport.insert(
                                        self.time + latency,
                                        (to_idx, InEvent::PeerDisconnected(peer)),
                                    );
                                }
                            }
                            OutEvent::EmitEvent(event) => {
                                debug!(peer = ?peer, "emit   {event:?}");
                                self.events.push_back((peer, event));
                            }
                        }
                    }
                }
            }
            debug!(
                tick = self.get_tick(),
                "~~ TICK (messages sent: {messages_sent})"
            );
        }
    }
    fn latency_between<PA: PeerAddress>(
        _latencies: &mut HashMap<ConnId<PA>, Duration>,
        _a: &PA,
        _b: &PA,
    ) -> Duration {
        DEFAULT_LATENCY
    }

    fn assert_synchronous_active<PA: PeerAddress, R>(network: &Network<PA, R>) -> bool {
        for state in network.peers.iter() {
            let peer = *state.endpoint();
            for other in state.swarm.active_view.iter() {
                let other_idx = network.peers_by_address.get(other).unwrap();
                let other_state = &network.peers.get(*other_idx).unwrap().swarm.active_view;
                if !other_state.contains(&peer) {
                    warn!(peer = ?peer, other = ?other, "missing active_view peer in other");
                    return false;
                }
            }
            for other in state.gossip.eager_push_peers.iter() {
                let other_idx = network.peers_by_address.get(other).unwrap();
                let other_state = &network
                    .peers
                    .get(*other_idx)
                    .unwrap()
                    .gossip
                    .eager_push_peers;
                if !other_state.contains(&peer) {
                    warn!(peer = ?peer, other = ?other, "missing eager_push peer in other");
                    return false;
                }
            }
        }
        true
    }

    type PeerId = usize;
    struct Simulator {
        gossip_config: Config,
        network: Network<PeerId, rand::rngs::StdRng>,
        config: SimulatorConfig,
        round_stats: Vec<RoundStats>,
    }
    struct SimulatorConfig {
        peers_count: usize,
        bootstrap_count: usize,
        bootstrap_ticks: usize,
        join_ticks: usize,
        warmup_ticks: usize,
        round_max_ticks: usize,
    }
    #[derive(Debug, Default)]
    struct RoundStats {
        ticks: usize,
        rmr: f32,
        ldh: u16,
    }
    impl Default for SimulatorConfig {
        fn default() -> Self {
            Self {
                peers_count: 100,
                bootstrap_count: 5,
                bootstrap_ticks: 50,
                join_ticks: 1,
                warmup_ticks: 300,
                round_max_ticks: 200,
            }
        }
    }
    impl Simulator {
        pub fn new(config: SimulatorConfig, gossip_config: Config) -> Self {
            Self {
                gossip_config,
                config,
                network: Network::new(Instant::now()),
                round_stats: Default::default(),
            }
        }
        pub fn init(&mut self) {
            for i in 0..self.config.peers_count {
                let rng = rand::rngs::StdRng::seed_from_u64(i as u64);
                self.network
                    .push(State::with_rng(i, self.gossip_config.clone(), rng.clone()));
            }
        }
        pub fn bootstrap(&mut self) {
            for i in 1..self.config.bootstrap_count {
                self.network.command(i, Command::Join(0));
            }
            self.network.ticks(self.config.bootstrap_ticks);
            let _ = self.network.events();

            for i in self.config.bootstrap_count..self.config.peers_count {
                let contact = i % self.config.bootstrap_count;
                self.network.command(i, Command::Join(contact));
                self.network.ticks(self.config.join_ticks);
                let _ = self.network.events();
            }
            self.network.ticks(self.config.warmup_ticks);
            let _ = self.network.events();
        }

        pub fn gossip_round(&mut self, from: PeerId, message: Bytes) {
            let prev_total_payload_counter = self.total_payload_messages();
            let mut expected: HashSet<usize> = HashSet::from_iter(
                self.network
                    .peers
                    .iter()
                    .map(|p| *p.endpoint())
                    .filter(|p| *p != from),
            );
            let expected_len = expected.len() as u64;
            self.network
                .command(from, Command::Broadcast(message.clone()));

            let mut tick = 0;
            loop {
                if expected.is_empty() {
                    break;
                }
                if tick > self.config.round_max_ticks {
                    break;
                }
                tick += 1;
                self.network.tick();
                let events = self.network.events();
                let received: HashSet<_> = events
                    .filter(|(_peer, event)| matches!(event,  Event::Received(recv) if recv == &message))
                    .map(|(peer, _msg)| peer)
                    .collect();
                for peer in received.iter() {
                    expected.remove(peer);
                }
                // eprintln!(
                //     "tick {tick:3} received {:5} remaining {:5} ",
                //     received.len(),
                //     expected.len(),
                // );
            }

            assert!(expected.is_empty(), "all nodes received the broadcast");
            let payload_counter = self.total_payload_messages() - prev_total_payload_counter;
            let rmr = (payload_counter as f32 / (expected_len as f32 - 1.)) - 1.;
            let ldh = self.max_ldh();
            let stats = RoundStats {
                ticks: tick,
                rmr,
                ldh,
            };
            self.round_stats.push(stats);
            self.reset_stats()
        }

        fn report_round_sums(&self) {
            let len = self.round_stats.len();
            let mut rmr = 0.;
            let mut ldh = 0.;
            let mut ticks = 0.;
            for round in self.round_stats.iter() {
                rmr += round.rmr;
                ldh += round.ldh as f32;
                ticks += round.ticks as f32;
            }
            rmr /= len as f32;
            ldh /= len as f32;
            ticks /= len as f32;
            eprintln!(
                "average over {} rounds with {} peers: RMR {rmr:.2} LDH {ldh:.2} ticks {ticks:.2}",
                self.round_stats.len(),
                self.network.peers.len(),
            );
            eprintln!("RMR = Relative Message Redundancy, LDH = Last Delivery Hop");
        }

        fn reset_stats(&mut self) {
            for state in self.network.peers.iter_mut() {
                state.gossip.stats = Default::default();
            }
        }

        fn max_ldh(&self) -> u16 {
            let mut max = 0;
            for state in self.network.peers.iter() {
                let stats = state.gossip.stats();
                max = max.max(stats.max_last_delivery_hop);
            }
            max
        }

        fn total_payload_messages(&self) -> u64 {
            let mut sum = 0;
            for state in self.network.peers.iter() {
                let stats = state.gossip.stats();
                sum += stats.payload_messages_received;
            }
            sum
        }
    }

    /// Helper struct for active connections. A sorted tuple.
    #[derive(Debug, Clone, PartialOrd, Ord, Eq, PartialEq, Hash)]
    pub struct ConnId<PA>([PA; 2]);
    impl<PA: Ord> ConnId<PA> {
        pub fn new(a: PA, b: PA) -> Self {
            let mut conn = [a, b];
            conn.sort();
            Self(conn)
        }
    }
    impl<PA: Ord> From<(PA, PA)> for ConnId<PA> {
        fn from((a, b): (PA, PA)) -> Self {
            Self::new(a, b)
        }
    }
    impl<PA: Copy> From<ConnId<PA>> for (PA, PA) {
        fn from(conn: ConnId<PA>) -> (PA, PA) {
            (conn.0[0], conn.0[1])
        }
    }

    fn sort<T: Ord + Clone>(items: Vec<T>) -> Vec<T> {
        let mut sorted = items;
        sorted.sort();
        sorted
    }
}
