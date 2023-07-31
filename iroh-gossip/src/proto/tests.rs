//! Simulation framework for testing the protocol implementation

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use bytes::Bytes;
use rand::Rng;
use rand_core::SeedableRng;
use tracing::{debug, warn};

use super::{
    util::TimerMap, Command, Config, Event, InEvent, OutEvent, PeerAddress, State, Timer, TopicId,
};

const TICK_DURATION: Duration = Duration::from_millis(10);
const DEFAULT_LATENCY: Duration = TICK_DURATION.saturating_mul(3);

/// Test network implementation.
///
/// Stores events in VecDeques and processes on ticks.
/// Timers are checked after each tick. The local time is increased with TICK_DURATION before
/// each tick.
///
/// Note: Panics when sending to an unknown peer.
pub struct Network<PA, R> {
    start: Instant,
    time: Instant,
    tick_duration: Duration,
    inqueues: Vec<VecDeque<InEvent<PA>>>,
    pub(crate) peers: Vec<State<PA, R>>,
    peers_by_address: HashMap<PA, usize>,
    conns: HashSet<ConnId<PA>>,
    events: VecDeque<(PA, TopicId, Event<PA>)>,
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

impl<PA: PeerAddress + Ord, R: Rng + Clone> Network<PA, R> {
    pub fn push(&mut self, peer: State<PA, R>) {
        let idx = self.inqueues.len();
        self.inqueues.push(VecDeque::new());
        self.peers_by_address.insert(*peer.me(), idx);
        self.peers.push(peer);
    }

    pub fn events(&mut self) -> impl Iterator<Item = (PA, TopicId, Event<PA>)> + '_ {
        self.events.drain(..)
    }

    pub fn events_sorted(&mut self) -> Vec<(PA, TopicId, Event<PA>)> {
        sort(self.events().collect())
    }

    pub fn conns(&self) -> Vec<(PA, PA)> {
        sort(self.conns.iter().cloned().map(Into::into).collect())
    }

    pub fn command(&mut self, peer: PA, topic: TopicId, command: Command<PA>) {
        debug!(?peer, "~~ COMMAND {command:?}");
        let idx = *self.peers_by_address.get(&peer).unwrap();
        push_back(&mut self.inqueues, idx, InEvent::Command(topic, command));
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
            let peer = *state.me();
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
                        OutEvent::EmitEvent(topic, event) => {
                            debug!(peer = ?peer, "emit   {event:?}");
                            self.events.push_back((peer, topic, event));
                        }
                        OutEvent::PeerData(_peer, _data) => {}
                    }
                }
            }
        }
        debug!(
            tick = self.get_tick(),
            "~~ TICK (messages sent: {messages_sent})"
        );
    }

    pub fn peer(&self, peer: &PA) -> Option<&State<PA, R>> {
        self.peers_by_address
            .get(peer)
            .cloned()
            .and_then(|idx| self.peers.get(idx))
    }

    pub fn get_active(&self, peer: &PA, topic: &TopicId) -> Option<Option<Vec<PA>>> {
        let peer = self.peer(peer)?;
        match peer.state(topic) {
            Some(state) => Some(Some(
                state.swarm.active_view.iter().cloned().collect::<Vec<_>>(),
            )),
            None => Some(None),
        }
    }
}
fn latency_between<PA: PeerAddress>(
    _latencies: &mut HashMap<ConnId<PA>, Duration>,
    _a: &PA,
    _b: &PA,
) -> Duration {
    DEFAULT_LATENCY
}

pub fn assert_synchronous_active<PA: PeerAddress, R: Rng + Clone>(
    network: &Network<PA, R>,
) -> bool {
    for state in network.peers.iter() {
        let peer = *state.me();
        for (topic, state) in state.states() {
            for other in state.swarm.active_view.iter() {
                let other_idx = network.peers_by_address.get(other).unwrap();
                let other_state = &network
                    .peers
                    .get(*other_idx)
                    .unwrap()
                    .state(topic)
                    .unwrap()
                    .swarm
                    .active_view;
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
                    .state(topic)
                    .unwrap()
                    .gossip
                    .eager_push_peers;
                if !other_state.contains(&peer) {
                    warn!(peer = ?peer, other = ?other, "missing eager_push peer in other");
                    return false;
                }
            }
        }
    }
    true
}

pub type PeerId = usize;

/// A simple simulator for the gossip protocol
pub struct Simulator {
    simulator_config: SimulatorConfig,
    protocol_config: Config,
    network: Network<PeerId, rand::rngs::StdRng>,
    round_stats: Vec<RoundStats>,
}
pub struct SimulatorConfig {
    pub peers_count: usize,
    pub bootstrap_count: usize,
    pub bootstrap_ticks: usize,
    pub join_ticks: usize,
    pub warmup_ticks: usize,
    pub round_max_ticks: usize,
}
#[derive(Debug, Default)]
pub struct RoundStats {
    ticks: usize,
    rmr: f32,
    ldh: u16,
}

pub const TOPIC: TopicId = TopicId::from_bytes([0u8; 32]);

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
    pub fn new(simulator_config: SimulatorConfig, protocol_config: Config) -> Self {
        Self {
            protocol_config,
            simulator_config,
            network: Network::new(Instant::now()),
            round_stats: Default::default(),
        }
    }
    pub fn init(&mut self) {
        for i in 0..self.simulator_config.peers_count {
            let rng = rand::rngs::StdRng::seed_from_u64(i as u64);
            self.network.push(State::new(
                i,
                Default::default(),
                self.protocol_config.clone(),
                rng.clone(),
            ));
        }
    }
    pub fn bootstrap(&mut self) {
        self.network.command(0, TOPIC, Command::Join(vec![]));
        for i in 1..self.simulator_config.bootstrap_count {
            self.network.command(i, TOPIC, Command::Join(vec![0]));
        }
        self.network.ticks(self.simulator_config.bootstrap_ticks);
        let _ = self.network.events();

        for i in self.simulator_config.bootstrap_count..self.simulator_config.peers_count {
            let contact = i % self.simulator_config.bootstrap_count;
            self.network.command(i, TOPIC, Command::Join(vec![contact]));
            self.network.ticks(self.simulator_config.join_ticks);
            let _ = self.network.events();
        }
        self.network.ticks(self.simulator_config.warmup_ticks);
        let _ = self.network.events();
    }

    pub fn gossip_round(&mut self, from: PeerId, message: Bytes) {
        let prev_total_payload_counter = self.total_payload_messages();
        let mut expected: HashSet<usize> = HashSet::from_iter(
            self.network
                .peers
                .iter()
                .map(|p| *p.me())
                .filter(|p| *p != from),
        );
        let expected_len = expected.len() as u64;
        self.network
            .command(from, TOPIC, Command::Broadcast(message.clone()));

        let mut tick = 0;
        loop {
            if expected.is_empty() {
                break;
            }
            if tick > self.simulator_config.round_max_ticks {
                break;
            }
            tick += 1;
            self.network.tick();
            let events = self.network.events();
            let received: HashSet<_> = events
                .filter(
                    |(_peer, _topic, event)| matches!(event,  Event::Received(recv, _) if recv == &message),
                )
                .map(|(peer, _topic, _msg)| peer)
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

    pub fn report_round_sums(&self) {
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
            let state = state.state_mut(&TOPIC).unwrap();
            state.gossip.stats = Default::default();
        }
    }

    fn max_ldh(&self) -> u16 {
        let mut max = 0;
        for state in self.network.peers.iter() {
            let state = state.state(&TOPIC).unwrap();
            let stats = state.gossip.stats();
            max = max.max(stats.max_last_delivery_hop);
        }
        max
    }

    fn total_payload_messages(&self) -> u64 {
        let mut sum = 0;
        for state in self.network.peers.iter() {
            let state = state.state(&TOPIC).unwrap();
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

pub fn sort<T: Ord + Clone>(items: Vec<T>) -> Vec<T> {
    let mut sorted = items;
    sorted.sort();
    sorted
}

pub fn report_round_distribution<PA: PeerAddress, R: Rng + Clone>(network: &Network<PA, R>) {
    let mut eager_distrib: BTreeMap<usize, usize> = BTreeMap::new();
    let mut lazy_distrib: BTreeMap<usize, usize> = BTreeMap::new();
    let mut active_distrib: BTreeMap<usize, usize> = BTreeMap::new();
    let mut passive_distrib: BTreeMap<usize, usize> = BTreeMap::new();
    let mut payload_recv = 0;
    let mut control_recv = 0;
    for state in network.peers.iter() {
        for (_topic, state) in state.states() {
            let stats = state.gossip.stats();
            *eager_distrib
                .entry(state.gossip.eager_push_peers.len())
                .or_default() += 1;
            *lazy_distrib
                .entry(state.gossip.lazy_push_peers.len())
                .or_default() += 1;
            *active_distrib
                .entry(state.swarm.active_view.len())
                .or_default() += 1;
            *passive_distrib
                .entry(state.swarm.passive_view.len())
                .or_default() += 1;
            payload_recv += stats.payload_messages_received;
            control_recv += stats.control_messages_received;
        }
    }
    // eprintln!("distributions {round_distrib:?}");
    eprintln!("payload_recv {payload_recv} control_recv {control_recv}");
    eprintln!("eager_distrib {eager_distrib:?}");
    eprintln!("lazy_distrib {lazy_distrib:?}");
    eprintln!("active_distrib {active_distrib:?}");
    eprintln!("passive_distrib {passive_distrib:?}");
}

// pub fn report_active<PA: PeerAddress, R: Rng + Clone>(network: &Network<PA, R>, topic: &TopicId) {
//     for state in &network.peers {
//         let me = state.me();
//         match state.state(topic) {
//             Some(state) => {
//                 let peers = state.swarm.active_view.iter().collect::<Vec<_>>();
//                 eprintln!("{me:?}: {:?}", peers);
//             }
//             None => {
//                 eprintln!("{me:?}: QUIT");
//             }
//         }
//     }
// }
