//! Implementation of the HyParView membership protocol
//!
//! The implementation is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luıs Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/dsn07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use derive_more::{From, Sub};
use rand::rngs::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::debug;

use super::{util::IndexSet, PeerAddress, PeerData, PeerInfo, IO};

/// Input event for HyParView
#[derive(Debug)]
pub enum InEvent<PA> {
    RecvMessage(PA, Message<PA>),
    TimerExpired(Timer<PA>),
    PeerDisconnected(PA),
    RequestJoin(PA),
    UpdatePeerData(PeerData),
    Quit,
}

/// Output event for HyParView
#[derive(Debug)]
pub enum OutEvent<PA> {
    SendMessage(PA, Message<PA>),
    ScheduleTimer(Duration, Timer<PA>),
    DisconnectPeer(PA),
    EmitEvent(Event<PA>),
    PeerData(PA, PeerData),
}

#[derive(Clone, Debug)]
pub enum Event<PA> {
    NeighborUp(PA),
    NeighborDown(PA),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Timer<PA> {
    DoShuffle,
    PendingNeighborRequest(PA),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message<PA> {
    /// Sent to a peer if you want to join the swarm
    Join(PeerData),
    /// When receiving Join, ForwardJoin is forwarded to the peer's ActiveView to introduce the
    /// new member.
    ForwardJoin(ForwardJoin<PA>),
    /// A shuffle request is sent occasionally to re-shuffle the PassiveView with contacts from
    /// other peers.
    Shuffle(Shuffle<PA>),
    /// Peers reply to Shuffle requests with a random subset of their PassiveView.
    ShuffleReply(ShuffleReply<PA>),
    /// Request to add sender to an active view of recipient. If `highPriority` is set, it cannot
    /// be denied.
    Neighbor(Neighbor),
    /// Request to disconnect from a peer.
    /// If `alive` is true, the other peer is not shutting down, so it should be added to the
    /// passive set.
    /// If `respond` is true, the peer should answer the disconnect request before shutting down
    /// the connection.
    Disconnect(Disconnect),
}

#[derive(From, Sub, Eq, PartialEq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct Ttl(pub u16);
impl Ttl {
    pub fn expired(&self) -> bool {
        *self == Ttl(0)
    }
    pub fn next(&self) -> Ttl {
        Ttl(self.0.saturating_sub(1))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ForwardJoin<PA> {
    peer: PeerInfo<PA>,
    ttl: Ttl,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Shuffle<PA> {
    origin: PA,
    nodes: Vec<PeerInfo<PA>>,
    ttl: Ttl,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ShuffleReply<PA> {
    nodes: Vec<PeerInfo<PA>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Priority {
    High,
    Low,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Neighbor {
    priority: Priority,
    data: PeerData,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Disconnect {
    alive: Alive,
    respond: Respond,
}

/// Configuration for the swarm membership layer
#[derive(Clone, Debug)]
pub struct Config {
    /// Number of peers to which active connections are maintained
    pub active_view_capacity: usize,
    /// Number of peers for which contact information is remembered,
    /// but to which we are not actively connected to.
    pub passive_view_capacity: usize,
    /// Number of hops a `ForwardJoin` message is propagated until the new peer's info
    /// is added to a peer's active view.
    pub active_random_walk_length: Ttl,
    /// Number of hops a `ForwardJoin` message is propagated until the new peer's info
    /// is added to a peer'passive active view.
    pub passive_random_walk_length: Ttl,
    /// Number of hops a `Shuffle` message is propagated until a peer replies to it.
    pub shuffle_random_walk_length: Ttl,
    /// Number of active peers to be included in a `Shuffle` request.
    pub shuffle_active_view_count: usize,
    /// Number of passive peers to be included in a `Shuffle` request.
    pub shuffle_passive_view_count: usize,
    /// Interval duration for shuffle requests
    pub shuffle_interval: Duration,
    /// Timeout after which a `Neighbor` request is considered failed
    pub neighbor_request_timeout: Duration,
}
impl Default for Config {
    /// Default values for the HyParView layer
    fn default() -> Self {
        Self {
            // From the paper (p9)
            active_view_capacity: 5,
            // From the paper (p9)
            passive_view_capacity: 30,
            // From the paper (p9)
            active_random_walk_length: Ttl(6),
            // From the paper (p9)
            passive_random_walk_length: Ttl(3),
            // From the paper (p9)
            shuffle_random_walk_length: Ttl(6),
            // From the paper (p9)
            shuffle_active_view_count: 3,
            // From the paper (p9)
            shuffle_passive_view_count: 4,
            // Wild guess
            shuffle_interval: Duration::from_secs(60),
            // Wild guess
            neighbor_request_timeout: Duration::from_millis(500),
        }
    }
}

pub type Respond = bool;
pub type Alive = bool;

#[derive(Default, Debug, Clone)]
pub struct Stats {
    total_connections: usize,
}

#[derive(Debug)]
pub struct State<PA, RG = ThreadRng> {
    me: PA,
    me_data: PeerData,
    pub(crate) active_view: IndexSet<PA>,
    pub(crate) passive_view: IndexSet<PA>,
    config: Config,
    shuffle_scheduled: bool,
    rng: RG,
    stats: Stats,
    pending_neighbor_requests: HashSet<PA>,
    peer_data: HashMap<PA, PeerData>,
}

impl<PA, RG> State<PA, RG>
where
    PA: PeerAddress,
    RG: Rng,
{
    pub fn new(me: PA, me_data: PeerData, config: Config, rng: RG) -> Self {
        Self {
            me,
            me_data,
            active_view: IndexSet::new(),
            passive_view: IndexSet::new(),
            config,
            shuffle_scheduled: false,
            rng,
            stats: Stats::default(),
            pending_neighbor_requests: Default::default(),
            peer_data: Default::default(),
        }
    }

    pub fn handle(&mut self, event: InEvent<PA>, now: Instant, io: &mut impl IO<PA>) {
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, now, io),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DoShuffle => self.handle_shuffle_timer(io),
                Timer::PendingNeighborRequest(peer) => self.handle_pending_neighbor_timer(peer, io),
            },
            InEvent::PeerDisconnected(peer) => self.handle_disconnect(peer, io),
            InEvent::RequestJoin(peer) => self.handle_join(peer, io),
            InEvent::UpdatePeerData(data) => {
                self.me_data = data;
            }
            InEvent::Quit => self.handle_quit(io),
        }

        // this will only happen on the first call
        if !self.shuffle_scheduled {
            io.push(OutEvent::ScheduleTimer(
                self.config.shuffle_interval,
                Timer::DoShuffle,
            ));
            self.shuffle_scheduled = true;
        }
    }

    fn handle_message(
        &mut self,
        from: PA,
        message: Message<PA>,
        now: Instant,
        io: &mut impl IO<PA>,
    ) {
        let is_disconnect = matches!(message, Message::Disconnect(Disconnect { .. }));
        if !is_disconnect && !self.active_view.contains(&from) {
            self.stats.total_connections += 1;
        }
        match message {
            Message::Join(data) => self.on_join(from, data, now, io),
            Message::ForwardJoin(details) => self.on_forward_join(from, details, now, io),
            Message::Shuffle(details) => self.on_shuffle(from, details, io),
            Message::ShuffleReply(details) => self.on_shuffle_reply(details, io),
            Message::Neighbor(details) => self.on_neighbor(from, details, now, io),
            Message::Disconnect(details) => self.on_disconnect(from, details, io),
        }

        // Disconnect from passive nodes right after receiving a message.
        if !is_disconnect && !self.active_view.contains(&from) {
            io.push(OutEvent::DisconnectPeer(from));
        }
    }

    fn handle_join(&mut self, peer: PA, io: &mut impl IO<PA>) {
        io.push(OutEvent::SendMessage(
            peer,
            Message::Join(self.me_data.clone()),
        ));
    }

    fn handle_disconnect(&mut self, peer: PA, io: &mut impl IO<PA>) {
        self.on_disconnect(
            peer,
            Disconnect {
                alive: true,
                respond: false,
            },
            io,
        );
    }

    fn handle_quit(&mut self, io: &mut impl IO<PA>) {
        let peers = self.active_view.iter().cloned().collect::<Vec<_>>();
        for peer in peers {
            self.on_disconnect(
                peer,
                Disconnect {
                    alive: false,
                    respond: true,
                },
                io,
            );
        }
    }

    fn on_join(&mut self, peer: PA, data: PeerData, now: Instant, io: &mut impl IO<PA>) {
        // "A node that receives a join request will start by adding the new
        // node to its active view, even if it has to drop a random node from it. (6)"
        self.add_active(peer, data.clone(), Priority::High, now, io);
        // "The contact node c will then send to all other nodes in its active view a ForwardJoin
        // request containing the new node identifier. Associated to the join procedure,
        // there are two configuration parameters, named Active Random Walk Length (ARWL),
        // that specifies the maximum number of hops a ForwardJoin request is propagated,
        // and Passive Random Walk Length (PRWL), that specifies at which point in the walk the node
        // is inserted in a passive view. To use these parameters, the ForwardJoin request carries
        // a “time to live” field that is initially set to ARWL and decreased at every hop. (7)"
        let ttl = self.config.active_random_walk_length;
        let peer_info = PeerInfo { id: peer, data };
        for node in self.active_view.iter_without(&peer) {
            let message = Message::ForwardJoin(ForwardJoin {
                peer: peer_info.clone(),
                ttl,
            });
            io.push(OutEvent::SendMessage(*node, message));
        }
    }

    fn on_forward_join(
        &mut self,
        sender: PA,
        message: ForwardJoin<PA>,
        now: Instant,
        io: &mut impl IO<PA>,
    ) {
        // "i) If the time to live is equal to zero or if the number of nodes in p’s active view is equal to one,
        // it will add the new node to its active view (7)"
        if message.ttl.expired() || self.active_view.len() <= 1 {
            self.add_active(
                message.peer.id,
                message.peer.data.clone(),
                Priority::High,
                now,
                io,
            );
        }
        // "ii) If the time to live is equal to PRWL, p will insert the new node into its passive view"
        else if message.ttl == self.config.passive_random_walk_length {
            self.add_passive(message.peer.id, message.peer.data.clone(), io);
        }
        // "iii) The time to live field is decremented."
        // "iv) If, at this point, n has not been inserted
        // in p’s active view, p will forward the request to a random node in its active view
        // (different from the one from which the request was received)."
        if !self.active_view.contains(&message.peer.id) {
            match self
                .active_view
                .pick_random_without(&[&sender], &mut self.rng)
            {
                None => {
                    // TODO: I think this is unreachable!() but will have to check, maybe decrease
                    // to warn
                    unreachable!("no peers in active view but also did not add this node on forward join, this should not happen");
                }
                Some(next) => {
                    let message = Message::ForwardJoin(ForwardJoin {
                        peer: message.peer,
                        ttl: message.ttl.next(),
                    });
                    io.push(OutEvent::SendMessage(*next, message));
                }
            }
        }
    }

    fn on_neighbor(&mut self, from: PA, details: Neighbor, now: Instant, io: &mut impl IO<PA>) {
        self.pending_neighbor_requests.remove(&from);
        // "A node q that receives a high priority neighbor request will always accept the request, even
        // if it has to drop a random member from its active view (again, the member that is dropped will
        // receive a Disconnect notification). If a node q receives a low priority Neighbor request, it will
        // only accept the request if it has a free slot in its active view, otherwise it will refuse the request."
        match details.priority {
            Priority::High => {
                self.add_active(from, details.data, Priority::High, now, io);
            }
            Priority::Low if !self.active_is_full() => {
                self.add_active(from, details.data, Priority::Low, now, io);
            }
            _ => {}
        }
    }

    fn peer_info(&self, id: &PA) -> Option<PeerInfo<PA>> {
        self.peer_data.get(id).map(|data| PeerInfo {
            id: *id,
            data: data.clone(),
        })
    }

    fn insert_peer_info(&mut self, peer_info: PeerInfo<PA>, io: &mut impl IO<PA>) {
        let old = self.peer_data.remove(&peer_info.id);
        let same = matches!(old, Some(old) if old == peer_info.data);
        if !same {
            io.push(OutEvent::PeerData(peer_info.id, peer_info.data.clone()));
        }
        self.peer_data.insert(peer_info.id, peer_info.data);
    }

    fn on_shuffle(&mut self, from: PA, shuffle: Shuffle<PA>, io: &mut impl IO<PA>) {
        if shuffle.ttl.expired() {
            let len = shuffle.nodes.len();
            for node in shuffle.nodes {
                self.add_passive(node.id, node.data, io);
            }
            let nodes = self
                .passive_view
                .shuffled_max(len, &mut self.rng)
                .into_iter()
                .map(|id| self.peer_info(&id).unwrap());
            let message = Message::ShuffleReply(ShuffleReply {
                nodes: nodes.collect(),
            });
            io.push(OutEvent::SendMessage(shuffle.origin, message));
        } else if let Some(node) = self
            .active_view
            .pick_random_without(&[&shuffle.origin, &from], &mut self.rng)
        {
            let message = Message::Shuffle(Shuffle {
                origin: shuffle.origin,
                nodes: shuffle.nodes,
                ttl: shuffle.ttl.next(),
            });
            io.push(OutEvent::SendMessage(*node, message));
        }
    }

    fn on_shuffle_reply(&mut self, message: ShuffleReply<PA>, io: &mut impl IO<PA>) {
        for node in message.nodes {
            self.add_passive(node.id, node.data, io);
        }
    }

    fn on_disconnect(&mut self, peer: PA, details: Disconnect, io: &mut impl IO<PA>) {
        self.pending_neighbor_requests.remove(&peer);
        self.remove_active(&peer, details.respond, io);
        if details.alive {
            if let Some(data) = self.peer_data.remove(&peer) {
                self.add_passive(peer, data, io);
            }
        } else {
            self.passive_view.remove(&peer);
        }
    }

    fn handle_shuffle_timer(&mut self, io: &mut impl IO<PA>) {
        if let Some(node) = self.active_view.pick_random(&mut self.rng) {
            let active = self.active_view.shuffled_without_max(
                &[node],
                self.config.shuffle_active_view_count,
                &mut self.rng,
            );
            let passive = self.passive_view.shuffled_without_max(
                &[node],
                self.config.shuffle_passive_view_count,
                &mut self.rng,
            );
            let nodes = active
                .iter()
                .chain(passive.iter())
                .map(|id| self.peer_info(id).unwrap());
            let message = Shuffle {
                origin: self.me,
                nodes: nodes.collect(),
                ttl: self.config.shuffle_random_walk_length,
            };
            io.push(OutEvent::SendMessage(*node, Message::Shuffle(message)));
        }
        io.push(OutEvent::ScheduleTimer(
            self.config.shuffle_interval,
            Timer::DoShuffle,
        ));
    }

    fn passive_is_full(&self) -> bool {
        self.passive_view.len() >= self.config.passive_view_capacity
    }

    fn active_is_full(&self) -> bool {
        self.active_view.len() >= self.config.active_view_capacity
    }

    /// Add a peer to the passive view.
    ///
    /// If the passive view is full, it will first remove a random peer and then insert the new peer.
    /// If a peer is currently in the active view it will not be added.
    fn add_passive(&mut self, peer: PA, data: PeerData, io: &mut impl IO<PA>) {
        self.insert_peer_info((peer, data).into(), io);
        if self.active_view.contains(&peer) || self.passive_view.contains(&peer) || peer == self.me
        {
            return;
        }
        if self.passive_is_full() {
            self.passive_view.remove_random(&mut self.rng);
        }
        self.passive_view.insert(peer);
    }

    /// Remove a peer from the active view.
    ///
    /// If respond is true, a Disconnect message will be sent to the peer.
    fn remove_active(&mut self, peer: &PA, respond: Respond, io: &mut impl IO<PA>) -> Option<PA> {
        self.active_view.get_index_of(peer).map(|idx| {
            let removed_peer = self
                .remove_active_by_index(idx, respond, RemovalReason::Disconnect, io)
                .unwrap();

            self.refill_active_from_passive(&[&removed_peer], io);

            removed_peer
        })
    }

    fn refill_active_from_passive(&mut self, skip_peers: &[&PA], io: &mut impl IO<PA>) {
        if self.active_view.len() + self.pending_neighbor_requests.len()
            >= self.config.active_view_capacity
        {
            return;
        }
        // "When a node p suspects that one of the nodes present in its active view has failed
        // (by either disconnecting or blocking), it selects a random node q from its passive view and
        // attempts to establish a TCP connection with q. If the connection fails to establish,
        // node q is considered failed and removed from p’s passive view; another node q′ is selected
        // at random and a new attempt is made. The procedure is repeated until a connection is established
        // with success." (p7)
        let mut skip_peers = skip_peers.to_vec();
        skip_peers.extend(self.pending_neighbor_requests.iter());

        if let Some(node) = self
            .passive_view
            .pick_random_without(&skip_peers, &mut self.rng)
        {
            let priority = match self.active_view.is_empty() {
                true => Priority::High,
                false => Priority::Low,
            };
            let message = Message::Neighbor(Neighbor {
                priority,
                data: self.me_data.clone(),
            });
            io.push(OutEvent::SendMessage(*node, message));
            // schedule a timer that checks if the node replied with a neighbor message,
            // otherwise try again with another passive node.
            io.push(OutEvent::ScheduleTimer(
                self.config.neighbor_request_timeout,
                Timer::PendingNeighborRequest(*node),
            ));
            self.pending_neighbor_requests.insert(*node);
        };
    }

    fn handle_pending_neighbor_timer(&mut self, peer: PA, io: &mut impl IO<PA>) {
        if self.pending_neighbor_requests.remove(&peer) {
            self.passive_view.remove(&peer);
            self.refill_active_from_passive(&[], io);
        }
    }

    fn remove_active_by_index(
        &mut self,
        peer_index: usize,
        respond: Respond,
        reason: RemovalReason,
        io: &mut impl IO<PA>,
    ) -> Option<PA> {
        if let Some(peer) = self.active_view.remove_index(peer_index) {
            if respond {
                let message = Message::Disconnect(Disconnect {
                    alive: true,
                    respond: false,
                });
                io.push(OutEvent::SendMessage(peer, message));
            }
            io.push(OutEvent::DisconnectPeer(peer));
            io.push(OutEvent::EmitEvent(Event::NeighborDown(peer)));
            let data = self.peer_data.remove(&peer).unwrap();
            self.add_passive(peer, data, io);
            debug!(peer = ?self.me, other = ?peer, "removed from active view, reason: {reason:?}");
            Some(peer)
        } else {
            None
        }
    }

    /// Remove a random peer from the active view.
    fn free_random_slot_in_active_view(&mut self, io: &mut impl IO<PA>) {
        if let Some(index) = self.active_view.pick_random_index(&mut self.rng) {
            self.remove_active_by_index(index, true, RemovalReason::Random, io);
        }
    }

    /// Add a peer to the active view.
    ///
    /// If the active view is currently full, a random peer will be removed first.
    /// Sends a Neighbor message to the peer. If high_priority is true, the peer
    /// may not deny the Neighbor request.
    fn add_active(
        &mut self,
        peer: PA,
        data: PeerData,
        priority: Priority,
        _now: Instant,
        io: &mut impl IO<PA>,
    ) -> bool {
        self.insert_peer_info((peer, data).into(), io);
        if self.active_view.contains(&peer) || peer == self.me {
            return true;
        }
        match (priority, self.active_is_full()) {
            (Priority::High, is_full) => {
                if is_full {
                    self.free_random_slot_in_active_view(io);
                }
                self.add_active_unchecked(peer, Priority::High, io);
                true
            }
            (Priority::Low, false) => {
                self.add_active_unchecked(peer, Priority::Low, io);
                true
            }
            (Priority::Low, true) => false,
        }
    }

    fn add_active_unchecked(&mut self, peer: PA, priority: Priority, io: &mut impl IO<PA>) {
        self.passive_view.remove(&peer);
        self.active_view.insert(peer);
        debug!(peer = ?self.me, other = ?peer, "add to active view");

        let message = Message::Neighbor(Neighbor {
            priority,
            data: self.me_data.clone(),
        });
        io.push(OutEvent::SendMessage(peer, message));
        io.push(OutEvent::EmitEvent(Event::NeighborUp(peer)));
    }
}

#[derive(Debug)]
enum RemovalReason {
    Disconnect,
    Random,
}
