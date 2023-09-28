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

use super::{util::IndexSet, PeerData, PeerIdentity, PeerInfo, IO};

/// Input event for HyParView
#[derive(Debug)]
pub enum InEvent<PI> {
    /// A [`Message`] was received from a peer.
    RecvMessage(PI, Message<PI>),
    /// A timer has expired.
    TimerExpired(Timer<PI>),
    /// A peer was disconnected on the IO layer.
    PeerDisconnected(PI),
    /// Send a join request to a peer.
    RequestJoin(PI),
    /// Update the peer data that is transmitted on join requests.
    UpdatePeerData(PeerData),
    /// Quit the swarm, informing peers about us leaving.
    Quit,
}

/// Output event for HyParView
#[derive(Debug)]
pub enum OutEvent<PI> {
    /// Ask the IO layer to send a [`Message`] to peer `PI`.
    SendMessage(PI, Message<PI>),
    /// Schedule a [`Timer`].
    ScheduleTimer(Duration, Timer<PI>),
    /// Ask the IO layer to close the connection to peer `PI`.
    DisconnectPeer(PI),
    /// Emit an [`Event`] to the application.
    EmitEvent(Event<PI>),
    /// New [`PeerData`] was received for peer `PI`.
    PeerData(PI, PeerData),
}

/// Event emitted by the [`State`] to the application.
#[derive(Clone, Debug)]
pub enum Event<PI> {
    /// A peer was added to our set of active connections.
    NeighborUp(PI),
    /// A peer was removed from our set of active connections.
    NeighborDown(PI),
}

/// Kinds of timers HyParView needs to schedule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Timer<PI> {
    DoShuffle,
    PendingNeighborRequest(PI),
}

/// Messages that we can send and receive from peers within the topic.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message<PI> {
    /// Sent to a peer if you want to join the swarm
    Join(Option<PeerData>),
    /// When receiving Join, ForwardJoin is forwarded to the peer's ActiveView to introduce the
    /// new member.
    ForwardJoin(ForwardJoin<PI>),
    /// A shuffle request is sent occasionally to re-shuffle the PassiveView with contacts from
    /// other peers.
    Shuffle(Shuffle<PI>),
    /// Peers reply to [`Message::Shuffle`] requests with a random peers from their active and
    /// passive views.
    ShuffleReply(ShuffleReply<PI>),
    /// Request to add sender to an active view of recipient. If [`Neighbor::priority`] is
    /// [`Priority::High`], the request cannot be denied.
    Neighbor(Neighbor),
    /// Request to disconnect from a peer.
    /// If [`Disconnect::alive`] is true, the other peer is not shutting down, so it should be
    /// added to the passive set.
    /// If [`Disconnect::respond`] is true, the peer should answer the disconnect request
    /// before shutting down the connection.
    Disconnect(Disconnect),
}

/// The time-to-live for this message.
///
/// Each time a message is forwarded, the `Ttl` is decreased by 1. If the `Ttl` reaches 0, it
/// should not be forwarded further.
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

/// A message informing other peers that a new peer joined the swarm for this topic.
///
/// Will be forwarded in a random walk until `ttl` reaches 0.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ForwardJoin<PI> {
    /// The peer that newly joined the swarm
    peer: PeerInfo<PI>,
    /// The time-to-live for this message
    ttl: Ttl,
}

/// Shuffle messages are sent occasionally to shuffle our passive view with peers from other peer's
/// active and passive views.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Shuffle<PI> {
    /// The peer that initiated the shuffle request.
    origin: PI,
    /// A random subset of the active and passive peers of the `origin` peer.
    nodes: Vec<PeerInfo<PI>>,
    /// The time-to-live for this message.
    ttl: Ttl,
}

/// Once a shuffle messages reaches a [`Ttl`] of 0, a peer replies with a `ShuffleReply`.
///
/// The reply is sent to the peer that initiated the shuffle and contains a subset of the active
/// and passive views of the peer at the end of the random walk.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ShuffleReply<PI> {
    /// A random subset of the active and passive peers of the peer sending the `ShuffleReply`.
    nodes: Vec<PeerInfo<PI>>,
}

/// The priority of a `Join` message
///
/// This is `High` if the sender does not have any active peers, and `Low` otherwise.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Priority {
    /// High priority join that may not be denied.
    ///
    /// A peer may only send high priority joins if it doesn't have any active peers at the moment.
    High,
    /// Low priority join that can be denied.
    Low,
}

/// A neighbor message is sent after adding a peer to our active view to inform them that we are
/// now neighbors.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Neighbor {
    /// The priority of the `Join` or `ForwardJoin` message that triggered this neighbor request.
    priority: Priority,
    /// The user data of the peer sending this message.
    data: Option<PeerData>,
}

/// Message sent when leaving the swarm or closing down to inform peers about us being gone.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Disconnect {
    /// Whether we are actually shutting down or closing the connection only because our limits are
    /// reached.
    alive: Alive,
    /// Whether we should reply to the peer with a Disconnect message.
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
    /// is added to a peer's passive view.
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

/// The state of the HyParView protocol
#[derive(Debug)]
pub struct State<PI, RG = ThreadRng> {
    /// Our peer identity
    me: PI,
    /// Our opaque user data to transmit to peers on join messages
    me_data: Option<PeerData>,
    /// The active view, i.e. peers we are connected to
    pub(crate) active_view: IndexSet<PI>,
    /// The passive view, i.e. peers we know about but are not connected to at the moment
    pub(crate) passive_view: IndexSet<PI>,
    /// Protocol configuration (cannot change at runtime)
    config: Config,
    /// Whether a shuffle timer is currently scheduled
    shuffle_scheduled: bool,
    /// Random number generator
    rng: RG,
    /// Statistics
    stats: Stats,
    /// The set of neighbor requests we sent out but did not yet receive a reply for
    pending_neighbor_requests: HashSet<PI>,
    /// The opaque user peer data we received for other peers
    peer_data: HashMap<PI, PeerData>,
}

impl<PI, RG> State<PI, RG>
where
    PI: PeerIdentity,
    RG: Rng,
{
    pub fn new(me: PI, me_data: Option<PeerData>, config: Config, rng: RG) -> Self {
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

    pub fn handle(&mut self, event: InEvent<PI>, now: Instant, io: &mut impl IO<PI>) {
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, now, io),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DoShuffle => self.handle_shuffle_timer(io),
                Timer::PendingNeighborRequest(peer) => self.handle_pending_neighbor_timer(peer, io),
            },
            InEvent::PeerDisconnected(peer) => self.handle_disconnect(peer, io),
            InEvent::RequestJoin(peer) => self.handle_join(peer, io),
            InEvent::UpdatePeerData(data) => {
                self.me_data = Some(data);
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
        from: PI,
        message: Message<PI>,
        now: Instant,
        io: &mut impl IO<PI>,
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

    fn handle_join(&mut self, peer: PI, io: &mut impl IO<PI>) {
        io.push(OutEvent::SendMessage(
            peer,
            Message::Join(self.me_data.clone()),
        ));
    }

    fn handle_disconnect(&mut self, peer: PI, io: &mut impl IO<PI>) {
        self.on_disconnect(
            peer,
            Disconnect {
                alive: true,
                respond: false,
            },
            io,
        );
    }

    fn handle_quit(&mut self, io: &mut impl IO<PI>) {
        for peer in self.active_view.clone().into_iter() {
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

    fn on_join(&mut self, peer: PI, data: Option<PeerData>, now: Instant, io: &mut impl IO<PI>) {
        // If the peer is already in our active view, there's nothing to do.
        if self.active_view.contains(&peer) {
            // .. but we still update the peer data.
            self.insert_peer_info((peer, data).into(), io);
            return;
        }
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
        sender: PI,
        message: ForwardJoin<PI>,
        now: Instant,
        io: &mut impl IO<PI>,
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
                    unreachable!("if the peer was not added, there are at least two peers in our active view.");
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

    fn on_neighbor(&mut self, from: PI, details: Neighbor, now: Instant, io: &mut impl IO<PI>) {
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

    /// Get the peer [`PeerInfo`] for a peer.
    fn peer_info(&self, id: &PI) -> PeerInfo<PI> {
        let data = self.peer_data.get(id).cloned();
        PeerInfo { id: *id, data }
    }

    fn insert_peer_info(&mut self, peer_info: PeerInfo<PI>, io: &mut impl IO<PI>) {
        if let Some(data) = peer_info.data {
            let old = self.peer_data.remove(&peer_info.id);
            let same = matches!(old, Some(old) if old == data);
            if !same {
                io.push(OutEvent::PeerData(peer_info.id, data.clone()));
            }
            self.peer_data.insert(peer_info.id, data);
        }
    }

    /// Handle a [`Message::Shuffle`]
    ///
    /// > A node q that receives a Shuffle request will first decrease its time to live. If the time
    /// to live of the message is greater than zero and the number of nodes in q’s active view is
    /// greater than 1, the node will select a random node from its active view, different from the
    /// one he received this shuffle message from, and simply forwards the Shuffle request.
    /// Otherwise, node q accepts the Shuffle request and send back (p.8)
    fn on_shuffle(&mut self, from: PI, shuffle: Shuffle<PI>, io: &mut impl IO<PI>) {
        if shuffle.ttl.expired() || self.active_view.len() <= 1 {
            let len = shuffle.nodes.len();
            for node in shuffle.nodes {
                self.add_passive(node.id, node.data, io);
            }
            let nodes = self
                .passive_view
                .shuffled_and_capped(len, &mut self.rng)
                .into_iter()
                .map(|id| self.peer_info(&id));
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

    fn on_shuffle_reply(&mut self, message: ShuffleReply<PI>, io: &mut impl IO<PI>) {
        for node in message.nodes {
            self.add_passive(node.id, node.data, io);
        }
    }

    fn on_disconnect(&mut self, peer: PI, details: Disconnect, io: &mut impl IO<PI>) {
        self.pending_neighbor_requests.remove(&peer);
        self.remove_active(&peer, details.respond, io);
        if details.alive {
            if let Some(data) = self.peer_data.remove(&peer) {
                self.add_passive(peer, Some(data), io);
            }
        } else {
            self.passive_view.remove(&peer);
        }
    }

    fn handle_shuffle_timer(&mut self, io: &mut impl IO<PI>) {
        if let Some(node) = self.active_view.pick_random(&mut self.rng) {
            let active = self.active_view.shuffled_without_and_capped(
                &[node],
                self.config.shuffle_active_view_count,
                &mut self.rng,
            );
            let passive = self.passive_view.shuffled_without_and_capped(
                &[node],
                self.config.shuffle_passive_view_count,
                &mut self.rng,
            );
            let nodes = active
                .iter()
                .chain(passive.iter())
                .map(|id| self.peer_info(id));
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
    fn add_passive(&mut self, peer: PI, data: Option<PeerData>, io: &mut impl IO<PI>) {
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
    fn remove_active(&mut self, peer: &PI, respond: Respond, io: &mut impl IO<PI>) -> Option<PI> {
        self.active_view.get_index_of(peer).map(|idx| {
            let removed_peer = self
                .remove_active_by_index(idx, respond, RemovalReason::Disconnect, io)
                .unwrap();

            self.refill_active_from_passive(&[&removed_peer], io);

            removed_peer
        })
    }

    fn refill_active_from_passive(&mut self, skip_peers: &[&PI], io: &mut impl IO<PI>) {
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

    fn handle_pending_neighbor_timer(&mut self, peer: PI, io: &mut impl IO<PI>) {
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
        io: &mut impl IO<PI>,
    ) -> Option<PI> {
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
            let data = self.peer_data.remove(&peer);
            self.add_passive(peer, data, io);
            debug!(other = ?peer, "removed from active view, reason: {reason:?}");
            Some(peer)
        } else {
            None
        }
    }

    /// Remove a random peer from the active view.
    fn free_random_slot_in_active_view(&mut self, io: &mut impl IO<PI>) {
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
        peer: PI,
        data: Option<PeerData>,
        priority: Priority,
        _now: Instant,
        io: &mut impl IO<PI>,
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

    fn add_active_unchecked(&mut self, peer: PI, priority: Priority, io: &mut impl IO<PI>) {
        self.passive_view.remove(&peer);
        self.active_view.insert(peer);
        debug!(other = ?peer, "add to active view");

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
