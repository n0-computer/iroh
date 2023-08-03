//! Implementation of the Plumtree epidemic broadcast tree protocol
//!
//! The implementation is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luıs Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{
    collections::{HashMap, HashSet, VecDeque},
    hash::Hash,
    time::Duration,
};

use bytes::Bytes;
use derive_more::{Add, From, Sub};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{util::idbytes_impls, PeerIdentity, IO};

/// A message identifier, which is the message content's blake3 hash.
#[derive(Serialize, Deserialize, Clone, Hash, Copy, PartialEq, Eq)]
pub struct MessageId([u8; 32]);
idbytes_impls!(MessageId, "MessageId");

impl MessageId {
    /// Create a `[MessageId]` by hashing the message content.
    ///
    /// This hashes the input with [`blake3::hash`].
    pub fn from_content(message: &[u8]) -> Self {
        Self::from(blake3::hash(message))
    }
}

/// Events Plumtree is informed of from the peer sampling service and IO layer.
#[derive(Debug)]
pub enum InEvent<PI> {
    /// A [`Message`] was received from the peer.
    RecvMessage(PI, Message),
    /// Broadcast the contained payload.
    Broadcast(Bytes),
    /// A timer has expired.
    TimerExpired(Timer),
    /// New member `PI` has joined the topic.
    NeighborUp(PI),
    /// Peer `PI` has disconnected from the topic.
    NeighborDown(PI),
}

/// Events Plumtree emits.
#[derive(Debug, PartialEq, Eq)]
pub enum OutEvent<PI> {
    /// Ask the IO layer to send a [`Message`] to peer `PI`.
    SendMessage(PI, Message),
    /// Schedule a [`Timer`].
    ScheduleTimer(Duration, Timer),
    /// Emit an [`Event`] to the application.
    EmitEvent(Event<PI>),
}

/// Kinds of timers Plumtree needs to schedule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Timer {
    /// Request the content for [`MessageId`] by sending [`Message::Graft`].
    ///
    /// The message will be sent to a peer that sent us an [`Message::IHave`] for this [`MessageId`],
    /// which will send us the message content in reply and also move the peer into the eager set.
    /// Will be a no-op if the message for [`MessageId`] was already received from another peer by now.
    SendGraft(MessageId),
    /// Dispatch the [`Message::IHave`] in our lazy push queue.
    DispatchLazyPush,
}

/// Event emitted by the [`State`] to the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event<PI> {
    /// A new gossip message was received.
    Received(
        /// The content of the gossip message.
        Bytes,
        /// The peer that we received the gossip message from. Note that this is not the peer that
        /// originally broadcasted the message, but the peer before us in the gossiping path.
        PI,
    ),
}

/// Number of delivery hops a message has taken.
#[derive(
    From, Add, Sub, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug, Hash,
)]
pub struct Round(u16);

impl Round {
    pub fn next(&self) -> Round {
        Round(self.0 + 1)
    }
}

/// Messages that we can send and receive from peers within the topic.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message {
    /// When receiving Gossip, emit as event and forward full message to eager peer and (after a
    /// delay) message IDs to lazy peers.
    Gossip(Gossip),
    /// When receiving Prune, move the peer from the eager to the lazy set.
    Prune,
    /// When receiving Graft, move the peer to the eager set and send the full content for the
    /// included message ID.
    Graft(Graft),
    /// When receiving IHave, do nothing initially, and request the messages for the included
    /// message IDs after some time if they aren't pushed eagerly to us.
    IHave(Vec<IHave>),
}

/// Payload messages transmitted by the protocol.
#[derive(Serialize, Deserialize, Clone, derive_more::Debug, PartialEq, Eq)]
pub struct Gossip {
    /// Id of the message.
    id: MessageId,
    /// Delivery round of the message.
    round: Round,
    /// Message contents.
    #[debug("<{}b>", content.len())]
    content: Bytes,
}

impl Gossip {
    /// Get a clone of this `Gossip` message and increase the delivery round by 1.
    pub fn next_round(self) -> Gossip {
        Gossip {
            id: self.id,
            content: self.content,
            round: self.round.next(),
        }
    }

    /// Validate that the message id is the blake3 hash of the message content.
    pub fn validate(&self) -> bool {
        let expected = MessageId::from_content(&self.content);
        expected == self.id
    }
}

/// Control message to inform peers we have a message without transmitting the whole payload.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IHave {
    /// Id of the message.
    id: MessageId,
    /// Delivery round of the message.
    round: Round,
}

/// Control message to signal a peer that they have been moved to the eager set, and to ask the
/// peer to do the same with this node.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Graft {
    /// Message id that triggers the graft, if any.
    /// On receiving a graft, the payload message must be sent in reply if a message id is set.
    id: Option<MessageId>,
    /// Delivery round of the [`Message::IHave`] that triggered this Graft message.
    round: Round,
}

/// Configuration for the gossip broadcast layer.
///
/// Currently, the expectation is that the configuration is the same for all peers in the
/// network (as recommended in the paper).
#[derive(Clone, Debug)]
pub struct Config {
    /// When receiving an [`IHave`] message, this timeout is registered. If the message for the
    /// [`IHave`] was not received once the timeout is expired, a [`Graft`] message is sent to the
    /// peer that sent us the [`IHave`] to request the message payload.
    ///
    /// The plumtree paper notes:
    /// > The timeout value is a protocol parameter that should be configured considering the
    /// diameter of the overlay and a target maximum recovery latency, defined by the application
    /// requirements. (p.8)
    pub graft_timeout_1: Duration,
    /// This timeout is registered when sending a [`Graft`] message. If a reply has not been
    /// received once the timeout expires, we send another [`Graft`] message to the next peer that
    /// sent us an [`IHave`] for this message.
    ///
    /// The plumtree paper notes:
    /// > This second timeout value should be smaller that the first, in the order of an average
    /// round trip time to a neighbor.
    pub graft_timeout_2: Duration,
    /// Timeout after which [`IHave`] messages are pushed to peers.
    pub dispatch_timeout: Duration,
    /// The protocol performs a tree optimization, which promotes lazy peers to eager peers if the
    /// [`Message::IHave`] messages received from them have a lower number of hops from the
    /// message's origin as the [`InEvent::Broadcast`] messages received from our eager peers. This
    /// parameter is the number of hops that the lazy peers must be closer to the origin than our
    /// eager peers to be promoted to become an eager peer.
    pub optimization_threshold: Round,
}

impl Default for Config {
    /// Sensible defaults for the plumtree configuration
    //
    // TODO: Find out what good defaults are for the three timeouts here. Current numbers are
    // guesses that need validation. The paper does not have concrete recommendations for these
    // numbers.
    fn default() -> Self {
        Self {
            // Paper: "The timeout value is a protocol parameter that should be configured considering
            // the diameter of the overlay and a target maximum recovery latency, defined by the
            // application requirements. This is a parameter that should be statically configured
            // at deployment time." (p. 8)
            //
            // Earthstar has 5ms it seems, see https://github.com/earthstar-project/earthstar/blob/1523c640fedf106f598bf79b184fb0ada64b1cc0/src/syncer/plum_tree.ts#L75
            // However in the paper it is more like a few roundtrips if I read things correctly.
            graft_timeout_1: Duration::from_millis(80),

            // Paper: "This second timeout value should be smaller that the first, in the order of an
            // average round trip time to a neighbor." (p. 9)
            //
            // Earthstar doesn't have this step from my reading.
            graft_timeout_2: Duration::from_millis(40),

            // Again, paper does not tell a recommended number here. Likely should be quite small,
            // as to not delay messages without need. This would also be the time frame in which
            // `IHave`s are aggregated to save on packets.
            //
            // Eartstar dispatches immediately from my reading.
            dispatch_timeout: Duration::from_millis(5),

            // This number comes from experiment settings the plumtree paper (p. 12)
            optimization_threshold: Round(7),
        }
    }
}

/// Stats about this topic's plumtree.
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Number of payload messages received so far.
    ///
    /// See [`Message::Gossip`].
    pub payload_messages_received: u64,
    /// Number of control messages received so far.
    ///
    /// See [`Message::Prune`], [`Message::Graft`], [`Message::IHave`].
    pub control_messages_received: u64,
    /// Max round seen so far.
    pub max_last_delivery_hop: u16,
}

/// State of the plumtree.
#[derive(Debug)]
pub struct State<PI> {
    /// Our address.
    me: PI,
    /// Configuration for this plumtree.
    config: Config,

    /// Set of peers used for payload exchange.
    pub(crate) eager_push_peers: HashSet<PI>,
    /// Set of peers used for control message exchange.
    pub(crate) lazy_push_peers: HashSet<PI>,

    lazy_push_queue: HashMap<PI, Vec<IHave>>,

    /// Messages for which a [`MessageId`] has been seen via a [`Message::IHave`] but we have not
    /// yet received the full payload. For each, we store the peers that have claimed to have this
    /// message.
    missing_messages: HashMap<MessageId, VecDeque<(PI, Round)>>,
    /// Messages for which the full payload has been seen.
    received_messages: HashSet<MessageId>,
    /// Payloads of received messages.
    cache: HashMap<MessageId, Gossip>,

    /// Message ids for which a [`Timer::SendGraft`] has been scheduled.
    graft_timer_scheduled: HashSet<MessageId>,
    /// Whether a [`Timer::DispatchLazyPush`] has been scheduled.
    dispatch_timer_scheduled: bool,

    /// [`Stats`] of this plumtree.
    pub(crate) stats: Stats,
}

impl<PI: PeerIdentity> State<PI> {
    /// Initialize the [`State`] of a plumtree.
    pub fn new(me: PI, config: Config) -> Self {
        Self {
            me,
            eager_push_peers: Default::default(),
            lazy_push_peers: Default::default(),
            lazy_push_queue: Default::default(),
            config,
            missing_messages: Default::default(),
            received_messages: Default::default(),
            graft_timer_scheduled: Default::default(),
            cache: Default::default(),
            dispatch_timer_scheduled: false,
            stats: Default::default(),
        }
    }

    /// Handle an [`InEvent`].
    pub fn handle(&mut self, event: InEvent<PI>, io: &mut impl IO<PI>) {
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, io),
            InEvent::Broadcast(data) => self.do_broadcast(data, io),
            InEvent::NeighborUp(peer) => self.on_neighbor_up(peer),
            InEvent::NeighborDown(peer) => self.on_neighbor_down(peer),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DispatchLazyPush => self.on_dispatch_timer(io),
                Timer::SendGraft(id) => {
                    self.on_send_graft_timer(id, io);
                }
            },
        }
    }

    /// Get access to the [`Stats`] of the plumtree.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Handle receiving a [`Message`].
    fn handle_message(&mut self, sender: PI, message: Message, io: &mut impl IO<PI>) {
        if matches!(message, Message::Gossip(_)) {
            self.stats.payload_messages_received += 1;
        } else {
            self.stats.control_messages_received += 1;
        }
        match message {
            Message::Gossip(details) => self.on_gossip(sender, details, io),
            Message::Prune => self.on_prune(sender),
            Message::IHave(details) => self.on_ihave(sender, details, io),
            Message::Graft(details) => self.on_graft(sender, details, io),
        }
    }

    /// Dispatches messages from lazy queue over to lazy peers.
    fn on_dispatch_timer(&mut self, io: &mut impl IO<PI>) {
        for (peer, list) in self.lazy_push_queue.drain() {
            io.push(OutEvent::SendMessage(peer, Message::IHave(list)));
        }

        self.dispatch_timer_scheduled = false;
    }

    /// Send a gossip message.
    ///
    /// Will be pushed in full to eager peers.
    /// Pushing the message id to the lazy peers is delayed by a timer.
    fn do_broadcast(&mut self, data: Bytes, io: &mut impl IO<PI>) {
        let id = MessageId::from_content(&data);
        let message = Gossip {
            id,
            round: Round(0),
            content: data,
        };
        self.received_messages.insert(id);
        self.cache.insert(id, message.clone());
        let me = self.me;
        self.eager_push(message.clone(), &me, io);
        self.lazy_push(message, &me, io);
    }

    /// Handle receiving a [`Message::Gossip`].
    fn on_gossip(&mut self, sender: PI, message: Gossip, io: &mut impl IO<PI>) {
        // Validate that the message id is the blake3 hash of the message content.
        if !message.validate() {
            // TODO: Do we want to take any measures against the sender if we received a message
            // with a spoofed message id?
            warn!(
                peer = ?sender,
                "Received a message with spoofed message id ({})", message.id
            );
            return;
        }

        // if we already received this message: move peer to lazy set
        // and notify peer about this.
        if self.received_messages.contains(&message.id) {
            self.add_lazy(sender);
            io.push(OutEvent::SendMessage(sender, Message::Prune));
        // otherwise store the message, emit to application and forward to peers
        } else {
            // insert the message in the list of received messages
            self.received_messages.insert(message.id);

            // increase the round for forwarding the message, and add to cache
            // to reply to Graft messages later
            // TODO: use an LRU cache for self.cache
            // TODO: add callback/event to application to get missing messages that were received before?
            let message = message.next_round();
            self.cache.insert(message.id, message.clone());

            // push the message to our peers
            self.eager_push(message.clone(), &sender, io);
            self.lazy_push(message.clone(), &sender, io);

            // cleanup places where we track missing messages
            self.graft_timer_scheduled.remove(&message.id);
            let previous_ihaves = self.missing_messages.remove(&message.id);
            // do the optimization step from the paper
            if let Some(previous_ihaves) = previous_ihaves {
                self.optimize_tree(&sender, &message, previous_ihaves, io);
            }

            // emit event to application
            io.push(OutEvent::EmitEvent(Event::Received(
                message.content,
                sender,
            )));

            self.stats.max_last_delivery_hop =
                self.stats.max_last_delivery_hop.max(message.round.0);
        }
    }

    /// Optimize the tree by pruning the `sender` of a [`Message::Gossip`] if we previously
    /// received a [`Message::IHave`] for the same message with a much lower number of delivery
    /// hops from the original broadcaster of the message.
    ///
    /// See [Config::optimization_threshold].
    fn optimize_tree(
        &mut self,
        gossip_sender: &PI,
        message: &Gossip,
        previous_ihaves: VecDeque<(PI, Round)>,
        io: &mut impl IO<PI>,
    ) {
        let round = message.round;
        let best_ihave = previous_ihaves
            .iter()
            .min_by(|(_a_peer, a_round), (_b_peer, b_round)| a_round.cmp(b_round))
            .copied();

        if let Some((ihave_peer, ihave_round)) = best_ihave {
            if (ihave_round < round) && (round - ihave_round) >= self.config.optimization_threshold
            {
                // Graft the sender of the IHave, but only if it's not already eager.
                if !self.eager_push_peers.contains(&ihave_peer) {
                    let message = Message::Graft(Graft {
                        id: None,
                        round: ihave_round,
                    });
                    io.push(OutEvent::SendMessage(ihave_peer, message));
                }
                // Prune the sender of the Gossip.
                io.push(OutEvent::SendMessage(*gossip_sender, Message::Prune));
            }
        }
    }

    /// Handle receiving a [`Message::Prune`].
    fn on_prune(&mut self, sender: PI) {
        self.add_lazy(sender);
    }

    /// Handle receiving a [`Message::IHave`].
    ///
    /// > When a node receives a IHAVE message, it simply marks the corresponding message as
    /// missing It then starts a timer, with a predefined timeout value, and waits for the missing
    /// message to be received via eager push before the timer expires. The timeout value is a
    /// protocol parameter that should be configured considering the diameter of the overlay and a
    /// target maximum recovery latency, defined by the application requirements. This is a
    /// parameter that should be statically configured at deployment time. (p8)
    fn on_ihave(&mut self, sender: PI, ihaves: Vec<IHave>, io: &mut impl IO<PI>) {
        for ihave in ihaves {
            if !self.received_messages.contains(&ihave.id) {
                self.missing_messages
                    .entry(ihave.id)
                    .or_default()
                    .push_back((sender, ihave.round));

                if !self.graft_timer_scheduled.contains(&ihave.id) {
                    self.graft_timer_scheduled.insert(ihave.id);
                    io.push(OutEvent::ScheduleTimer(
                        self.config.graft_timeout_1,
                        Timer::SendGraft(ihave.id),
                    ));
                }
            }
        }
    }

    /// A scheduled [`Timer::SendGraft`] has reached it's deadline.
    fn on_send_graft_timer(&mut self, id: MessageId, io: &mut impl IO<PI>) {
        // if the message was received before the timer ran out, there is no need to request it
        // again
        if self.received_messages.contains(&id) {
            return;
        }
        // get the first peer that advertised this message
        let entry = self
            .missing_messages
            .get_mut(&id)
            .and_then(|entries| entries.pop_front());
        if let Some((peer, round)) = entry {
            self.add_eager(peer);
            let message = Message::Graft(Graft {
                id: Some(id),
                round,
            });
            io.push(OutEvent::SendMessage(peer, message));

            // "when a GRAFT message is sent, another timer is started to expire after a certain timeout,
            // to ensure that the message will be requested to another neighbor if it is not received
            // meanwhile. This second timeout value should be smaller that the first, in the order of
            // an average round trip time to a neighbor." (p9)
            io.push(OutEvent::ScheduleTimer(
                self.config.graft_timeout_2,
                Timer::SendGraft(id),
            ));
        }
    }

    /// Handle receiving a [`Message::Graft`].
    fn on_graft(&mut self, sender: PI, details: Graft, io: &mut impl IO<PI>) {
        self.add_eager(sender);
        if let Some(id) = details.id {
            if let Some(message) = self.cache.get(&id) {
                io.push(OutEvent::SendMessage(
                    sender,
                    Message::Gossip(message.clone()),
                ));
            }
        }
    }

    /// Handle a [`InEvent::NeighborUp`] when a peer joins the topic.
    fn on_neighbor_up(&mut self, peer: PI) {
        self.add_eager(peer);
    }

    /// Handle a [`InEvent::NeighborDown`] when a peer leaves the topic.
    /// > When a neighbor is detected to leave the overlay, it is simple removed from the
    /// membership. Furthermore, the record of IHAVE messages sent from failed members is deleted
    /// from the missing history. (p9)
    fn on_neighbor_down(&mut self, peer: PI) {
        self.missing_messages.retain(|_message_id, ihaves| {
            ihaves.retain(|(ihave_peer, _round)| *ihave_peer != peer);
            !ihaves.is_empty()
        });
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.remove(&peer);
    }

    /// Moves peer into eager set.
    fn add_eager(&mut self, peer: PI) {
        self.lazy_push_peers.remove(&peer);
        self.eager_push_peers.insert(peer);
    }

    /// Moves peer into lazy set.
    fn add_lazy(&mut self, peer: PI) {
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.insert(peer);
    }

    /// Immediatelly sends message to eager peers.
    fn eager_push(&mut self, gossip: Gossip, sender: &PI, io: &mut impl IO<PI>) {
        for peer in self
            .eager_push_peers
            .iter()
            .filter(|peer| **peer != self.me && *peer != sender)
        {
            io.push(OutEvent::SendMessage(
                *peer,
                Message::Gossip(gossip.clone()),
            ));
        }
    }

    /// Queue lazy message announcements into the queue that will be sent out as batched
    /// [`Message::IHave`] messages once the [`Timer::DispatchLazyPush`] timer is triggered.
    fn lazy_push(&mut self, gossip: Gossip, sender: &PI, io: &mut impl IO<PI>) {
        for peer in self.lazy_push_peers.iter().filter(|x| *x != sender) {
            self.lazy_push_queue.entry(*peer).or_default().push(IHave {
                id: gossip.id,
                round: gossip.round,
            });
        }
        if !self.dispatch_timer_scheduled {
            io.push(OutEvent::ScheduleTimer(
                self.config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            self.dispatch_timer_scheduled = true;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn optimize_tree() {
        let mut io = VecDeque::new();
        let config: Config = Default::default();
        let mut state = State::new(1, config.clone());

        // we receive an IHave message from peer 2
        // it has `round: 2` which means that the the peer that sent us the IHave was
        // two hops away from the original sender of the message
        let content: Bytes = b"hi".to_vec().into();
        let id = MessageId::from_content(&content);
        let event = InEvent::RecvMessage(
            2u32,
            Message::IHave(vec![IHave {
                id,
                round: Round(2),
            }]),
        );
        state.handle(event, &mut io);
        io.clear();
        // we then receive a `Gossip` message with the same `MessageId` from peer 3
        // the message has `round: 6`, which means it travelled 6 hops until it reached us
        // this is less hops than to peer 2, but not enough to trigger the optimization
        // because we use the default config which has `optimization_threshold: 7`
        let event = InEvent::RecvMessage(
            3,
            Message::Gossip(Gossip {
                id,
                round: Round(6),
                content: content.clone(),
            }),
        );
        state.handle(event, &mut io);
        let expected = {
            // we expect a dispatch timer schedule and receive event, but no Graft or Prune
            // messages
            let mut io = VecDeque::new();
            io.push(OutEvent::ScheduleTimer(
                config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            io.push(OutEvent::EmitEvent(Event::Received(content, 3)));
            io
        };
        assert_eq!(io, expected);
        io.clear();

        // now we run the same flow again but this time peer 3 is 9 hops away from the message's
        // sender. message's sender. this will trigger the optimization:
        // peer 2 will be promoted to eager and peer 4 demoted to lazy

        let content: Bytes = b"hi2".to_vec().into();
        let id = MessageId::from_content(&content);
        let event = InEvent::RecvMessage(
            2u32,
            Message::IHave(vec![IHave {
                id,
                round: Round(2),
            }]),
        );
        state.handle(event, &mut io);
        io.clear();

        let event = InEvent::RecvMessage(
            3,
            Message::Gossip(Gossip {
                id,
                round: Round(9),
                content: content.clone(),
            }),
        );
        state.handle(event, &mut io);
        let expected = {
            // this time we expect the Graft and Prune messages to be sent, performing the
            // optimization step
            let mut io = VecDeque::new();
            io.push(OutEvent::SendMessage(
                2,
                Message::Graft(Graft {
                    id: None,
                    round: Round(2),
                }),
            ));
            io.push(OutEvent::SendMessage(3, Message::Prune));
            io.push(OutEvent::EmitEvent(Event::Received(content, 3)));
            io
        };
        assert_eq!(io, expected);
    }

    #[test]
    fn spoofed_messages_are_ignored() {
        let config: Config = Default::default();
        let mut state = State::new(1, config.clone());

        // we recv a correct gossip message and expect the Received event to be emitted
        let content: Bytes = b"hello1".to_vec().into();
        let message = Message::Gossip(Gossip {
            content: content.clone(),
            round: Round(1),
            id: MessageId::from_content(&content),
        });
        let mut io = VecDeque::new();
        state.handle(InEvent::RecvMessage(2, message), &mut io);
        let expected = {
            let mut io = VecDeque::new();
            io.push(OutEvent::ScheduleTimer(
                config.dispatch_timeout,
                Timer::DispatchLazyPush,
            ));
            io.push(OutEvent::EmitEvent(Event::Received(content, 2)));
            io
        };
        assert_eq!(io, expected);

        // now we recv with a spoofed id and expect no event to be emitted
        let content: Bytes = b"hello2".to_vec().into();
        let message = Message::Gossip(Gossip {
            content: content.clone(),
            round: Round(1),
            id: MessageId::from_content(b"foo"),
        });
        let mut io = VecDeque::new();
        state.handle(InEvent::RecvMessage(2, message), &mut io);
        let expected = VecDeque::new();
        assert_eq!(io, expected);
    }
}
