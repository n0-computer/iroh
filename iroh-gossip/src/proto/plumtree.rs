//! Implementation of the Plumtree epidemic broadcast tree protocol
//!
//! The implementation is based on [this paper][paper] by Joao Leitao, Jose Pereira, Luıs Rodrigues
//! and the [example implementation][impl] by Bartosz Sypytkowski
//!
//! [paper]: https://asc.di.fct.unl.pt/~jleitao/pdf/srds07-leitao.pdf
//! [impl]: https://gist.github.com/Horusiath/84fac596101b197da0546d1697580d99

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    hash::Hash,
    time::Duration,
};

use bytes::Bytes;
use derive_more::{Add, From, Sub};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};

use super::{PeerAddress, IO};

#[derive(Debug)]
pub enum InEvent<PA> {
    RecvMessage(PA, Message),
    Broadcast(Bytes),
    TimerExpired(Timer),
    NeighborUp(PA),
    NeighborDown(PA),
    PeerDisconnected(PA),
}

#[derive(Debug, PartialEq, Eq)]
pub enum OutEvent<PA> {
    SendMessage(PA, Message),
    ScheduleTimer(Duration, Timer),
    EmitEvent(Event),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Timer {
    SendGraft(MessageId),
    DispatchLazyPush,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Received(Bytes),
}

/// A message identifier, which is the message content's blake3 hash
#[derive(Serialize, Deserialize, Clone, Copy, Eq)]
pub struct MessageId([u8; 32]);

impl MessageId {
    /// Create a `MessageId` by hashing the message content.
    ///
    /// This hashes the input with [`blake3::hash`].
    pub fn from_content(message: &[u8]) -> Self {
        Self::from(blake3::hash(message))
    }
}

impl From<blake3::Hash> for MessageId {
    fn from(hash: blake3::Hash) -> Self {
        Self(hash.into())
    }
}

impl std::hash::Hash for MessageId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl PartialEq for MessageId {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}", text)
    }
}
impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.0);
        text.make_ascii_lowercase();
        write!(f, "{}…{}", &text[..5], &text[(text.len() - 2)..])
    }
}

#[derive(
    From, Add, Sub, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug, Hash,
)]
pub struct Round(u16);

impl Round {
    pub fn next(&self) -> Round {
        Round(self.0 + 1)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Message {
    /// When receiving Gossip, emit as event and forward full message to eager peer
    /// and (after a delay) message IDs to lazy peers.
    Gossip(Gossip),
    /// When receiving Prune, move the peer from the eager to the lazy set
    Prune,
    /// When receiving Graft, move the peer to the eager set and send the full content for the
    /// included message ID.
    Graft(Graft),
    /// When receiving IHave, do nothing initially, and request the messages for the included
    /// message IDs after some time if they aren't pushed eagerly to us.
    IHave(Vec<IHave>),
}

#[derive(Serialize, Deserialize, Clone, derive_more::Debug, PartialEq, Eq)]
pub struct Gossip {
    id: MessageId,
    round: Round,
    #[debug("<{}b>", content.len())]
    content: Bytes,
}
impl Gossip {
    pub fn next_round(self) -> Gossip {
        Gossip {
            id: self.id,
            content: self.content,
            round: self.round.next(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct IHave {
    id: MessageId,
    round: Round,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Graft {
    id: Option<MessageId>,
    round: Round,
}

/// Configuration for the gossip broadcast layer
///
/// Currently, the expectation is that the configuration is the same for all peers in the
/// network (as recommended in the paper).
#[derive(Clone, Debug)]
pub struct Config {
    /// When receiving an `IHave` message, this timeout is registered. If the message for the
    /// `IHave` was not received once the timeout is expired, a `Graft` message is sent to the peer
    /// that sent us the `IHave` to request the message payload.
    ///
    /// The plumtree paper notes: "The timeout value is a protocol parameter that should be configured
    /// considering the diameter of the overlay and a target maximum recovery latency, defined by the
    /// application requirements." (p.8)
    pub graft_timeout_1: Duration,
    /// This timeout is registered when sending a `Graft` message. If a reply has not been received
    /// once the timeout expires, we send another `Graft` message to the next peer that sent us an
    /// `IHave` for this message.
    ///
    /// The plumtree paper notes: "This second timeout value should be smaller that the first, in
    /// the order of an average round trip time to a neighbor"
    pub graft_timeout_2: Duration,
    /// Timeout after which `IHave` messages are pushed to peers.
    pub dispatch_timeout: Duration,
    /// The protocol performs a tree optimization, which promotes lazy peers to eager peers if the
    /// `Ihave` messages received from them have a lower number of hops from the message's origin
    /// as the `Broadcast` messages received from our eager peers. The `optimization_threshold` is
    /// the number of hops that the lazy peers must be closer to the origin than our eager peers
    /// to be promoted to become an eager peer.
    pub optimization_threshold: Round,
}
impl Default for Config {
    /// Sensible defaults for the plumtree configuration
    //
    /// TODO: Find out what good defaults are for the three timeout here.
    /// Current numbers are guesses that need validation. The paper does not have concrete
    /// recommendations for these numbers.
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

#[derive(Debug, Default, Clone)]
pub struct Stats {
    pub payload_messages_received: u64,
    pub control_messages_received: u64,
    pub max_last_delivery_hop: u16,
}

#[derive(Debug)]
pub struct State<PA> {
    me: PA,
    config: Config,

    pub(crate) eager_push_peers: HashSet<PA>,
    pub(crate) lazy_push_peers: HashSet<PA>,

    lazy_push_queue: HashMap<PA, Vec<IHave>>,

    missing_messages: HashMap<MessageId, VecDeque<(PA, Round)>>,
    received_messages: IndexSet<MessageId>,
    cache: HashMap<MessageId, Gossip>,

    graft_timer_scheduled: HashSet<MessageId>,
    dispatch_timer_scheduled: bool,

    pub(crate) stats: Stats,
}

impl<PA: PeerAddress> State<PA> {
    pub fn new(me: PA, config: Config) -> Self {
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

    pub fn handle(&mut self, event: InEvent<PA>, io: &mut impl IO<PA>) {
        match event {
            InEvent::RecvMessage(from, message) => self.handle_message(from, message, io),
            InEvent::Broadcast(data) => self.do_broadcast(data, io),
            InEvent::NeighborUp(peer) => self.on_neighbor_up(peer),
            InEvent::NeighborDown(peer) => self.on_neighbor_down(peer),
            InEvent::PeerDisconnected(peer) => self.on_neighbor_down(peer),
            InEvent::TimerExpired(timer) => match timer {
                Timer::DispatchLazyPush => self.on_dispatch_timer(io),
                Timer::SendGraft(id) => {
                    self.on_send_graft_timer(id, io);
                }
            },
        }
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    fn handle_message(&mut self, sender: PA, message: Message, io: &mut impl IO<PA>) {
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
    fn on_dispatch_timer(&mut self, io: &mut impl IO<PA>) {
        for (peer, list) in self.lazy_push_queue.drain() {
            io.push(OutEvent::SendMessage(peer, Message::IHave(list)));
        }

        self.dispatch_timer_scheduled = false;
    }

    /// Send a gossip message.
    /// Will be pushed in full to eager peers.
    /// Pushing the message ids to the lazy peers is delayed by a timer.
    fn do_broadcast(&mut self, data: Bytes, io: &mut impl IO<PA>) {
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

    fn on_gossip(&mut self, sender: PA, message: Gossip, io: &mut impl IO<PA>) {
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
            io.push(OutEvent::EmitEvent(Event::Received(message.content)));

            self.stats.max_last_delivery_hop =
                self.stats.max_last_delivery_hop.max(message.round.0);
        }
    }

    fn optimize_tree(
        &mut self,
        sender: &PA,
        message: &Gossip,
        previous_ihaves: VecDeque<(PA, Round)>,
        io: &mut impl IO<PA>,
    ) {
        let round = message.round;
        let best_ihave = previous_ihaves
            .iter()
            .min_by(|(_froma, ra), (_fromb, rb)| ra.cmp(rb))
            .copied();

        if let Some((ihave_node, ihave_round)) = best_ihave {
            if (ihave_round < round) && (round - ihave_round) >= self.config.optimization_threshold
            {
                let message = Message::Graft(Graft {
                    id: None,
                    round: ihave_round,
                });
                io.push(OutEvent::SendMessage(ihave_node, message));
                io.push(OutEvent::SendMessage(*sender, Message::Prune));
            }
        }
    }

    fn on_prune(&mut self, sender: PA) {
        self.add_lazy(sender);
    }

    // "When a node receives a IHAVE message, it simply marks the corresponding message as missing
    // It then starts a timer, with a predefined timeout value, and waits for the missing message to be
    // received via eager push before the timer expires. The timeout value is a protocol parameter
    // that should be configured considering the diameter of the overlay and a target maximum recovery latency, defined
    // by the application requirements. This is a parameter that should be statically configured at deployment time." (p8)
    fn on_ihave(&mut self, sender: PA, ihaves: Vec<IHave>, io: &mut impl IO<PA>) {
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

    fn on_send_graft_timer(&mut self, id: MessageId, io: &mut impl IO<PA>) {
        if self.received_messages.contains(&id) {
            return;
        }
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

    fn on_graft(&mut self, sender: PA, details: Graft, io: &mut impl IO<PA>) {
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

    fn on_neighbor_up(&mut self, peer: PA) {
        self.add_eager(peer);
    }

    // "When a neighbor is detected to leave the overlay, it is simple removed from the membership.
    // Furthermore, the record of IHAVE messages sent from failed members is deleted from the missing history" (p9)
    fn on_neighbor_down(&mut self, peer: PA) {
        self.missing_messages.retain(|_message_id, ihaves| {
            ihaves.retain(|(ihave_peer, _round)| *ihave_peer != peer);
            !ihaves.is_empty()
        });
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.remove(&peer);
    }

    /// Moves peer into eager set.
    fn add_eager(&mut self, peer: PA) {
        self.eager_push_peers.insert(peer);
        self.lazy_push_peers.remove(&peer);
    }

    /// Moves peer into lazy set.
    fn add_lazy(&mut self, peer: PA) {
        self.eager_push_peers.remove(&peer);
        self.lazy_push_peers.insert(peer);
    }

    /// Immediatelly sends message to eager peers.
    fn eager_push(&mut self, gossip: Gossip, sender: &PA, io: &mut impl IO<PA>) {
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
    fn lazy_push(&mut self, gossip: Gossip, sender: &PA, io: &mut impl IO<PA>) {
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
            io.push(OutEvent::EmitEvent(Event::Received(content)));
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
            io.push(OutEvent::EmitEvent(Event::Received(content)));
            io
        };
        assert_eq!(io, expected);
    }
}
