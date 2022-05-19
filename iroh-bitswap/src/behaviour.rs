//! Implements handling of
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashSet, VecDeque};
use std::num::NonZeroU8;
use std::task::{Context, Poll};

use ahash::AHashMap;
use bytes::Bytes;
use cid::Cid;
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::handler::OneShotHandler;
use libp2p::swarm::{
    IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use tracing::{debug, instrument, trace, warn};

use crate::message::{BitswapMessage, Priority};
use crate::protocol::BitswapProtocol;
use crate::query::{Query, QueryState};
use crate::Block;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitswapEvent {
    ReceivedBlock(PeerId, Cid, Bytes),
    ReceivedWant(PeerId, Cid, Priority),
    ReceivedCancel(PeerId, Cid),
}

type BitswapHandler = OneShotHandler<BitswapProtocol, BitswapMessage, HandlerEvent>;

/// Network behaviour that handles sending and receiving IPFS blocks.
#[derive(Default)]
pub struct Bitswap {
    /// Queue of events to report to the user.
    events: VecDeque<NetworkBehaviourAction<BitswapEvent, BitswapHandler>>,
    // TODO: limit size
    queries: VecDeque<Query>,
    // TODO: limit size
    sessions: AHashMap<PeerId, Session>,
    config: BitswapConfig,
}

#[derive(Debug)]
enum Session {
    /// Connected, but not used in a query.
    Available,
    /// Requested in a query, but not connected.
    New(usize),
    Dialing(usize),
    Connected(usize),
    // Disconnected will be removed from the list
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitswapConfig {
    /// Limit of how many providers are concurrently dialed.
    dial_concurrency_factor_providers: NonZeroU8,
    /// Limit of how many dials are done per provider peer.
    dial_concurrency_factor_peer: NonZeroU8,
}

impl Default for BitswapConfig {
    fn default() -> Self {
        BitswapConfig {
            dial_concurrency_factor_providers: 32.try_into().unwrap(),
            dial_concurrency_factor_peer: 32.try_into().unwrap(),
        }
    }
}

impl Bitswap {
    /// Create a new `Bitswap`.
    pub fn new(config: BitswapConfig) -> Self {
        Bitswap {
            config,
            ..Default::default()
        }
    }

    /// Request the given block from the list of providers.
    #[instrument(skip(self))]
    pub fn want_block<'a>(&mut self, cid: Cid, priority: Priority, providers: HashSet<PeerId>) {
        debug!("want_block: {}", cid);
        for provider in providers.iter() {
            self.create_session(provider);
        }

        self.queries.push_back(Query::Get {
            providers: providers.into_iter().collect(),
            cid,
            priority,
            state: QueryState::New,
        });
    }

    #[instrument(skip(self))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) {
        self.create_session(peer_id);

        self.queries.push_back(Query::Send {
            receiver: *peer_id,
            block: Block { cid, data },
            state: QueryState::New,
        });
    }

    fn create_session(&mut self, peer_id: &PeerId) {
        let session = self.sessions.entry(*peer_id).or_insert(Session::New(1));
        match session {
            Session::Available => {
                // already connected
                trace!("already connected to {}", peer_id);
                *session = Session::Connected(1);
            }
            Session::Connected(count) => {
                *count += 1;
            }
            _ => {}
        }
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, cid: &Cid) {
        debug!("cancel_block: {}", cid);
        let mut cancels = VecDeque::new();
        self.queries.retain(|query| match query {
            Query::Get {
                providers: _,
                cid: c,
                priority: _,
                state,
            } => {
                let to_remove = cid == c;
                if to_remove {
                    if let QueryState::Sent(providers) = state {
                        // send out cancels to the providers
                        cancels.push_back(Query::Cancel {
                            providers: providers.clone(),
                            cid: *cid,
                            state: QueryState::New,
                        });
                    }
                }
                !to_remove
            }
            Query::Cancel { .. } => true,
            Query::Send { .. } => true,
        });

        self.queries.extend(cancels);
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HandlerEvent {
    Void,
    Bitswap(BitswapMessage),
}

impl From<()> for HandlerEvent {
    fn from(_: ()) -> Self {
        HandlerEvent::Void
    }
}

impl From<BitswapMessage> for HandlerEvent {
    fn from(msg: BitswapMessage) -> Self {
        HandlerEvent::Bitswap(msg)
    }
}

impl NetworkBehaviour for Bitswap {
    type ConnectionHandler = BitswapHandler;
    type OutEvent = BitswapEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        Default::default()
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Default::default()
    }

    #[instrument(skip(self))]
    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        let session = self.sessions.entry(*peer_id).or_insert(Session::Available);
        match session {
            Session::Dialing(count) | Session::New(count) => {
                *session = Session::Connected(*count);
            }
            _ => {}
        }
    }

    #[instrument(skip(self, _handler))]
    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        _conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
        if remaining_established > 0 {
            return;
        }
        self.sessions.remove(peer_id);
    }

    #[instrument(skip(self))]
    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        match message {
            HandlerEvent::Void => {}
            HandlerEvent::Bitswap(mut message) => {
                // Process incoming message.
                let mut cancels = VecDeque::new();
                while let Some(block) = message.pop_block() {
                    let mut wanted_block = false;
                    self.queries.retain(|query| {
                        match query {
                            Query::Get {
                                providers,
                                cid,
                                priority: _,
                                state,
                            } => {
                                if &block.cid == cid {
                                    wanted_block = true;
                                    for provider in providers {
                                        destroy_session(&mut self.sessions, provider);
                                    }

                                    if let QueryState::Sent(providers) = state {
                                        // send out cancels to the providers
                                        let mut providers = providers.clone();
                                        providers.remove(&peer_id);
                                        if !providers.is_empty() {
                                            cancels.push_back(Query::Cancel {
                                                providers,
                                                cid: block.cid,
                                                state: QueryState::New,
                                            });
                                        }
                                    }
                                    false
                                } else {
                                    true
                                }
                            }
                            Query::Cancel { .. } => true,
                            Query::Send { .. } => true,
                        }
                    });
                    if wanted_block {
                        let event = BitswapEvent::ReceivedBlock(peer_id, block.cid, block.data);
                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }
                }

                self.queries.extend(cancels);

                // Propagate Want Events
                for (cid, priority) in message.wantlist().blocks() {
                    let event = BitswapEvent::ReceivedWant(peer_id, *cid, priority);
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
                }

                // TODO: cancle Query::Send

                // Propagate Cancel Events
                for cid in message.wantlist().cancels() {
                    let event = BitswapEvent::ReceivedCancel(peer_id, *cid);
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        _: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        // process sessions

        // limit parallel dials
        let skip_dialing = current_dials(&self.sessions)
            >= self.config.dial_concurrency_factor_providers.get() as _;

        for (peer_id, session) in &mut self.sessions {
            match session {
                Session::New(count) => {
                    if skip_dialing {
                        // no dialing this round
                        continue;
                    }
                    trace!("Dialing {}", peer_id);
                    let handler = Self::ConnectionHandler::default();
                    *session = Session::Dialing(*count);
                    return Poll::Ready(NetworkBehaviourAction::Dial {
                        opts: DialOpts::peer_id(*peer_id)
                            .condition(PeerCondition::Always)
                            .override_dial_concurrency_factor(
                                self.config.dial_concurrency_factor_peer,
                            )
                            .build(),
                        handler,
                    });
                }
                Session::Dialing(_) | Session::Available => {
                    // Nothing to do yet
                }
                Session::Connected(_) => {
                    if self.queries.is_empty() {
                        *session = Session::Available;
                        continue;
                    }

                    // Aggregate all queries for this peer
                    let mut msg = BitswapMessage::default();

                    trace!(
                        "connected {}, looking for queries: {}",
                        peer_id,
                        self.queries.len()
                    );
                    let mut provider_has_queries = false;
                    for query in self.queries.iter_mut().filter(|query| match query {
                        Query::Get { providers, .. } | Query::Cancel { providers, .. } => {
                            providers.contains(peer_id)
                        }
                        Query::Send { receiver, .. } => receiver == peer_id,
                    }) {
                        provider_has_queries = true;
                        match query {
                            Query::Get {
                                providers,
                                cid,
                                priority,
                                state,
                            } => {
                                msg.wantlist_mut().want_block(cid, *priority);

                                providers.remove(peer_id);

                                // update state
                                match state {
                                    QueryState::New => {
                                        *state = QueryState::Sent([*peer_id].into_iter().collect());
                                    }
                                    QueryState::Sent(sent_providers) => {
                                        sent_providers.insert(*peer_id);
                                    }
                                }
                            }
                            Query::Cancel {
                                providers,
                                cid,
                                state,
                            } => {
                                msg.wantlist_mut().cancel_block(cid);

                                providers.remove(peer_id);

                                // update state
                                match state {
                                    QueryState::New => {
                                        *state = QueryState::Sent([*peer_id].into_iter().collect());
                                    }
                                    QueryState::Sent(sent_providers) => {
                                        sent_providers.insert(*peer_id);
                                    }
                                }
                            }
                            Query::Send {
                                block,
                                state,
                                receiver,
                            } => match state {
                                QueryState::New => {
                                    msg.add_block(block.clone());
                                    *state = QueryState::Sent([*receiver].into_iter().collect());
                                }
                                QueryState::Sent(_) => {}
                            },
                        }
                    }

                    if provider_has_queries && msg.is_empty() {
                        warn!("created invalid message: {:?}", msg);
                    }

                    if !provider_has_queries {
                        *session = Session::Available;
                    } else if !msg.is_empty() {
                        trace!("sending message to {} {:?}", peer_id, msg,);
                        return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                            peer_id: *peer_id,
                            handler: NotifyHandler::Any,
                            event: msg,
                        });
                    }
                }
            }
        }
        Poll::Pending
    }
}

fn current_dials(sessions: &AHashMap<PeerId, Session>) -> usize {
    sessions
        .values()
        .filter(|s| matches!(s, Session::Dialing(_)))
        .count()
}

fn destroy_session(sessions: &mut AHashMap<PeerId, Session>, peer_id: &PeerId) {
    if let Some(session) = sessions.get_mut(peer_id) {
        match session {
            Session::Connected(count) | Session::New(count) | Session::Dialing(count) => {
                *count -= 1;
                if *count == 0 {
                    *session = Session::Available;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

    use futures::channel::mpsc;
    use futures::prelude::*;
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::transport::upgrade::Version;
    use libp2p::core::transport::Boxed;
    use libp2p::identity::Keypair;
    use libp2p::swarm::{SwarmBuilder, SwarmEvent};
    use libp2p::tcp::TokioTcpConfig;
    use libp2p::yamux::YamuxConfig;
    use libp2p::{noise, PeerId, Swarm, Transport};
    use tracing::trace;

    use super::*;
    use crate::block::tests::create_block;
    use crate::Block;

    fn mk_transport() -> (PeerId, Boxed<(PeerId, StreamMuxerBox)>) {
        let local_key = Keypair::generate_ed25519();

        let auth_config = {
            let dh_keys = noise::Keypair::<noise::X25519Spec>::new()
                .into_authentic(&local_key)
                .expect("Noise key generation failed");

            noise::NoiseConfig::xx(dh_keys).into_authenticated()
        };

        let peer_id = local_key.public().to_peer_id();
        let transport = TokioTcpConfig::new()
            .nodelay(true)
            .upgrade(Version::V1)
            .authenticate(auth_config)
            .multiplex(YamuxConfig::default())
            .timeout(Duration::from_secs(20))
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
            .map_err(|err| Error::new(ErrorKind::Other, err))
            .boxed();
        (peer_id, transport)
    }

    #[tokio::test]
    async fn test_bitswap_behaviour() {
        env_logger::init();

        let (peer1_id, trans) = mk_transport();
        let mut swarm1 = SwarmBuilder::new(trans, Bitswap::default(), peer1_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        let (peer2_id, trans) = mk_transport();
        let mut swarm2 = SwarmBuilder::new(trans, Bitswap::default(), peer2_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);
        Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

        let Block {
            cid: cid_orig,
            data: data_orig,
        } = create_block(&b"hello world"[..]);
        let cid = cid_orig;

        let peer1 = async move {
            while swarm1.next().now_or_never().is_some() {}

            for l in Swarm::listeners(&swarm1) {
                tx.send(l.clone()).await.unwrap();
            }

            loop {
                match swarm1.next().await {
                    Some(SwarmEvent::Behaviour(BitswapEvent::ReceivedWant(peer_id, cid, _))) => {
                        if cid == cid_orig {
                            swarm1.behaviour_mut().send_block(
                                &peer_id,
                                cid_orig,
                                data_orig.clone(),
                            );
                        }
                    }
                    ev => trace!("peer1: {:?}", ev),
                }
            }
        };

        let peer2 = async move {
            Swarm::dial(&mut swarm2, rx.next().await.unwrap()).unwrap();
            swarm2
                .behaviour_mut()
                .want_block(cid, 1000, [peer1_id].into_iter().collect());

            loop {
                match swarm2.next().await {
                    Some(SwarmEvent::Behaviour(BitswapEvent::ReceivedBlock(_, _, data))) => {
                        return data
                    }
                    ev => trace!("peer2: {:?}", ev),
                }
            }
        };

        let block = future::select(Box::pin(peer1), Box::pin(peer2))
            .await
            .factor_first()
            .0;
        assert_eq!(&block[..], b"hello world");
    }
}
