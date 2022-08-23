//! Implements handling of
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::task::{Context, Poll};
use std::time::Duration;

use ahash::AHashSet;
use bytes::Bytes;
use cid::Cid;
use iroh_metrics::inc;
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, record};
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::handler::OneShotHandler;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
    OneShotHandlerConfig, PollParameters, SubstreamProtocol,
};
use tracing::{debug, instrument, trace, warn};

use crate::message::{BitswapMessage, Priority};
use crate::protocol::{BitswapProtocol, Upgrade};
use crate::query::{QueryId, QueryManager};
use crate::session::{Config as SessionConfig, SessionManager};

const MAX_PROVIDERS: usize = 10_000; // yolo

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitswapEvent {
    OutboundQueryCompleted { id: QueryId, result: QueryResult },
    InboundRequest { request: InboundRequest },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueryResult {
    Want(WantResult),
    FindProviders(FindProvidersResult),
    Send(SendResult),
    SendHave(SendHaveResult),
    Cancel(CancelResult),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum WantResult {
    Ok {
        sender: PeerId,
        cid: Cid,
        data: Bytes,
    },
    Err(QueryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum FindProvidersResult {
    Ok { cid: Cid, peers: AHashSet<PeerId> },
    Err(QueryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendHaveResult {
    Ok,
    Err(QueryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendResult {
    Ok,
    Err(QueryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelResult {
    Ok,
    Err(QueryError),
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub enum QueryError {
    #[error("timeout")]
    Timeout,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundRequest {
    Want {
        sender: PeerId,
        cid: Cid,
        priority: Priority,
    },
    WantHave {
        sender: PeerId,
        cid: Cid,
        priority: Priority,
    },
    Cancel {
        sender: PeerId,
        cid: Cid,
    },
}

pub type BitswapHandler = OneShotHandler<BitswapProtocol, BitswapMessage, HandlerEvent>;

/// Network behaviour that handles sending and receiving IPFS blocks.
#[derive(Default)]
pub struct Bitswap {
    /// Queue of events to report to the user.
    events: VecDeque<NetworkBehaviourAction<BitswapEvent, BitswapHandler>>,
    queries: QueryManager,
    sessions: SessionManager,
    #[allow(dead_code)]
    config: BitswapConfig,
    known_peers: HashMap<PeerId, PeerState>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum PeerState {
    Unknown,
    Connected,
    Disconnected,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct BitswapConfig {
    pub session: SessionConfig,
}

impl Bitswap {
    /// Create a new `Bitswap`.
    pub fn new(config: BitswapConfig) -> Self {
        let sessions = SessionManager::new(config.session.clone());
        Bitswap {
            config,
            sessions,
            ..Default::default()
        }
    }

    pub fn add_peer(&mut self, peer: PeerId) {
        self.known_peers.insert(peer, PeerState::Unknown);
    }

    /// Request the given block from the list of providers.
    #[instrument(skip(self))]
    pub fn want_block<'a>(
        &mut self,
        cid: Cid,
        priority: Priority,
        providers: HashSet<PeerId>,
    ) -> QueryId {
        debug!("want_block: {}", cid);
        for provider in providers.iter() {
            self.sessions.create_session(provider);
        }

        record!(BitswapMetrics::Providers, providers.len() as u64);
        self.queries
            .want(cid, priority, providers.into_iter().collect())
    }

    #[instrument(skip(self, data))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) -> QueryId {
        debug!("send_block: {}", cid);

        record!(BitswapMetrics::BlockBytesOut, data.len() as u64);
        self.sessions.create_session(peer_id);
        self.queries.send(*peer_id, cid, data)
    }

    #[instrument(skip(self))]
    pub fn send_have_block(&mut self, peer_id: &PeerId, cid: Cid) -> QueryId {
        debug!("send_have_block: {}", cid);

        self.sessions.create_session(peer_id);
        self.queries.send_have(*peer_id, cid)
    }

    #[instrument(skip(self))]
    pub fn find_providers(&mut self, cid: Cid, priority: Priority) -> QueryId {
        debug!("find_providers: {}", cid);

        // TODO: better strategies, than just all peers.
        // TODO: use peers that connect later
        let peers: AHashSet<_> = self
            .connected_peers()
            .map(|p| p.to_owned())
            .take(MAX_PROVIDERS)
            .collect();
        debug!("with peers: {:?}", &peers);
        for peer in peers.iter() {
            self.sessions.create_session(peer);
        }

        self.queries.find_providers(cid, priority, peers)
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, cid: &Cid) -> Option<QueryId> {
        debug!("cancel_block: {}", cid);
        self.queries.cancel(cid)
    }

    fn connected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.known_peers
            .iter()
            .filter_map(|(id, state)| match state {
                PeerState::Connected | PeerState::Unknown => Some(id),
                PeerState::Disconnected => None,
            })
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HandlerEvent {
    Upgrade,
    Bitswap(BitswapMessage),
}

impl From<Upgrade> for HandlerEvent {
    fn from(_: Upgrade) -> Self {
        HandlerEvent::Upgrade
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
        OneShotHandler::new(
            SubstreamProtocol::new(Default::default(), ()),
            OneShotHandlerConfig {
                keep_alive_timeout: Duration::from_secs(30),
                outbound_substream_timeout: Duration::from_secs(30),
                max_dial_negotiated: 64,
            },
        )
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
        if other_established == 0 {
            self.sessions.new_connection(peer_id);
        }
        let val = self
            .known_peers
            .entry(*peer_id)
            .or_insert(PeerState::Unknown);

        *val = PeerState::Connected;
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
        if remaining_established == 0 {
            self.sessions.disconnected(peer_id);
            self.queries.disconnected(peer_id);
            if let Some(val) = self.known_peers.get_mut(peer_id) {
                *val = PeerState::Disconnected;
            }
        }
    }

    #[instrument(skip(self, _handler))]
    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        _error: &DialError,
    ) {
        trace!("failed to dial");
        if let Some(ref peer_id) = peer_id {
            self.sessions.dial_failure(peer_id);
            self.queries.dial_failure(peer_id);

            // remove peers we can't dial
            self.known_peers.remove(peer_id);
        }
    }

    #[instrument(skip(self))]
    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        match message {
            HandlerEvent::Upgrade => {
                // outbound upgrade
            }
            HandlerEvent::Bitswap(mut message) => {
                inc!(BitswapMetrics::Requests);

                // Process incoming message.
                while let Some(block) = message.pop_block() {
                    record!(BitswapMetrics::BlockBytesIn, block.data.len() as u64);

                    let (unused_providers, query_ids) =
                        self.queries.process_block(&peer_id, &block);
                    for query_id in query_ids {
                        let event = BitswapEvent::OutboundQueryCompleted {
                            id: query_id,
                            result: QueryResult::Want(WantResult::Ok {
                                sender: peer_id,
                                cid: block.cid,
                                data: block.data.clone(),
                            }),
                        };

                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }
                    for provider in unused_providers {
                        self.sessions.destroy_session(&provider);
                    }
                }

                for bp in message.block_presences() {
                    let results = self.queries.process_block_presence(peer_id, bp);
                    for (query_id, peers) in results {
                        let event = BitswapEvent::OutboundQueryCompleted {
                            id: query_id,
                            result: QueryResult::FindProviders(FindProvidersResult::Ok {
                                cid: bp.cid,
                                peers,
                            }),
                        };

                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }
                }

                // Propagate Want Events
                for (cid, priority) in message.wantlist().blocks() {
                    let event = BitswapEvent::InboundRequest {
                        request: InboundRequest::Want {
                            sender: peer_id,
                            cid: *cid,
                            priority,
                        },
                    };
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
                }

                // Propagate WantHave Events
                for (cid, priority) in message.wantlist().want_have_blocks() {
                    let event = BitswapEvent::InboundRequest {
                        request: InboundRequest::WantHave {
                            sender: peer_id,
                            cid: *cid,
                            priority,
                        },
                    };
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
                }

                // TODO: cancel Query::Send

                // Propagate Cancel Events
                for cid in message.wantlist().cancels() {
                    inc!(BitswapMetrics::Cancels);
                    let event = BitswapEvent::InboundRequest {
                        request: InboundRequest::Cancel {
                            sender: peer_id,
                            cid: *cid,
                        },
                    };

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

        // process sessions & queries
        if let Some(action) = self.sessions.poll(&mut self.queries) {
            return Poll::Ready(action);
        }

        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use futures::channel::mpsc;
    use futures::prelude::*;
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::transport::upgrade::Version;
    use libp2p::core::transport::Boxed;
    use libp2p::identity::Keypair;
    use libp2p::swarm::{SwarmBuilder, SwarmEvent};
    use libp2p::tcp::{GenTcpConfig, TokioTcpTransport};
    use libp2p::yamux::YamuxConfig;
    use libp2p::{noise, PeerId, Swarm, Transport};
    use tracing::trace;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
        let transport = TokioTcpTransport::new(GenTcpConfig::default().nodelay(true))
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
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

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

        let received_have_orig = AtomicBool::new(false);

        let received_have = &received_have_orig;
        let peer1 = async move {
            while swarm1.next().now_or_never().is_some() {}

            for l in Swarm::listeners(&swarm1) {
                tx.send(l.clone()).await.unwrap();
            }

            loop {
                match swarm1.next().await {
                    Some(SwarmEvent::Behaviour(BitswapEvent::InboundRequest {
                        request:
                            InboundRequest::WantHave {
                                sender,
                                cid,
                                priority,
                            },
                    })) => {
                        trace!("peer1: wanthave: {}", cid);
                        assert_eq!(cid_orig, cid);
                        assert_eq!(priority, 1000);
                        swarm1.behaviour_mut().send_have_block(&sender, cid_orig);
                        received_have.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::InboundRequest {
                        request: InboundRequest::Want { sender, cid, .. },
                    })) => {
                        trace!("peer1: want: {}", cid);
                        assert_eq!(cid_orig, cid);

                        swarm1
                            .behaviour_mut()
                            .send_block(&sender, cid_orig, data_orig.clone());
                    }
                    ev => trace!("peer1: {:?}", ev),
                }
            }
        };

        let peer2 = async move {
            Swarm::dial(&mut swarm2, rx.next().await.unwrap()).unwrap();

            let mut want_id = None;
            let mut orig_id = None;
            let orig_cid = cid;
            loop {
                match swarm2.next().await {
                    Some(SwarmEvent::ConnectionEstablished {
                        peer_id,
                        num_established,
                        ..
                    }) => {
                        assert_eq!(u32::from(num_established), 1);
                        assert_eq!(peer_id, peer1_id);

                        // wait for the connection to send the want
                        want_id = Some(swarm2.behaviour_mut().find_providers(cid, 1000));
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        id,
                        result: QueryResult::FindProviders(FindProvidersResult::Ok { cid, peers }),
                    })) => {
                        trace!("peer2: findproviders: {}", cid);
                        assert_eq!(orig_cid, cid);
                        assert_eq!(peers.len(), 1);
                        assert_eq!(want_id.unwrap(), id);

                        assert!(peers.contains(&peer1_id));

                        assert!(received_have.load(std::sync::atomic::Ordering::SeqCst));

                        orig_id = Some(swarm2.behaviour_mut().want_block(
                            cid,
                            1000,
                            [peer1_id].into_iter().collect(),
                        ));
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        id,
                        result: QueryResult::Want(WantResult::Ok { sender, cid, data }),
                    })) => {
                        assert_eq!(orig_id.unwrap(), id);
                        assert_eq!(sender, peer1_id);
                        assert_eq!(orig_cid, cid);
                        return data;
                    }
                    ev => trace!("peer2: {:?}", ev),
                }
            }
        };

        let block = future::select(Box::pin(peer1), Box::pin(peer2))
            .await
            .factor_first()
            .0;

        assert!(received_have.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(&block[..], b"hello world");
    }
}
