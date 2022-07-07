//! Implements handling of
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashSet, VecDeque};
use std::task::{Context, Poll};

use bytes::Bytes;
use cid::Cid;
use iroh_metrics::bitswap::Metrics;
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::handler::OneShotHandler;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use prometheus_client::registry::Registry;
use tracing::{debug, instrument, trace, warn};

use crate::message::{BitswapMessage, Priority};
use crate::protocol::{BitswapProtocol, Upgrade};
use crate::query::{QueryId, QueryManager};
use crate::session::{Config as SessionConfig, SessionManager};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitswapEvent {
    OutboundQueryCompleted { id: QueryId, result: QueryResult },
    InboundRequest { request: InboundRequest },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum QueryResult {
    Want(WantResult),
    Send(SendResult),
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
    metrics: Metrics,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct BitswapConfig {
    pub session: SessionConfig,
}

impl Bitswap {
    /// Create a new `Bitswap`.
    pub fn new(config: BitswapConfig, registry: &mut Registry) -> Self {
        let sessions = SessionManager::new(config.session.clone());
        Bitswap {
            config,
            sessions,
            metrics: Metrics::new(registry),
            ..Default::default()
        }
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

        self.metrics.providers_total.inc_by(providers.len() as u64);
        self.queries
            .want(cid, priority, providers.into_iter().collect())
    }

    #[instrument(skip(self))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) -> QueryId {
        debug!("send_block: {}", cid);

        self.metrics.sent_block_bytes.inc_by(data.len() as u64);
        self.sessions.create_session(peer_id);
        self.queries.send(*peer_id, cid, data)
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, cid: &Cid) -> Option<QueryId> {
        debug!("cancel_block: {}", cid);
        self.queries.cancel(cid)
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
        if other_established == 0 {
            self.sessions.new_connection(peer_id);
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
        if remaining_established == 0 {
            self.sessions.disconnected(peer_id);
            self.queries.disconnected(peer_id);
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
        }
    }

    #[instrument(skip(self))]
    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        match message {
            HandlerEvent::Upgrade => {
                // outbound upgrade
            }
            HandlerEvent::Bitswap(mut message) => {
                self.metrics.requests_total.inc();

                // Process incoming message.
                while let Some(block) = message.pop_block() {
                    self.metrics
                        .received_block_bytes
                        .inc_by(block.data().len() as u64);

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

                // TODO: cancel Query::Send

                // Propagate Cancel Events
                for cid in message.wantlist().cancels() {
                    self.metrics.canceled_total.inc();
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

        let peer1 = async move {
            while swarm1.next().now_or_never().is_some() {}

            for l in Swarm::listeners(&swarm1) {
                tx.send(l.clone()).await.unwrap();
            }

            loop {
                match swarm1.next().await {
                    Some(SwarmEvent::Behaviour(BitswapEvent::InboundRequest {
                        request: InboundRequest::Want { sender, cid, .. },
                    })) => {
                        if cid == cid_orig {
                            swarm1
                                .behaviour_mut()
                                .send_block(&sender, cid_orig, data_orig.clone());
                        }
                    }
                    ev => trace!("peer1: {:?}", ev),
                }
            }
        };

        let peer2 = async move {
            Swarm::dial(&mut swarm2, rx.next().await.unwrap()).unwrap();
            let orig_id =
                swarm2
                    .behaviour_mut()
                    .want_block(cid, 1000, [peer1_id].into_iter().collect());
            let orig_cid = cid;
            loop {
                match swarm2.next().await {
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        id,
                        result: QueryResult::Want(WantResult::Ok { sender, cid, data }),
                    })) => {
                        assert_eq!(orig_id, id);
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
        assert_eq!(&block[..], b"hello world");
    }
}
