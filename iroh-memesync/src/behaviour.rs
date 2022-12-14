//! Implements handling of
//! - `/ipfs/memesync/1.0.0`.

use std::collections::VecDeque;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use cid::Cid;
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters,
};
use tracing::{debug, trace, warn};

use crate::handler::{Handler, HandlerConfig, HandlerEvent};
use crate::store::Store;
use crate::{Query, QueryId, Request};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemesyncEvent {
    OutboundQueryProgress {
        id: QueryId,
        index: u32,
        last: bool,
        data: Bytes,
        links: Vec<(Option<String>, Cid)>,
        cid: Cid,
    },
    OutboundQueryFailed {
        id: QueryId,
        reason: Reason,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reason {
    NoProvidersLeft,
    Timeout,
    InvalidResponse,
}

/// Network behaviour that handles sending and receiving IPFS blocks.
pub struct Memesync<S: Store> {
    /// Queue of events to report to the user.
    events: VecDeque<NetworkBehaviourAction<MemesyncEvent, Handler<S>>>,
    #[allow(dead_code)]
    config: Config,
    store: S,
    queries: AHashMap<QueryId, QueryState>,
    query_id: u64,
    connections: AHashMap<PeerId, AHashSet<ConnectionId>>,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Config {}

impl<S: Store> Memesync<S> {
    /// Create a new `Memesync`.
    pub fn new(store: S, config: Config) -> Self {
        Memesync {
            config,
            events: Default::default(),
            store,
            queries: Default::default(),
            query_id: 0,
            connections: Default::default(),
        }
    }

    /// Request the given block from the list of providers.
    pub fn get(&mut self, query: Query, providers: Vec<(PeerId, Vec<Multiaddr>)>) -> QueryId {
        debug!("get: {:?}", query);

        if let Some((query_id, _)) = self
            .queries
            .iter()
            .find(|(_, query_state)| query_state.query == query)
        {
            return *query_id;
        }

        let query_id = self.next_query_id();

        // Optimization for queries to already connected peers
        let active_peer = if let Some((provider, _)) = providers.first() {
            if let Some(conns) = self.connections.get(provider) {
                Some((
                    *provider,
                    QueryPeerState::Connected(*conns.iter().next().unwrap()),
                ))
            } else {
                None
            }
        } else {
            None
        };

        self.queries.insert(
            query_id,
            QueryState {
                query,
                providers,
                start: Instant::now(),
                active_peer,
            },
        );

        query_id
    }

    fn next_query_id(&mut self) -> QueryId {
        let query_id = QueryId::from(self.query_id);
        self.query_id += 1;
        query_id
    }

    /// Cancel the given query.
    pub fn cancel_query(&mut self, id: QueryId) {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueryState {
    /// The query being worked on.
    query: Query,
    /// Peers that we expect this content to be providing.
    providers: Vec<(PeerId, Vec<Multiaddr>)>,
    /// When this query started.
    start: Instant,
    /// Current active peer.
    active_peer: Option<(PeerId, QueryPeerState)>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum QueryPeerState {
    New,
    Dialing,
    Connected(ConnectionId),
    RequestSent { outstanding_queries: usize },
}

impl<S: Store> NetworkBehaviour for Memesync<S> {
    type ConnectionHandler = Handler<S>;
    type OutEvent = MemesyncEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        Handler::new(
            self.store.clone(),
            HandlerConfig {
                keep_alive_timeout: Duration::from_secs(60),
                outbound_substream_timeout: Duration::from_secs(10),
                max_dial_negotiated: 8,
            },
        )
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Default::default()
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        self.connections
            .entry(*peer_id)
            .or_default()
            .insert(*connection_id);

        if other_established == 0 {
            for query_state in self.queries.values_mut() {
                if let Some((peer, ref mut query_peer_state)) = query_state.active_peer {
                    if peer == *peer_id && matches!(*query_peer_state, QueryPeerState::Dialing) {
                        *query_peer_state = QueryPeerState::Connected(*connection_id);
                    }
                }
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
        if let Some(conns) = self.connections.get_mut(peer_id) {
            conns.remove(connection_id);
            if conns.is_empty() {
                self.connections.remove(peer_id);
            }
        }

        if remaining_established == 0 {
            self.connections.remove(peer_id);
        }
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        dial_error: &DialError,
    ) {
        if let Some(ref peer_id) = peer_id {
            trace!("failed to dial {}: {:?}", peer_id, dial_error);

            self.connections.remove(peer_id);

            for query_state in self.queries.values_mut() {
                if let Some((ref peer, ref mut query_peer_state)) = query_state.active_peer {
                    if *peer == *peer_id && matches!(*query_peer_state, QueryPeerState::Dialing) {
                        query_state.active_peer = None;
                    }
                }
            }
        }
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        match message {
            HandlerEvent::Upgrade => {
                // outbound upgrade
            }
            HandlerEvent::RequestFailed { request, err } => {}
            HandlerEvent::ResponseError { id } => {
                warn!("invalid response received from {}", peer_id);
                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                    MemesyncEvent::OutboundQueryFailed {
                        id,
                        reason: Reason::InvalidResponse,
                    },
                ));
            }
            HandlerEvent::ResponseProgress {
                id,
                index,
                last,
                data,
                links,
                cid,
            } => {
                trace!("incoming response from {}", peer_id);
                if let Some(query_state) = self.queries.get_mut(&id) {
                    if let Some((query_peer_id, query_peer_state)) = &mut query_state.active_peer {
                        if *query_peer_id == peer_id {
                            if let QueryPeerState::RequestSent {
                                outstanding_queries,
                            } = query_peer_state
                            {
                                // got the answer matching our request

                                if last {
                                    *outstanding_queries -= 1;
                                }

                                // remove query it is done
                                if *outstanding_queries == 0 {
                                    self.queries.remove(&id);
                                }

                                // emit event with the result
                                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                                    MemesyncEvent::OutboundQueryProgress {
                                        id,
                                        index,
                                        last,
                                        data,
                                        links,
                                        cid,
                                    },
                                ));
                            } else {
                                warn!(
                                    "received query response in invalid state: {:?}",
                                    query_peer_state
                                );
                            }
                        } else {
                            warn!(
                                "received query ({:?}) response from {} but expected {}",
                                id, peer_id, query_peer_id
                            );
                        }
                    } else {
                        warn!(
                            "received unknown query response {:?} from {} (no active peer)",
                            id, peer_id,
                        );
                    }
                } else {
                    warn!(
                        "received unknown query response {:?} from {} (unkown query)",
                        id, peer_id
                    );
                }
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn poll(
        &mut self,
        _cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        // TODO: limit?
        let mut to_remove = Vec::new();
        let mut event = None;
        for (query_id, query_state) in &mut self.queries {
            match query_state.active_peer {
                None => {
                    // Dial the first one
                    if let Some((peer_id, addrs)) = query_state.providers.pop() {
                        trace!("[{:?}] dialing {}", query_id, peer_id);

                        if let Some(conns) = self.connections.get(&peer_id) {
                            // already connected
                            let conn_id = *conns.iter().next().expect("should not be empty");
                            query_state.active_peer =
                                Some((peer_id, QueryPeerState::Connected(conn_id)));
                        } else {
                            query_state.active_peer = Some((peer_id, QueryPeerState::Dialing));
                            event = Some(Poll::Ready(NetworkBehaviourAction::Dial {
                                opts: DialOpts::peer_id(peer_id).addresses(addrs).build(),
                                handler: self.new_handler(),
                            }));
                            break;
                        }
                    } else {
                        // No providers left
                        to_remove.push(*query_id);
                        event = Some(Poll::Ready(NetworkBehaviourAction::GenerateEvent(
                            MemesyncEvent::OutboundQueryFailed {
                                id: *query_id,
                                reason: Reason::NoProvidersLeft,
                            },
                        )));
                        break;
                    }
                }
                Some((peer_id, ref mut query_peer_state)) => {
                    match query_peer_state {
                        QueryPeerState::Dialing | QueryPeerState::RequestSent { .. } => {
                            // TODO: check for timeout
                        }
                        QueryPeerState::Connected(conn_id) => {
                            trace!("[{:?}] sending request to {}", query_id, peer_id);
                            let conn_id = *conn_id;
                            *query_peer_state = QueryPeerState::RequestSent {
                                outstanding_queries: 1,
                            };
                            // Send message
                            event = Some(Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                                peer_id,
                                handler: libp2p::swarm::NotifyHandler::One(conn_id),
                                event: Request::from_query(*query_id, query_state.query.clone()),
                            }));
                            break;
                        }
                        QueryPeerState::New => {
                            // already handled above
                        }
                    }
                }
            }
        }

        for id in &to_remove {
            trace!("removing query: {:?}", id);
            self.queries.remove(id);
        }

        event.unwrap_or(Poll::Pending)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

    use bytes::Bytes;
    use cid::Cid;
    use futures::channel::mpsc;
    use futures::prelude::*;
    use libipld::prelude::*;
    use libp2p::core::muxing::StreamMuxerBox;
    use libp2p::core::transport::upgrade::Version;
    use libp2p::core::transport::Boxed;
    use libp2p::identity::Keypair;
    use libp2p::swarm::{SwarmBuilder, SwarmEvent};
    use libp2p::tcp::{tokio::Transport as TokioTcpTransport, Config as GenTcpConfig};
    use libp2p::yamux::YamuxConfig;
    use libp2p::{noise, PeerId, Swarm, Transport};
    use tracing::trace;
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    use super::*;
    use crate::block::tests::create_random_block_v1;
    use crate::block::Block;
    use crate::store::MemoryStore;
    use crate::Path;

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
    async fn test_memesync_behaviour() {
        tracing_subscriber::registry()
            .with(fmt::layer().pretty())
            .with(EnvFilter::from_default_env())
            .init();

        struct TestCase {
            name: &'static str,
            blocks: Vec<(Block, Vec<(String, Cid)>)>,
            expected_blocks: Vec<Bytes>,
            query: Query,
        }

        let block = create_random_block_v1();

        let ipld_child_1 = libipld::ipld!({
            "child": "is_cool",
            "number": 1,
        });
        let encoded_child_1 = libipld::cbor::DagCborCodec.encode(&ipld_child_1).unwrap();
        let block_child_1 =
            Block::from_v1_data(libipld::cbor::DagCborCodec.into(), &encoded_child_1);

        let ipld_child_2 = libipld::ipld!({
            "child": "is_cool",
            "number": 2,
        });
        let encoded_child_2 = libipld::cbor::DagCborCodec.encode(&ipld_child_2).unwrap();
        let block_child_2 =
            Block::from_v1_data(libipld::cbor::DagCborCodec.into(), &encoded_child_2);

        let ipld_child_2_1 = libipld::ipld!({
            "child": "is_nested",
            "number": "2_1",
            "next": *block_child_2.cid(),
        });
        let encoded_child_2_1 = libipld::cbor::DagCborCodec.encode(&ipld_child_2_1).unwrap();
        let block_child_2_1 =
            Block::from_v1_data(libipld::cbor::DagCborCodec.into(), &encoded_child_2_1);

        let ipld_root = libipld::ipld!({
            "hello": "world",
            "link": *block_child_1.cid(),
        });
        let encoded_root = libipld::cbor::DagCborCodec.encode(&ipld_root).unwrap();

        let ipld_two_children = libipld::ipld!({
            "hello": "world",
            "child1": *block_child_1.cid(),
            "child2": *block_child_2.cid(),
        });
        let encoded_two_children = libipld::cbor::DagCborCodec
            .encode(&ipld_two_children)
            .unwrap();
        let block_two_children =
            Block::from_v1_data(libipld::cbor::DagCborCodec.into(), &encoded_two_children);

        let ipld_two_one_children = libipld::ipld!({
            "hello": "world",
            "child2_1": *block_child_2_1.cid(),
            "child1": *block_child_1.cid(),
        });
        let encoded_two_one_children = libipld::cbor::DagCborCodec
            .encode(&ipld_two_one_children)
            .unwrap();
        let block_two_one_children = Block::from_v1_data(
            libipld::cbor::DagCborCodec.into(),
            &encoded_two_one_children,
        );

        let mut set = HashSet::new();
        libipld::cbor::DagCborCodec
            .references::<libipld::Ipld, _>(&encoded_root, &mut set)
            .unwrap();
        assert_eq!(set.len(), 1);

        let block_root = Block::from_v1_data(libipld::cbor::DagCborCodec.into(), &encoded_root);

        let cases = [
            // <root>
            TestCase {
                name: "single block",
                blocks: vec![(block.clone(), Vec::new())],
                expected_blocks: vec![block.data().clone()],
                query: Query::from_path((*block.cid()).into()),
            },
            // <root>/link
            TestCase {
                name: "<root>/link",
                blocks: vec![
                    (
                        block_root.clone(),
                        vec![("link".into(), *block_child_1.cid())],
                    ),
                    (block_child_1.clone(), vec![]),
                ],
                expected_blocks: vec![block_root.data().clone(), block_child_1.data().clone()],
                query: Query::from_path(Path::from(*block_root.cid()).join("link")),
            },
            // <root>/**
            TestCase {
                name: "<root>/** (single child)",
                blocks: vec![
                    (
                        block_root.clone(),
                        vec![("link".into(), *block_child_1.cid())],
                    ),
                    (block_child_1.clone(), vec![]),
                ],
                expected_blocks: vec![block_root.data().clone(), block_child_1.data().clone()],
                query: Query {
                    path: Path::from(*block_root.cid()),
                    recursion: crate::Recursion::Some {
                        depth: 1,
                        direction: crate::RecursionDirection::BreadthFirst,
                    },
                },
            },
            // <root>/** (two direct children)
            TestCase {
                name: "<root>/** (two direct children), limit: 1, breadth first",
                blocks: vec![
                    (
                        block_two_children.clone(),
                        vec![
                            ("child1".into(), *block_child_1.cid()),
                            ("child2".into(), *block_child_2.cid()),
                        ],
                    ),
                    (block_child_1.clone(), vec![]),
                    (block_child_2.clone(), vec![]),
                ],
                expected_blocks: vec![
                    block_two_children.data().clone(),
                    block_child_1.data().clone(),
                    block_child_2.data().clone(),
                ],
                query: Query {
                    path: Path::from(*block_two_children.cid()),
                    recursion: crate::Recursion::Some {
                        depth: 1,
                        direction: crate::RecursionDirection::BreadthFirst,
                    },
                },
            },
            TestCase {
                name: "<root>/** (two direct children, one nested child), limit: 2, breadth first",
                blocks: vec![
                    (
                        block_two_one_children.clone(),
                        vec![
                            ("child1".into(), *block_child_1.cid()), // links are sorted through cbor encoding..
                            ("child2_1".into(), *block_child_2_1.cid()),
                        ],
                    ),
                    (block_child_1.clone(), vec![]),
                    (
                        block_child_2_1.clone(),
                        vec![("next".into(), *block_child_2.cid())],
                    ),
                    (block_child_2.clone(), vec![]),
                ],
                expected_blocks: vec![
                    block_two_one_children.data().clone(),
                    block_child_1.data().clone(),
                    block_child_2_1.data().clone(),
                    block_child_2.data().clone(),
                ],
                query: Query {
                    path: Path::from(*block_two_one_children.cid()),
                    recursion: crate::Recursion::Some {
                        depth: 2,
                        direction: crate::RecursionDirection::BreadthFirst,
                    },
                },
            },
            TestCase {
                name: "<root>/** (two direct children, one nested child), limit: 1, breadth first",
                blocks: vec![
                    (
                        block_two_one_children.clone(),
                        vec![
                            ("child1".into(), *block_child_1.cid()),
                            ("child2_1".into(), *block_child_2_1.cid()),
                        ],
                    ),
                    (block_child_1.clone(), vec![]),
                    (
                        block_child_2_1.clone(),
                        vec![("next".into(), *block_child_2.cid())],
                    ),
                    (block_child_2.clone(), vec![]),
                ],
                expected_blocks: vec![
                    block_two_one_children.data().clone(),
                    block_child_1.data().clone(),
                    block_child_2_1.data().clone(),
                ],
                query: Query {
                    path: Path::from(*block_two_one_children.cid()),
                    recursion: crate::Recursion::Some {
                        depth: 1,
                        direction: crate::RecursionDirection::BreadthFirst,
                    },
                },
            },
        ];

        for case in cases {
            println!("---- {} ----", case.name);
            let (peer1_id, trans) = mk_transport();
            let store1 = MemoryStore::default();
            {
                let mut store = store1.write().await;
                for (block, links) in &case.blocks {
                    store.insert(*block.cid(), (block.data().clone(), links.to_vec()));
                }
            }
            let mut swarm1 = SwarmBuilder::with_tokio_executor(
                trans,
                Memesync::new(store1, Config::default()),
                peer1_id,
            )
            .build();

            let (peer2_id, trans) = mk_transport();
            let store2 = MemoryStore::default();
            let mut swarm2 = SwarmBuilder::with_tokio_executor(
                trans,
                Memesync::new(store2, Config::default()),
                peer2_id,
            )
            .build();

            let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);
            Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

            let peer1 = async move {
                while swarm1.next().now_or_never().is_some() {}

                for l in Swarm::listeners(&swarm1) {
                    tx.send(l.clone()).await.unwrap();
                }

                loop {
                    match swarm1.next().await {
                        Some(SwarmEvent::Behaviour(MemesyncEvent::OutboundQueryFailed {
                            id: _,
                            reason,
                        })) => {
                            panic!("peer1: query failed: {:?}", reason);
                        }
                        ev => trace!("peer1: {:?}", ev),
                    }
                }
            };

            let peer2 = async move {
                let addr_peer1 = rx.next().await.unwrap();
                let orig_id = swarm2.behaviour_mut().get(
                    case.query,
                    [(peer1_id, vec![addr_peer1])].into_iter().collect(),
                );

                let mut responses = Vec::new();
                loop {
                    match swarm2.next().await {
                        Some(SwarmEvent::Behaviour(MemesyncEvent::OutboundQueryFailed {
                            id: _,
                            reason,
                        })) => {
                            panic!("peer2: query failed: {:?}", reason);
                        }
                        Some(SwarmEvent::Behaviour(MemesyncEvent::OutboundQueryProgress {
                            id,
                            last,
                            data,
                            ..
                        })) => {
                            assert_eq!(orig_id, id);
                            responses.push(data);
                            if last {
                                break;
                            }
                        }
                        Some(SwarmEvent::Behaviour(MemesyncEvent::OutboundQueryFailed {
                            id,
                            reason,
                        })) => {
                            panic!("unexpected error {:?}: {:?}", id, reason);
                        }
                        ev => trace!("peer2: {:?}", ev),
                    }
                }
                responses
            };

            let (responses, _): (Vec<_>, _) = future::select(Box::pin(peer1), Box::pin(peer2))
                .await
                .factor_first();

            let expected: Vec<Bytes> = case.expected_blocks;
            let received: Vec<_> = responses.into_iter().collect();
            assert_eq!(expected, received, "{}", case.name);
        }
    }
}
