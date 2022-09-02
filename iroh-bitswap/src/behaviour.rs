//! Implements handling of
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashSet, VecDeque};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use caches::{Cache, PutResult};
use cid::Cid;
use iroh_metrics::inc;
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, record};
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use tracing::{debug, instrument, trace, warn};

use crate::handler::{BitswapHandler, BitswapHandlerIn, HandlerEvent};
use crate::message::{BitswapMessage, BlockPresence, Priority};
use crate::protocol::ProtocolConfig;
use crate::Block;

const MAX_PROVIDERS: usize = 10000; // yolo

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitswapEvent {
    OutboundQueryCompleted { result: QueryResult },
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
    Err {
        cid: Cid,
        error: QueryError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum FindProvidersResult {
    Ok { cid: Cid, provider: PeerId },
    Err { cid: Cid, error: QueryError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendHaveResult {
    Ok(Cid),
    Err { cid: Cid, error: QueryError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SendResult {
    Ok(Cid),
    Err { cid: Cid, error: QueryError },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancelResult {
    Ok(Cid),
    Err { cid: Cid, error: QueryError },
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

/// Network behaviour that handles sending and receiving IPFS blocks.
pub struct Bitswap {
    /// Queue of events to report to the user.
    events: VecDeque<NetworkBehaviourAction<BitswapEvent, BitswapHandler>>,
    #[allow(dead_code)]
    config: BitswapConfig,
    /// Peers we know about that we can talk bitswap to.
    known_peers: caches::RawLRU<PeerId, ()>,
    /// Current ledgers.
    ledgers: caches::RawLRU<PeerId, Ledger>,
    /// Current connections.
    connections: caches::RawLRU<PeerId, ConnState>,
}

#[derive(Debug, Clone, PartialEq)]
struct Ledger {
    msg: BitswapMessage,
}

impl Ledger {
    fn is_empty(&self) -> bool {
        self.msg.is_empty()
    }

    fn has_blocks(&self) -> bool {
        !self.msg.blocks().is_empty()
    }

    fn send_message(&mut self) -> BitswapMessage {
        std::mem::take(&mut self.msg)
    }

    fn want_block(&mut self, cid: &Cid, priority: Priority) {
        self.msg.wantlist_mut().want_block(cid, priority);
    }

    fn cancel_block(&mut self, cid: &Cid) {
        self.msg.wantlist_mut().cancel_block(cid);
    }

    fn remove_block(&mut self, cid: &Cid) {
        self.msg.wantlist_mut().remove_block(cid);
    }

    fn send_block(&mut self, cid: Cid, data: Bytes) {
        self.msg.add_block(Block { cid, data });
    }

    fn want_have_block(&mut self, cid: &Cid, priority: Priority) {
        self.msg.wantlist_mut().want_have_block(cid, priority);
    }

    fn remove_want_block(&mut self, cid: &Cid) {
        self.msg.wantlist_mut().remove_want_block(cid);
    }

    fn send_have_block(&mut self, cid: Cid) {
        self.msg.add_block_presence(BlockPresence::have(cid));
    }
}

impl Default for Ledger {
    fn default() -> Self {
        // default to full for the first one
        let mut msg = BitswapMessage::default();
        msg.wantlist_mut().set_full(true);

        Ledger { msg }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum ConnState {
    Connected,
    Disconnected,
    Dialing,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BitswapConfig {
    pub max_cached_peers: usize,
    pub max_ledgers: usize,
    pub idle_timeout: Duration,
}

impl Default for BitswapConfig {
    fn default() -> Self {
        BitswapConfig {
            max_cached_peers: 20_000,
            max_ledgers: 1024,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

impl Default for Bitswap {
    fn default() -> Self {
        Self::new(BitswapConfig::default())
    }
}

impl Bitswap {
    /// Create a new `Bitswap`.
    pub fn new(config: BitswapConfig) -> Self {
        let known_peers = caches::RawLRU::new(config.max_cached_peers).unwrap();
        let ledgers = caches::RawLRU::new(config.max_ledgers).unwrap();
        let connections = caches::RawLRU::new(config.max_cached_peers).unwrap();

        Bitswap {
            config,
            known_peers,
            ledgers,
            connections,
            events: Default::default(),
        }
    }

    /// Notifies about a peer that speaks the bitswap protocol.
    pub fn add_peer(&mut self, peer: PeerId) {
        if let PutResult::Put = self.known_peers.put(peer, ()) {
            inc!(BitswapMetrics::KnownPeers);
        }
    }

    /// Checks if the given peer is currently connected.
    #[allow(clippy::wrong_self_convention)]
    fn is_connected(&mut self, peer_id: &PeerId) -> bool {
        self.connections
            .get(peer_id)
            .map(|s| matches!(s, ConnState::Connected))
            .unwrap_or_default()
    }

    /// Adds a peer to the known_peers list, with the provided state.
    fn with_ledger<F, T>(&mut self, peer: PeerId, f: F) -> T
    where
        F: FnOnce(&mut Ledger) -> T,
    {
        if let Some(state) = self.ledgers.get_mut(&peer) {
            f(state)
        } else {
            let mut ledger = Ledger::default();
            let res = f(&mut ledger);
            self.ledgers.put(peer, ledger);
            res
        }
    }

    /// Request the given block from the list of providers.
    #[instrument(skip(self))]
    pub fn want_block<'a>(&mut self, cid: Cid, priority: Priority, providers: HashSet<PeerId>) {
        debug!("want_block: {}", cid);
        inc!(BitswapMetrics::WantedBlocks);
        record!(BitswapMetrics::Providers, providers.len() as u64);
        for provider in providers.iter() {
            self.with_ledger(*provider, |state| {
                state.want_block(&cid, priority);
            });
        }

        record!(BitswapMetrics::Providers, providers.len() as u64);
    }

    #[instrument(skip(self, data))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) {
        debug!("send_block: {}", cid);

        record!(BitswapMetrics::BlockBytesOut, data.len() as u64);

        self.with_ledger(*peer_id, |state| {
            state.send_block(cid, data);
        });
    }

    #[instrument(skip(self))]
    pub fn send_have_block(&mut self, peer_id: &PeerId, cid: Cid) {
        debug!("send_have_block: {}", cid);

        self.with_ledger(*peer_id, |state| {
            state.send_have_block(cid);
        });
    }

    #[instrument(skip(self))]
    pub fn find_providers(&mut self, cid: Cid, priority: Priority) {
        debug!("find_providers: {}", cid);
        inc!(BitswapMetrics::WantHaveBlocks);

        // TODO: better strategies, than just all peers.
        // TODO: use peers that connect later

        let providers: Vec<_> = self
            .known_peers
            .keys()
            .take(MAX_PROVIDERS)
            .copied()
            .collect();
        for provider in providers {
            self.with_ledger(provider, |peer| {
                peer.want_have_block(&cid, priority);
            });
        }
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, cid: &Cid) {
        inc!(BitswapMetrics::CancelBlocks);

        debug!("cancel_block: {}", cid);
        for state in self.ledgers.values_mut() {
            state.cancel_block(cid);
        }
    }

    #[instrument(skip(self))]
    pub fn cancel_want_block(&mut self, cid: &Cid) {
        inc!(BitswapMetrics::CancelWantBlocks);

        debug!("cancel_block: {}", cid);
        for state in self.ledgers.values_mut() {
            state.remove_want_block(cid);
        }
    }
}

impl NetworkBehaviour for Bitswap {
    type ConnectionHandler = BitswapHandler;
    type OutEvent = BitswapEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        let protocol_config = ProtocolConfig::default();
        BitswapHandler::new(protocol_config, self.config.idle_timeout)
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
            inc!(BitswapMetrics::ConnectedPeers);
            self.add_peer(*peer_id);
            self.connections.put(*peer_id, ConnState::Connected);

            let msg = self.with_ledger(*peer_id, |state| {
                if !state.is_empty() {
                    // queue up message to be sent as soon as we are connected
                    return Some(NetworkBehaviourAction::NotifyHandler {
                        peer_id: *peer_id,
                        handler: NotifyHandler::Any,
                        event: BitswapHandlerIn::Message(state.send_message()),
                    });
                }

                None
            });

            if let Some(msg) = msg {
                inc!(BitswapMetrics::MessagesSent);
                inc!(BitswapMetrics::EventsBackpressureIn);
                self.events.push_back(msg);
            }
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
            inc!(BitswapMetrics::DisconnectedPeers);
            self.connections.put(*peer_id, ConnState::Disconnected);
        }
    }

    #[instrument(skip(self, _handler))]
    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &DialError,
    ) {
        if let Some(ref peer_id) = peer_id {
            inc!(BitswapMetrics::DisconnectedPeers);

            match error {
                DialError::ConnectionLimit(_) => {
                    // we can retry later
                    self.connections.put(*peer_id, ConnState::Disconnected);
                }
                _ => {
                    trace!("dial failure {:?}: {:?}", peer_id, error);

                    // remove peers we can't dial
                    inc!(BitswapMetrics::ForgottenPeers);
                    self.known_peers.remove(peer_id);
                    self.ledgers.remove(peer_id);
                    self.connections.remove(peer_id);
                }
            }
        }
    }

    #[instrument(skip(self))]
    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        inc!(BitswapMetrics::MessagesReceived);
        match message {
            HandlerEvent::Message { mut message } => {
                inc!(BitswapMetrics::Requests);

                // Process incoming message.
                while let Some(block) = message.pop_block() {
                    record!(BitswapMetrics::BlockBytesIn, block.data.len() as u64);

                    for (id, state) in self.ledgers.iter_mut() {
                        if id == &peer_id {
                            state.remove_block(&block.cid);
                        } else {
                            state.cancel_block(&block.cid);
                        }
                    }

                    let event = BitswapEvent::OutboundQueryCompleted {
                        result: QueryResult::Want(WantResult::Ok {
                            sender: peer_id,
                            cid: block.cid,
                            data: block.data.clone(),
                        }),
                    };

                    inc!(BitswapMetrics::EventsBackpressureIn);
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
                }

                for bp in message.block_presences() {
                    for (_, state) in self.ledgers.iter_mut() {
                        state.remove_want_block(&bp.cid);
                    }

                    let event = BitswapEvent::OutboundQueryCompleted {
                        result: QueryResult::FindProviders(FindProvidersResult::Ok {
                            cid: bp.cid,
                            provider: peer_id,
                        }),
                    };
                    inc!(BitswapMetrics::EventsBackpressureIn);
                    self.events
                        .push_back(NetworkBehaviourAction::GenerateEvent(event));
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
                    inc!(BitswapMetrics::EventsBackpressureIn);
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
                    inc!(BitswapMetrics::EventsBackpressureIn);
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

                    inc!(BitswapMetrics::EventsBackpressureIn);
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
            inc!(BitswapMetrics::EventsBackpressureOut);
            return Poll::Ready(event);
        }

        let mut msg = None;
        let mut to_remove = None;

        for (peer_id, peer_state) in self.ledgers.iter_mut() {
            // make progress on connected peers first, that have wants
            if self.is_connected(peer_id) {
                if peer_state.has_blocks() {
                    inc!(BitswapMetrics::PollActionConnectedWants);
                    // connected, send message
                    // TODO: limit size
                    // TODO: limit how ofen we send

                    trace!("sending message to {}", peer_id);
                    msg = Some(Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id: *peer_id,
                        handler: NotifyHandler::Any,
                        event: BitswapHandlerIn::Message(peer_state.send_message()),
                    }));
                    to_remove = Some(*peer_id);
                    break;
                }

                // make progress on connected peers that have no wants
                if !peer_state.is_empty() {
                    inc!(BitswapMetrics::PollActionConnected);
                    // connected, send message
                    // TODO: limit size
                    // TODO: limit how ofen we send

                    trace!("sending message to {}", peer_id);
                    msg = Some(Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id: *peer_id,
                        handler: NotifyHandler::Any,
                        event: BitswapHandlerIn::Message(peer_state.send_message()),
                    }));
                    to_remove = Some(*peer_id);
                    break;
                }
            } else if !peer_state.is_empty() {
                inc!(BitswapMetrics::PollActionNotConnected);
                // not connected, need to dial

                self.connections.put(*peer_id, ConnState::Dialing);
                let handler = self.new_handler();
                msg = Some(Poll::Ready(NetworkBehaviourAction::Dial {
                    opts: DialOpts::peer_id(*peer_id).build(),
                    handler,
                }));
                break;
            }
        }

        if let Some(to_remove) = to_remove {
            self.ledgers.remove(&to_remove);
        }

        if let Some(msg) = msg {
            return msg;
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
            let addr = rx.next().await.unwrap();
            trace!("peer2: dialing peer1 at {}", addr);
            Swarm::dial(&mut swarm2, addr).unwrap();

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
                        swarm2.behaviour_mut().find_providers(cid, 1000);
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        result:
                            QueryResult::FindProviders(FindProvidersResult::Ok { cid, provider }),
                    })) => {
                        trace!("peer2: findproviders: {}", cid);
                        assert_eq!(orig_cid, cid);

                        assert_eq!(provider, peer1_id);

                        assert!(received_have.load(std::sync::atomic::Ordering::SeqCst));

                        swarm2.behaviour_mut().want_block(
                            cid,
                            1000,
                            [peer1_id].into_iter().collect(),
                        );
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        result: QueryResult::Want(WantResult::Ok { sender, cid, data }),
                    })) => {
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
