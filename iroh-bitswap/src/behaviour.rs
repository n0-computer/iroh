//! Implements handling of
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use cid::Cid;
use futures::StreamExt;
use iroh_metrics::inc;
use iroh_metrics::{bitswap::BitswapMetrics, core::MRecorder, record};
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    DialError, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler,
    PollParameters,
};
use tracing::{debug, error, instrument, trace, warn};
use wasm_timer::Interval;

use crate::handler::{BitswapHandler, BitswapHandlerIn, HandlerEvent};
use crate::message::{BitswapMessage, BlockPresence, Priority};
use crate::protocol::ProtocolConfig;
use crate::{Block, ProtocolId};

const MAX_CONCURRENT_DIALS: usize = 50;
const MAX_PROVIDERS: usize = 100;
const MESSAGE_DELAY: Duration = Duration::from_millis(150);
const HEARTBEAT_DELAY: Duration = Duration::from_millis(100);

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
        ctx: Vec<u64>,
        sender: PeerId,
        cid: Cid,
        data: Bytes,
    },
    Err {
        ctx: Vec<u64>,
        cid: Cid,
        error: QueryError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum FindProvidersResult {
    Ok {
        ctx: Vec<u64>,
        cid: Cid,
        provider: PeerId,
    },
    Err {
        ctx: Vec<u64>,
        cid: Cid,
        error: QueryError,
    },
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
    known_peers: AHashMap<PeerId, Option<ProtocolId>>,
    /// Current ledgers.
    ledgers: AHashMap<PeerId, Ledger>,
    /// Index into connected peers.
    connected_peers: AHashMap<PeerId, ConnectionId>,
    /// List of peers to dial
    dial_peers: AHashSet<PeerId>,
    /// List of peers being dialed
    dialing_peers: AHashSet<PeerId>,
    wants: AHashMap<Cid, Want>,
    want_haves: AHashMap<Cid, WantHave>,
    connection_limit: bool,
    heartbeat: Interval,
    providers: AHashMap<Cid, AHashSet<PeerId>>,
    wants_for_peer: AHashMap<PeerId, AHashMap<Cid, Want>>,
    want_haves_for_peer: AHashMap<PeerId, AHashMap<Cid, WantHave>>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct Want {
    ctx: Vec<u64>,
    priority: Priority,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct WantHave {
    ctx: Vec<u64>,
    priority: Priority,
}

#[derive(Debug)]
struct Ledger {
    msg: BitswapMessage,
    last_send: Instant,
    conn: ConnState,
    ctx_wants: AHashMap<Cid, Vec<u64>>,
    ctx_want_haves: AHashMap<Cid, Vec<u64>>,
    full: bool,
}

impl Ledger {
    fn new() -> Self {
        // default to full for the first one
        let mut msg = BitswapMessage::default();
        msg.wantlist_mut().set_full(true);

        Ledger {
            msg,
            last_send: Instant::now(),
            conn: ConnState::Disconnected,
            ctx_wants: Default::default(),
            ctx_want_haves: Default::default(),
            full: true,
        }
    }

    fn poll_timer(&mut self, cx: &mut Context) -> Poll<()> {
        if self.last_send.elapsed() < MESSAGE_DELAY {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(())
    }

    fn has_blocks(&self) -> bool {
        !self.msg.blocks().is_empty() || !self.msg.block_presences().is_empty()
    }

    fn send_message(mut self: Pin<&mut Self>) -> BitswapMessage {
        let full = if self.full {
            self.full = false;
            true
        } else {
            false
        };

        self.msg.wantlist_mut().set_full(full);
        self.last_send = Instant::now();

        // some cleanup
        self.ctx_wants.retain(|_, c| !c.is_empty());
        self.ctx_want_haves.retain(|_, c| !c.is_empty());

        let new_msg = BitswapMessage::default();
        std::mem::replace(&mut self.msg, new_msg)
    }

    fn send_block(&mut self, cid: Cid, data: Bytes) {
        self.msg.add_block(Block { cid, data });
    }

    fn send_have_block(&mut self, cid: Cid) {
        self.msg.add_block_presence(BlockPresence::have(cid));
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum ConnState {
    Connected(Option<ProtocolId>, ConnectionId),
    Disconnected,
    Dialing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitswapConfig {
    pub max_cached_peers: usize,
    pub max_ledgers: usize,
    pub idle_timeout: Duration,
    pub protocol_config: ProtocolConfig,
}

impl Default for BitswapConfig {
    fn default() -> Self {
        BitswapConfig {
            max_cached_peers: 20_000,
            max_ledgers: 1024,
            idle_timeout: Duration::from_secs(30),
            protocol_config: ProtocolConfig::default(),
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
        Bitswap {
            config,
            known_peers: Default::default(),
            ledgers: Default::default(),
            connected_peers: Default::default(),
            dialing_peers: Default::default(),
            dial_peers: Default::default(),
            events: Default::default(),
            wants: Default::default(),
            want_haves: Default::default(),
            connection_limit: false,
            heartbeat: Interval::new(HEARTBEAT_DELAY),
            providers: Default::default(),
            wants_for_peer: Default::default(),
            want_haves_for_peer: Default::default(),
        }
    }

    pub fn supported_protocols(&self) -> &[ProtocolId] {
        &self.config.protocol_config.protocol_ids
    }

    /// Notifies about a peer that speaks the bitswap protocol.
    pub fn add_peer(&mut self, peer: PeerId, protocol: Option<ProtocolId>) {
        self.known_peers.insert(peer, protocol);
        inc!(BitswapMetrics::KnownPeers);
    }

    /// Adds a peer to the known_peers list, with the provided state.
    fn with_ledger<F, T>(&mut self, peer: PeerId, f: F) -> T
    where
        F: FnOnce(&mut Ledger) -> T,
    {
        if let Some(state) = self.ledgers.get_mut(&peer) {
            f(state)
        } else {
            let mut ledger = Ledger::new();
            let res = f(&mut ledger);
            self.ledgers.insert(peer, ledger);
            self.add_peer(peer, None);
            res
        }
    }

    /// Request the given block from the list of providers.
    #[instrument(skip(self))]
    pub fn want_block<'a>(
        &mut self,
        ctx: u64,
        cid: Cid,
        priority: Priority,
        providers: HashSet<PeerId>,
    ) {
        debug!("context:{} want_block: {}", ctx, cid);
        inc!(BitswapMetrics::WantedBlocks);
        record!(BitswapMetrics::Providers, providers.len() as u64);

        let entry = self.wants.entry(cid).or_default();
        entry.ctx.push(ctx);
        entry.priority = priority;

        let entry = self.providers.entry(cid).or_default();
        for provider in providers.into_iter() {
            entry.insert(provider);
            let entry = self.wants_for_peer.entry(provider).or_default();
            let inner_entry = entry.entry(cid).or_default();
            inner_entry.ctx.push(ctx);
            inner_entry.priority = priority;
            if !self.connected_peers.contains_key(&provider) {
                self.dial_peers.insert(provider);
            }
        }
    }

    #[instrument(skip(self, data))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) {
        debug!("send_block: {}", cid);

        record!(BitswapMetrics::BlockBytesOut, data.len() as u64);
        if !self.connected_peers.contains_key(peer_id) {
            self.dial_peers.insert(*peer_id);
        }
        self.with_ledger(*peer_id, |state| {
            state.send_block(cid, data);
        });
    }

    #[instrument(skip(self))]
    pub fn send_have_block(&mut self, peer_id: &PeerId, cid: Cid) {
        debug!("send_have_block: {}", cid);

        if !self.connected_peers.contains_key(peer_id) {
            self.dial_peers.insert(*peer_id);
        }

        self.with_ledger(*peer_id, |state| {
            state.send_have_block(cid);
        });
    }

    #[instrument(skip(self))]
    pub fn find_providers(&mut self, ctx: u64, cid: Cid, priority: Priority) {
        debug!("context:{} find_providers: {}", ctx, cid);
        inc!(BitswapMetrics::WantHaveBlocks);

        // TODO: better strategies, than just all peers.
        // TODO: use peers that connect later

        let mut peers: AHashSet<PeerId> = self.connected_peers.keys().take(500).copied().collect();

        for peer in self.known_peers.iter().filter_map(|(key, value)| {
            // Only supported on 1.2.0
            if value == &None || value == &Some(ProtocolId::Bitswap120) {
                return Some(key);
            }
            None
        }) {
            if peers.len() >= MAX_PROVIDERS {
                break;
            }
            peers.insert(*peer);
        }

        let entry = self.want_haves.entry(cid).or_default();
        entry.ctx.push(ctx);
        entry.priority = priority;

        for peer in peers {
            let entry = self.want_haves_for_peer.entry(peer).or_default();
            let inner_entry = entry.entry(cid).or_default();
            inner_entry.ctx.push(ctx);
            inner_entry.priority = priority;

            if !self.connected_peers.contains_key(&peer) {
                self.dial_peers.insert(peer);
            }
        }
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, ctx: u64, cid: &Cid) {
        inc!(BitswapMetrics::CancelBlocks);

        debug!("context:{} cancel_block: {}", ctx, cid);
        let mut remove = false;
        if let Some(wants) = self.wants.get_mut(cid) {
            if let Some(i) = wants.ctx.iter().position(|x| *x == ctx) {
                wants.ctx.remove(i);
                if wants.ctx.is_empty() {
                    remove = true;
                }
            }
        }
        // clear out empty
        if remove {
            self.wants.remove(cid);
        }

        // TODO: send out cancels
    }

    #[instrument(skip(self))]
    pub fn cancel_want_block(&mut self, ctx: u64, cid: &Cid) {
        inc!(BitswapMetrics::CancelWantBlocks);

        debug!("cancel_want_block: {}", cid);
        let mut remove = false;
        if let Some(want_haves) = self.want_haves.get_mut(cid) {
            if let Some(i) = want_haves.ctx.iter().position(|x| *x == ctx) {
                want_haves.ctx.remove(i);
                if want_haves.ctx.is_empty() {
                    remove = true;
                }
            }
        }

        // clear out empty
        if remove {
            self.want_haves.remove(cid);
        }

        // TODO: send out cancels
    }
}

impl NetworkBehaviour for Bitswap {
    type ConnectionHandler = BitswapHandler;
    type OutEvent = BitswapEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        let protocol_config = self.config.protocol_config.clone();
        BitswapHandler::new(protocol_config, self.config.idle_timeout)
    }

    fn addresses_of_peer(&mut self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        Default::default()
    }

    #[instrument(skip(self))]
    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        conn: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        other_established: usize,
    ) {
        trace!("base connection to {}", peer_id);
        if other_established == 0 {
            inc!(BitswapMetrics::ConnectedPeers);
            self.add_peer(*peer_id, None);
            self.dialing_peers.remove(peer_id);
            self.dial_peers.remove(peer_id);
            self.connected_peers.insert(*peer_id, *conn);
            self.with_ledger(*peer_id, |state| {
                state.conn = ConnState::Connected(None, *conn);
            });
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
            self.connected_peers.remove(peer_id);
            self.dialing_peers.remove(peer_id);
            self.with_ledger(*peer_id, |state| {
                state.conn = ConnState::Disconnected;
            });
            self.connection_limit = false;
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
            self.dialing_peers.remove(peer_id);

            match error {
                DialError::ConnectionLimit(_) => {
                    self.connection_limit = true;
                    self.connected_peers.remove(peer_id);
                    self.with_ledger(*peer_id, |state| {
                        state.conn = ConnState::Disconnected;
                    });
                }
                DialError::DialPeerConditionFalse(_) => {}
                _ => {
                    trace!("dial failure {:?}: {:?}", peer_id, error);

                    // remove peers we can't dial
                    inc!(BitswapMetrics::ForgottenPeers);
                    self.known_peers.remove(peer_id);
                    self.ledgers.remove(peer_id);
                    self.connected_peers.remove(peer_id);
                    self.dial_peers.remove(peer_id);
                }
            }
        }
    }

    #[instrument(skip(self))]
    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, message: HandlerEvent) {
        match message {
            HandlerEvent::ProtocolNotSuppported => {
                inc!(BitswapMetrics::ForgottenPeers);
                self.known_peers.remove(&peer_id);
                self.ledgers.remove(&peer_id);
                self.connected_peers.remove(&peer_id);
                self.dial_peers.remove(&peer_id);
            }
            HandlerEvent::Connected { protocol } => {
                trace!("connected to {} with {:?}", peer_id, protocol);
                self.with_ledger(peer_id, |state| {
                    state.conn = ConnState::Connected(Some(protocol), connection);
                });
                self.known_peers.insert(peer_id, Some(protocol));
                self.connected_peers.insert(peer_id, connection);
            }
            HandlerEvent::Message { mut message } => {
                inc!(BitswapMetrics::MessagesReceived);
                inc!(BitswapMetrics::Requests);

                // Process incoming message.
                let mut cancel_wants = Vec::new();

                while let Some(block) = message.pop_block() {
                    record!(BitswapMetrics::BlockBytesIn, block.data.len() as u64);
                    inc!(BitswapMetrics::CancelBlocks);

                    let now = Instant::now();
                    let is_valid = iroh_util::verify_hash(&block.cid, &block.data);
                    trace!("block validated in {}ms", now.elapsed().as_millis());
                    match is_valid {
                        Some(true) => {
                            // all good
                        }
                        Some(false) => {
                            // TODO: maybe blacklist peer?
                            warn!("invalid block received");
                            continue;
                        }
                        None => {
                            warn!("unknown hash function {}", block.cid.hash().code());
                        }
                    }

                    cancel_wants.push(block.cid);
                    if let Some(wants) = self.wants.remove(&block.cid) {
                        let event = BitswapEvent::OutboundQueryCompleted {
                            result: QueryResult::Want(WantResult::Ok {
                                ctx: wants.ctx,
                                sender: peer_id,
                                cid: block.cid,
                                data: block.data.clone(),
                            }),
                        };

                        inc!(BitswapMetrics::EventsBackpressureIn);
                        self.events
                            .push_back(NetworkBehaviourAction::GenerateEvent(event));
                    }
                }

                for cid in
                    cancel_wants
                        .into_iter()
                        .chain(message.block_presences().iter().filter_map(|bp| {
                            if bp.is_have() {
                                Some(bp.cid)
                            } else {
                                None
                            }
                        }))
                {
                    inc!(BitswapMetrics::CancelWantBlocks);
                    if let Some(want_haves) = self.want_haves.remove(&cid) {
                        let event = BitswapEvent::OutboundQueryCompleted {
                            result: QueryResult::FindProviders(FindProvidersResult::Ok {
                                ctx: want_haves.ctx,
                                cid,
                                provider: peer_id,
                            }),
                        };
                        inc!(BitswapMetrics::EventsBackpressureIn);
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
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        trace!("tick");
        if let Some(event) = self.events.pop_front() {
            inc!(BitswapMetrics::EventsBackpressureOut);
            return Poll::Ready(event);
        }

        while let Poll::Ready(_) = self.heartbeat.poll_next_unpin(cx) {
            trace!("tick:heartbeat");

            for (peer_id, conn_id) in &self.connected_peers {
                match self.ledgers.get_mut(peer_id) {
                    Some(peer_state) => match peer_state.poll_timer(cx) {
                        Poll::Ready(()) => {
                            trace!("tick:timer:{}", peer_id);
                            // Do we have any blocks for this peer, or do we have any wants for this peer?
                            let wants = self.wants_for_peer.remove(peer_id);
                            let want_haves = self.want_haves_for_peer.remove(peer_id);
                            if peer_state.has_blocks() || wants.is_some() || want_haves.is_some() {
                                let mut bs_msg = Pin::new(peer_state).send_message();
                                let wantlist = bs_msg.wantlist_mut();
                                if let Some(wants) = wants {
                                    for (cid, want) in wants {
                                        wantlist.want_block(&cid, want.priority);
                                    }
                                }

                                if let Some(want_haves) = want_haves {
                                    for (cid, want_have) in want_haves {
                                        wantlist.want_have_block(&cid, want_have.priority);
                                    }
                                }

                                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                                    peer_id: *peer_id,
                                    handler: NotifyHandler::One(*conn_id),
                                    event: BitswapHandlerIn::Message(bs_msg),
                                });
                            }
                        }
                        Poll::Pending => {
                            continue;
                        }
                    },
                    None => {
                        error!("missing ledger state for connected peer: {}", peer_id);
                    }
                }
            }

            // Nothing to do on connected peers, establish new connections
            if !self.connection_limit && self.dialing_peers.len() < MAX_CONCURRENT_DIALS {
                for peer_id in &self.dial_peers {
                    if !self.ledgers.contains_key(peer_id) {
                        self.ledgers.insert(*peer_id, Ledger::new());
                    }
                    let peer_state = self.ledgers.get_mut(peer_id).unwrap();

                    inc!(BitswapMetrics::AttemptedDials);
                    trace!("dialing {}", peer_id);
                    let peer_id = *peer_id;
                    self.dialing_peers.insert(peer_id);
                    self.dial_peers.remove(&peer_id);
                    peer_state.conn = ConnState::Dialing;
                    let handler = BitswapHandler::new(
                        self.config.protocol_config.clone(),
                        self.config.idle_timeout,
                    );

                    return Poll::Ready(NetworkBehaviourAction::Dial {
                        opts: DialOpts::peer_id(peer_id).build(),
                        handler,
                    });
                }
            }
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
    use crate::block::tests::*;
    use crate::{Block, ProtocolId};

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
                tokio::task::spawn(fut);
            }))
            .build();

        let (peer2_id, trans) = mk_transport();
        let mut swarm2 = SwarmBuilder::new(trans, Bitswap::default(), peer2_id)
            .executor(Box::new(|fut| {
                tokio::task::spawn(fut);
            }))
            .build();

        let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);
        Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

        let Block {
            cid: cid_orig,
            data: data_orig,
        } = create_block_v1(&b"hello world"[..]);
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

            let find_ctx = 0;
            let want_ctx = 1;
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
                        swarm2.behaviour_mut().find_providers(find_ctx, cid, 1000);
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        result:
                            QueryResult::FindProviders(FindProvidersResult::Ok { ctx, cid, provider }),
                    })) => {
                        trace!("peer2: findproviders: {}", cid);
                        assert_eq!(orig_cid, cid);
                        assert_eq!(vec![find_ctx], ctx);
                        assert_eq!(provider, peer1_id);

                        assert!(received_have.load(std::sync::atomic::Ordering::SeqCst));

                        swarm2.behaviour_mut().want_block(
                            want_ctx,
                            cid,
                            1000,
                            [peer1_id].into_iter().collect(),
                        );
                    }
                    Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                        result:
                            QueryResult::Want(WantResult::Ok {
                                ctx,
                                sender,
                                cid,
                                data,
                            }),
                    })) => {
                        assert_eq!(vec![want_ctx], ctx);
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

    #[tokio::test]
    async fn test_bitswap_multiprotocol() {
        // tracing_subscriber::registry()
        //     .with(fmt::layer().pretty())
        //     .with(EnvFilter::from_default_env())
        //     .init();

        #[derive(Debug)]
        struct TestCase {
            peer1_protocols: Vec<ProtocolId>,
            peer2_protocols: Vec<ProtocolId>,
            expected_protocol: ProtocolId,
        }

        let tests = [
            // All with only, 1.2.0
            TestCase {
                peer1_protocols: vec![ProtocolId::Bitswap120],
                peer2_protocols: vec![ProtocolId::Bitswap120],
                expected_protocol: ProtocolId::Bitswap120,
            },
            // Prefer 1.2.0 over others
            TestCase {
                peer1_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                ],
                peer2_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                ],
                expected_protocol: ProtocolId::Bitswap120,
            },
            // Prefer 1.1.0 over others
            TestCase {
                peer1_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                ],
                peer2_protocols: vec![ProtocolId::Bitswap110, ProtocolId::Bitswap100],
                expected_protocol: ProtocolId::Bitswap110,
            },
            // Fallback
            TestCase {
                peer1_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                ],
                peer2_protocols: vec![ProtocolId::Bitswap100],
                expected_protocol: ProtocolId::Bitswap100,
            },
            // Fallback
            TestCase {
                peer1_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                ],
                peer2_protocols: vec![ProtocolId::Bitswap120],
                expected_protocol: ProtocolId::Bitswap120,
            },
            // Fallback
            TestCase {
                peer1_protocols: vec![
                    ProtocolId::Bitswap120,
                    ProtocolId::Bitswap110,
                    ProtocolId::Bitswap100,
                    ProtocolId::Legacy,
                ],
                peer2_protocols: vec![ProtocolId::Legacy],
                expected_protocol: ProtocolId::Legacy,
            },
        ];

        for case in tests {
            println!("case: {:?}", case);
            let expected_protocol = case.expected_protocol;
            let supports_providers = expected_protocol == ProtocolId::Bitswap120;

            let peer1_config = BitswapConfig {
                protocol_config: ProtocolConfig {
                    protocol_ids: case.peer1_protocols.clone(),
                    ..Default::default()
                },
                ..Default::default()
            };
            let (peer1_id, trans) = mk_transport();
            let mut swarm1 = SwarmBuilder::new(trans, Bitswap::new(peer1_config), peer1_id)
                .executor(Box::new(|fut| {
                    tokio::task::spawn(fut);
                }))
                .build();

            let peer2_config = BitswapConfig {
                protocol_config: ProtocolConfig {
                    protocol_ids: case.peer2_protocols.clone(),
                    ..Default::default()
                },
                ..Default::default()
            };
            let (peer2_id, trans) = mk_transport();
            let mut swarm2 = SwarmBuilder::new(trans, Bitswap::new(peer2_config), peer2_id)
                .executor(Box::new(|fut| {
                    tokio::task::spawn(fut);
                }))
                .build();

            let (mut tx, mut rx) = mpsc::channel::<Multiaddr>(1);
            Swarm::listen_on(&mut swarm1, "/ip4/127.0.0.1/tcp/0".parse().unwrap()).unwrap();

            let Block {
                cid: cid_orig,
                data: data_orig,
            } = {
                match expected_protocol {
                    ProtocolId::Legacy | ProtocolId::Bitswap100 => {
                        create_block_v0(&b"hello world"[..])
                    }
                    _ => create_block_v1(&b"hello world"[..]),
                }
            };
            let cid = cid_orig;

            let received_have_orig = AtomicBool::new(!supports_providers);

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
                            match swarm1.behaviour_mut().ledgers.get(&peer2_id).unwrap().conn {
                                ConnState::Connected(Some(p), _) => {
                                    assert_eq!(p, expected_protocol);
                                }
                                other => {
                                    panic!("invalid state: {:?}", other);
                                }
                            }

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

                            // wait for the connection

                            if supports_providers {
                                swarm2.behaviour_mut().find_providers(0, cid, 1000);
                            } else {
                                swarm2.behaviour_mut().want_block(
                                    0,
                                    cid,
                                    1000,
                                    [peer1_id].into_iter().collect(),
                                );
                            }
                        }
                        Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                            result:
                                QueryResult::FindProviders(FindProvidersResult::Ok {
                                    ctx: _,
                                    cid,
                                    provider,
                                }),
                        })) => {
                            assert!(
                                supports_providers,
                                "must not be executed when providers are not supported"
                            );
                            match swarm2.behaviour_mut().ledgers.get(&peer1_id).unwrap().conn {
                                ConnState::Connected(Some(p), _) => {
                                    assert_eq!(p, expected_protocol);
                                }
                                other => {
                                    panic!("invalid state: {:?}", other);
                                }
                            }

                            trace!("peer2: findproviders: {}", cid);
                            assert_eq!(orig_cid, cid);

                            assert_eq!(provider, peer1_id);

                            assert!(received_have.load(std::sync::atomic::Ordering::SeqCst));

                            swarm2.behaviour_mut().want_block(
                                0,
                                cid,
                                1000,
                                [peer1_id].into_iter().collect(),
                            );
                        }
                        Some(SwarmEvent::Behaviour(BitswapEvent::OutboundQueryCompleted {
                            result:
                                QueryResult::Want(WantResult::Ok {
                                    ctx: _,
                                    sender,
                                    cid,
                                    data,
                                }),
                        })) => {
                            match swarm2.behaviour_mut().ledgers.get(&peer1_id).unwrap().conn {
                                ConnState::Connected(Some(p), _) => {
                                    assert_eq!(p, expected_protocol);
                                }
                                other => {
                                    panic!("invalid state: {:?}", other);
                                }
                            }

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
}
