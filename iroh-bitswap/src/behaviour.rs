//! Implements handling of
//! - `/ipfs/bitswap/1.0.0`,
//! - `/ipfs/bitswap/1.1.0` and
//! - `/ipfs/bitswap/1.2.0`.

use std::collections::{HashMap, VecDeque};
use std::task::{Context, Poll};

use ahash::{AHashMap, AHashSet};
use bytes::Bytes;
use cid::Cid;
use libp2p::core::connection::ConnectionId;
use libp2p::core::{ConnectedPoint, Multiaddr, PeerId};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::handler::OneShotHandler;
use libp2p::swarm::{
    IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
};
use tracing::{debug, instrument, trace};

use crate::block::Block;
use crate::ledger::Ledger;
use crate::message::{BitswapMessage, Priority};
use crate::protocol::BitswapConfig;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BitswapEvent {
    ReceivedBlock(PeerId, Cid, Bytes),
    ReceivedWant(PeerId, Cid, Priority),
    ReceivedCancel(PeerId, Cid),
}

/// Network behaviour that handles sending and receiving IPFS blocks.
#[derive(Default)]
pub struct Bitswap {
    /// Queue of events to report to the user.
    events: VecDeque<
        NetworkBehaviourAction<
            BitswapEvent,
            OneShotHandler<BitswapConfig, BitswapMessage, BitswapMessage>,
        >,
    >,
    /// List of peers to send messages to.
    target_peers: AHashSet<PeerId>,
    /// Ledger
    connected_peers: HashMap<PeerId, Ledger>,
    /// Wanted blocks
    wanted_blocks: AHashMap<Cid, Priority>,
}

impl Bitswap {
    /// Create a new `Bitswap`.
    pub fn new() -> Self {
        Default::default()
    }

    fn ledger(&mut self, peer_id: &PeerId) -> &mut Ledger {
        self.connected_peers.get_mut(peer_id).unwrap()
    }

    /// Connect to peer.
    ///
    /// Called from discovery protocols like mdns or kademlia.
    #[instrument(skip(self))]
    pub fn connect(&mut self, peer_id: PeerId) {
        if !self.target_peers.insert(peer_id) {
            return;
        }
        trace!("  queuing dial_peer to {}", peer_id.to_base58());
        let handler = self.new_handler();
        self.events.push_back(NetworkBehaviourAction::Dial {
            opts: DialOpts::peer_id(peer_id)
                .condition(PeerCondition::NotDialing)
                .build(),
            handler,
        });
    }

    /// Sends a block to the peer.
    ///
    /// Called from a Strategy.
    #[instrument(skip(self))]
    pub fn send_block(&mut self, peer_id: &PeerId, cid: Cid, data: Bytes) {
        self.ledger(peer_id).add_block(Block { cid, data });
    }

    /// Sends a block to all peers that sent a want.
    pub fn send_block_all(&mut self, cid: &Cid, data: Bytes) {
        let peers: Vec<_> = self.peers_want(cid).cloned().collect();
        for peer_id in &peers {
            self.send_block(peer_id, *cid, data.clone());
        }
    }

    /// Sends the wantlist to the peer.
    #[instrument(skip(self))]
    fn send_want_list(&mut self, peer_id: &PeerId) {
        debug!("sending wantlist to {}", peer_id);
        if self.wanted_blocks.is_empty() {
            return;
        }
        let ledger = self.connected_peers.get_mut(peer_id).unwrap();
        for (cid, priority) in &self.wanted_blocks {
            ledger.want(cid, *priority);
        }
    }

    /// Queues the wanted block for all peers.
    ///
    /// A user request
    #[instrument(skip(self))]
    pub async fn want_block(&mut self, cid: Cid, priority: Priority) {
        for (_peer_id, ledger) in self.connected_peers.iter_mut() {
            ledger.want(&cid, priority);
        }
        self.wanted_blocks.insert(cid, priority);
    }

    #[instrument(skip(self))]
    pub async fn want_blocks(&mut self, cids: Vec<Cid>, priority: Priority) {
        debug!(
            "want_blocks from {} peers: {:?}",
            self.connected_peers.len(),
            cids
        );
        for (_peer_id, ledger) in self.connected_peers.iter_mut() {
            ledger.want_many(&cids, priority);
        }
        for cid in cids.into_iter() {
            self.wanted_blocks.insert(cid, priority);
        }
    }

    /// Removes the block from our want list and updates all peers.
    ///
    /// Can be either a user request or be called when the block was received.
    #[instrument(skip(self))]
    pub fn cancel_block(&mut self, cid: &Cid) {
        for (_peer_id, ledger) in self.connected_peers.iter_mut() {
            ledger.cancel(cid);
        }
        self.wanted_blocks.remove(cid);
    }

    /// Retrieves the want list of a peer.
    pub fn wantlist(&self, peer_id: Option<&PeerId>) -> Vec<(Cid, Priority)> {
        if let Some(peer_id) = peer_id {
            self.connected_peers
                .get(peer_id)
                .map(|ledger| {
                    ledger
                        .wantlist()
                        .map(|(cid, priority)| (*cid, priority))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            self.wanted_blocks
                .iter()
                .map(|(cid, priority)| (*cid, *priority))
                .collect()
        }
    }

    /// Retrieves the connected bitswap peers.
    pub fn peers(&self) -> impl Iterator<Item = &PeerId> {
        self.connected_peers.iter().map(|(peer_id, _)| peer_id)
    }

    /// Retrieves the peers that want a block.
    pub fn peers_want<'a>(&'a self, cid: &'a Cid) -> impl Iterator<Item = &'a PeerId> {
        self.connected_peers
            .iter()
            .filter_map(move |(peer_id, ledger)| {
                if ledger.peer_wants(cid) {
                    Some(peer_id)
                } else {
                    None
                }
            })
    }
}

impl NetworkBehaviour for Bitswap {
    type ConnectionHandler = OneShotHandler<BitswapConfig, BitswapMessage, BitswapMessage>;
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
        debug!("connected {} ({})", peer_id, other_established);
        if other_established > 0 {
            return;
        }

        self.connected_peers.insert(*peer_id, Ledger::new());

        // only send wantlist if this is a new connection
        self.send_want_list(peer_id);
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
        debug!("disconnected {} ({})", peer_id, remaining_established);
        if remaining_established > 0 {
            return;
        }

        self.connected_peers.remove(peer_id);
    }

    #[instrument(skip(self))]
    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        mut message: BitswapMessage,
    ) {
        // Update the ledger.
        self.ledger(&peer_id).receive(&message);

        // Process incoming messages.
        while let Some(Block { cid, data }) = message.pop_block() {
            if !self.wanted_blocks.contains_key(&cid) {
                debug!("dropping block {}", cid.to_string());
                continue;
            }
            // Cancel the block.
            self.cancel_block(&cid);
            let event = BitswapEvent::ReceivedBlock(peer_id, cid, data);
            self.events
                .push_back(NetworkBehaviourAction::GenerateEvent(event));
        }
        for (cid, priority) in message.want() {
            let event = BitswapEvent::ReceivedWant(peer_id, *cid, priority);
            self.events
                .push_back(NetworkBehaviourAction::GenerateEvent(event));
        }
        for cid in message.cancel() {
            let event = BitswapEvent::ReceivedCancel(peer_id, *cid);
            self.events
                .push_back(NetworkBehaviourAction::GenerateEvent(event));
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
        for (peer_id, ledger) in &mut self.connected_peers {
            if let Some(message) = ledger.send() {
                return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                    peer_id: *peer_id,
                    handler: NotifyHandler::Any,
                    event: message,
                });
            }
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
    use libp2p::tcp::TokioTcpConfig;
    use libp2p::yamux::YamuxConfig;
    use libp2p::{noise, PeerId, Swarm, Transport};

    use super::*;
    use crate::block::tests::create_block;

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
        let mut swarm1 = SwarmBuilder::new(trans, Bitswap::new(), peer1_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        let (peer2_id, trans) = mk_transport();
        let mut swarm2 = SwarmBuilder::new(trans, Bitswap::new(), peer2_id)
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
            swarm2.behaviour_mut().want_block(cid, 1000).await;

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
