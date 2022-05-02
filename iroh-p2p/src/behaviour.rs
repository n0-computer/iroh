use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::config::Libp2pConfig;
use crate::discovery::{DiscoveryBehaviour, DiscoveryConfig, DiscoveryOut};
use bytes::Bytes;
use cid::Cid;
use futures::channel::oneshot;
use iroh_bitswap::{Bitswap, BitswapEvent, Priority};
use libp2p::core::identity::Keypair;
use libp2p::core::PeerId;
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::record::Key;
use libp2p::kad::QueryId;
use libp2p::ping::{Ping, PingEvent, PingFailure, PingSuccess};
use libp2p::request_response::RequestResponseConfig;
use libp2p::swarm::{
    NetworkBehaviour, NetworkBehaviourAction, NetworkBehaviourEventProcess, PollParameters,
};
use libp2p::{Multiaddr, NetworkBehaviour};
use tracing::{trace, warn};

lazy_static::lazy_static! {
    static ref VERSION: &'static str = env!("CARGO_PKG_VERSION");
}

/// Libp2p behaviour for the node.
#[derive(NetworkBehaviour)]
#[behaviour(
    out_event = "NodeBehaviourEvent",
    poll_method = "poll",
    event_process = true
)]
pub(crate) struct NodeBehaviour {
    discovery: DiscoveryBehaviour,
    ping: Ping,
    identify: Identify,
    bitswap: Bitswap,
    #[behaviour(ignore)]
    events: Vec<NodeBehaviourEvent>,
}

/// Event type which is emitted from the [NodeBehaviour] into the libp2p service.
#[derive(Debug)]
pub(crate) enum NodeBehaviourEvent {
    PeerConnected(PeerId),
    PeerDisconnected(PeerId),
    BitswapReceivedBlock(PeerId, Cid, Bytes),
    BitswapReceivedWant(PeerId, Cid),
}

impl NetworkBehaviourEventProcess<DiscoveryOut> for NodeBehaviour {
    fn inject_event(&mut self, event: DiscoveryOut) {
        match event {
            DiscoveryOut::Connected(peer) => {
                self.bitswap.connect(peer);
                self.events.push(NodeBehaviourEvent::PeerConnected(peer));
            }
            DiscoveryOut::Disconnected(peer) => {
                self.events.push(NodeBehaviourEvent::PeerDisconnected(peer));
            }
        }
    }
}

impl NetworkBehaviourEventProcess<BitswapEvent> for NodeBehaviour {
    fn inject_event(&mut self, event: BitswapEvent) {
        match event {
            BitswapEvent::ReceivedBlock(peer_id, cid, data) => {
                // The `cid` from this event has a different type
                let cid = cid.to_bytes();
                match Cid::try_from(cid) {
                    Ok(cid) => self
                        .events
                        .push(NodeBehaviourEvent::BitswapReceivedBlock(peer_id, cid, data)),
                    Err(e) => {
                        warn!("Fail to convert Cid: {}", e.to_string());
                    }
                }
            }
            BitswapEvent::ReceivedWant(peer_id, cid, _priority) => {
                // The `cid` from this event has a different type
                let cid = cid.to_bytes();
                match Cid::try_from(cid) {
                    Ok(cid) => self
                        .events
                        .push(NodeBehaviourEvent::BitswapReceivedWant(peer_id, cid)),
                    Err(e) => {
                        warn!("Fail to convert Cid: {}", e.to_string());
                    }
                }
            }
            BitswapEvent::ReceivedCancel(_peer_id, _cid) => {
                // TODO: Determine how to handle cancel
                trace!("BitswapEvent::ReceivedCancel, unimplemented");
            }
        }
    }
}

impl NetworkBehaviourEventProcess<PingEvent> for NodeBehaviour {
    fn inject_event(&mut self, event: PingEvent) {
        match event.result {
            Ok(PingSuccess::Ping { rtt }) => {
                trace!(
                    "PingSuccess::Ping rtt to {} is {} ms",
                    event.peer.to_base58(),
                    rtt.as_millis()
                );
            }
            Ok(PingSuccess::Pong) => {
                trace!("PingSuccess::Pong from {}", event.peer.to_base58());
            }
            Err(PingFailure::Timeout) => {
                trace!("PingFailure::Timeout {}", event.peer.to_base58());
            }
            Err(PingFailure::Other { error }) => {
                trace!("PingFailure::Other {}: {}", event.peer.to_base58(), error);
            }
            Err(PingFailure::Unsupported) => {
                trace!("PingFailure::Unsupported {}", event.peer.to_base58());
            }
        }
    }
}

impl NetworkBehaviourEventProcess<IdentifyEvent> for NodeBehaviour {
    fn inject_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, info } => {
                trace!("Identified Peer {}", peer_id);
                trace!("protocol_version {}", info.protocol_version);
                trace!("agent_version {}", info.agent_version);
                trace!("listening_ addresses {:?}", info.listen_addrs);
                trace!("observed_address {}", info.observed_addr);
                trace!("protocols {:?}", info.protocols);
            }
            IdentifyEvent::Sent { .. } => (),
            IdentifyEvent::Pushed { .. } => (),
            IdentifyEvent::Error { .. } => (),
        }
    }
}

impl NodeBehaviour {
    /// Consumes the events list when polled.
    fn poll(
        &mut self,
        _cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<
        NetworkBehaviourAction<
            <Self as NetworkBehaviour>::OutEvent,
            <Self as NetworkBehaviour>::ConnectionHandler,
        >,
    > {
        if !self.events.is_empty() {
            return Poll::Ready(NetworkBehaviourAction::GenerateEvent(self.events.remove(0)));
        }
        Poll::Pending
    }

    pub async fn new(local_key: &Keypair, config: &Libp2pConfig) -> Self {
        let bitswap = Bitswap::new();

        let mut discovery_config = DiscoveryConfig::new(local_key.public());
        discovery_config
            .with_mdns(config.mdns)
            .with_kademlia(config.kademlia)
            .with_user_defined(config.bootstrap_peers.clone())
            // TODO allow configuring this through config.
            .discovery_limit(config.target_peer_count as u64);

        let mut req_res_config = RequestResponseConfig::default();
        req_res_config.set_request_timeout(Duration::from_secs(20));
        req_res_config.set_connection_keep_alive(Duration::from_secs(20));

        NodeBehaviour {
            discovery: discovery_config.finish().await,
            ping: Ping::default(),
            identify: Identify::new(IdentifyConfig::new("ipfs/0.1.0".into(), local_key.public())),
            bitswap,
            events: vec![],
        }
    }

    /// Bootstrap Kademlia network
    pub fn bootstrap(&mut self) -> Result<QueryId, String> {
        self.discovery.bootstrap()
    }

    /// Returns a map of peer ids and their multiaddresses
    pub fn peer_addresses(&mut self) -> &HashMap<PeerId, Vec<Multiaddr>> {
        self.discovery.peer_addresses()
    }

    /// Send a block to a peer over bitswap
    #[allow(dead_code)]
    pub fn send_block(
        &mut self,
        peer_id: &PeerId,
        cid: Cid,
        data: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        self.bitswap.send_block(peer_id, cid, data);
        Ok(())
    }

    /// Send a request for data over bitswap
    #[allow(dead_code)]
    pub async fn want_block(&mut self, cid: Cid, priority: Priority) -> Result<(), Box<dyn Error>> {
        self.bitswap.want_block(cid, priority).await;
        Ok(())
    }

    pub async fn want_blocks(
        &mut self,
        cids: Vec<Cid>,
        priority: Priority,
    ) -> Result<(), Box<dyn Error>> {
        self.bitswap.want_blocks(cids, priority).await;
        Ok(())
    }

    pub fn add_address(&mut self, peer: &PeerId, addr: Multiaddr) {
        self.discovery.add_address(peer, addr);
    }

    pub fn providers(
        &mut self,
        key: Key,
        response_channel: oneshot::Sender<Option<Result<HashSet<PeerId>, String>>>,
    ) {
        self.discovery.providers(key, response_channel)
    }
}
