use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use cid::Cid;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::RpcError;

#[tarpc::service]
pub trait P2p {
    async fn version() -> Result<String, RpcError>;
    async fn shutdown() -> Result<(), RpcError>;
    async fn fetch_bitswap(
        context_id: u64,
        cid: Cid,
        providers: Vec<PeerId>,
    ) -> Result<Bytes, RpcError>;
    async fn fetch_provider_dht(key: Cid, limit: usize) -> Result<HashSet<PeerId>, RpcError>;
    async fn stop_session_bitswap(context_id: u64) -> Result<(), RpcError>;
    async fn notify_new_blocks_bitswap(blocks: Vec<(Cid, Bytes)>) -> Result<(), RpcError>;
    async fn get_listening_addrs() -> Result<(PeerId, Vec<Multiaddr>), RpcError>;
    async fn get_peers() -> Result<HashMap<PeerId, Vec<Multiaddr>>, RpcError>;
    async fn peer_connect(peer: PeerId, addrs: Option<Vec<Multiaddr>>) -> Result<(), RpcError>;
    async fn peer_disconnect(peer: PeerId) -> Result<(), RpcError>;
    async fn lookup(peer: PeerId, addr: Option<Multiaddr>) -> Result<PeerInfo, RpcError>;
    async fn gossipsub_add_explicit_peer(peer: PeerId) -> Result<(), RpcError>;
    async fn gossipsub_all_mesh_peers() -> Result<Vec<PeerId>, RpcError>;
    async fn gossipsub_all_peers() -> Result<Vec<(PeerId, Vec<String>)>, RpcError>;
    async fn gossipsub_mesh_peers(topic_hash: String) -> Result<Vec<PeerId>, RpcError>;
    async fn gossipsub_publish(topic_hash: String, data: Bytes) -> Result<Vec<u8>, RpcError>;
    async fn gossipsub_remove_explicit_peer(peer: PeerId) -> Result<(), RpcError>;
    async fn gossipsub_subscribe(topic: String) -> Result<bool, RpcError>;
    async fn gossipsub_topics() -> Result<Vec<String>, RpcError>;
    async fn gossipsub_unsubscribe(topic: String) -> Result<bool, RpcError>;
    async fn start_providing(key: Vec<u8>) -> Result<(), RpcError>;
    async fn stop_providing(key: Vec<u8>) -> Result<(), RpcError>;
    async fn local_peer_id() -> Result<PeerId, RpcError>;
    async fn external_addrs() -> Result<Vec<Multiaddr>, RpcError>;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub protocol_version: String,
    pub agent_version: String,
    pub listen_addrs: Vec<Multiaddr>,
    pub protocols: Vec<String>,
    pub observed_addrs: Vec<Multiaddr>,
}
