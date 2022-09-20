use std::collections::HashSet;
use std::path::Path;

// should we use anyhow errors in the public API? or should we
// define fine-grained errors instead? I went with anyhow for the time
// being as many of the underlying services use it
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use libp2p::gossipsub::MessageId;
use libp2p::{Multiaddr, PeerId};

pub struct Id {
    pub peer_id: PeerId,
    pub listen_addrs: Vec<Multiaddr>,
    pub local_addrs: Vec<Multiaddr>,
}

#[derive(Debug)]
pub enum Ping {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

pub trait Api<P: P2p, S: Store>: Main + GetAdd {
    fn p2p(&self) -> Result<P>;
    fn store(&self) -> Result<S>;
}

#[async_trait]
pub trait Main {
    async fn version(&self) -> Result<String>;
}

#[async_trait]
pub trait GetAdd {
    // XXX get and add are centered around the filesystem.
    // We can imagine an underlying version that produces a stream of
    // Out as well.
    async fn get(&self, cid: Cid, path: &Path) -> Result<()>;
    async fn add(&self, path: &Path) -> Result<Cid>;
}

#[async_trait]
pub trait P2pConnectDisconnect {
    async fn connect(&self, peer_id: PeerId, addrs: &[Multiaddr]) -> Result<()>;
    async fn disconnect(&self, peer_id: PeerId) -> Result<()>;
}

#[async_trait]
pub trait P2pId {
    async fn p2p_version(&self) -> Result<String>;
    async fn local_peer_id(&self) -> Result<PeerId>;
    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>>;
    async fn addrs_local(&self) -> Result<Vec<Multiaddr>>;
    // can be implemented on the trait itself as it combines others
    async fn id(&self) -> Result<Id>;
    // async fn addrs gets a map right now
    async fn peers(&self) -> Result<Vec<PeerId>>;
    async fn ping(&self, ping_args: &[Ping], count: usize) -> Result<()>;
}

#[async_trait]
pub trait P2pFetch {
    async fn fetch_bitswap(&self, cid: Cid, providers: &[PeerId]) -> Result<Bytes>;
    async fn fetch_providers(&self, cid: Cid) -> Result<HashSet<PeerId>>;
}

#[async_trait]
pub trait P2pGossipsub {
    async fn publish(&self, topic: &str, file: Option<&Path>) -> Result<MessageId>;
    async fn subscribe(&self, topic: &str) -> Result<bool>;
    async fn unsubscribe(&self, topic: &str) -> Result<bool>;
}

pub trait P2p: P2pConnectDisconnect + P2pId + P2pFetch + P2pGossipsub {}

#[async_trait]
pub trait StoreMain {
    async fn store_version(&self) -> Result<String>;
    async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>>;
}

#[async_trait]
pub trait StoreBlock {
    async fn block_get(&self, cid: Cid) -> Result<Option<Bytes>>;
    async fn block_put(&self, data: &Bytes) -> Result<Cid>;
    async fn block_has(&self, cid: Cid) -> Result<bool>;
}

pub trait Store: StoreMain + StoreBlock {}
