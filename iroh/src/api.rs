use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_resolver::resolver::Path as IpfsPath;
use libp2p::gossipsub::MessageId;
use libp2p::{Multiaddr, PeerId};
#[cfg(fake)]
use mockall::automock;

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

#[cfg_attr(fake, automock)]
pub trait Api<P: P2p, S: Store>: Accessors<P, S> + GetAdd {}

#[cfg_attr(fake, automock)]
pub trait Accessors<P: P2p, S: Store> {
    fn p2p(&self) -> Result<P>;
    fn store(&self) -> Result<S>;
}

#[cfg_attr(fake, automock)]
#[async_trait(?Send)]
pub trait GetAdd {
    async fn get(&self, ipfs_path: &IpfsPath, output_path: Option<&Path>) -> Result<()>;
    async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid>;
}

impl<T: Accessors<P, S> + GetAdd, P: P2p, S: Store> Api<P, S> for T {}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait P2pConnectDisconnect {
    async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()>;
    async fn disconnect(&self, peer_id: &PeerId) -> Result<()>;
}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait P2pId: Sync {
    async fn p2p_version(&self) -> Result<String>;
    async fn local_peer_id(&self) -> Result<PeerId>;
    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>>;
    async fn addrs_local(&self) -> Result<Vec<Multiaddr>>;
    // in the future, can be implemented on the trait itself as it combines others
    async fn id(&self) -> Result<Id>;
    async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>>;
    async fn peer_ids(&self) -> Result<Vec<PeerId>> {
        let map = self.peers().await?;
        let mut peer_ids: Vec<PeerId> = map.into_keys().collect();
        peer_ids.sort();
        Ok(peer_ids)
    }
    async fn ping(&self, ping_args: &[Ping], count: usize) -> Result<()>;
}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait P2pFetch {
    async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes>;
    async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>>;
}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait P2pGossipsub {
    async fn publish(&self, topic: &str, file: Option<&Path>) -> Result<MessageId>;
    async fn subscribe(&self, topic: &str) -> Result<bool>;
    async fn unsubscribe(&self, topic: &str) -> Result<bool>;
}

#[cfg_attr(fake, automock)]
pub trait P2p: P2pConnectDisconnect + P2pId + P2pFetch + P2pGossipsub {}

impl<T: P2pConnectDisconnect + P2pId + P2pFetch + P2pGossipsub> P2p for T {}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait StoreMain {
    async fn store_version(&self) -> Result<String>;
    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>>;
}

#[cfg_attr(fake, automock)]
#[async_trait]
pub trait StoreBlock {
    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>>;
    async fn block_put(&self, data: &Bytes) -> Result<Cid>;
    async fn block_has(&self, cid: &Cid) -> Result<bool>;
}

#[cfg_attr(fake, automock)]
pub trait Store: StoreMain + StoreBlock {}

impl<T: StoreMain + StoreBlock> Store for T {}
