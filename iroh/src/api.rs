
pub struct Id {
    peer_id: PeerId,
    listen_addrs: Vec<Multiaddr>,
    local_addrs: Vec<Multiaddr>,
}

#[async_trait]
pub trait Main {
    async fn version(&self) -> Result<String>;
    // these are really on p2p
    async fn peers(&self) -> Result<Vec<PeerId>>;
    async fn ping(&self, peer_id: PeerId, multi_addr: Multiaddr, count: usize) -> Result<()>;
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
pub trait ConnectDisconnect {
    async fn connect(&self, peer_id: PeerId, addrs: &[Multiaddress]) -> Result<()>;
    async fn disconnect(&self, peer_id: PeerId) -> Result<()>;
}

#[async_trait]
pub trait P2pId {
    // this is an API almost identical to what we want to expose to the user
    async fn p2p_version(&self) -> Result<String>;
    async fn local_peer_id(&self) -> Result<PeerId>;
    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>>;
    async fn addrs_local(&self) -> Result<Vec<Multiaddr>>;
    // can be implemented on the trait itself as it combines others
    async fn id(&self) -> Result<Id>;
    // async fn addrs gets a map right now
}

#[async_trait]
pub trait P2pFetch {
    async fn fetch_bitswap(&self, cid: Cid, providers: &[PeerId]) -> Result<Bytes>;
    async fn fetch_providers(&self, cid: Cid) -> Result<Vec<PeerId>>;
}

#[async_trait]
pub trait P2pGossipsub {
    async fn publish(topic: &str, file: Option<&Path>) -> Result<MessageId>;
    async fn subscribe(topic: &str) -> Result<()>;
    async fn unsubscribe(topic: &str) -> Result<()>;
}

#[async_trait]
pub trait Store {
    async fn store_version(&self) -> Result<String>;
    async fn get_links(&self, cid: Cid) -> Result<Vec<Cid>>;
}

#[async_trait]
pub trait StoreBlock {
    async fn block_get(&self, cid: Cid) -> Result<Bytes>;
    async fn block_put(&self, data: &Bytes) -> Result<Cid>;
    async fn block_has(&self, cid: Cid) -> Result<bool>;
}