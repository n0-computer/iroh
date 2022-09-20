use std::collections::HashSet;
use std::path::Path;

use crate::api;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use libp2p::gossipsub::MessageId;
use libp2p::{Multiaddr, PeerId};

// what do we want from a fake implementation?
// return error
// return some value
// return empty (if list)
// return multiple values

pub struct FakeApi {
    failing: bool,
}

pub struct FakeP2p {
    failing: bool,
}

pub struct FakeStore {
    failing: bool,
}

impl FakeApi {
    pub fn new(failing: bool) -> Self {
        Self { failing }
    }
}

impl Default for FakeApi {
    fn default() -> Self {
        Self::new(false)
    }
}

impl FakeP2p {
    fn new(failing: bool) -> Self {
        Self { failing }
    }
}

impl Default for FakeP2p {
    fn default() -> Self {
        Self::new(false)
    }
}

impl FakeStore {
    fn new(failing: bool) -> Self {
        Self { failing }
    }
}

impl Default for FakeStore {
    fn default() -> Self {
        Self::new(false)
    }
}

#[async_trait]
impl api::Api<FakeP2p, FakeStore> for FakeApi {
    fn p2p(&self) -> Result<FakeP2p> {
        Ok(FakeP2p::new(self.failing))
    }

    fn store(&self) -> Result<FakeStore> {
        Ok(FakeStore::new(self.failing))
    }
}

#[async_trait]
impl api::Main for FakeApi {
    async fn version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }
}

#[async_trait]
impl api::GetAdd for FakeApi {
    async fn get(&self, cid: Cid, output: &Path) -> Result<()> {
        if self.failing {
            return Err(anyhow::anyhow!("failing"));
        }
        // XXX should really affect the file system
        Ok(())
    }

    async fn add(&self, path: &Path) -> Result<Cid> {
        if self.failing {
            return Err(anyhow::anyhow!("failing"));
        }
        Ok(Cid::default())
    }
}

#[async_trait]
impl api::P2pConnectDisconnect for FakeP2p {
    async fn connect(&self, peer_id: PeerId, addrs: &[Multiaddr]) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl api::P2pId for FakeP2p {
    async fn p2p_version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        Ok(PeerId::random())
    }

    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>> {
        Ok(vec![])
    }

    async fn addrs_local(&self) -> Result<Vec<Multiaddr>> {
        Ok(vec![])
    }

    async fn id(&self) -> Result<api::Id> {
        Ok(api::Id {
            peer_id: self.local_peer_id().await?,
            listen_addrs: self.addrs_listen().await?,
            local_addrs: self.addrs_local().await?,
        })
    }

    async fn peers(&self) -> Result<Vec<PeerId>> {
        Ok(vec![])
    }

    async fn ping(&self, ping_args: &[api::Ping], count: usize) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl api::P2pFetch for FakeP2p {
    async fn fetch_bitswap(&self, cid: Cid, providers: &[PeerId]) -> Result<Bytes> {
        Ok(Bytes::default())
    }

    async fn fetch_providers(&self, cid: Cid) -> Result<HashSet<PeerId>> {
        Ok(HashSet::new())
    }
}

#[async_trait]
impl api::P2pGossipsub for FakeP2p {
    async fn publish(&self, topic: &str, file: Option<&Path>) -> Result<MessageId> {
        Ok(MessageId::new(&[]))
    }

    async fn subscribe(&self, topic: &str) -> Result<bool> {
        Ok(true)
    }

    async fn unsubscribe(&self, topic: &str) -> Result<bool> {
        Ok(true)
    }
}

#[async_trait]
impl api::P2p for FakeP2p {}

#[async_trait]
impl api::StoreMain for FakeStore {
    async fn store_version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }

    async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        Ok(Some(vec![]))
    }
}

#[async_trait]
impl api::StoreBlock for FakeStore {
    async fn block_get(&self, cid: Cid) -> Result<Option<Bytes>> {
        Ok(Some(Bytes::default()))
    }

    async fn block_put(&self, data: &Bytes) -> Result<Cid> {
        Ok(Cid::default())
    }

    async fn block_has(&self, cid: Cid) -> Result<bool> {
        Ok(false)
    }
}

#[async_trait]
impl api::Store for FakeStore {}
