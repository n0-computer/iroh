use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh::api;
use iroh_resolver::resolver::Path as IpfsPath;
use libp2p::gossipsub::MessageId;
use libp2p::{Multiaddr, PeerId};

pub struct FakeApi {}

pub struct FakeP2p {}

pub struct FakeStore {}

impl FakeApi {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for FakeApi {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeP2p {
    fn new() -> Self {
        Self {}
    }
}

impl Default for FakeP2p {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeStore {
    fn new() -> Self {
        Self {}
    }
}

impl Default for FakeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl api::Accessors<FakeP2p, FakeStore> for FakeApi {
    fn p2p(&self) -> Result<FakeP2p> {
        Ok(FakeP2p::new())
    }

    fn store(&self) -> Result<FakeStore> {
        Ok(FakeStore::new())
    }
}

#[async_trait]
impl api::GetAdd for FakeApi {
    async fn get(&self, ipfs_path: &IpfsPath, output: Option<&Path>) -> Result<()> {
        // XXX should really affect the file system
        Ok(())
    }

    async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid> {
        Ok(Cid::default())
    }
}

#[async_trait]
impl api::P2pConnectDisconnect for FakeP2p {
    async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        Ok(())
    }

    async fn disconnect(&self, peer_id: &PeerId) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl api::P2pId for FakeP2p {
    async fn p2p_version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        Ok(PeerId::from_bytes(&[
            0, 32, 213, 223, 174, 101, 171, 227, 94, 23, 72, 55, 121, 197, 126, 154, 49, 64, 153,
            109, 184, 172, 249, 168, 157, 71, 59, 151, 11, 77, 147, 45, 125, 158,
        ])?)
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

    async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        let mut m: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();
        let addr1: Multiaddr = "/ip4/127.0.0.1".parse().unwrap();
        let addr2: Multiaddr = "/ip4/192.168.1.1".parse().unwrap();
        let addr3: Multiaddr = "/ip4/192.168.1.2".parse().unwrap();
        let addr4: Multiaddr = "/ip4/192.168.1.4".parse().unwrap();
        m.insert(
            PeerId::from_bytes(&[
                0, 32, 15, 231, 162, 148, 52, 155, 40, 187, 217, 170, 125, 185, 68, 142, 156, 196,
                145, 178, 64, 74, 19, 27, 9, 171, 111, 35, 88, 236, 103, 150, 96, 66,
            ])?,
            vec![addr1, addr2],
        );
        m.insert(
            PeerId::from_bytes(&[
                0, 32, 144, 137, 53, 144, 57, 13, 191, 157, 254, 110, 136, 212, 131, 241, 179, 29,
                38, 29, 207, 62, 126, 215, 213, 49, 248, 43, 143, 40, 123, 93, 248, 222,
            ])?,
            vec![addr3, addr4],
        );
        Ok(m)
    }

    async fn ping(&self, ping_args: &[api::Ping], count: usize) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl api::P2pFetch for FakeP2p {
    async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes> {
        Ok(Bytes::default())
    }

    async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>> {
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
impl api::StoreMain for FakeStore {
    async fn store_version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }

    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        Ok(Some(vec![]))
    }
}

#[async_trait]
impl api::StoreBlock for FakeStore {
    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>> {
        Ok(Some(Bytes::default()))
    }

    async fn block_put(&self, data: &Bytes) -> Result<Cid> {
        Ok(Cid::default())
    }

    async fn block_has(&self, cid: &Cid) -> Result<bool> {
        Ok(false)
    }
}
