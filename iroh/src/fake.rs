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

// [0, 32, 248, 148, 216, 155, 10, 73, 243, 238, 199, 250, 98, 83, 132, 64, 146, 251, 9, 239, 10, 160, 141, 84, 236, 131, 45, 219, 102, 169, 130, 87, 228, 18]
// [0, 32, 15, 231, 162, 148, 52, 155, 40, 187, 217, 170, 125, 185, 68, 142, 156, 196, 145, 178, 64, 74, 19, 27, 9, 171, 111, 35, 88, 236, 103, 150, 96, 66]
// [0, 32, 144, 137, 53, 144, 57, 13, 191, 157, 254, 110, 136, 212, 131, 241, 179, 29, 38, 29, 207, 62, 126, 215, 213, 49, 248, 43, 143, 40, 123, 93, 248, 222]
// [0, 32, 244, 254, 113, 145, 50, 96, 197, 79, 230, 84, 208, 133, 40, 109, 190, 197, 133, 53, 35, 101, 203, 157, 143, 231, 108, 131, 185, 202, 68, 224, 145, 7]
// [0, 32, 126, 8, 233, 50, 187, 182, 207, 102, 154, 36, 53, 138, 20, 237, 67, 236, 214, 176, 75, 78, 66, 161, 97, 80, 226, 43, 101, 144, 255, 245, 235, 251]
// [0, 32, 66, 198, 99, 160, 220, 46, 224, 86, 184, 254, 86, 81, 162, 118, 175, 253, 158, 91, 142, 126, 227, 59, 217, 153, 201, 82, 70, 62, 140, 54, 124, 213]
// [0, 32, 1, 107, 58, 247, 230, 86, 117, 89, 243, 139, 175, 31, 238, 78, 26, 194, 101, 30, 134, 50, 132, 35, 255, 109, 94, 40, 159, 240, 183, 121, 89, 5]
// [0, 32, 146, 172, 241, 45, 32, 149, 12, 71, 236, 117, 214, 164, 171, 25, 185, 113, 235, 59, 167, 149, 194, 126, 60, 189, 6, 193, 73, 42, 135, 212, 174, 105]
// [0, 32, 41, 20, 114, 73, 5, 144, 211, 175, 24, 0, 137, 118, 73, 190, 210, 158, 168, 20, 83, 59, 76, 238, 153, 90, 217, 93, 6, 196, 134, 0, 120, 27]

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

    async fn peers(&self) -> Result<Vec<PeerId>> {
        Ok(vec![
            PeerId::from_bytes(&[
                0, 32, 15, 231, 162, 148, 52, 155, 40, 187, 217, 170, 125, 185, 68, 142, 156, 196,
                145, 178, 64, 74, 19, 27, 9, 171, 111, 35, 88, 236, 103, 150, 96, 66,
            ])?,
            PeerId::from_bytes(&[
                0, 32, 144, 137, 53, 144, 57, 13, 191, 157, 254, 110, 136, 212, 131, 241, 179, 29,
                38, 29, 207, 62, 126, 215, 213, 49, 248, 43, 143, 40, 123, 93, 248, 222,
            ])?,
        ])
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

// #[test]
// fn test_peer_ids() {
//     for i in 0..10 {
//         let id = PeerId::random();
//         println!("{:?}", id.to_bytes());
//     }
// }
