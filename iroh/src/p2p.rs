use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use crate::getadd::{add, get};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_rpc_client::{Client, P2pClient, StoreClient};
use libp2p::gossipsub::{MessageId, TopicHash};
use libp2p::{Multiaddr, PeerId};
use mockall::automock;
use tokio::{fs::File, io::stdin, io::AsyncReadExt};

pub struct Id {
    pub peer_id: PeerId,
    pub listen_addrs: Vec<Multiaddr>,
    pub local_addrs: Vec<Multiaddr>,
}

pub struct ClientP2p<'a> {
    client: &'a P2pClient,
}

#[derive(Debug)]
pub enum Ping {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

impl<'a> ClientP2p<'a> {
    pub fn new(client: &'a P2pClient) -> Self {
        Self { client }
    }
}

#[automock]
#[async_trait]
pub trait P2p: Sync {
    async fn p2p_version(&self) -> Result<String>;
    async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()>;
    async fn disconnect(&self, peer_id: &PeerId) -> Result<()>;
    async fn local_peer_id(&self) -> Result<PeerId>;
    async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>>;
    async fn peer_ids(&self) -> Result<Vec<PeerId>>;
    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>>;
    async fn addrs_local(&self) -> Result<Vec<Multiaddr>>;
    async fn id(&self) -> Result<Id>;
    async fn ping(&self, ping_args: &[Ping], count: usize) -> Result<()>;
    async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes>;
    async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>>;
    async fn publish<'a>(&self, topic: &str, file: Option<&'a Path>) -> Result<MessageId>;
    async fn subscribe(&self, topic: &str) -> Result<bool>;
    async fn unsubscribe(&self, topic: &str) -> Result<bool>;
}

#[async_trait]
impl<'a> P2p for ClientP2p<'a> {
    async fn p2p_version(&self) -> Result<String> {
        self.client.version().await
    }

    async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        self.client.connect(*peer_id, addrs.to_vec()).await
    }

    async fn disconnect(&self, peer_id: &PeerId) -> Result<()> {
        self.client.disconnect(*peer_id).await
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        self.client.local_peer_id().await
    }

    async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        self.client.get_peers().await
    }

    async fn peer_ids(&self) -> Result<Vec<PeerId>> {
        let map = self.peers().await?;
        Ok(map.into_keys().collect())
    }

    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>> {
        let (_, addrs) = self.client.get_listening_addrs().await?;
        Ok(addrs)
    }

    async fn addrs_local(&self) -> Result<Vec<Multiaddr>> {
        self.client.external_addresses().await
    }

    async fn id(&self) -> Result<Id> {
        Ok(Id {
            peer_id: self.local_peer_id().await?,
            listen_addrs: self.addrs_listen().await?,
            local_addrs: self.addrs_local().await?,
        })
    }

    async fn ping(&self, ping_args: &[Ping], count: usize) -> Result<()> {
        todo!("{:?} {:?}", ping_args, count);
    }

    async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes> {
        let providers: HashSet<PeerId> = providers.iter().cloned().collect();
        self.client.fetch_bitswap(*cid, providers).await
    }

    async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>> {
        self.client.fetch_providers(cid).await
    }

    async fn publish<'b>(&self, topic: &str, file: Option<&'b Path>) -> Result<MessageId> {
        let mut v: Vec<u8> = Vec::new();
        if let Some(file) = file {
            let mut f = File::open(file).await?;
            f.read_to_end(&mut v).await?;
        } else {
            stdin().read_to_end(&mut v).await?;
        }
        self.client
            .gossipsub_publish(TopicHash::from_raw(topic), Bytes::from(v))
            .await
    }

    async fn subscribe(&self, topic: &str) -> Result<bool> {
        self.client
            .gossipsub_subscribe(TopicHash::from_raw(topic))
            .await
    }

    async fn unsubscribe(&self, topic: &str) -> Result<bool> {
        self.client
            .gossipsub_unsubscribe(TopicHash::from_raw(topic))
            .await
    }
}
