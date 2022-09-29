use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::rc::Rc;

use crate::getadd::{add, get};
use anyhow::Result;
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

#[derive(Debug)]
pub enum Ping {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

pub struct Api {
    client: Rc<Client>,
}

#[automock]
impl Api {
    pub fn new(client: Client) -> Api {
        let client = Rc::new(client);
        Api { client }
    }

    pub fn p2p(&self) -> Result<P2p> {
        let p2p_client = self.client.try_p2p()?;
        Ok(P2p::new(p2p_client))
    }

    pub fn store(&self) -> Result<Store> {
        let store_client = self.client.try_store()?;
        Ok(Store::new(store_client))
    }

    pub async fn get<'a>(&self, ipfs_path: &IpfsPath, output: Option<&'a Path>) -> Result<()> {
        get(&self.client, ipfs_path, output).await
    }

    pub async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid> {
        add(&self.client, path, recursive, no_wrap).await
    }
}

pub struct P2p {
    client: Rc<P2pClient>,
}

#[automock]
impl P2p {
    fn new(client: &P2pClient) -> Self {
        let client = Rc::new(client.clone());
        Self { client }
    }
    pub async fn p2p_version(&self) -> Result<String> {
        self.client.version().await
    }

    pub async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        self.client.connect(*peer_id, addrs.to_vec()).await
    }

    pub async fn disconnect(&self, peer_id: &PeerId) -> Result<()> {
        self.client.disconnect(*peer_id).await
    }

    pub async fn local_peer_id(&self) -> Result<PeerId> {
        self.client.local_peer_id().await
    }

    pub async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        self.client.get_peers().await
    }

    pub async fn addrs_listen(&self) -> Result<Vec<Multiaddr>> {
        let (_, addrs) = self.client.get_listening_addrs().await?;
        Ok(addrs)
    }

    pub async fn addrs_local(&self) -> Result<Vec<Multiaddr>> {
        self.client.external_addresses().await
    }

    pub async fn id(&self) -> Result<Id> {
        Ok(Id {
            peer_id: self.local_peer_id().await?,
            listen_addrs: self.addrs_listen().await?,
            local_addrs: self.addrs_local().await?,
        })
    }

    pub async fn ping(&self, ping_args: &[Ping], count: usize) -> Result<()> {
        todo!("{:?} {:?}", ping_args, count);
    }

    pub async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes> {
        let providers: HashSet<PeerId> = providers.iter().cloned().collect();
        self.client.fetch_bitswap(*cid, providers).await
    }

    pub async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>> {
        self.client.fetch_providers(cid).await
    }

    pub async fn publish<'a>(&self, topic: &str, file: Option<&'a Path>) -> Result<MessageId> {
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

    pub async fn subscribe(&self, topic: &str) -> Result<bool> {
        self.client
            .gossipsub_subscribe(TopicHash::from_raw(topic))
            .await
    }

    pub async fn unsubscribe(&self, topic: &str) -> Result<bool> {
        self.client
            .gossipsub_unsubscribe(TopicHash::from_raw(topic))
            .await
    }
}

pub struct Store {
    client: Rc<StoreClient>,
}

#[automock]
impl Store {
    fn new(client: &StoreClient) -> Self {
        let client = Rc::new(client.clone());
        Self { client }
    }

    pub async fn store_version(&self) -> Result<String> {
        self.client.version().await
    }

    pub async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        self.client.get_links(*cid).await
    }

    pub async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>> {
        self.client.get(*cid).await
    }

    pub async fn block_put(&self, _data: &Bytes) -> Result<Cid> {
        // this awaits ramfox's work in the resolver
        // would be nice if that work only relied on the store and not
        // on the full client
        todo!("not yet")
    }

    pub async fn block_has(&self, cid: &Cid) -> Result<bool> {
        self.client.has(*cid).await
    }
}
