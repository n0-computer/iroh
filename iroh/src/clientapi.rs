use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::api;
use crate::getadd::{add, get};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_resolver::resolver::Path as IpfsPath;
use iroh_rpc_client::{Client, P2pClient, StoreClient};
use libp2p::{
    gossipsub::{MessageId, TopicHash},
    Multiaddr, PeerId,
};
use tokio::{fs::File, io::stdin, io::AsyncReadExt};

pub struct ClientApi<'a> {
    rpc: &'a Client,
}

impl<'a> ClientApi<'a> {
    pub fn new(client: &'a Client) -> ClientApi<'a> {
        ClientApi { rpc: client }
    }
}

pub struct ClientP2p<'a> {
    rpc: &'a P2pClient,
}

pub struct ClientStore<'a> {
    rpc: &'a StoreClient,
}

impl<'a> api::Accessors<ClientP2p<'a>, ClientStore<'a>> for ClientApi<'a> {
    fn p2p(&self) -> Result<ClientP2p<'a>> {
        Ok(ClientP2p {
            rpc: self.rpc.try_p2p()?,
        })
    }

    fn store(&self) -> Result<ClientStore<'a>> {
        Ok(ClientStore {
            rpc: self.rpc.try_store()?,
        })
    }
}

#[async_trait(?Send)]
impl<'a> api::GetAdd for ClientApi<'a> {
    async fn get(&self, ipfs_path: &IpfsPath, output: Option<&Path>) -> Result<()> {
        get(self.rpc, ipfs_path, output).await
    }

    async fn add(&self, path: &Path, recursive: bool, no_wrap: bool) -> Result<Cid> {
        add(self.rpc, path, recursive, no_wrap).await
    }
}

#[async_trait]
impl<'a> api::P2pConnectDisconnect for ClientP2p<'a> {
    async fn connect(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> Result<()> {
        self.rpc.connect(*peer_id, addrs.to_vec()).await
    }

    async fn disconnect(&self, peer_id: &PeerId) -> Result<()> {
        self.rpc.disconnect(*peer_id).await
    }
}

#[async_trait]
impl<'a> api::P2pId for ClientP2p<'a> {
    async fn p2p_version(&self) -> Result<String> {
        self.rpc.version().await
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        self.rpc.local_peer_id().await
    }

    async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        self.rpc.get_peers().await
    }

    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>> {
        let (_, addrs) = self.rpc.get_listening_addrs().await?;
        Ok(addrs)
    }

    async fn addrs_local(&self) -> Result<Vec<Multiaddr>> {
        self.rpc.external_addresses().await
    }

    async fn id(&self) -> Result<api::Id> {
        Ok(api::Id {
            peer_id: self.local_peer_id().await?,
            listen_addrs: self.addrs_listen().await?,
            local_addrs: self.addrs_local().await?,
        })
    }

    async fn ping(&self, ping_args: &[api::Ping], count: usize) -> Result<()> {
        todo!("{:?} {:?}", ping_args, count);
    }
}

#[async_trait]
impl<'a> api::P2pFetch for ClientP2p<'a> {
    async fn fetch_bitswap(&self, cid: &Cid, providers: &[PeerId]) -> Result<Bytes> {
        let providers: HashSet<PeerId> = providers.iter().cloned().collect();
        self.rpc.fetch_bitswap(*cid, providers).await
    }

    async fn fetch_providers(&self, cid: &Cid) -> Result<HashSet<PeerId>> {
        self.rpc.fetch_providers(cid).await
    }
}

#[async_trait]
impl<'a> api::P2pGossipsub for ClientP2p<'a> {
    async fn publish(&self, topic: &str, file: Option<&Path>) -> Result<MessageId> {
        let mut v: Vec<u8> = Vec::new();
        if let Some(file) = file {
            let mut f = File::open(file).await?;
            f.read_to_end(&mut v).await?;
        } else {
            stdin().read_to_end(&mut v).await?;
        }
        self.rpc
            .gossipsub_publish(TopicHash::from_raw(topic), Bytes::from(v))
            .await
    }

    async fn subscribe(&self, topic: &str) -> Result<bool> {
        self.rpc
            .gossipsub_subscribe(TopicHash::from_raw(topic))
            .await
    }

    async fn unsubscribe(&self, topic: &str) -> Result<bool> {
        self.rpc
            .gossipsub_unsubscribe(TopicHash::from_raw(topic))
            .await
    }
}

#[async_trait]
impl<'a> api::StoreMain for ClientStore<'a> {
    async fn store_version(&self) -> Result<String> {
        self.rpc.version().await
    }

    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        self.rpc.get_links(*cid).await
    }
}

#[async_trait]
impl<'a> api::StoreBlock for ClientStore<'a> {
    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>> {
        self.rpc.get(*cid).await
    }

    async fn block_put(&self, _data: &Bytes) -> Result<Cid> {
        // this awaits ramfox's work in the resolver
        // would be nice if that work only relied on the store and not
        // on the full client
        todo!("not yet")
    }

    async fn block_has(&self, cid: &Cid) -> Result<bool> {
        self.rpc.has(*cid).await
    }
}
