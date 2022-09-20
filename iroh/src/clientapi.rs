use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::api;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_ctl::config::{Config, CONFIG_FILE_NAME, ENV_PREFIX};
use iroh_rpc_client::{Client, P2pClient, StoreClient};
use iroh_util::{iroh_config_path, make_config};
use libp2p::{
    gossipsub::{MessageId, TopicHash},
    Multiaddr, PeerId,
};
use tokio::{fs::File, io::stdin, io::AsyncReadExt};

pub struct ClientApi<'a> {
    rpc: &'a Client,
}

// api.connect()
// api.p2p_connect()

// api.p2p().connect() // could fail because no p2p, or because connect fails

// api.try_p2p()?.connect()

impl<'a> ClientApi<'a> {
    // what are the Rust conventions for an async new?
    pub async fn new(client: &'a Client) -> Result<ClientApi<'a>> {
        Ok(ClientApi { rpc: client })
    }
}

pub struct ClientP2p<'a> {
    rpc: &'a P2pClient,
}

pub struct ClientStore<'a> {
    rpc: &'a StoreClient,
}

#[async_trait]
impl<'a> api::Api<ClientP2p<'a>, ClientStore<'a>> for ClientApi<'a> {
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

#[async_trait]
impl<'a> api::Main for ClientApi<'a> {
    // XXX what's up with version in the existing implementation? some clap version thing?
    async fn version(&self) -> Result<String> {
        Ok("0.0.0".to_string())
    }
}

#[async_trait]
impl<'a> api::GetAdd for ClientApi<'a> {
    // XXX this awaits ramfox's work in the resolver
    async fn get(&self, cid: Cid, output: &Path) -> Result<()> {
        todo!("{:?} {:?}", cid, output);
    }

    async fn add(&self, path: &Path) -> Result<Cid> {
        todo!("{:?}", path);
    }
}

#[async_trait]
impl<'a> api::P2pConnectDisconnect for ClientP2p<'a> {
    async fn connect(&self, peer_id: PeerId, addrs: &[Multiaddr]) -> Result<()> {
        // XXX why does the client want a vec instead of a &[Multiaddr]?
        self.rpc.connect(peer_id, addrs.to_vec()).await
    }

    async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        self.rpc.disconnect(peer_id).await
    }
}

#[async_trait]
impl<'a> api::P2pId for ClientP2p<'a> {
    async fn p2p_version(&self) -> Result<String> {
        self.rpc.version().await
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        todo!("Need to port local_peer_id from branch");
        // self.rpc.try_p2p()?.local_peer_id().await
    }

    async fn peers(&self) -> Result<Vec<PeerId>> {
        Ok(self.rpc.get_peers().await?.into_keys().collect())
    }

    async fn addrs_listen(&self) -> Result<Vec<Multiaddr>> {
        let (peer_id, addrs) = self.rpc.get_listening_addrs().await?;
        Ok(addrs)
    }

    async fn addrs_local(&self) -> Result<Vec<Multiaddr>> {
        todo!("Need to port external_addresses from branch");
        // self.rpc.try_p2p()?.external_addresses().await
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
    async fn fetch_bitswap(&self, cid: Cid, providers: &[PeerId]) -> Result<Bytes> {
        let providers: HashSet<PeerId> = providers.iter().cloned().collect();
        self.rpc.fetch_bitswap(cid, providers).await
    }

    async fn fetch_providers(&self, cid: Cid) -> Result<HashSet<PeerId>> {
        // XXX this returns a HashSet not a Vec
        self.rpc.fetch_providers(&cid).await
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
impl<'a> api::P2p for ClientP2p<'a> {}

#[async_trait]
impl<'a> api::StoreMain for ClientStore<'a> {
    async fn store_version(&self) -> Result<String> {
        self.rpc.version().await
    }

    async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        self.rpc.get_links(cid).await
    }
}

#[async_trait]
impl<'a> api::StoreBlock for ClientStore<'a> {
    async fn block_get(&self, cid: Cid) -> Result<Option<Bytes>> {
        self.rpc.get(cid).await
    }

    async fn block_put(&self, data: &Bytes) -> Result<Cid> {
        // this awaits ramfox's work in the resolver
        todo!("not yet")
    }

    async fn block_has(&self, cid: Cid) -> Result<bool> {
        self.rpc.has(cid).await
    }
}

#[async_trait]
impl<'a> api::Store for ClientStore<'a> {}

pub async fn create_client(
    cli_path: Option<PathBuf>,
    overrides_map: HashMap<String, String>,
) -> Result<Client> {
    let cfg_path = iroh_config_path(CONFIG_FILE_NAME)?;
    let sources = vec![Some(cfg_path), cli_path];
    let config = make_config(
        // default
        Config::default(),
        // potential config files
        sources,
        // env var prefix for this config
        ENV_PREFIX,
        // map of present command line arguments
        overrides_map,
    )
    .unwrap();
    // let metrics_handle = iroh_metrics::MetricsHandle::new(MetricsConfig::default())
    //     .await
    //     .expect("failed to initialize metrics");
    Client::new(config.rpc_client).await
}
