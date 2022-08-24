use std::{collections::HashSet, path::Path, sync::Arc};

use anyhow::{ensure, Result};
use async_trait::async_trait;
use cid::Cid;
use iroh_p2p::{config, Keychain, MemoryStorage, NetworkEvent, Node};
use iroh_resolver::{
    parse_links,
    resolver::{ContentLoader, LoadedCid, LoaderContext, Resolver, Source, IROH_STORE},
};
use iroh_rpc_client::Client;
use iroh_rpc_types::Addr;
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Ticket {
    pub peer_id: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub topic: String,
}

impl Ticket {
    pub fn as_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("failed to serialize")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let ticket = bincode::deserialize(bytes)?;
        Ok(ticket)
    }
}

pub struct P2pNode {
    p2p_task: JoinHandle<()>,
    store_task: JoinHandle<()>,
    rpc: Client,
    resolver: Resolver<Loader>,
}

/// Wrapper struct to implement custom content loading
#[derive(Debug, Clone)]
pub struct Loader {
    client: Client,
    providers: Arc<Mutex<HashSet<PeerId>>>,
}

impl Loader {
    pub fn new(client: Client) -> Self {
        Loader {
            client,
            providers: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn providers(&self) -> &Arc<Mutex<HashSet<PeerId>>> {
        &self.providers
    }
}

#[async_trait]
impl ContentLoader for Loader {
    async fn load_cid(&self, cid: &Cid, _ctx: &mut LoaderContext) -> Result<LoadedCid> {
        let cid = *cid;
        let providers = self.providers.lock().await.clone();

        match self.client.try_store()?.get(cid).await {
            Ok(Some(data)) => {
                return Ok(LoadedCid {
                    data,
                    source: Source::Store(IROH_STORE),
                });
            }
            Ok(None) => {}
            Err(err) => {
                warn!("failed to fetch data from store {}: {:?}", cid, err);
            }
        }

        ensure!(!providers.is_empty(), "no providers supplied");

        let res = self
            .client
            .try_p2p()?
            .fetch_bitswap(cid, providers.clone())
            .await;
        let bytes = match res {
            Ok(bytes) => bytes,
            Err(err) => {
                error!("Bitswap error: {:#?}", err);
                return Err(err);
            }
        };

        let cloned = bytes.clone();
        let rpc = self.clone();
        {
            let clone2 = cloned.clone();
            let links =
                tokio::task::spawn_blocking(move || parse_links(&cid, &clone2).unwrap_or_default())
                    .await
                    .unwrap_or_default();

            rpc.client.try_store()?.put(cid, cloned, links).await?;
        }

        Ok(LoadedCid {
            data: bytes,
            source: Source::Bitswap,
        })
    }
}

impl P2pNode {
    pub async fn new(port: u16, db_path: &Path) -> Result<(Self, Receiver<NetworkEvent>)> {
        let (rpc_p2p_addr_server, rpc_p2p_addr_client) = Addr::new_mem();
        let (rpc_store_addr_server, rpc_store_addr_client) = Addr::new_mem();

        let rpc_store_client_config = iroh_rpc_client::Config {
            p2p_addr: Some(rpc_p2p_addr_client.clone()),
            store_addr: Some(rpc_store_addr_client.clone()),
            gateway_addr: None,
        };
        let rpc_p2p_client_config = iroh_rpc_client::Config {
            p2p_addr: Some(rpc_p2p_addr_client.clone()),
            store_addr: Some(rpc_store_addr_client.clone()),
            gateway_addr: None,
        };
        let config = config::Config {
            libp2p: config::Libp2pConfig {
                listening_multiaddr: format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap(),
                mdns: false,
                kademlia: true,
                autonat: true,
                relay_client: true,
                bootstrap_peers: Default::default(), // disable bootstrap for now
                relay_server: false,
                max_conns_in: 8,
                max_conns_out: 8,
                ..Default::default()
            },
            rpc_client: rpc_p2p_client_config.clone(),
            metrics: Default::default(),
        };

        let rpc = Client::new(rpc_p2p_client_config).await?;
        let loader = Loader::new(rpc.clone());
        let resolver = iroh_resolver::resolver::Resolver::new(loader);

        let store_config = iroh_store::Config {
            path: db_path.to_path_buf(),
            rpc_client: rpc_store_client_config,
            metrics: iroh_metrics::config::Config {
                tracing: false, // disable tracing by default
                ..Default::default()
            },
        };

        let store = if store_config.path.exists() {
            iroh_store::Store::open(store_config).await?
        } else {
            iroh_store::Store::create(store_config).await?
        };

        let kc = Keychain::<MemoryStorage>::new();
        let mut p2p = Node::new(config, rpc_p2p_addr_server, kc).await?;
        let events = p2p.network_events();

        let p2p_task = tokio::task::spawn(async move {
            if let Err(err) = p2p.run().await {
                error!("{:?}", err);
            }
        });

        let store_task = tokio::spawn(async move {
            iroh_store::rpc::new(rpc_store_addr_server, store)
                .await
                .unwrap()
        });

        Ok((
            Self {
                p2p_task,
                store_task,
                rpc,
                resolver,
            },
            events,
        ))
    }

    pub fn rpc(&self) -> &Client {
        &self.rpc
    }

    pub fn resolver(&self) -> &Resolver<Loader> {
        &self.resolver
    }

    pub async fn close(self) -> Result<()> {
        self.rpc.p2p.unwrap().shutdown().await?;
        self.store_task.abort();
        self.p2p_task.await?;
        self.store_task.await.ok();
        Ok(())
    }
}
