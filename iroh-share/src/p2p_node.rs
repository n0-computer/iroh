use std::{collections::HashSet, path::Path, sync::Arc};

use anyhow::{bail, ensure, Context, Result};
use async_channel::Receiver;
use async_trait::async_trait;
use cid::Cid;
use iroh_metrics::store::Metrics;
use iroh_p2p::{config, Keychain, MemoryStorage, NetworkEvent, Node};
use iroh_resolver::{
    parse_links,
    resolver::{ContentLoader, LoadedCid, Resolver, Source, IROH_STORE},
    verify_hash,
};
use iroh_rpc_client::Client;
use libp2p::{Multiaddr, PeerId};
use prometheus_client::registry::Registry;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinHandle};
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    async fn load_cid(&self, cid: &Cid) -> Result<LoadedCid> {
        let cid = *cid;
        match self.client.store.get(cid).await {
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

        let providers = self.providers.lock().await.clone();
        ensure!(!providers.is_empty(), "no providers supplied");

        let bytes = self
            .client
            .p2p
            .fetch_bitswap(cid, providers)
            .await
            .context("bitswap fetch")?;

        // verify cid
        let bytes_clone = bytes.clone();
        match tokio::task::spawn_blocking(move || verify_hash(&cid, &bytes_clone)).await? {
            Some(true) => {
                // all good
            }
            Some(false) => {
                bail!("invalid hash {:?}", cid.hash());
            }
            None => {
                warn!(
                    "unable to verify hash, unknown hash function {} for {}",
                    cid.hash().code(),
                    cid
                );
            }
        }

        let cloned = bytes.clone();
        let rpc = self.clone();
        {
            let clone2 = cloned.clone();
            let links =
                tokio::task::spawn_blocking(move || parse_links(&cid, &clone2).unwrap_or_default())
                    .await
                    .unwrap_or_default();

            rpc.client.store.put(cid, cloned, links).await?;
        }

        Ok(LoadedCid {
            data: bytes,
            source: Source::Bitswap,
        })
    }
}

impl P2pNode {
    pub async fn new(
        port: u16,
        rpc_p2p_port: u16,
        rpc_store_port: u16,
        db_path: &Path,
    ) -> Result<(Self, Receiver<NetworkEvent>)> {
        let rpc_p2p_addr = format!("0.0.0.0:{rpc_p2p_port}").parse().unwrap();
        let rpc_store_addr = format!("0.0.0.0:{rpc_store_port}").parse().unwrap();
        let rpc_client_config = iroh_rpc_client::Config {
            p2p_addr: rpc_p2p_addr,
            store_addr: rpc_store_addr,
            ..Default::default()
        };
        let config = config::Libp2pConfig {
            listening_multiaddr: format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap(),
            mdns: true,
            rpc_addr: rpc_p2p_addr,
            rpc_client: rpc_client_config.clone(),
            ..Default::default()
        };

        let rpc = Client::new(&config.rpc_client).await?;
        let loader = Loader::new(rpc.clone());
        let mut prom_registry = Registry::default();
        let resolver = iroh_resolver::resolver::Resolver::new(loader, &mut prom_registry);

        let store_config = iroh_store::Config {
            path: db_path.to_path_buf(),
            rpc_addr: rpc_store_addr,
            rpc_client: rpc_client_config.clone(),
            metrics: Default::default(),
        };

        let store_metrics = Metrics::new(&mut prom_registry);
        let store = if store_config.path.exists() {
            iroh_store::Store::open(store_config, store_metrics).await?
        } else {
            iroh_store::Store::create(store_config, store_metrics).await?
        };

        let kc = Keychain::<MemoryStorage>::new();
        let mut p2p = Node::new(config, kc, &mut prom_registry).await?;
        let events = p2p.network_events();

        let p2p_task = tokio::task::spawn(async move {
            if let Err(err) = p2p.run().await {
                error!("{:?}", err);
            }
        });

        let store_task =
            tokio::spawn(async move { iroh_store::rpc::new(rpc_store_addr, store).await.unwrap() });

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
        self.rpc.p2p.shutdown().await?;
        self.store_task.abort();
        self.p2p_task.await?;
        self.store_task.await.ok();
        Ok(())
    }
}
