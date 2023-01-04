use std::path::Path;

use anyhow::Result;
use iroh_p2p::{config, Config, Keychain, MemoryStorage, NetworkEvent, Node};
use iroh_resolver::resolver::Resolver;
use iroh_rpc_client::Client;
use iroh_rpc_types::Addr;
use iroh_unixfs::content_loader::{FullLoader, FullLoaderConfig};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;
use tracing::error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug)]
pub struct P2pNode {
    p2p_task: JoinHandle<()>,
    store_task: JoinHandle<()>,
    rpc: Client,
    resolver: Resolver<FullLoader>,
}

impl P2pNode {
    pub async fn new(port: u16, db_path: &Path) -> Result<(Self, Receiver<NetworkEvent>)> {
        let rpc_p2p_addr_server = Addr::new_mem();
        let rpc_p2p_addr_client = rpc_p2p_addr_server.clone();
        let rpc_store_addr_server = Addr::new_mem();
        let rpc_store_addr_client = rpc_store_addr_server.clone();

        let rpc_store_client_config = iroh_rpc_client::Config {
            p2p_addr: Some(rpc_p2p_addr_client.clone()),
            store_addr: Some(rpc_store_addr_client.clone()),
            gateway_addr: None,
            channels: Some(1),
        };
        let rpc_p2p_client_config = iroh_rpc_client::Config {
            p2p_addr: Some(rpc_p2p_addr_client.clone()),
            store_addr: Some(rpc_store_addr_client.clone()),
            gateway_addr: None,
            channels: Some(1),
        };
        let mut libp2p_config = config::Libp2pConfig::default();
        libp2p_config.listening_multiaddrs =
            vec![format!("/ip4/0.0.0.0/tcp/{port}").parse().unwrap()];
        libp2p_config.mdns = false;
        libp2p_config.kademlia = false;
        libp2p_config.autonat = true;
        libp2p_config.relay_client = true;
        libp2p_config.bootstrap_peers = Default::default(); // disable bootstrap for now
        libp2p_config.relay_server = false;
        libp2p_config.bitswap_client = false;
        libp2p_config.bitswap_server = false;
        libp2p_config.memesync = true;
        libp2p_config.max_conns_in = 8;
        libp2p_config.max_conns_out = 8;
        let config = Config {
            libp2p: libp2p_config,
            rpc_client: rpc_p2p_client_config.clone(),
            key_store_path: db_path.parent().unwrap().to_path_buf(),
        };

        let rpc = Client::new(rpc_p2p_client_config).await?;
        let loader = FullLoader::new(
            rpc.clone(),
            FullLoaderConfig {
                indexer: None,
                http_gateways: Default::default(),
                providers: Default::default(),
            },
        )?;
        let resolver = iroh_resolver::resolver::Resolver::new(loader);

        let store_config = iroh_store::Config {
            path: db_path.to_path_buf(),
            rpc_client: rpc_store_client_config,
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

    pub fn resolver(&self) -> &Resolver<FullLoader> {
        &self.resolver
    }

    pub async fn close(self) -> Result<()> {
        self.rpc.try_p2p().unwrap().shutdown().await?;
        self.store_task.abort();
        self.p2p_task.await?;
        self.store_task.await.ok();
        Ok(())
    }
}
