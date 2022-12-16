use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use crate::config::Config;
use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::status::{ClientStatus, ServiceStatus, ServiceType};
use crate::store::StoreClient;
use anyhow::{Context, Result};
use futures::{Stream, StreamExt};

#[derive(Debug, Clone)]
pub struct Client {
    pub gateway: Option<GatewayClient>,
    p2p: P2pLBClient,
    store: StoreLBClient,
}

/// Provides a load balanced client for the store service
/// The client will round robin between all available StoreClients
#[derive(Debug, Clone)]
pub(crate) struct StoreLBClient {
    clients: Vec<StoreClient>,
    pos: Arc<AtomicUsize>,
}

impl Default for StoreLBClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreLBClient {
    /// round robin load balancing
    pub fn get(&self) -> Option<StoreClient> {
        if self.clients.is_empty() {
            return None;
        }
        let pos = self.pos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let c = self.clients.get(pos % self.clients.len()).unwrap();
        Some(c.clone())
    }

    pub fn new() -> Self {
        Self {
            clients: vec![],
            pos: Arc::new(AtomicUsize::new(0)),
        }
    }
}

/// Provides a load balanced client for the p2p service
/// The client will round robin between all available P2pClients
#[derive(Debug, Clone)]
pub(crate) struct P2pLBClient {
    clients: Vec<P2pClient>,
    pos: Arc<AtomicUsize>,
}

impl Default for P2pLBClient {
    fn default() -> Self {
        Self::new()
    }
}

impl P2pLBClient {
    /// round robin load balancing
    pub fn get(&self) -> Option<P2pClient> {
        if self.clients.is_empty() {
            return None;
        }
        let pos = self.pos.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let c = self.clients.get(pos % self.clients.len()).unwrap();
        Some(c.clone())
    }

    pub fn new() -> Self {
        Self {
            clients: vec![],
            pos: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Client {
    pub async fn new(cfg: Config) -> Result<Self> {
        let Config {
            gateway_addr,
            p2p_addr,
            store_addr,
            channels,
        } = cfg;

        let gateway = if let Some(addr) = gateway_addr {
            Some(
                GatewayClient::new(addr)
                    .await
                    .context("Could not create gateway rpc client")?,
            )
        } else {
            None
        };

        let n_channels = channels.unwrap_or(1);

        let mut p2p = P2pLBClient::new();
        if let Some(addr) = p2p_addr {
            for _i in 0..n_channels {
                let sc = P2pClient::new(addr.clone())
                    .await
                    .context("Could not create store rpc client")?;
                p2p.clients.push(sc);
            }
        }

        let mut store = StoreLBClient::new();
        if let Some(addr) = store_addr {
            for _i in 0..n_channels {
                let sc = StoreClient::new(addr.clone())
                    .await
                    .context("Could not create store rpc client")?;
                store.clients.push(sc);
            }
        }

        Ok(Client {
            gateway,
            p2p,
            store,
        })
    }

    pub fn try_p2p(&self) -> Result<P2pClient> {
        self.p2p.get().context("missing rpc p2p connnection")
    }

    pub fn try_gateway(&self) -> Result<&GatewayClient> {
        self.gateway
            .as_ref()
            .context("missing rpc gateway connnection")
    }

    pub fn try_store(&self) -> Result<StoreClient> {
        self.store.get().context("missing rpc store connection")
    }

    pub async fn check(&self) -> crate::status::ClientStatus {
        let g = if let Some(ref g) = self.gateway {
            let (s, v) = g.check().await;
            Some(ServiceStatus::new(ServiceType::Gateway, s, v))
        } else {
            None
        };
        let p = if let Some(ref p) = self.p2p.get() {
            let (s, v) = p.check().await;
            Some(ServiceStatus::new(ServiceType::P2p, s, v))
        } else {
            None
        };
        let s = if let Some(ref s) = self.store.get() {
            let (s, v) = s.check().await;
            Some(ServiceStatus::new(ServiceType::Store, s, v))
        } else {
            None
        };
        ClientStatus::new(g, p, s)
    }

    pub async fn watch(self) -> impl Stream<Item = ClientStatus> {
        async_stream::stream! {
            let mut status: ClientStatus = Default::default();
            let mut streams = Vec::new();

            if let Some(ref g) = self.gateway {
                let g = g.watch().await;
                let g = g.map(|(status, version)| ServiceStatus::new(ServiceType::Gateway, status, version));
                streams.push(g.boxed());
            }
            if let Some(ref p) = self.p2p.get() {
                let p = p.watch().await;
                let p = p.map(|(status, version)| ServiceStatus::new(ServiceType::P2p, status, version));
                streams.push(p.boxed());
            }
            if let Some(ref s) = self.store.get() {
                let s = s.watch().await;
                let s = s.map(|(status, version)| ServiceStatus::new(ServiceType::Store, status, version));
                streams.push(s.boxed());
            }

            let mut stream = futures::stream::select_all(streams);
            while let Some(s) = stream.next().await {
                status.update(s);
                yield status.clone();
            }
        }
    }
}
