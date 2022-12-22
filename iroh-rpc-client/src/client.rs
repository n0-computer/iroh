use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use futures::{Stream, StreamExt};
use iroh_rpc_types::config::RpcConfig;

use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::status::{ClientStatus, ServiceStatus, ServiceType};
use crate::store::StoreClient;

/// High level client to use other iroh services.
///
/// These clients use the irpc mechanism from the quic-rpc crate to communicate to the
/// services.  Depending on the configuration the clients can connect to remote iroh
/// services or to in-process services using an in-memory communication channel.
///
/// The client configuration can also be changed at any point and new clients will be
/// instantiated under the hood.  Furthermore there can be multiple channels resulting in
/// load-balancing clients to remote services.
///
/// To benefit from these you must always retrieve the client using the [`Client::try_p2p`],
/// [`Client::try_gateway`] and [`Client::try_store`] methods and not store the returned
/// clients long-term.
#[derive(Debug, Clone)]
pub struct Client {
    gateway: Arc<RwLock<Option<GatewayClient>>>,
    p2p: Arc<RwLock<P2pLBClient>>,
    store: Arc<RwLock<StoreLBClient>>,
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
    pub fn new(cfg: RpcConfig) -> Result<Self> {
        let RpcConfig {
            gateway_addr,
            p2p_addr,
            store_addr,
            channels,
        } = cfg;

        let gateway = if let Some(addr) = gateway_addr {
            Some(GatewayClient::new(addr).context("Could not create gateway rpc client")?)
        } else {
            None
        };

        let n_channels = channels.unwrap_or(1);

        let mut p2p = P2pLBClient::new();
        if let Some(addr) = p2p_addr {
            for _i in 0..n_channels {
                let sc =
                    P2pClient::new(addr.clone()).context("Could not create store rpc client")?;
                p2p.clients.push(sc);
            }
        }

        let mut store = StoreLBClient::new();
        if let Some(addr) = store_addr {
            for _i in 0..n_channels {
                let sc =
                    StoreClient::new(addr.clone()).context("Could not create store rpc client")?;
                store.clients.push(sc);
            }
        }

        Ok(Client {
            gateway: Arc::new(RwLock::new(gateway)),
            p2p: Arc::new(RwLock::new(p2p)),
            store: Arc::new(RwLock::new(store)),
        })
    }

    /// Reconfigures the RPC client.
    ///
    /// This essentially creates new clients with the given configuration and swaps out the
    /// underlying clients so that new uses via [`Client::try_p2p`], [`Client::try_store`]
    /// and [`Client::try_gateway`] will return the new clients.
    pub fn reconfigure(&self, config: RpcConfig) -> Result<()> {
        let Client {
            gateway,
            p2p,
            store,
        } = Client::new(config)?;
        *self.gateway.write().unwrap() = gateway.read().unwrap().as_ref().cloned();
        *self.p2p.write().unwrap() = p2p.read().unwrap().clone();
        *self.store.write().unwrap() = store.read().unwrap().clone();
        Ok(())
    }

    pub fn try_p2p(&self) -> Result<P2pClient> {
        self.p2p
            .read()
            .unwrap()
            .get()
            .context("missing rpc p2p connnection")
    }

    pub fn try_gateway(&self) -> Result<GatewayClient> {
        self.gateway
            .read()
            .unwrap()
            .as_ref()
            .cloned()
            .context("missing rpc gateway connnection")
    }

    pub fn try_store(&self) -> Result<StoreClient> {
        self.store
            .read()
            .unwrap()
            .get()
            .context("missing rpc store connection")
    }

    pub async fn check(&self) -> crate::status::ClientStatus {
        let g = if let Some(ref g) = *self.gateway.read().unwrap() {
            let (s, v) = g.check().await;
            Some(ServiceStatus::new(ServiceType::Gateway, s, v))
        } else {
            None
        };
        let p = if let Some(ref p) = self.p2p.read().unwrap().get() {
            let (s, v) = p.check().await;
            Some(ServiceStatus::new(ServiceType::P2p, s, v))
        } else {
            None
        };
        let s = if let Some(ref s) = self.store.read().unwrap().get() {
            let (s, v) = s.check().await;
            Some(ServiceStatus::new(ServiceType::Store, s, v))
        } else {
            None
        };
        ClientStatus::new(g, p, s)
    }

    pub async fn watch(self) -> impl Stream<Item = ClientStatus> + Send {
        let opt_gateway = self.gateway.read().unwrap().as_ref().cloned();
        let opt_p2p = self.p2p.read().unwrap().get();
        let opt_store = self.store.read().unwrap().get();
        async_stream::stream! {
            let mut status: ClientStatus = Default::default();
            let mut streams = Vec::new();
            if let Some(ref g) = opt_gateway {
                let g = g.watch().await;
                let g = g.map(|(status, version)|
                              ServiceStatus::new(ServiceType::Gateway, status, version));
                streams.push(g.boxed());
            }
            if let Some(ref p) = opt_p2p {
                let p = p.watch().await;
                let p = p.map(|(status, version)|
                              ServiceStatus::new(ServiceType::P2p, status, version));
                streams.push(p.boxed());
            }
            if let Some(ref s) = opt_store {
                let s = s.watch().await;
                let s = s.map(|(status, version)|
                              ServiceStatus::new(ServiceType::Store, status, version));
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
