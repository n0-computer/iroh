use std::collections::HashMap;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use async_stream::stream;
use futures::{Stream, StreamExt};

use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::status::ServiceStatus;
use crate::store::StoreClient;

#[derive(Debug, Clone)]
pub struct Client {
    pub gateway: GatewayClient,
    pub p2p: P2pClient,
    pub store: StoreClient,
}

impl Client {
    pub async fn new(cfg: &RpcClientConfig) -> Result<Self> {
        let gateway = GatewayClient::new(cfg.gateway_addr)
            .await
            .context("Could not create gateway rpc client")?;
        let p2p = P2pClient::new(cfg.p2p_addr)
            .await
            .context("Could not create p2p rpc client")?;
        let store = StoreClient::new(cfg.store_addr)
            .await
            .context("Could not create store rpc client")?;

        Ok(Client {
            gateway,
            p2p,
            store,
        })
    }

    pub async fn check(&self) -> HashMap<String, ServiceStatus> {
        let mut s = HashMap::default();
        s.insert("store".into(), self.store.check().await);
        s.insert("p2p".into(), self.p2p.check().await);
        s.insert("gateway".into(), self.gateway.check().await);
        s
    }

    pub async fn watch(self) -> impl Stream<Item = HashMap<String, ServiceStatus>> {
        stream! {
            let mut statuses = self.check().await;
            yield statuses.clone();
            let store_status = self.store.watch().await;
            futures::pin_mut!(store_status);
            let p2p_status = self.p2p.watch().await;
            futures::pin_mut!(p2p_status);
            let gateway_status = self.gateway.watch().await;
            futures::pin_mut!(gateway_status);
            loop {
            tokio::select! {
                Some(status) = store_status.next() => {
                    statuses.insert("store".into(), status);
                    yield statuses.clone();
                }
                Some(status) = p2p_status.next() => {
                    statuses.insert("p2p".into(), status);
                    yield statuses.clone();
                }
                Some(status) = gateway_status.next() => {
                    statuses.insert("gateway".into(), status);
                    yield statuses.clone();
                }
            }
            }
        }
    }
}

#[derive(Debug, Clone)]
// Config for the rpc Client
pub struct RpcClientConfig {
    // gateway rpc address
    pub gateway_addr: SocketAddr,
    // p2p rpc address
    pub p2p_addr: SocketAddr,
    // store rpc address
    pub store_addr: SocketAddr,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            gateway_addr: "0.0.0.0:4400".parse().unwrap(),
            p2p_addr: "0.0.0.0:4401".parse().unwrap(),
            store_addr: "0.0.0.0:4402".parse().unwrap(),
        }
    }
}
