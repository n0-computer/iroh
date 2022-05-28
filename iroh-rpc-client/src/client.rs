use std::net::SocketAddr;

use anyhow::{Context, Result};
use async_stream::stream;
use futures::{Stream, StreamExt};

use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::status::StatusTable;
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

    pub async fn check(&self) -> StatusTable {
        StatusTable::new(
            self.gateway.check().await,
            self.p2p.check().await,
            self.store.check().await,
        )
    }

    pub async fn watch(self) -> impl Stream<Item = StatusTable> {
        stream! {
            let mut status_table: StatusTable = Default::default();
            yield status_table.clone();
            let store_status = self.store.watch().await;
            tokio::pin!(store_status);
            let p2p_status = self.p2p.watch().await;
            tokio::pin!(p2p_status);
            let gateway_status = self.gateway.watch().await;
            tokio::pin!(gateway_status);
            loop {
                tokio::select! {
                    Some(status) = store_status.next() => {
                        status_table.update(status).unwrap() ;
                        yield status_table.clone();
                    }
                    Some(status) = p2p_status.next() => {
                        status_table.update(status).unwrap();
                        yield status_table.clone();
                    }
                    Some(status) = gateway_status.next() => {
                        status_table.update(status).unwrap();
                        yield status_table.clone();
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
