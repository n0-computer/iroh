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
            let gateway_status = self.gateway.watch().await;
            tokio::pin!(gateway_status);
            let p2p_status = self.p2p.watch().await;
            tokio::pin!(p2p_status);
            let store_status = self.store.watch().await;
            tokio::pin!(store_status);
            loop {
                tokio::select! {
                    Some(status) = gateway_status.next() => {
                        status_table.update(status).unwrap();
                        yield status_table.clone();
                    }
                    Some(status) = p2p_status.next() => {
                        status_table.update(status).unwrap();
                        yield status_table.clone();
                    }
                    Some(status) = store_status.next() => {
                        status_table.update(status).unwrap() ;
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

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_rpc_types::test::test_server;
    use tonic::transport::Server as TonicServer;
    use tonic_health::{
        server::{health_reporter, HealthReporter},
        ServingStatus,
    };

    use crate::status::{ServiceStatus, StatusRow, StatusTable};
    use crate::{gateway, network, store};

    struct TestService {}
    #[tonic::async_trait]
    impl test_server::Test for TestService {}

    async fn make_service(
        name: &'static str,
        addr: SocketAddr,
    ) -> Result<(HealthReporter, tokio::task::JoinHandle<()>)> {
        let (mut reporter, service) = health_reporter();
        reporter
            .set_serving::<test_server::TestServer<TestService>>()
            .await;

        let task = tokio::spawn(async move {
            TonicServer::builder()
                .add_service(service)
                .serve(addr)
                .await
                .unwrap();
        });
        reporter
            .set_service_status(name, ServingStatus::Serving)
            .await;

        Ok((reporter, task))
    }

    #[tokio::test]
    async fn client_status() {
        let cfg = RpcClientConfig::default();

        let gateway_name = gateway::NAME;
        let p2p_name = network::NAME;
        let store_name = store::NAME;
        let (mut gateway_reporter, gateway_task) =
            make_service(gateway_name, cfg.gateway_addr).await.unwrap();
        let (mut p2p_reporter, p2p_task) = make_service(p2p_name, cfg.p2p_addr).await.unwrap();
        let (mut store_reporter, store_task) =
            make_service(store_name, cfg.store_addr).await.unwrap();
        let client = Client::new(&cfg).await.unwrap();

        // test `check`
        let mut expect = StatusTable::new(
            StatusRow::new(gateway_name, 1, ServiceStatus::Serving),
            StatusRow::new(p2p_name, 1, ServiceStatus::Serving),
            StatusRow::new(store_name, 1, ServiceStatus::Serving),
        );
        let mut got = client.check().await;
        assert_eq!(expect, got);

        // test `watch`
        let stream = client.watch().await;
        tokio::pin!(stream);

        // each status gets reported for the first time in a non-deterministic order
        stream.next().await.unwrap();
        stream.next().await.unwrap();
        got = stream.next().await.unwrap();

        // use display names that are currently hard-wired into `Client`
        expect.gateway.name = "gateway";
        expect.p2p.name = "p2p";
        expect.store.name = "store";
        assert_eq!(expect, got);

        // update gateway
        expect
            .update(StatusRow::new(gateway_name, 1, ServiceStatus::Unknown))
            .unwrap();
        gateway_reporter
            .set_service_status(gateway_name, ServingStatus::Unknown)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        // update p2p
        expect
            .update(StatusRow::new(p2p_name, 1, ServiceStatus::NotServing))
            .unwrap();
        p2p_reporter
            .set_service_status(p2p_name, ServingStatus::NotServing)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        // update store
        expect
            .update(StatusRow::new(store_name, 1, ServiceStatus::Unknown))
            .unwrap();
        store_reporter
            .set_service_status(store_name, ServingStatus::Unknown)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        gateway_task.abort();
        p2p_task.abort();
        store_task.abort();
    }
}
