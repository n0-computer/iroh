use anyhow::{Context, Result};
use futures::{Stream, StreamExt};

use crate::config::Config;
use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::store::StoreClient;

#[derive(Debug, Clone)]
pub struct Client {
    pub gateway: GatewayClient,
    pub p2p: P2pClient,
    pub store: StoreClient,
}

impl Client {
    pub async fn new(cfg: &Config) -> Result<Self> {
        let gateway = GatewayClient::new(&cfg.gateway_addr)
            .await
            .context("Could not create gateway rpc client")?;

        let p2p = P2pClient::new(&cfg.p2p_addr)
            .await
            .context("Could not create p2p rpc client")?;
        let store = StoreClient::new(&cfg.store_addr)
            .await
            .context("Could not create store rpc client")?;

        Ok(Client {
            gateway,
            p2p,
            store,
        })
    }

    #[cfg(feature = "grpc")]
    pub async fn check(&self) -> crate::status::StatusTable {
        crate::status::StatusTable::new(
            self.gateway.check().await,
            self.p2p.check().await,
            self.store.check().await,
        )
    }

    #[cfg(feature = "grpc")]
    pub async fn watch(self) -> impl Stream<Item = crate::status::StatusTable> {
        async_stream::stream! {
            let mut status_table: crate::status::StatusTable = Default::default();
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

// TODO: write tests for mem transport
#[cfg(all(test, feature = "grpc"))]
mod tests {
    use super::*;
    use std::net::SocketAddr;

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
        let cfg = Config::default();

        let gateway_name = gateway::NAME;
        let p2p_name = network::NAME;
        let store_name = store::NAME;

        // make the services with the expected service names
        let (mut gateway_reporter, gateway_task) = make_service(
            gateway::SERVICE_NAME,
            cfg.gateway_addr.try_as_socket_addr().unwrap(),
        )
        .await
        .unwrap();
        let (mut p2p_reporter, p2p_task) = make_service(
            network::SERVICE_NAME,
            cfg.p2p_addr.try_as_socket_addr().unwrap(),
        )
        .await
        .unwrap();
        let (mut store_reporter, store_task) = make_service(
            store::SERVICE_NAME,
            cfg.store_addr.try_as_socket_addr().unwrap(),
        )
        .await
        .unwrap();
        let client = Client::new(&cfg).await.unwrap();

        // test `check`
        // expect the names to be the hard-coded display names
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

        assert_eq!(expect, got);

        // update gateway
        expect
            .update(StatusRow::new(gateway_name, 1, ServiceStatus::Unknown))
            .unwrap();
        gateway_reporter
            .set_service_status(gateway::SERVICE_NAME, ServingStatus::Unknown)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        // update p2p
        expect
            .update(StatusRow::new(p2p_name, 1, ServiceStatus::NotServing))
            .unwrap();
        p2p_reporter
            .set_service_status(network::SERVICE_NAME, ServingStatus::NotServing)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        // update store
        expect
            .update(StatusRow::new(store_name, 1, ServiceStatus::Unknown))
            .unwrap();
        store_reporter
            .set_service_status(store::SERVICE_NAME, ServingStatus::Unknown)
            .await;
        let got = stream.next().await.unwrap();
        assert_eq!(expect, got);

        gateway_task.abort();
        p2p_task.abort();
        store_task.abort();
    }
}
