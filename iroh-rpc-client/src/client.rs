use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use anyhow::{Context, Result};
#[cfg(feature = "grpc")]
use futures::{Stream, StreamExt};

use crate::config::Config;
use crate::gateway::GatewayClient;
use crate::network::P2pClient;
use crate::store::StoreClient;

#[derive(Debug, Clone)]
pub struct Client {
    pub gateway: Option<GatewayClient>,
    p2p: P2pLBClient,
    store: StoreLBClient,
}

/// Provides a load balanced client for the store service
/// The client will round robin between all available StoreClients
#[derive(Debug, Clone)]
pub struct StoreLBClient {
    clients: Vec<StoreClient>,
    pos: Arc<AtomicUsize>,
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
pub struct P2pLBClient {
    clients: Vec<P2pClient>,
    pos: Arc<AtomicUsize>,
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

    #[cfg(feature = "grpc")]
    pub async fn check(&self) -> crate::status::StatusTable {
        let g = if let Some(ref g) = self.gateway {
            Some(g.check().await)
        } else {
            None
        };
        let p = if let Some(ref p) = self.p2p.get() {
            Some(p.check().await)
        } else {
            None
        };
        let s = if let Some(ref s) = self.store.get() {
            Some(s.check().await)
        } else {
            None
        };
        crate::status::StatusTable::new(g, p, s)
    }

    #[cfg(feature = "grpc")]
    pub async fn watch(self) -> impl Stream<Item = crate::status::StatusTable> {
        async_stream::stream! {
            let mut status_table: crate::status::StatusTable = Default::default();
            let mut streams = Vec::new();

            if let Some(ref g) = self.gateway {
                let g = g.watch().await;
                streams.push(g.boxed());
            }
            if let Some(ref p) = self.p2p.get() {
                let p = p.watch().await;
                streams.push(p.boxed());
            }
            if let Some(ref s) = self.store.get() {
                let s = s.watch().await;
                streams.push(s.boxed());
            }

            let mut stream = futures::stream::select_all(streams);
            while let Some(status) = stream.next().await {
                status_table.update(status).unwrap();
                yield status_table.clone();
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
        let cfg = Config::default_grpc();

        let gateway_name = gateway::NAME;
        let p2p_name = network::NAME;
        let store_name = store::NAME;

        // make the services with the expected service names
        let (mut gateway_reporter, gateway_task) = make_service(
            gateway::SERVICE_NAME,
            cfg.gateway_addr
                .as_ref()
                .unwrap()
                .try_as_socket_addr()
                .unwrap(),
        )
        .await
        .unwrap();
        let (mut p2p_reporter, p2p_task) = make_service(
            network::SERVICE_NAME,
            cfg.p2p_addr.as_ref().unwrap().try_as_socket_addr().unwrap(),
        )
        .await
        .unwrap();
        let (mut store_reporter, store_task) = make_service(
            store::SERVICE_NAME,
            cfg.store_addr
                .as_ref()
                .unwrap()
                .try_as_socket_addr()
                .unwrap(),
        )
        .await
        .unwrap();
        let client = Client::new(cfg).await.unwrap();

        // test `check`
        // expect the names to be the hard-coded display names
        let mut expect = StatusTable::new(
            Some(StatusRow::new(gateway_name, 1, ServiceStatus::Serving)),
            Some(StatusRow::new(p2p_name, 1, ServiceStatus::Serving)),
            Some(StatusRow::new(store_name, 1, ServiceStatus::Serving)),
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
