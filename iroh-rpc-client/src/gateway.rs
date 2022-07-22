use std::net::SocketAddr;

use anyhow::Result;
use futures::Stream;
use iroh_rpc_types::gateway;
use tonic::transport::{Channel, Endpoint};
use tonic_health::proto::health_client::HealthClient;

use crate::status::{self, StatusRow};

// name that the health service registers the gateway client as
// this is derived from the protobuf definition of a `GatewayServer`
pub(crate) const SERVICE_NAME: &str = "gateway.Gateway";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "gateway";

#[derive(Debug, Clone)]
pub struct GatewayClient {
    health: HealthClient<Channel>,
    gateway: gateway::gateway_client::GatewayClient<Channel>,
}

impl GatewayClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = Endpoint::new(format!("http://{}", addr))?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let health_client = HealthClient::new(conn.clone());
        let gateway_client = gateway::gateway_client::GatewayClient::new(conn);

        Ok(GatewayClient {
            health: health_client,
            gateway: gateway_client,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self.gateway.clone().version(req).await?;
        Ok(res.into_inner().version)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.health.clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.health.clone(), SERVICE_NAME, NAME).await
    }
}
