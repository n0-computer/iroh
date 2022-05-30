use std::net::SocketAddr;

use anyhow::Result;
use futures::Stream;
use tonic::transport::{Channel, Endpoint};
use tonic_health::proto::health_client::HealthClient;

use crate::status::{self, StatusRow};

// name that the health service registers the gateway client as
// this is derived from the protobuf definition of a `GatewayServer`
pub(crate) const NAME: &str = "gateway.Gateway";

#[derive(Debug, Clone)]
pub struct GatewayClient {
    health: HealthClient<Channel>,
}

impl GatewayClient {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = Endpoint::new(format!("http://{}", addr))?
            .keep_alive_while_idle(true)
            .connect_lazy();

        let health_client = HealthClient::new(conn);

        Ok(GatewayClient {
            health: health_client,
        })
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.health.clone(), NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.health.clone(), NAME).await
    }
}
