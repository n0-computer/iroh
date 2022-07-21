use anyhow::Result;
use futures::Stream;

use crate::backend::GatewayBackend;
use crate::config::Addr;
use crate::status::{self, StatusRow};

// name that the health service registers the gateway client as
// this is derived from the protobuf definition of a `GatewayServer`
pub(crate) const SERVICE_NAME: &str = "gateway.Gateway";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "gateway";

#[derive(Debug, Clone)]
pub struct GatewayClient {
    backend: GatewayBackend,
}

impl GatewayClient {
    pub async fn new(addr: &Addr) -> Result<Self> {
        match addr {
            Addr::GrpcHttp2(addr) => {
                let backend = GatewayBackend::new(*addr)?;
                Ok(GatewayClient { backend })
            }
            Addr::GrpcUds(_) => unimplemented!(),
            Addr::Mem => unimplemented!(),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let req = iroh_metrics::req::trace_tonic_req(());
        let res = self.backend.client().clone().version(req).await?;
        Ok(res.into_inner().version)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        status::check(self.backend.health().clone(), SERVICE_NAME, NAME).await
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        status::watch(self.backend.health().clone(), SERVICE_NAME, NAME).await
    }
}
