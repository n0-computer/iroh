use super::status::StatusRow;
use super::ServiceStatus;
use anyhow::Result;
use futures::Stream;
use iroh_rpc_types::gateway::*;
use std::fmt;

pub(crate) const NAME: &str = "gateway";

#[derive(Clone)]
pub struct GatewayClient {
    client: quic_rpc::RpcClient<GatewayService, crate::ChannelTypes>,
}

impl fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient2")
            .field("client", &self.client)
            .finish()
    }
}

impl GatewayClient {
    pub async fn new(addr: GatewayAddr) -> anyhow::Result<Self> {
        let client = crate::open_client::<GatewayService>(addr).await?;
        Ok(Self { client })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(VersionRequest).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        let status: ServiceStatus = self
            .version()
            .await
            .map(|_| ServiceStatus::Serving)
            .unwrap_or_else(|_e| ServiceStatus::Unknown);
        StatusRow {
            name: "gateway",
            number: 1,
            status,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        // todo
        futures::stream::pending()
    }
}
