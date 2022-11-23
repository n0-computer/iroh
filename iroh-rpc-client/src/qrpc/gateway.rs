use super::status::StatusRow;
use super::ServiceStatus;
use anyhow::Result;
use futures::Stream;
use iroh_rpc_types::qrpc::gateway::*;
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
    pub async fn new(
        addr: iroh_rpc_types::qrpc::addr::Addr<GatewayService>,
    ) -> anyhow::Result<Self> {
        match addr {
            iroh_rpc_types::qrpc::addr::Addr::Qrpc(addr) => {
                todo!()
            }
            iroh_rpc_types::qrpc::addr::Addr::Mem(channel) => {
                let channel = quic_rpc::combined::Channel::new(Some(channel), None);
                Ok(Self {
                    client: quic_rpc::RpcClient::new(channel),
                })
            }
        }
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
            .unwrap_or_else(|e| ServiceStatus::Unknown);
        StatusRow {
            name: "gateway",
            number: 1,
            status,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        futures::stream::pending()
    }
}
