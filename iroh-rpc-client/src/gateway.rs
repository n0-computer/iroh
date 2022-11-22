use std::fmt;

#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};
use crate::ServiceStatus;
use anyhow::Result;
#[cfg(feature = "grpc")]
use futures::Stream;
#[cfg(feature = "grpc")]
use iroh_rpc_types::gateway::gateway_client::GatewayClient as GrpcGatewayClient;
use iroh_rpc_types::{
    gateway::{Gateway, GatewayClientAddr, GatewayClientBackend},
    Addr,
};
#[cfg(feature = "grpc")]
use tonic::transport::Endpoint;
#[cfg(feature = "grpc")]
use tonic_health::proto::health_client::HealthClient;

impl_client!(Gateway);

impl GatewayClient {
    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.backend.version(()).await?;
        Ok(res.version)
    }
}

use iroh_rpc_types::qrpc::gateway::*;

#[derive(Clone)]
pub struct GatewayClient2 {
    client: quic_rpc::RpcClient<GatewayService, crate::ChannelTypes>,
}

impl fmt::Debug for GatewayClient2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient2")
            .field("client", &self.client)
            .finish()
    }
}

impl GatewayClient2 {
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
