#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};
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
