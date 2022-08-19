use anyhow::Result;
use async_trait::async_trait;
use iroh_rpc_types::gateway::{Gateway as RpcGateway, GatewayServerAddr, VersionResponse};

#[derive(Default)]
pub struct Gateway {}

#[async_trait]
impl RpcGateway for Gateway {
    #[tracing::instrument(skip(self))]
    async fn version(&self, _: ()) -> Result<VersionResponse> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(VersionResponse { version })
    }
}

#[cfg(feature = "grpc")]
impl iroh_rpc_types::NamedService for Gateway {
    const NAME: &'static str = "gateway";
}

#[allow(dead_code)]
pub async fn new(addr: GatewayServerAddr, gateway: Gateway) -> Result<()> {
    iroh_rpc_types::gateway::serve(addr, gateway).await
}
