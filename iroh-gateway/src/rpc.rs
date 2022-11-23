use anyhow::Result;
use async_trait::async_trait;
use iroh_rpc_types::gateway::{GatewayServerAddr, VersionResponse};

#[derive(Default)]
pub struct Gateway {}

impl Gateway {
    #[tracing::instrument(skip(self))]
    async fn version(&self, _: ()) -> Result<VersionResponse> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(VersionResponse { version })
    }
}

impl iroh_rpc_types::NamedService for Gateway {
    const NAME: &'static str = "gateway";
}

pub async fn new(addr: GatewayServerAddr, gateway: Gateway) -> Result<()> {
    todo!()
}
