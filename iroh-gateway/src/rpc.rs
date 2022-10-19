use anyhow::Result;
use iroh_rpc_types::{
    gateway::{Gateway as RpcGateway, GatewayRequest, GatewayResponse},
    impl_serve, RpcError,
};
use tarpc::context::Context;

impl_serve!(Gateway, Gateway, GatewayRequest, GatewayResponse);

#[derive(Default, Clone)]
pub struct Gateway {}

#[tarpc::server]
impl RpcGateway for Gateway {
    async fn version(self, _ctx: Context) -> Result<String, RpcError> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(version)
    }
}
