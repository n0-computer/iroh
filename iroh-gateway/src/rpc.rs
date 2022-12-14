use std::result;

use anyhow::Result;
use iroh_rpc_client::{create_server, GatewayServer, ServerError, ServerSocket};
use iroh_rpc_types::gateway::{
    GatewayAddr, GatewayRequest, GatewayService, VersionRequest, VersionResponse,
};
use tracing::info;

#[derive(Default, Debug, Clone)]
pub struct Gateway {}

impl Gateway {
    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        let version = env!("CARGO_PKG_VERSION").to_string();
        VersionResponse { version }
    }
}

impl iroh_rpc_types::NamedService for Gateway {
    const NAME: &'static str = "gateway";
}

/// dispatch a single request from the server
async fn dispatch(
    s: GatewayServer,
    req: GatewayRequest,
    chan: ServerSocket<GatewayService>,
    target: Gateway,
) -> result::Result<(), ServerError> {
    use GatewayRequest::*;
    match req {
        Version(req) => s.rpc(req, chan, target, Gateway::version).await,
    }
}

pub async fn new(addr: GatewayAddr, gw: Gateway) -> Result<()> {
    info!("gateway rpc listening on: {}", addr);
    let server = create_server::<GatewayService>(addr).await?;
    loop {
        match server.accept_one().await {
            Ok((req, chan)) => {
                tokio::spawn(dispatch(server.clone(), req, chan, gw.clone()));
            }
            Err(cause) => {
                tracing::error!("gateway rpc accept error: {}", cause);
            }
        }
    }
}
