use anyhow::Result;
use iroh_rpc_client::create_server;
use iroh_rpc_types::gateway::{
    GatewayAddr, GatewayRequest, GatewayService, VersionRequest, VersionResponse,
};

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

pub async fn new(addr: GatewayAddr, gw: Gateway) -> Result<()> {
    let server = create_server::<GatewayService>(addr).await?;
    loop {
        let s = server.clone();
        if let Ok((req, chan)) = s.accept_one().await {
            tracing::info!("accepted connection");
            let gw = gw.clone();
            tokio::spawn(async move {
                use GatewayRequest::*;
                let target = gw.clone();
                match req {
                    Version(req) => s.rpc(req, chan, target, Gateway::version).await,
                }
            });
        } else {
            tracing::warn!("accept failed");
        }
    }
}
