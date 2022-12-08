use anyhow::Result;
use futures::StreamExt;
use iroh_rpc_client::create_server_stream;
use iroh_rpc_types::gateway::{
    GatewayRequest, GatewayServerAddr, GatewayService, VersionRequest, VersionResponse,
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

pub async fn new(addr: GatewayServerAddr, gw: Gateway) -> Result<()> {
    let mut stream = create_server_stream::<GatewayService>(addr).await?;
    while let Some(server) = stream.next().await {
        let s = server?;
        if let Ok((req, chan)) = s.accept_one().await {
            tracing::info!("accepted connection");
            let s = s.clone();
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
    Ok(())
}
