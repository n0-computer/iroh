use std::result;

use anyhow::Result;
use futures::stream::Stream;
use iroh_rpc_client::{create_server, GatewayServer, ServerError, ServerSocket, HEALTH_POLL_WAIT};
use iroh_rpc_types::{
    gateway::{GatewayAddr, GatewayRequest, GatewayService},
    VersionRequest, VersionResponse, WatchRequest, WatchResponse,
};
use tracing::info;

use crate::VERSION;

#[derive(Default, Debug, Clone)]
pub struct Gateway {}

impl Gateway {
    #[tracing::instrument(skip(self))]
    fn watch(self, _: WatchRequest) -> impl Stream<Item = WatchResponse> {
        async_stream::stream! {
            loop {
                yield WatchResponse { version: VERSION.to_string() };
                tokio::time::sleep(HEALTH_POLL_WAIT).await;
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: VERSION.to_string(),
        }
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
        Watch(req) => s.server_streaming(req, chan, target, Gateway::watch).await,
        Version(req) => s.rpc(req, chan, target, Gateway::version).await,
    }
}

pub async fn new(addr: GatewayAddr, gw: Gateway, print_address: bool) -> Result<()> {
    info!("gateway rpc listening on: {}", addr);
    let server = create_server::<GatewayService>(addr, print_address).await?;
    loop {
        match server.accept_one().await {
            Ok((req, chan)) => {
                tokio::spawn(dispatch(server.clone(), req, chan, gw.clone()));
            }
            Err(cause) => {
                tracing::debug!("gateway rpc accept error: {}", cause);
            }
        }
    }
}
