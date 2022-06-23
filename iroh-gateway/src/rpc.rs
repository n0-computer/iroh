use std::net::SocketAddr;

use anyhow::Result;
use iroh_rpc_types::gateway::gateway_server;
use iroh_rpc_types::gateway::VersionResponse;
use tonic::{
    transport::{NamedService, Server as TonicServer},
    Request, Response,
};
use tonic_health::server::health_reporter;

struct Gateway {}

#[tonic::async_trait]
impl gateway_server::Gateway for Gateway {
    #[tracing::instrument(skip(self))]
    async fn version(
        &self,
        _request: Request<()>,
    ) -> Result<Response<VersionResponse>, tonic::Status> {
        let version = env!("CARGO_PKG_VERSION").to_string();
        Ok(Response::new(VersionResponse { version }))
    }
}

impl NamedService for Gateway {
    const NAME: &'static str = "gateway";
}

pub async fn new(addr: SocketAddr) -> Result<()> {
    let (mut health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<gateway_server::GatewayServer<Gateway>>()
        .await;

    TonicServer::builder()
        .add_service(health_service)
        .add_service(gateway_server::GatewayServer::new(Gateway {}))
        .serve(addr)
        .await?;
    Ok(())
}
