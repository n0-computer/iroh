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

// name that the health service registers the gateway client as
// this is derived from the protobuf definition of a `GatewayServer`
pub(crate) const SERVICE_NAME: &str = "gateway.Gateway";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "gateway";

#[derive(Debug, Clone)]
pub struct GatewayClient {
    backend: GatewayClientBackend,
}

impl GatewayClient {
    pub async fn new(addr: GatewayClientAddr) -> Result<Self> {
        match addr {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => {
                let conn = Endpoint::new(format!("http://{}", addr))?
                    .keep_alive_while_idle(true)
                    .connect_lazy();

                let client = GrpcGatewayClient::new(conn.clone());
                let health = HealthClient::new(conn);

                Ok(GatewayClient {
                    backend: GatewayClientBackend::Grpc { client, health },
                })
            }
            #[cfg(all(feature = "grpc", unix))]
            Addr::GrpcUds(path) => {
                use tokio::net::UnixStream;
                use tonic::transport::Uri;

                let path = std::sync::Arc::new(path);
                // dummy addr
                let conn = Endpoint::new("http://[..]:50051")?
                    .keep_alive_while_idle(true)
                    .connect_with_connector_lazy(tower::service_fn(move |_: Uri| {
                        let path = path.clone();
                        UnixStream::connect(path.as_ref().clone())
                    }));

                let client = GrpcGatewayClient::new(conn.clone());
                let health = HealthClient::new(conn);

                Ok(GatewayClient {
                    backend: GatewayClientBackend::Grpc { client, health },
                })
            }
            #[cfg(feature = "mem")]
            Addr::Mem(s, r) => Ok(GatewayClient {
                backend: GatewayClientBackend::Mem(s, r),
            }),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.backend.version(()).await?;
        Ok(res.version)
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        match &self.backend {
            GatewayClientBackend::Grpc { health, .. } => {
                status::check(health.clone(), SERVICE_NAME, NAME).await
            }
            _ => {
                todo!()
            }
        }
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        match &self.backend {
            GatewayClientBackend::Grpc { health, .. } => {
                status::watch(health.clone(), SERVICE_NAME, NAME).await
            }
            _ => {
                todo!()
            }
        }
    }
}
