#[cfg(feature = "grpc")]
use crate::status::{self, StatusRow};
use anyhow::Result;
#[cfg(feature = "grpc")]
use futures::Stream;
#[cfg(feature = "grpc")]
use iroh_rpc_types::gateway::gateway_client::GatewayClient as GrpcGatewayClient;
use iroh_rpc_types::{gateway::Gateway, Addr};
#[cfg(feature = "grpc")]
use tonic::transport::{Channel, Endpoint};
#[cfg(feature = "grpc")]
use tonic_health::proto::health_client::HealthClient;

// name that the health service registers the gateway client as
// this is derived from the protobuf definition of a `GatewayServer`
pub(crate) const SERVICE_NAME: &str = "gateway.Gateway";

// the display name that we expect to see in the StatusTable
pub(crate) const NAME: &str = "gateway";

#[derive(Debug, Clone)]
pub enum GatewayClient {
    #[cfg(feature = "grpc")]
    Grpc {
        client: GrpcGatewayClient<Channel>,
        health: HealthClient<Channel>,
    },
    #[cfg(feature = "mem")]
    Mem,
}

impl GatewayClient {
    pub async fn new(addr: &Addr) -> Result<Self> {
        match addr {
            #[cfg(feature = "grpc")]
            Addr::GrpcHttp2(addr) => {
                let conn = Endpoint::new(format!("http://{}", addr))?
                    .keep_alive_while_idle(true)
                    .connect_lazy();

                let client = GrpcGatewayClient::new(conn.clone());
                let health = HealthClient::new(conn);

                Ok(GatewayClient::Grpc { client, health })
            }
            #[cfg(feature = "grpc")]
            Addr::GrpcUds(_) => unimplemented!(),
            #[cfg(feature = "mem")]
            Addr::Mem => Ok(GatewayClient::Mem),
        }
    }

    fn backend(&self) -> &impl Gateway {
        match self {
            #[cfg(feature = "grpc")]
            Self::Grpc { client, .. } => client,
            #[cfg(feature = "mem")]
            Self::Mem => {
                todo!()
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.backend().version(()).await?;
        Ok(res.version)
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        match self {
            Self::Grpc { health, .. } => status::check(health.clone(), SERVICE_NAME, NAME).await,
            Self::Mem => {
                todo!()
            }
        }
    }

    #[cfg(feature = "grpc")]
    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        match self {
            Self::Grpc { health, .. } => status::watch(health.clone(), SERVICE_NAME, NAME).await,
            Self::Mem => {
                todo!()
            }
        }
    }
}
