use std::fmt;

use anyhow::Result;
use async_stream::stream;
use futures::{Stream, StreamExt};
use iroh_rpc_types::gateway::*;

use crate::{status::StatusType, ServiceStatus};

pub(crate) const NAME: &str = "gateway";

#[derive(Clone)]
pub struct GatewayClient {
    client: quic_rpc::RpcClient<GatewayService, crate::ChannelTypes>,
}

impl fmt::Debug for GatewayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayClient2")
            .field("client", &self.client)
            .finish()
    }
}

impl GatewayClient {
    pub async fn new(addr: GatewayAddr) -> anyhow::Result<Self> {
        let client = crate::open_client::<GatewayService>(addr).await?;
        Ok(Self { client })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(VersionRequest).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> ServiceStatus {
        let (status, version) = match self.version().await {
            Ok(version) => (StatusType::Serving, version),
            Err(_) => (StatusType::Down, String::new()),
        };
        ServiceStatus {
            name: "gateway",
            number: 1,
            status,
            version,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = ServiceStatus> {
        let client = self.client.clone();
        stream! {
            loop {
                let res = client.server_streaming(WatchRequest).await;
                match res {
                    Ok(mut res) => {
                        while let Some(v) = res.next().await {
                            let (status, version) = v.map_or((StatusType::Down, String::new()), |v| (StatusType::Serving, v.version));
                            yield ServiceStatus::new("gateway", 1, status, version);
                        }
                    },
                    Err(_) => {
                        yield ServiceStatus::new("gateway", 1, StatusType::Down, "");
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
        }
    }
}
