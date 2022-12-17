use std::fmt;

use anyhow::Result;
use async_stream::stream;
use futures::{Stream, StreamExt};
use iroh_rpc_types::{gateway::*, VersionRequest, WatchRequest};

use crate::{StatusType, HEALTH_POLL_WAIT};

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
    pub async fn check(&self) -> (StatusType, String) {
        match self.version().await {
            Ok(version) => (StatusType::Serving, version),
            Err(_) => (StatusType::Down, String::new()),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = (StatusType, String)> {
        let client = self.client.clone();
        stream! {
            loop {
                let res = client.server_streaming(WatchRequest).await;
                if let Ok(mut res) = res {
                    while let Some(Ok(version)) = res.next().await {
                        yield (StatusType::Serving, version.version);
                    }
                }
                yield (StatusType::Down, String::new());
                tokio::time::sleep(HEALTH_POLL_WAIT).await;
            }
        }
    }
}
