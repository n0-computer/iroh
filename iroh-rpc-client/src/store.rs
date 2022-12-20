use anyhow::Result;
use async_stream::stream;
use bytes::Bytes;
use cid::Cid;
use futures::{Stream, StreamExt};
use iroh_rpc_types::{store::*, VersionRequest, WatchRequest};

use crate::open_client;
use crate::{StatusType, HEALTH_POLL_WAIT};

#[derive(Debug, Clone)]
pub struct StoreClient {
    client: quic_rpc::RpcClient<StoreService, crate::ChannelTypes>,
}

impl StoreClient {
    pub async fn new(addr: StoreAddr) -> anyhow::Result<Self> {
        let client = open_client(addr).await?;
        Ok(Self { client })
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(VersionRequest).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.client.rpc(PutRequest { cid, blob, links }).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self, blocks))]
    pub async fn put_many(&self, blocks: Vec<(Cid, Bytes, Vec<Cid>)>) -> Result<()> {
        let blocks = blocks
            .into_iter()
            .map(|(cid, blob, links)| PutRequest { cid, blob, links })
            .collect();
        self.client.rpc(PutManyRequest { blocks }).await??;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>> {
        let res = self.client.rpc(GetRequest { cid }).await??;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let res = self.client.rpc(HasRequest { cid }).await??;
        Ok(res.has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let res = self.client.rpc(GetLinksRequest { cid }).await??;
        Ok(res.links)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_size(&self, cid: Cid) -> Result<Option<u64>> {
        let res = self.client.rpc(GetSizeRequest { cid }).await??;
        Ok(res.size)
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
