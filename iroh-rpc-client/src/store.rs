use crate::status::StatusRow;
use crate::{open_client, ServiceStatus};
use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::store::*;

pub(crate) const NAME: &str = "store";

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
    pub async fn check(&self) -> StatusRow {
        let status: ServiceStatus = self
            .version()
            .await
            .map(|_| ServiceStatus::Serving)
            .unwrap_or_else(|_e| ServiceStatus::Unknown);
        StatusRow {
            name: "store",
            number: 3,
            status,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        // todo
        futures::stream::pending()
    }
}
