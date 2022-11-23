use crate::status::StatusRow;
use crate::ServiceStatus;
use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use futures::Stream;
use iroh_rpc_types::qrpc;
use iroh_rpc_types::qrpc::store::*;

pub(crate) const NAME: &str = "store";

#[derive(Debug, Clone)]
pub struct StoreClient {
    client: quic_rpc::RpcClient<StoreService, crate::ChannelTypes>,
}

impl StoreClient {
    pub async fn new(addr: StoreClientAddr) -> anyhow::Result<Self> {
        match addr {
            iroh_rpc_types::qrpc::addr::Addr::Qrpc(addr) => {
                todo!()
            }
            iroh_rpc_types::qrpc::addr::Addr::Mem(channel) => {
                let channel = quic_rpc::combined::Channel::new(Some(channel), None);
                Ok(Self {
                    client: quic_rpc::RpcClient::new(channel),
                })
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn version(&self) -> Result<String> {
        let res = self.client.rpc(VersionRequest).await?;
        Ok(res.version)
    }

    #[tracing::instrument(skip(self, blob))]
    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.client
            .rpc(qrpc::store::PutRequest { cid, blob, links })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self, blocks))]
    pub async fn put_many(&self, blocks: Vec<(Cid, Bytes, Vec<Cid>)>) -> Result<()> {
        let blocks = blocks
            .into_iter()
            .map(|(cid, blob, links)| qrpc::store::PutRequest { cid, blob, links })
            .collect();
        self.client
            .rpc(qrpc::store::PutManyRequest { blocks })
            .await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: Cid) -> Result<Option<Bytes>> {
        let res = self.client.rpc(qrpc::store::GetRequest { cid }).await?;
        Ok(res.data)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let res = self.client.rpc(qrpc::store::HasRequest { cid }).await?;
        Ok(res.has)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let res = self
            .client
            .rpc(qrpc::store::GetLinksRequest { cid })
            .await?;
        Ok(res.links)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_size(&self, cid: Cid) -> Result<Option<u64>> {
        let res = self.client.rpc(qrpc::store::GetSizeRequest { cid }).await?;
        Ok(res.size)
    }

    #[tracing::instrument(skip(self))]
    pub async fn check(&self) -> StatusRow {
        let status: ServiceStatus = self
            .version()
            .await
            .map(|_| ServiceStatus::Serving)
            .unwrap_or_else(|e| ServiceStatus::Unknown);
        StatusRow {
            name: "store",
            number: 3,
            status,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn watch(&self) -> impl Stream<Item = StatusRow> {
        futures::stream::pending()
    }
}
