use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use iroh_rpc_client::StoreClient;
#[cfg(feature = "mock")]
use mockall::automock;

pub struct ClientStore<'a> {
    client: &'a StoreClient,
}

impl<'a> ClientStore<'a> {
    pub fn new(client: &'a StoreClient) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait Store {
    async fn store_version(&self) -> Result<String>;
    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>>;
    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>>;
    async fn block_put(&self, _data: &Bytes) -> Result<Cid>;
    async fn block_has(&self, cid: &Cid) -> Result<bool>;
}

#[async_trait]
impl<'a> Store for ClientStore<'a> {
    async fn store_version(&self) -> Result<String> {
        self.client.version().await
    }

    async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        self.client.get_links(*cid).await
    }

    async fn block_get(&self, cid: &Cid) -> Result<Option<Bytes>> {
        self.client.get(*cid).await
    }

    async fn block_put(&self, _data: &Bytes) -> Result<Cid> {
        todo!("not yet")
    }

    async fn block_has(&self, cid: &Cid) -> Result<bool> {
        self.client.has(*cid).await
    }
}
