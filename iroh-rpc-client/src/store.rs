use std::time::{Duration, SystemTime};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use cid::Cid;

use tarpc::context::Context;

impl_client!(Store);

const DEFAULT_DEADLINE: Duration = Duration::from_secs(60);

fn default_context() -> Context {
    let mut ctx = Context::current();
    ctx.deadline = SystemTime::now() + DEFAULT_DEADLINE;
    ctx
}

impl StoreClient {
    pub async fn version(&self) -> Result<String> {
        let res = self.backend().await?.version(default_context()).await??;
        Ok(res)
    }

    pub async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.backend()
            .await?
            .put(default_context(), cid, blob, links)
            .await??;
        Ok(())
    }

    pub async fn put_many(&self, blocks: Vec<(Cid, Bytes, Vec<Cid>)>) -> Result<()> {
        self.backend()
            .await?
            .put_many(default_context(), blocks)
            .await??;
        Ok(())
    }

    pub async fn get(&self, cid: Cid) -> Result<Option<BytesMut>> {
        let res = self.backend().await?.get(default_context(), cid).await??;
        Ok(res)
    }

    pub async fn has(&self, cid: Cid) -> Result<bool> {
        let res = self.backend().await?.has(default_context(), cid).await??;
        Ok(res)
    }

    pub async fn get_links(&self, cid: Cid) -> Result<Option<Vec<Cid>>> {
        let links = self
            .backend()
            .await?
            .get_links(default_context(), cid)
            .await??;

        if links.is_empty() {
            Ok(None)
        } else {
            Ok(Some(links))
        }
    }

    pub async fn get_size(&self, cid: Cid) -> Result<Option<u64>> {
        let size = self
            .backend()
            .await?
            .get_size(default_context(), cid)
            .await??;
        Ok(size)
    }
}
