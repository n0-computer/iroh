use std::{pin::Pin, sync::Arc};

use anyhow::Result;
use async_stream::stream;
use async_trait::async_trait;
use bytes::Bytes;
use cid::Cid;
use futures::{Stream, StreamExt};
use iroh_rpc_client::Client;
use iroh_unixfs::Block;

/// How many chunks to buffer up when adding content.
const _ADD_PAR: usize = 24;

#[async_trait]
pub trait Store: 'static + Send + Sync + Clone {
    async fn has(&self, &cid: Cid) -> Result<bool>;
    async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()>;
    async fn put_many(&self, blocks: Vec<Block>) -> Result<()>;
}

#[async_trait]
impl Store for Client {
    async fn has(&self, cid: Cid) -> Result<bool> {
        self.try_store()?.has(cid).await
    }

    async fn put(&self, cid: Cid, blob: Bytes, links: Vec<Cid>) -> Result<()> {
        self.try_store()?.put(cid, blob, links).await
    }

    async fn put_many(&self, blocks: Vec<Block>) -> Result<()> {
        self.try_store()?
            .put_many(blocks.into_iter().map(|x| x.into_parts()).collect())
            .await
    }
}

#[async_trait]
impl Store for Arc<tokio::sync::Mutex<std::collections::HashMap<Cid, Bytes>>> {
    async fn has(&self, cid: Cid) -> Result<bool> {
        Ok(self.lock().await.contains_key(&cid))
    }
    async fn put(&self, cid: Cid, blob: Bytes, _links: Vec<Cid>) -> Result<()> {
        self.lock().await.insert(cid, blob);
        Ok(())
    }

    async fn put_many(&self, blocks: Vec<Block>) -> Result<()> {
        let mut this = self.lock().await;
        for block in blocks {
            this.insert(*block.cid(), block.data().clone());
        }
        Ok(())
    }
}

fn add_blocks_to_store_chunked<S: Store>(
    store: S,
    mut blocks: Pin<Box<dyn Stream<Item = Result<Block>>>>,
) -> impl Stream<Item = Result<(Cid, u64)>> {
    let mut chunk = Vec::new();
    let mut chunk_size = 0u64;
    const MAX_CHUNK_SIZE: u64 = 1024 * 1024 * 16;
    stream! {
        while let Some(block) = blocks.next().await {
            let block = block?;
            let block_size = block.data().len() as u64;
            let cid = *block.cid();
            let raw_data_size = block.raw_data_size().unwrap_or_default();
            tracing::info!("adding chunk of {} bytes", chunk_size);
            if chunk_size + block_size > MAX_CHUNK_SIZE {
                store.put_many(std::mem::take(&mut chunk)).await?;
                chunk_size = 0;
            }
            chunk.push(block);
            chunk_size += block_size;
            yield Ok((
                cid,
                raw_data_size,
            ));
        }
        // make sure to also send the last chunk!
        store.put_many(chunk).await?;
    }
}

pub async fn add_blocks_to_store<S: Store>(
    store: Option<S>,
    blocks: Pin<Box<dyn Stream<Item = Result<Block>>>>,
) -> impl Stream<Item = Result<(Cid, u64)>> {
    add_blocks_to_store_chunked(store.unwrap(), blocks)
}
