use std::pin::Pin;

use anyhow::Result;
use async_stream::stream;
use cid::Cid;
use futures::{Stream, StreamExt};
use iroh_rpc_client::StoreClient;
use iroh_unixfs::Block;

/// How many chunks to buffer up when adding content.
const _ADD_PAR: usize = 24;

/// The StoreApi allows you to communicate with the Iroh store.
///
/// This is trivially clone-able.
#[derive(Debug, Clone)]
pub struct StoreApi {
    client: StoreClient,
}

impl StoreApi {
    /// Create a new StoreApi from a [`StoreClient`]
    pub fn new(client: StoreClient) -> Self {
        Self { client }
    }

    /// Check if the store has the give [`Cid`]
    pub async fn has(&self, cid: Cid) -> Result<bool> {
        self.client.has(cid).await
    }

    /// Add a [`Block`] to the store.
    pub async fn put(&self, block: Block) -> Result<()> {
        let (cid, blob, links) = block.into_parts();
        self.client.put(cid, blob, links).await
    }

    /// Add a list of [`Block`] to the store.
    async fn put_many(&self, blocks: Vec<Block>) -> Result<()> {
        self.client
            .put_many(blocks.into_iter().map(|x| x.into_parts()).collect())
            .await
    }

    /// Add a stream of [`Block`] to the store
    pub async fn put_blocks(
        &self,
        blocks: Pin<Box<dyn Stream<Item = Result<Block>> + Send>>,
    ) -> impl Stream<Item = Result<(Cid, u64)>> {
        add_blocks_to_store_chunked(self.clone(), blocks)
    }
}

fn add_blocks_to_store_chunked(
    store: StoreApi,
    mut blocks: Pin<Box<dyn Stream<Item = Result<Block>> + Send>>,
) -> impl Stream<Item = Result<(Cid, u64)>> {
    let mut chunk = Vec::new();
    let mut chunk_size = 0u64;
    const MAX_CHUNK_SIZE: u64 = 1024 * 1024;
    stream! {
        while let Some(block) = blocks.next().await {
            let block = block?;
            let block_size = block.data().len() as u64 + block.links().len() as u64 * 128;
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
