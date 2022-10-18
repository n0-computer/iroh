use ahash::AHashMap;
use anyhow::Result;
use cid::Cid;
use tokio::sync::mpsc;

use crate::{block::Block, Store};

/// Maintains a pool of workers that make requests to the blockstore.
#[derive(Debug)]
pub struct BlockstoreManager<S: Store> {
    store: S,
    // pending_gauge -> iroh-metrics
    // active_gauge -> iroh-metrics
}

impl<S: Store> BlockstoreManager<S> {
    /// Creates a new manager.
    pub async fn new(store: S, _worker_count: usize) -> Self {
        BlockstoreManager { store }
    }

    pub async fn stop(self) -> Result<()> {
        Ok(())
    }

    pub async fn get_block_sizes(&self, keys: &[Cid]) -> Result<AHashMap<Cid, usize>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, mut r) = mpsc::channel(1);

        let store = self.store.clone();
        let keys = keys.to_vec();
        tokio::task::spawn(async move {
            for cid in keys {
                if let Ok(size) = store.get_size(&cid).await {
                    s.send(Some((cid, size))).await.ok();
                } else {
                    s.send(None).await.ok();
                }
            }
        });

        while let Some(r) = r.recv().await {
            if let Some((cid, block)) = r {
                res.insert(cid, block);
            }
        }

        Ok(res)
    }

    pub async fn get_blocks(&self, keys: &[Cid]) -> Result<AHashMap<Cid, Block>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, mut r) = mpsc::channel(1);

        let store = self.store.clone();
        let keys = keys.to_vec();
        tokio::task::spawn(async move {
            for cid in keys {
                if let Ok(block) = store.get(&cid).await {
                    s.send(Some((cid, block))).await.ok();
                } else {
                    s.send(None).await.ok();
                }
            }
        });

        while let Some(r) = r.recv().await {
            if let Some((cid, block)) = r {
                res.insert(cid, block);
            }
        }

        Ok(res)
    }
}
