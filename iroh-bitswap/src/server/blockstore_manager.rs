use ahash::AHashMap;
use anyhow::{anyhow, Result};
use awaitgroup::WaitGroup;
use cid::Cid;
use futures::{future::BoxFuture, Future, FutureExt};
use tokio::sync::oneshot;
use tracing::error;

use crate::{block::Block, Store};

/// Maintains a pool of workers that make requests to the blockstore.
#[derive(Debug)]
pub struct BlockstoreManager<S: Store> {
    store: S,
    // pending_gauge -> iroh-metrics
    // active_gauge -> iroh-metrics
    jobs: async_channel::Sender<BoxFuture<'static, ()>>,
    workers: Vec<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)>,
}

impl<S: Store> BlockstoreManager<S> {
    /// Creates a new manager.
    pub async fn new(store: S, worker_count: usize) -> Self {
        let jobs: (
            async_channel::Sender<_>,
            async_channel::Receiver<BoxFuture<'static, ()>>,
        ) = async_channel::bounded(1024);
        let mut workers = Vec::with_capacity(worker_count);

        let rt = tokio::runtime::Handle::current();
        for _ in 0..worker_count {
            let jobs_receiver = jobs.1.clone();
            let (closer_s, mut closer_r) = oneshot::channel();

            let handle = rt.spawn(async move {
                loop {
                    tokio::select! {
                        _ = &mut closer_r => {
                            // shutdown
                            break;
                        }
                        job = jobs_receiver.recv() => {
                            if let Ok(job) = job {
                                // dec!(pending);
                                // inc!(active);
                                job.await;
                                // dec!(active);
                            }
                        }
                    }
                }
            });
            workers.push((closer_s, handle));
        }

        BlockstoreManager {
            store,
            jobs: jobs.0,
            workers,
        }
    }

    pub async fn stop(mut self) -> Result<()> {
        while let Some((closer, handle)) = self.workers.pop() {
            match closer.send(()) {
                Ok(_) => handle.await.map_err(|e| anyhow!("{:?}", e))?,
                Err(err) => {
                    error!("failed to shutdown blockstore manager: {:?}", err);
                }
            }
        }
        Ok(())
    }

    pub async fn add_job(&self, job: BoxFuture<'static, ()>) -> Result<()> {
        self.jobs.send(job).await.unwrap();
        // inc!(pending);

        Ok(())
    }

    pub async fn get_block_sizes(&self, keys: &[Cid]) -> Result<AHashMap<Cid, usize>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, r) = async_channel::bounded(keys.len());

        let store = self.store.clone();
        self.job_per_key(keys, move |cid: Cid| async move {
            if let Ok(size) = store.get_size(&cid).await {
                s.send(Some((cid, size))).await.ok();
            } else {
                s.send(None).await.ok();
            }
        })
        .await?;

        while let Ok(r) = r.recv().await {
            if let Some((cid, size)) = r {
                res.insert(cid, size);
            }
        }

        Ok(res)
    }

    pub async fn get_blocks(&self, keys: &[Cid]) -> Result<AHashMap<Cid, Block>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, r) = async_channel::bounded(keys.len());

        let store = self.store.clone();
        self.job_per_key(keys, move |cid: Cid| async move {
            if let Ok(block) = store.get(&cid).await {
                s.send(Some((cid, block))).await.ok();
            } else {
                s.send(None).await.ok();
            }
        })
        .await?;

        while let Ok(r) = r.recv().await {
            if let Some((cid, block)) = r {
                res.insert(cid, block);
            }
        }

        Ok(res)
    }

    /// Executes the given job function for each key, returning an error
    /// if queuing any of the jobs fails.
    async fn job_per_key<F, FU>(&self, keys: &[Cid], job_fn: F) -> Result<()>
    where
        F: FnOnce(Cid) -> FU + Send + Sync + Clone + 'static,
        FU: Future<Output = ()> + Send + 'static,
    {
        let mut wg = WaitGroup::new();

        for key in keys {
            let key = *key;
            let wg = wg.worker();
            let job_fn = job_fn.clone();
            self.add_job(
                async move {
                    job_fn(key).await;
                    wg.done();
                }
                .boxed(),
            )
            .await?;
        }

        wg.wait().await;
        Ok(())
    }
}
