use std::thread::JoinHandle;

use ahash::AHashMap;
use anyhow::{anyhow, Result};
use cid::Cid;
use crossbeam::channel::{bounded, Receiver, Sender};
use crossbeam::sync::WaitGroup;

use crate::{block::Block, Store};

/// Maintains a pool of workers that make requests to the blockstore.
#[derive(Debug)]
pub struct BlockstoreManager<S: Store> {
    store: S,
    // pending_gauge -> iroh-metrics
    // active_gauge -> iroh-metrics
    jobs: Sender<Box<dyn FnOnce() + Send + Sync>>,
    workers: Vec<(Sender<()>, JoinHandle<()>)>,
}

impl<S: Store> BlockstoreManager<S> {
    /// Creates a new manager.
    pub fn new(store: S, worker_count: usize) -> Self {
        let jobs: (Sender<_>, Receiver<Box<dyn FnOnce() + Send + Sync>>) = bounded(1024);
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let jobs_receiver = jobs.1.clone();
            let (closer_s, closer_r) = crossbeam::channel::bounded(1);

            let handle = std::thread::spawn(move || {
                loop {
                    crossbeam::channel::select! {
                        recv(closer_r) -> _ => {
                            break;
                        }
                        recv(jobs_receiver) -> job => {
                            if let Ok(job) = job {
                                // dec!(pending);
                                // inc!(active);
                                (job)();
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

    pub fn stop(&mut self) -> Result<()> {
        while let Some((closer, handle)) = self.workers.pop() {
            closer.send(()).ok();
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }
        Ok(())
    }

    pub fn add_job<F: FnOnce() + Send + Sync + 'static>(&self, job: F) -> Result<()> {
        self.jobs.send(Box::new(job))?;
        // inc!(pending);

        Ok(())
    }

    pub fn get_block_sizes(&self, keys: &[Cid]) -> Result<AHashMap<Cid, usize>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, r) = bounded(keys.len());

        let store = self.store.clone();
        self.job_per_key(keys, move |cid: Cid| {
            let size = tokio::runtime::Handle::current().block_on(async move {
                store.get_size(&cid).await
            });
            if let Ok(size) = size {
                s.send(Some((cid, size))).ok();
            } else {
                s.send(None).ok();
            }
        })?;

        while let Ok(r) = r.recv() {
            if let Some((cid, size)) = r {
                res.insert(cid, size);
            }
        }

        Ok(res)
    }

    pub fn get_blocks(&self, keys: &[Cid]) -> Result<AHashMap<Cid, Block>> {
        let mut res = AHashMap::new();
        if keys.is_empty() {
            return Ok(res);
        }
        let (s, r) = bounded(keys.len());

        let store = self.store.clone();
        self.job_per_key(keys, move |cid: Cid| {
            let block = tokio::runtime::Handle::current().block_on(async move {
                store.get(&cid).await
            });
            if let Ok(block) = block {
                s.send(Some((cid, block))).ok();
            } else {
                s.send(None).ok();
            }
        })?;

        while let Ok(r) = r.recv() {
            if let Some((cid, block)) = r {
                res.insert(cid, block);
            }
        }

        Ok(res)
    }

    /// Executes the given job function for each key, returning an error
    /// if queuing any of the jobs fails.
    fn job_per_key<F>(&self, keys: &[Cid], job_fn: F) -> Result<()>
    where
        F: FnOnce(Cid) + Send + Sync + Clone + 'static,
    {
        let wg = WaitGroup::new();

        for key in keys {
            let key = *key;
            let wg = wg.clone();
            let job_fn = job_fn.clone();
            self.add_job(move || {
                job_fn(key);
                drop(wg);
            })?;
        }

        wg.wait();
        Ok(())
    }
}
