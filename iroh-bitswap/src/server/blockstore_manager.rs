use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use ahash::AHashMap;
use anyhow::{ensure, Result};
use cid::Cid;
use crossbeam::channel::{bounded, Receiver, Sender};
use crossbeam::sync::WaitGroup;

use crate::{block::Block, Store};

/// Maintains a pool of workers that make requests to the blockstore.
#[derive(Debug)]
pub struct BlockstoreManager {
    store: Store,
    worker_count: usize,
    // pending_gauge -> iroh-metrics
    // active_gauge -> iroh-metrics
    jobs: (
        Sender<Box<dyn FnOnce() + Send + Sync>>,
        Receiver<Box<dyn FnOnce() + Send + Sync>>,
    ),
    workers: Vec<JoinHandle<()>>,
    should_stop: Arc<AtomicBool>,
}

impl BlockstoreManager {
    /// Creates a new manager.
    pub fn new(store: Store, worker_count: usize) -> Self {
        let jobs = bounded(1024);
        BlockstoreManager {
            store,
            jobs,
            worker_count,
            workers: Vec::with_capacity(worker_count),
            should_stop: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start(&mut self) {
        self.should_stop.store(false, Ordering::SeqCst);
        for _ in 0..self.worker_count {
            let should_stop = self.should_stop.clone();
            let jobs_receiver = self.jobs.1.clone();
            let handle = std::thread::spawn(move || {
                while !should_stop.load(Ordering::SeqCst) {
                    if let Ok(job) = jobs_receiver.recv() {
                        // dec!(pending);
                        // inc!(active);
                        (job)();
                        // dec!(active);
                    }
                }
            });
            self.workers.push(handle);
        }
    }

    pub fn add_job<F: FnOnce() + Send + Sync + 'static>(&self, job: F) -> Result<()> {
        ensure!(!self.should_stop.load(Ordering::SeqCst), "shutting down");

        self.jobs.0.send(Box::new(job))?;
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
            if let Ok(size) = store.get_size(&cid) {
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
            if let Ok(block) = store.get(&cid) {
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
