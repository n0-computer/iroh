use std::sync::Arc;

use anyhow::{anyhow, Result};
use cid::Cid;
use futures::future::BoxFuture;
use futures::FutureExt;
use iroh_metrics::bitswap::BitswapMetrics;
use iroh_metrics::core::MRecorder;
use iroh_metrics::inc;
use libp2p::PeerId;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, trace, warn};

use self::{
    decision::{Config as DecisionConfig, Engine as DecisionEngine, Envelope},
    score_ledger::Receipt,
};
use crate::{block::Block, message::BitswapMessage, network::Network, Store};

mod blockstore_manager;
mod decision;
mod ewma;
mod ledger;
mod peer_ledger;
mod score_ledger;
mod task_merger;

const PROVIDE_KEYS_BUFFER_SIZE: usize = 2048;

#[derive(Debug)]
pub struct Config {
    /// The total number of threads sending outgoing messages.
    pub task_worker_count: usize,
    pub provide_enabled: bool,
    pub has_block_buffer_size: usize,
    pub decision_config: DecisionConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            task_worker_count: 8,
            provide_enabled: true,
            has_block_buffer_size: 256,
            decision_config: DecisionConfig::default(),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub peers: Vec<PeerId>,
    pub provide_buf_len: usize,
    pub blocks_sent: u64,
    pub data_sent: u64,
}

#[derive(Debug, Clone)]
pub struct Server<S: Store> {
    // sent_histogram -> iroh-metrics
    // send_time_histogram -> iroh-metric
    /// Decision engine for which who to send which blocks to.
    engine: Arc<DecisionEngine<S>>,
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Counters for various statistics.
    counters: Mutex<Stat>,
    /// Channel for newly added blocks, which are to be provided to the network.
    /// Blocks in this channel get buffered and fed to the `provider_keys` channel
    /// later on to avoid too much network activiy.
    new_blocks: mpsc::Sender<Cid>,
    /// Wether or not to make provide announcements.
    provide_enabled: bool,
    workers: Vec<(oneshot::Sender<()>, JoinHandle<()>)>,
    provide_worker: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
    provide_collector: Option<(oneshot::Sender<()>, JoinHandle<()>)>,
}

impl<S: Store> Server<S> {
    pub async fn new(network: Network, store: S, config: Config) -> Self {
        let engine = DecisionEngine::new(store, *network.self_id(), config.decision_config).await;
        let provide_keys = mpsc::channel(PROVIDE_KEYS_BUFFER_SIZE);
        let new_blocks = mpsc::channel(config.has_block_buffer_size);
        let task_worker_count = config.task_worker_count;
        let mut workers = Vec::with_capacity(config.task_worker_count);
        let provide_enabled = config.provide_enabled;
        let mut provide_worker = None;
        let mut provide_collector = None;

        let engine = Arc::new(engine);

        // start up workers to handle requests from other nodes for the data on this node
        let rt = tokio::runtime::Handle::current();
        for _ in 0..task_worker_count {
            let (closer_s, mut closer_r) = oneshot::channel();
            let outbox = engine.outbox();
            let engine = engine.clone();
            let network = network.clone();

            let handle = rt.spawn(async move {
                loop {
                    inc!(BitswapMetrics::ServerTaskLoopTick);
                    tokio::select! {
                        biased;
                        _ = &mut closer_r => {
                            // shutdown
                            break;
                        }
                        envelope = outbox.recv() => {
                            match envelope {
                                Ok(Ok(envelope)) => {
                                    // let start = Instant::now();
                                    engine.message_sent(&envelope.peer, &envelope.message).await;
                                    send_blocks(&network, envelope).await;
                                    // self.send_time_histogram.observe(start.elapsed());
                                }
                                Ok(Err(_e)) => {
                                    continue;
                                }
                                Err(_) => {
                                    // channel gone, shutdown
                                    break;
                                }
                            }
                        }
                    }
                }
            });
            workers.push((closer_s, handle));
        }

        if provide_enabled {
            {
                let (closer_s, mut closer_r) = oneshot::channel();
                let mut new_blocks = new_blocks.1;
                let provide_keys = provide_keys.0;

                // worker managing sending out provide messages
                let handle = rt.spawn(async move {
                    loop {
                        inc!(BitswapMetrics::ServerKeyProviderTaskLoopTick);
                        tokio::select! {
                            biased;
                            _ = &mut closer_r => {
                                // shutdown
                                break;
                            }
                            block_key = new_blocks.recv() => {
                                match block_key {
                                    Some(block_key) => {
                                        if let Err(err) = provide_keys.send(block_key).await {
                                            error!("failed to send provide key: {:?}", err);
                                            break;
                                        }
                                    }
                                    None => {
                                        // channel got closed
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
                provide_collector = Some((closer_s, handle));
            }
            {
                let (closer_s, mut closer_r) = oneshot::channel();
                let mut provide_keys = provide_keys.1;
                let network = network.clone();
                let handle = rt.spawn(async move {
                    // originally spawns a limited amount of workers per key
                    loop {
                        inc!(BitswapMetrics::ServerProviderTaskLoopTick);
                        tokio::select! {
                            biased;
                            _ = &mut closer_r => {
                                // shutdown
                                break;
                            }
                            key = provide_keys.recv() => {
                                match key {
                                    Some(key) => {
                                        // TODO: timeout
                                        if let Err(err) = network.provide(key).await {
                                            warn!("failed to provide: {}: {:?}", key, err);
                                        }
                                    }
                                    None => {
                                        // channel closed
                                        break;
                                    }
                                }
                            }
                        }
                    }
                });
                provide_worker = Some((closer_s, handle));
            }
        }

        Server {
            engine,
            inner: Arc::new(Inner {
                counters: Mutex::new(Stat::default()),
                new_blocks: new_blocks.0,
                provide_enabled,
                workers,
                provide_worker,
                provide_collector,
            }),
        }
    }

    /// Returns aggregated data about blocks swapped and communication with a given peer.
    pub async fn ledger_for_peer(&self, peer: &PeerId) -> Option<Receipt> {
        self.engine.ledger_for_peer(peer).await
    }

    /// Returns the currently understood list of blocks requested by a given peer.
    pub async fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        self.engine
            .wantlist_for_peer(peer)
            .await
            .into_iter()
            .map(|e| e.cid)
            .collect()
    }

    pub async fn stop(self) -> Result<()> {
        // trigger shutdown of the worker threads
        // wait for all workers to be done
        let mut inner =
            Arc::try_unwrap(self.inner).map_err(|_| anyhow!("Server refs not shutdown yet"))?;
        while let Some((closer, handle)) = inner.workers.pop() {
            if closer.send(()).is_ok() {
                handle.await.map_err(|e| anyhow!("{:?}", e))?;
            }
        }

        if let Some((closer, handle)) = inner.provide_collector.take() {
            if closer.send(()).is_ok() {
                handle.await.map_err(|e| anyhow!("{:?}", e))?;
            }
        }

        if let Some((closer, handle)) = inner.provide_worker.take() {
            if closer.send(()).is_ok() {
                handle.await.map_err(|e| anyhow!("{:?}", e))?;
            }
        }

        // stop the decision engine
        Arc::try_unwrap(self.engine)
            .map_err(|_| anyhow!("engine refs not shutdown yet"))?
            .stop()
            .await?;

        Ok(())
    }

    /// Returns aggregated stats about the server operations.
    pub async fn stat(&self) -> Result<Stat> {
        let mut counters = self.inner.counters.lock().await;
        // TODO:
        // counters.provide_buf_len = self.new_blocks.len();
        counters.peers = self.engine.peers().await.into_iter().collect();
        counters.peers.sort();

        Ok(counters.clone())
    }

    /// Announces the existence of blocks to the bitswap server.
    /// Potentially it will notify its peers about it.
    /// The blocks are not stored by bitswap, so the caller has to ensure to
    /// store them in the store, befor calling this method.
    pub async fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        //  send wanted blocks to the decision engine
        self.engine.notify_new_blocks(blocks).await;
        if self.inner.provide_enabled {
            for block in blocks {
                if let Err(err) = self.inner.new_blocks.send(*block.cid()).await {
                    warn!("failed to send new blocks: {:?}", err);
                }
            }
        }

        Ok(())
    }

    pub async fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        trace!("server:receive_message from {}: {:?}", peer, message);
        inc!(BitswapMetrics::MessagesProcessingServer);
        self.engine.message_received(peer, message).await;
        // TODO: only track useful messages
    }

    /// Notifies the decision engine that a peer is well behaving
    /// and gave us usefull data, potentially increasing it's score and making us
    /// send them more data in exchange.
    pub fn received_blocks_cb(
        &self,
    ) -> Box<dyn Fn(PeerId, Vec<Block>) -> BoxFuture<'static, ()> + 'static + Send + Sync> {
        let engine = self.engine.clone();

        Box::new(move |from: PeerId, blocks: Vec<Block>| {
            let engine = engine.clone();
            async move {
                engine.received_blocks(from, blocks).await;
            }
            .boxed()
        })
    }

    pub async fn peer_connected(&self, peer: &PeerId) {
        self.engine.peer_connected(peer).await;
    }

    pub async fn peer_disconnected(&self, peer: &PeerId) {
        self.engine.peer_disconnected(peer).await;
    }
}

async fn send_blocks(network: &Network, envelope: Envelope) {
    let Envelope {
        peer,
        message,
        sent_tasks,
        queue,
        work_signal,
    } = envelope;

    if let Err(err) = network.send_message(peer, message).await {
        debug!("failed to send message {}: {:?}", peer, err);
    }

    // trigger sent updates
    queue.tasks_done(peer, &sent_tasks).await;
    work_signal.notify_one();
}
