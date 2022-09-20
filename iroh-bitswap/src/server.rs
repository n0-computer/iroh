use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use anyhow::{anyhow, Result};
use cid::Cid;
use libp2p::PeerId;
use tracing::{debug, error, warn};

use self::{
    decision::{Config as DecisionConfig, Engine as DecisionEngine, Envelope},
    score_ledger::Receipt,
};
use crate::{block::Block, message::BitswapMessage, network::Network, Store};
use crossbeam::channel::Sender;

mod blockstore_manager;
mod decision;
mod ewma;
mod ledger;
mod peer_ledger;
mod score_ledger;
mod task_merger;

const PROVIDE_KEYS_BUFFER_SIZE: usize = 2048;
const PROVIDE_WORKER_MAX: usize = 6;

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

#[derive(Debug)]
pub struct Server<S: Store> {
    // sent_histogram -> iroh-metrics
    // send_time_histogram -> iroh-metric
    /// Decision engine for which who to send which blocks to.
    engine: Arc<DecisionEngine<S>>,
    /// Provides interaction with the network.
    network: Network,
    /// Counters for various statistics.
    counters: Mutex<Stat>,
    /// Channel for newly added blocks, which are to be provided to the network.
    /// Blocks in this channel get buffered and fed to the `provider_keys` channel
    /// later on to avoid too much network activiy.
    new_blocks: Sender<Cid>,
    /// Wether or not to make provide announcements.
    provide_enabled: bool,
    workers: Vec<(Sender<()>, JoinHandle<()>)>,
    provide_worker: Option<(Sender<()>, JoinHandle<()>)>,
    provide_collector: Option<(Sender<()>, JoinHandle<()>)>,
}

impl<S: Store> Server<S> {
    pub fn new(network: Network, store: S, config: Config) -> Self {
        let engine = DecisionEngine::new(store, *network.self_id(), config.decision_config);
        let provide_keys = crossbeam::channel::bounded(PROVIDE_KEYS_BUFFER_SIZE);
        let new_blocks = crossbeam::channel::bounded(config.has_block_buffer_size);
        let task_worker_count = config.task_worker_count;
        let mut workers = Vec::with_capacity(config.task_worker_count);
        let provide_enabled = config.provide_enabled;
        let mut provide_worker = None;
        let mut provide_collector = None;

        let engine = Arc::new(engine);

        // start up workers to handle requests from other nodes for the data on this node
        for _ in 0..task_worker_count {
            let (closer_s, closer_r) = crossbeam::channel::bounded(1);
            let outbox = engine.outbox();
            let engine = engine.clone();
            let network = network.clone();

            let handle = std::thread::spawn(move || {
                loop {
                    crossbeam::channel::select! {
                        recv(closer_r) -> _ => {
                            break;
                        }
                        recv(outbox) -> envelope => {
                            match envelope {
                                Ok(Ok(envelope)) => {
                                    // let start = Instant::now();
                                    engine.message_sent(&envelope.peer, &envelope.message);
                                    send_blocks(&network, envelope);
                                    // self.send_time_histogram.observe(start.elapsed());
                                }
                                Ok(Err(_e)) => {
                                    continue;
                                }
                                Err(_e) => {
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
                let (closer_s, closer_r) = crossbeam::channel::bounded(1);
                let new_blocks = new_blocks.1;
                let provide_keys = provide_keys.0;

                // worker managing sending out provide messages
                let handle = std::thread::spawn(move || {
                    loop {
                        crossbeam::channel::select! {
                            recv(closer_r) -> _ => {
                                break;
                            }
                            recv(new_blocks) -> block_key => {
                                if let Ok(block_key) = new_blocks.recv() {
                                    if let Err(err) = provide_keys.send(block_key) {
                                        error!("failed to send provide key: {:?}", err);
                                        break;
                                    }
                                } else {
                                    // channel got closed
                                    break;
                                }
                            }
                        }
                    }
                });
                provide_collector = Some((closer_s, handle));
            }
            {
                let (closer_s, closer_r) = crossbeam::channel::bounded(1);
                let provide_keys = provide_keys.1;
                let network = network.clone();
                let handle = std::thread::spawn(move || {
                    // originally spawns a limited amount of workers per key
                    loop {
                        crossbeam::channel::select! {
                            recv(closer_r) -> _ => {
                                break;
                            }
                            recv(provide_keys) -> key => {
                                match key {
                                    Ok(key) => {
                                        // TODO: timeout
                                        if let Err(err) = network.provide(key) {
                                            warn!("failed to provide: {}: {:?}", key, err);
                                        }
                                    }
                                    Err(_e) => {
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
            network,
            counters: Mutex::new(Stat::default()),
            new_blocks: new_blocks.0,
            provide_enabled,
            workers,
            provide_worker,
            provide_collector,
        }
    }

    pub fn ledger_for_peer(&self, peer: &PeerId) -> Option<Receipt> {
        self.engine.ledger_for_peer(peer)
    }

    pub fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        self.engine
            .wantlist_for_peer(peer)
            .into_iter()
            .map(|e| e.cid)
            .collect()
    }

    pub fn close(mut self) -> Result<()> {
        // trigger shutdown of the worker threads
        // wait for all workers to be done
        while let Some((closer, handle)) = self.workers.pop() {
            closer.send(()).ok();
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }

        if let Some((closer, handle)) = self.provide_collector.take() {
            closer.send(()).ok();
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }

        if let Some((closer, handle)) = self.provide_worker.take() {
            closer.send(()).ok();
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }

        // stop the decision engine
        Arc::try_unwrap(self.engine)
            .map_err(|_| anyhow!("engine refs not shutdown yet"))?
            .stop()?;

        Ok(())
    }

    /// Returns aggregated stats about the server operations.
    pub fn stat(&self) -> Result<Stat> {
        let mut counters = self.counters.lock().unwrap();
        counters.provide_buf_len = self.new_blocks.len();
        counters.peers = self.engine.peers().into_iter().collect();
        counters.peers.sort();

        Ok(counters.clone())
    }

    /// Announces the existence of blocks to the bitswap server.
    /// Potentially it will notify its peers about it.
    /// The blocks are not stored by bitswap, so the caller has to ensure to
    /// store them in the store, befor calling this method.
    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        //  send wanted blocks to the decision engine
        self.engine.notify_new_blocks(blocks);
        if self.provide_enabled {
            for block in blocks {
                self.new_blocks.send(*block.cid()).ok();
            }
        }

        Ok(())
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        self.engine.message_received(peer, message);
        // TODO: only track useful messages
    }

    /// Notifies the decision engine that a peer is well behaving
    /// and gave us usefull data, potentially increasing it's score and making us
    /// send them more data in exchange.
    pub fn received_blocks(&self, from: &PeerId, blks: &[Block]) {
        // Called by the client
        self.engine.received_blocks(from, blks);
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        self.engine.peer_connected(peer);
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        self.engine.peer_disconnected(peer);
    }
}

fn send_blocks(network: &Network, envelope: Envelope) {
    if let Err(err) = network.send_message(envelope.peer, envelope.message) {
        debug!("failed to send message {}: {:?}", envelope.peer, err);
    }

    // trigger sent updates
    envelope
        .queue
        .tasks_done(envelope.peer, &envelope.sent_tasks);
    envelope.work_signal.send(()).ok();
}
