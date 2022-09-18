use std::{
    sync::{
        mpsc::{sync_channel, Receiver, SyncSender},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

use anyhow::{anyhow, Result};
use cid::Cid;
use libp2p::PeerId;
use tracing::debug;

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
const PROVIDE_WORKER_MAX: usize = 6;

#[derive(Debug)]
pub struct Config {
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
pub struct Server {
    // sent_histogram -> iroh-metrics
    // send_time_histogram -> iroh-metric
    /// Decision engine for which who to send which blocks to.
    engine: Arc<DecisionEngine>,
    /// Provides interaction with the network.
    network: Network,
    /// Counters for various statistics.
    counters: Mutex<Stat>,
    /// The total number of workers sending outgoing messages.
    task_worker_count: usize,
    /// Channel for newly added blocks, which are to be provided to the network.
    /// Blocks in this channel get buffered and fed to the `provider_keys` channel
    /// later on to avoid too much network activiy.
    new_blocks: (SyncSender<Cid>, Receiver<Cid>),
    /// Directly feeds provide workers.
    provide_keys: (SyncSender<Cid>, Receiver<Cid>),
    /// The size of the channel buffer to use.
    has_block_buffer_size: usize,
    /// Wether or not to make provide announcements.
    provide_enabled: bool,
    closer: bus::Bus<()>,
    workers: Vec<JoinHandle<()>>,
}

/// The total number of simultaneous threads sending outgoing messages.
const DEFAULT_BITSWAP_TASK_WORKER_COUNT: usize = 8;

impl Server {
    pub fn new(network: Network, store: Store, config: Config) -> Self {
        let engine = DecisionEngine::new(store, *network.self_id(), config.decision_config);
        let provide_keys = sync_channel(PROVIDE_KEYS_BUFFER_SIZE);
        let new_blocks = sync_channel(config.has_block_buffer_size);

        let mut server = Server {
            engine: Arc::new(engine),
            network,
            counters: Mutex::new(Stat::default()),
            task_worker_count: config.task_worker_count,
            new_blocks,
            provide_keys,
            has_block_buffer_size: config.has_block_buffer_size,
            provide_enabled: config.provide_enabled,
            closer: bus::Bus::new(config.task_worker_count),
            workers: Vec::with_capacity(config.task_worker_count),
        };

        server.start_workers();

        server
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

    fn start_workers(&mut self) {
        Arc::get_mut(&mut self.engine)
            .expect("must not be cloned yet")
            .start_workers();

        // start up workers to handle requests from other nodes for the data on this node

        for _ in 0..self.task_worker_count {
            let mut closer = self.closer.add_rx();
            let outbox = self.engine.outbox();
            let engine = self.engine.clone();
            let network = self.network.clone();

            let handle = std::thread::spawn(move || {
                loop {
                    if closer.try_recv().is_ok() {
                        break;
                    }

                    // TODO: no busy looping
                    if let Ok(envelope) = outbox.try_recv() {
                        match envelope {
                            Ok(envelope) => {
                                // let start = Instant::now();
                                engine.message_sent(&envelope.peer, &envelope.message);
                                send_blocks(&network, envelope);
                                // self.send_time_histogram.observe(start.elapsed());
                            }
                            Err(_e) => {
                                continue;
                            }
                        }
                    }
                }
            });
            self.workers.push(handle);
        }

        if self.provide_enabled {
            todo!()
        }
    }

    pub fn close(mut self) -> Result<()> {
        // trigger shutdown of the worker threads
        self.closer.broadcast(());

        // wait for all workers to be done
        while let Some(handle) = self.workers.pop() {
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }

        // stop the decision engine
        Arc::get_mut(&mut self.engine)
            .ok_or_else(|| anyhow!("engine refs not shutdown yet"))?
            .stop_workers()?;

        Ok(())
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        todo!()
    }

    pub fn stat(&self) -> Result<Stat> {
        todo!()
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        self.engine.message_received(peer, message);
        // TODO: only track useful messages
    }

    /// Notifies the decision engine that a peer is well behaving
    /// and gave us usefull data, potentially increasing it's score and making us
    /// send them more data in exchange.
    pub fn received_blocks(&self, from: &PeerId, blks: &[Block]) {
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
