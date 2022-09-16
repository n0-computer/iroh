use std::sync::{
    mpsc::{sync_channel, Receiver, SyncSender},
    Mutex,
};

use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;

use self::{
    decision::{Config as DecisionConfig, Engine as DecisionEngine},
    score_ledger::Receipt,
};
use crate::{block::Block, message::BitswapMessage, network::Network, Store};

mod blockstore_manager;
mod decision;
mod ledger;
mod peer_ledger;
mod score_ledger;

const PROVIDE_KEYS_BUFFER_SIZE: usize = 2048;
const PROVIDE_WORKER_MAX: usize = 6;

#[derive(Debug)]
pub struct Config {
    pub task_worker_count: usize,
    pub provide_enabled: bool,
    pub has_block_buffer_size: usize,
    pub decision_config: DecisionConfig,
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
    engine: DecisionEngine,
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
}

/// The total number of simultaneous threads sending outgoing messages.
const DEFAULT_BITSWAP_TASK_WORKER_COUNT: usize = 8;

impl Server {
    pub fn new(network: Network, store: Store, config: Config) -> Self {
        let engine = DecisionEngine::new(store, *network.self_id(), config.decision_config);
        let provide_keys = sync_channel(PROVIDE_KEYS_BUFFER_SIZE);
        let new_blocks = sync_channel(config.has_block_buffer_size);

        let server = Server {
            engine,
            network,
            counters: Mutex::new(Stat::default()),
            task_worker_count: config.task_worker_count,
            new_blocks,
            provide_keys,
            has_block_buffer_size: config.has_block_buffer_size,
            provide_enabled: config.provide_enabled,
        };

        server.start_workers();

        server
    }

    fn start_workers(&self) {
        todo!()
    }

    pub fn ledger_for_peer(&self, peer: &PeerId) -> &Receipt {
        self.engine.ledger_for_peer(peer)
    }

    pub fn close(self) -> Result<()> {
        todo!()
    }

    pub fn notify_new_blocks(&self, blocks: &[Block]) -> Result<()> {
        todo!()
    }

    pub fn stat(&self) -> Result<Stat> {
        todo!()
    }

    pub fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<Cid> {
        todo!()
    }

    pub fn peer_connected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn peer_disconnected(&self, peer: &PeerId) {
        todo!()
    }

    pub fn receive_message(&self, peer: &PeerId, message: &BitswapMessage) {
        todo!()
    }
}
