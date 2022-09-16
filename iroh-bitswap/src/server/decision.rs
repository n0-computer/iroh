use std::{
    fmt::Debug,
    sync::{Mutex, RwLock},
    time::Duration,
};

use ahash::AHashMap;
use cid::Cid;
use libp2p::PeerId;

use crate::{peer_task_queue::PeerTaskQueue, Store};

use super::{
    blockstore_manager::BlockstoreManager,
    ledger::Ledger,
    peer_ledger::PeerLedger,
    score_ledger::{DefaultScoreLedger, Receipt},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskInfo {
    peer: PeerId,
    /// The cid of the block.
    cid: Cid,
    /// Tasks can be want-have ro want-block.
    is_want_block: bool,
    /// Wether to immediately send a response if the block is not found.
    send_dont_have: bool,
    /// The size of the block corresponding to the task.
    block_size: usize,
    /// Wether the block was found.
    have_block: bool,
}

/// Used for task prioritization.
/// It should return true if task 'ta' has higher priority than task 'tb'
pub trait TaskComparator: Fn(&TaskInfo, &TaskInfo) -> bool + Debug {}

impl<F: Fn(&TaskInfo, &TaskInfo) -> bool + Debug> TaskComparator for F {}

// Used to accept / deny requests for a CID coming from a PeerID
// It should return true if the request should be fullfilled.
pub trait PeerBlockRequestFilter: Fn(&PeerId, &Cid) -> bool + Debug {}

impl<F: Fn(&PeerId, &Cid) -> bool + Debug> PeerBlockRequestFilter for F {}

/// Assigns a specifc score to a peer.
pub trait ScorePeerFunc: Fn(&PeerId, usize) + Send + Sync {}
impl<F: Fn(&PeerId, usize) + Send + Sync> ScorePeerFunc for F {}

#[derive(Debug)]
pub struct Config {
    pub peer_block_request_filter: Option<Box<dyn PeerBlockRequestFilter>>,
    pub task_comparator: Option<Box<dyn TaskComparator>>,
    // TODO: check if this needs to be configurable
    // pub score_ledger: Option<ScoreLedger>,
    pub engine_task_worker_count: usize,
    /// Indicates what to do when the engine receives a want-block
    /// for a block that is not in the blockstore. Either
    /// - Send a DONT_HAVE message
    /// - Simply don't respond
    /// This option is only used for testing.
    // TODO: cfg[test]
    pub send_dont_haves: bool,
    /// Sets the number of worker threads used for blockstore operations in
    /// the decision engine.
    pub engine_blockstore_worker_count: usize,
    pub target_message_size: usize,
    /// escribes approximately how much work we are will to have outstanding to a peer at any
    /// given time.
    /// Setting it to 0 will disable any limiting.
    pub max_outstanding_bytes_per_peer: usize,
    pub max_replace_size: usize,
}

// Note: tagging peers is not supported by rust-libp2p, so currently not implemented

#[derive(Debug)]
pub struct Engine {
    /// Priority queue of requests received from peers.
    peer_task_queue: PeerTaskQueue,
    outbox: (),
    blockstore_manager: BlockstoreManager,
    ledger_map: RwLock<AHashMap<PeerId, Ledger>>,
    /// Tracks which peers are waiting for a Cid,
    peer_ledger: PeerLedger,
    /// Tracks scores for peers.
    score_ledger: DefaultScoreLedger,
    ticker: Duration,
    task_worker_count: usize,
    target_message_size: usize,
    /// The maximum size of the block, in bytes, up to which we will
    /// replace a want-have with a want-block.
    max_block_size_replace_has_with_block: usize,
    send_dont_haves: bool,
    self_id: PeerId,
    // pending_gauge -> iroh-metrics
    // active_guage -> iroh-metrics
    metrics_update_counter: Mutex<usize>, // ?? atomic
    task_comparator: Option<Box<dyn TaskComparator>>,
    peer_block_request_filter: Option<Box<dyn PeerBlockRequestFilter>>,
    bstore_worker_count: usize,
    max_outstanding_bytes_per_peer: usize,
}

impl Engine {
    pub fn new(store: Store, self_id: PeerId, config: Config) -> Self {
        // TODO: insert options for peertaskqueue

        Engine {
            peer_task_queue: PeerTaskQueue::new(),
            outbox: (),
            blockstore_manager: BlockstoreManager::new(
                store,
                config.engine_blockstore_worker_count,
            ),
            ledger_map: Default::default(),
            peer_ledger: PeerLedger::default(),
            score_ledger: DefaultScoreLedger::new(Box::new(|peer, score| {
                if score == 0 {
                    // untag peer("useful")
                } else {
                    // tag peer("useful", score)
                }
            })),
            ticker: Duration::from_millis(100),
            task_worker_count: config.engine_task_worker_count,
            target_message_size: config.target_message_size,
            max_block_size_replace_has_with_block: config.max_replace_size,
            send_dont_haves: config.send_dont_haves,
            self_id,
            metrics_update_counter: Default::default(),
            task_comparator: config.task_comparator,
            peer_block_request_filter: config.peer_block_request_filter,
            bstore_worker_count: config.engine_blockstore_worker_count,
            max_outstanding_bytes_per_peer: config.max_outstanding_bytes_per_peer,
        }
    }

    fn update_metrics(&self) {
        let mut counter = self.metrics_update_counter.lock().unwrap();
        *counter += 1;

        if *counter % 100 == 0 {
            // let stats = self.peer_task_queue.stats();
            // set!(active, stats.num_active)
            // set!(pending, stats.num_pending)
        }
    }

    fn start_score_ledger(&mut self) {
        self.score_ledger.start();
        // TODO: call stop on drop/close
    }

    fn start_blockstore_manager(&mut self) {
        self.blockstore_manager.start();
        // TODO: call stop on drop/close
    }

    /// Start up workers to handle requests from other nodes for the data on this node.
    pub fn start_workers(&mut self) {
        self.start_blockstore_manager();
        self.start_score_ledger();

        for i in 0..self.task_worker_count {
            todo!()
        }
    }

    /// Returns the aggregated data communication for the given peer.
    pub fn ledger_for_peer(&self, peer: &PeerId) -> &Receipt {
        todo!()
        // self.score_ledger.get_receipt(peer)
    }
}
