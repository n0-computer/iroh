use std::{
    fmt::Debug,
    sync::{Arc, Mutex, RwLock},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, bail, Result};
use cid::Cid;
use crossbeam::channel::{Receiver, Sender};
use libp2p::PeerId;
use tracing::{info, warn};

use crate::{
    message::{BitswapMessage, BlockPresence, BlockPresenceType, Entry, WantType},
    peer_task_queue::{PeerTaskQueue, Task},
    Store,
};

use super::{
    blockstore_manager::BlockstoreManager,
    ledger::Ledger,
    peer_ledger::PeerLedger,
    score_ledger::{DefaultScoreLedger, Receipt},
    task_merger::TaskData,
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
    peer_task_queue: PeerTaskQueue<Cid, TaskData>,
    outbox: (Sender<Result<Envelope>>, Receiver<Result<Envelope>>),
    blockstore_manager: Arc<RwLock<BlockstoreManager>>,
    ledger_map: RwLock<AHashMap<PeerId, Arc<Mutex<Ledger>>>>,
    /// Tracks which peers are waiting for a Cid,
    peer_ledger: Mutex<PeerLedger>,
    /// Tracks scores for peers.
    score_ledger: DefaultScoreLedger,
    ticker: Receiver<Instant>,
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
    /// Bus to signal shutdown to all worker threads.
    worker_closer: bus::Bus<()>,
    /// List of handles to worker threads.
    workers: Vec<JoinHandle<()>>,
    work_signal: (Sender<()>, Receiver<()>),
}

impl Engine {
    pub fn new(store: Store, self_id: PeerId, config: Config) -> Self {
        // TODO: insert options for peertaskqueue

        // TODO: limit?
        let outbox = crossbeam::channel::bounded(1024);
        let work_signal = crossbeam::channel::bounded(1024);
        let ticker = crossbeam::channel::tick(Duration::from_millis(100));

        Engine {
            peer_task_queue: PeerTaskQueue::new(),
            outbox,
            blockstore_manager: Arc::new(RwLock::new(BlockstoreManager::new(
                store,
                config.engine_blockstore_worker_count,
            ))),
            ledger_map: Default::default(),
            peer_ledger: Mutex::new(PeerLedger::default()),
            score_ledger: DefaultScoreLedger::new(Box::new(|peer, score| {
                if score == 0 {
                    // untag peer("useful")
                } else {
                    // tag peer("useful", score)
                }
            })),
            ticker,
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
            worker_closer: bus::Bus::new(config.engine_task_worker_count),
            workers: Vec::with_capacity(config.engine_task_worker_count),
            work_signal,
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

    /// Start up workers to handle requests from other nodes for the data on this node.
    pub fn start_workers(&mut self) {
        self.blockstore_manager.write().unwrap().start();
        self.score_ledger.start();

        for _ in 0..self.task_worker_count {
            let outbox = self.outbox.0.clone();
            let mut outer_close = self.worker_closer.add_rx();
            let mut inner_close = self.worker_closer.add_rx();
            let target_message_size = self.target_message_size;
            let peer_task_queue = self.peer_task_queue.clone();
            let ticker = self.ticker.clone();
            let work_signal = self.work_signal.clone();
            let blockstore_manager = self.blockstore_manager.clone();

            let handle = std::thread::spawn(move || {
                while outer_close.try_recv().is_err() {
                    let envelope = next_envelope(
                        work_signal.0.clone(),
                        &work_signal.1,
                        &ticker,
                        &mut inner_close,
                        target_message_size,
                        peer_task_queue.clone(),
                        blockstore_manager.clone(),
                    );
                    outbox.send(envelope).ok();
                }
            });
            self.workers.push(handle);
        }
    }

    /// Shuts down workers.
    pub fn stop_workers(&mut self) -> Result<()> {
        self.blockstore_manager.write().unwrap().stop()?;
        self.score_ledger.stop()?;

        // TODO: should this just be called on drop?
        self.worker_closer.broadcast(());
        while let Some(handle) = self.workers.pop() {
            handle.join().map_err(|e| anyhow!("{:?}", e))?;
        }

        Ok(())
    }

    /// Returns the aggregated data communication for the given peer.
    pub fn ledger_for_peer(&self, peer: &PeerId) -> Option<Receipt> {
        self.score_ledger.receipt(peer)
    }

    /// Returns a list of peers with whom the local node has active sessions.
    pub fn peers(&self) -> AHashSet<PeerId> {
        // TODO: can this avoid the allocation?
        self.ledger_map.read().unwrap().keys().copied().collect()
    }

    /// MessageReceived is called when a message is received from a remote peer.
    /// For each item in the wantlist, add a want-have or want-block entry to the
    /// request queue (this is later popped off by the workerTasks)
    pub fn message_received(&self, peer: &PeerId, message: &BitswapMessage) {
        if message.is_empty() {
            info!("received empty message from {}", peer);
        }

        let mut new_work_exists = false;
        let (wants, cancels, denials) = self.split_wants(peer, message.wantlist());

        // get block sizes
        let mut want_ks = AHashSet::new();
        for entry in &wants {
            want_ks.insert(entry.cid);
        }
        let want_ks: Vec<_> = want_ks.into_iter().collect();
        let block_sizes = match self
            .blockstore_manager
            .read()
            .unwrap()
            .get_block_sizes(&want_ks)
        {
            Ok(s) => s,
            Err(err) => {
                warn!("failed to fetch block sizes: {:?}", err);
                return;
            }
        };

        {
            let mut peer_ledger = self.peer_ledger.lock().unwrap();
            for want in &wants {
                peer_ledger.wants(*peer, want.cid);
            }
            for canel in &cancels {
                peer_ledger.cancel_want(peer, &canel.cid);
            }
        }

        // get the ledger for the peer
        let l = self.find_or_create(peer);
        let mut ledger = l.lock().unwrap();

        // if the peer sent a full wantlist, clear the existing wantlist.
        if message.full() {
            ledger.clear_wantlist();
        }
        let mut active_entries = Vec::new();
        for entry in &cancels {
            if ledger.cancel_want(&entry.cid).is_some() {
                self.peer_task_queue.remove(entry.cid, *peer);
            }
        }

        let send_dont_have = |entries: &mut Vec<_>, new_work_exists: &mut bool, entry: &Entry| {
            // only add the task to the queue if the requester wants DONT_HAVE
            if self.send_dont_haves && entry.send_dont_have {
                let cid = entry.cid;
                *new_work_exists = true;
                let is_want_block = entry.want_type == WantType::Block;
                entries.push(Task {
                    topic: cid,
                    priority: entry.priority as isize,
                    work: BlockPresence::encoded_len_for_cid(cid),
                    data: TaskData {
                        block_size: 0,
                        have_block: false,
                        is_want_block,
                        send_dont_have: entry.send_dont_have,
                    },
                });
            }
        };

        // deny access to blocks
        for entry in &denials {
            send_dont_have(&mut active_entries, &mut new_work_exists, entry);
        }

        // for each want-have/want-block
        for entry in &wants {
            let cid = entry.cid;

            // add each want-have/want-block to the ledger
            ledger.wants(cid, entry.priority, entry.want_type);

            if let Some(block_size) = block_sizes.get(&cid) {
                // the block was found
                new_work_exists = true;
                let is_want_block = self.send_as_block(entry.want_type, *block_size);
                let entry_size = if is_want_block {
                    *block_size
                } else {
                    BlockPresence::encoded_len_for_cid(cid)
                };

                active_entries.push(Task {
                    topic: cid,
                    priority: entry.priority as isize,
                    work: entry_size,
                    data: TaskData {
                        is_want_block,
                        send_dont_have: entry.send_dont_have,
                        block_size: *block_size,
                        have_block: true,
                    },
                });
            } else {
                // if the block was not found
                send_dont_have(&mut active_entries, &mut new_work_exists, entry);
            }
        }

        if !active_entries.is_empty() {
            self.peer_task_queue.push_tasks(*peer, active_entries);
            self.update_metrics();
        }

        if new_work_exists {
            self.signal_new_work();
        }
    }

    pub fn message_sent(&self, peer: &PeerId, message: &BitswapMessage) {
        let l = self.find_or_create(peer);
        let mut ledger = l.lock().unwrap();

        // remove sent blocks from the want list for the peer
        for block in message.blocks() {
            self.score_ledger
                .add_to_sent_bytes(*ledger.partner(), block.data().len());
            ledger
                .wantlist_mut()
                .remove_type(block.cid(), WantType::Block);
        }

        // remove sent block presences from the wantlist for the peer
        for bp in message.block_presences() {
            // don't record sent data, we reserve that for data blocks
            if bp.typ == BlockPresenceType::Have {
                ledger.wantlist_mut().remove_type(&bp.cid, WantType::Have);
            }
        }
    }

    fn split_wants<'a>(
        &self,
        peer: &PeerId,
        entries: impl Iterator<Item = &'a Entry>,
    ) -> (Vec<&'a Entry>, Vec<&'a Entry>, Vec<&'a Entry>) {
        let mut wants = Vec::new();
        let mut cancels = Vec::new();
        let mut denials = Vec::new();

        for entry in entries {
            if entry.cancel {
                cancels.push(entry);
            } else {
                if let Some(ref filter) = self.peer_block_request_filter {
                    if (filter)(peer, &entry.cid) {
                        wants.push(entry);
                    } else {
                        denials.push(entry);
                    }
                } else {
                    wants.push(entry);
                }
            }
        }

        (wants, cancels, denials)
    }

    /// Called when a new peer connects, which means we will start sending blocks to this peer.
    pub fn peer_connected(&self, peer: PeerId) {
        let mut ledger_map = self.ledger_map.write().unwrap();
        let _ = ledger_map
            .entry(peer)
            .or_insert_with(|| Arc::new(Mutex::new(Ledger::new(peer))));

        self.score_ledger.peer_connected(peer);
    }

    /// Called when a peer is disconnected.
    pub fn peer_disconnected(&self, peer: PeerId) {
        let mut ledger_map = self.ledger_map.write().unwrap();
        if let Some(e) = ledger_map.remove(&peer) {
            let mut entry = e.lock().unwrap();
            let mut peer_ledger = self.peer_ledger.lock().unwrap();
            for want in entry.entries() {
                peer_ledger.cancel_want(&peer, &want.cid);
            }
        }

        self.score_ledger.peer_disconnected(&peer);
    }

    fn signal_new_work(&self) {
        self.work_signal.0.send(()).ok();
    }

    fn send_as_block(&self, want_type: WantType, block_size: usize) -> bool {
        let is_want_block = want_type == WantType::Block;
        is_want_block || block_size <= self.max_block_size_replace_has_with_block
    }

    fn find_or_create(&self, peer: &PeerId) -> Arc<Mutex<Ledger>> {
        if !self.ledger_map.read().unwrap().contains_key(peer) {
            self.ledger_map
                .write()
                .unwrap()
                .insert(*peer, Arc::new(Mutex::new(Ledger::new(*peer))));
        }
        self.ledger_map.read().unwrap().get(peer).unwrap().clone()
    }

    fn num_bytes_sent_to(&self, peer: &PeerId) -> u64 {
        self.ledger_for_peer(peer)
            .map(|l| l.sent)
            .unwrap_or_default()
    }

    fn num_bytes_recv_from(&self, peer: &PeerId) -> u64 {
        self.ledger_for_peer(peer)
            .map(|l| l.recv)
            .unwrap_or_default()
    }
}

/// Contains a message for a specific peer.
#[derive(Debug)]
pub struct Envelope {
    pub peer: PeerId,
    pub message: BitswapMessage,
    pub sent_tasks: Vec<Task<Cid, TaskData>>,
    pub queue: PeerTaskQueue<Cid, TaskData>,
    pub work_signal: Sender<()>,
}

/// The work being executed in the task workers.
fn next_envelope(
    work_signal_sender: Sender<()>,
    work_signal_receiver: &Receiver<()>,
    ticker: &Receiver<Instant>,
    inner_close: &mut bus::BusReader<()>,
    target_message_size: usize,
    peer_task_queue: PeerTaskQueue<Cid, TaskData>,
    blockstore_manager: Arc<RwLock<BlockstoreManager>>,
) -> Result<Envelope> {
    loop {
        // pop some tasks off the request queue
        let (mut peer, mut next_tasks, mut pending_bytes) =
            peer_task_queue.pop_tasks(target_message_size);
        // self.update_metrics();

        while next_tasks.is_empty() {
            if inner_close.try_recv().is_ok() {
                bail!("closed before finishing")
            }
            if let Ok(()) = work_signal_receiver.try_recv() {
                let (new_peer, new_tasks, new_pending_bytes) =
                    peer_task_queue.pop_tasks(target_message_size);
                // self.update_metrics();
                peer = new_peer;
                next_tasks = new_tasks;
                pending_bytes = new_pending_bytes;
            }

            if ticker.try_recv().is_ok() {
                // When a task is cancelled, the qeue may be "frozen"
                // for a period of time. We periodically "thaw" the queue
                // to make sure it doesn't get suck in a frozen state.
                peer_task_queue.thaw_round();

                let (new_peer, new_tasks, new_pending_bytes) =
                    peer_task_queue.pop_tasks(target_message_size);
                // self.update_metrics();
                peer = new_peer;
                next_tasks = new_tasks;
                pending_bytes = new_pending_bytes;
            }
        }

        // create a new message
        let mut msg = BitswapMessage::new(false);
        msg.set_pending_bytes(pending_bytes.unwrap_or_default() as _);

        // split out want-blocks, want-have and DONT_HAVEs
        let mut block_cids = Vec::new();
        let mut block_tasks = AHashMap::new();

        for task in &next_tasks {
            if task.data.have_block {
                if task.data.is_want_block {
                    block_cids.push(task.topic);
                    block_tasks.insert(task.topic, task);
                } else {
                    // add HAVEs to the message
                    msg.add_have(task.topic);
                }
            } else {
                // add DONT_HAVEs to the message
                msg.add_dont_have(task.topic);
            }
        }

        // Fetch blocks from the store
        let mut blocks = blockstore_manager.read().unwrap().get_blocks(&block_cids)?;

        for (cid, task) in block_tasks {
            if let Some(block) = blocks.remove(&cid) {
                msg.add_block(block);
            } else {
                // block was not found
                if task.data.send_dont_have {
                    msg.add_dont_have(cid);
                }
            }
        }

        // nothing to see here
        if msg.is_empty() {
            peer_task_queue.tasks_done(peer, &next_tasks);
            continue;
        }

        return Ok(Envelope {
            peer,
            message: msg,
            sent_tasks: next_tasks,
            queue: peer_task_queue,
            work_signal: work_signal_sender,
        });
    }
}
