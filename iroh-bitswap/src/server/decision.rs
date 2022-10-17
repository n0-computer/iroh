use std::{fmt::Debug, sync::Arc, time::Duration};

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, Result};
use cid::Cid;
use iroh_metrics::{bitswap::BitswapMetrics, inc, record};
use libp2p::PeerId;
use tokio::{
    sync::{oneshot, Mutex, Notify, RwLock},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

use crate::{
    block::Block,
    client::wantlist,
    message::{BitswapMessage, BlockPresence, BlockPresenceType, Entry, WantType},
    peer_task_queue::{Config as PTQConfig, PeerTaskQueue, Task},
    Store,
};

use super::{
    blockstore_manager::BlockstoreManager,
    ledger::Ledger,
    peer_ledger::PeerLedger,
    score_ledger::{DefaultScoreLedger, Receipt},
    task_merger::{TaskData, TaskMerger},
};
use iroh_metrics::core::MRecorder;

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

// Used to accept / deny requests for a CID coming from a PeerID
// It should return true if the request should be fullfilled.
pub trait PeerBlockRequestFilter:
    Fn(&PeerId, &Cid) -> bool + Debug + 'static + Sync + Send
{
}

impl<F: Fn(&PeerId, &Cid) -> bool + Debug + 'static + Sync + Send> PeerBlockRequestFilter for F {}

/// Assigns a specifc score to a peer.
pub trait ScorePeerFunc: Fn(&PeerId, usize) + Send + Sync {}
impl<F: Fn(&PeerId, usize) + Send + Sync> ScorePeerFunc for F {}

#[derive(Debug)]
pub struct Config {
    pub peer_block_request_filter: Option<Box<dyn PeerBlockRequestFilter>>,
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

impl Default for Config {
    fn default() -> Self {
        Config {
            peer_block_request_filter: None,
            engine_task_worker_count: 8,
            send_dont_haves: true,
            engine_blockstore_worker_count: 128,
            target_message_size: 16 * 1024,
            max_outstanding_bytes_per_peer: 1 << 20,
            max_replace_size: 1024,
        }
    }
}

// Note: tagging peers is not supported by rust-libp2p, so currently not implemented

#[derive(Debug)]
pub struct Engine<S: Store> {
    /// Priority queue of requests received from peers.
    peer_task_queue: PeerTaskQueue<Cid, TaskData, TaskMerger>,
    outbox: async_channel::Receiver<Result<Envelope>>,
    blockstore_manager: Arc<RwLock<BlockstoreManager<S>>>,
    ledger_map: RwLock<AHashMap<PeerId, Arc<Mutex<Ledger>>>>,
    /// Tracks which peers are waiting for a Cid,
    peer_ledger: Mutex<PeerLedger>,
    /// Tracks scores for peers.
    score_ledger: DefaultScoreLedger,
    /// The maximum size of the block, in bytes, up to which we will
    /// replace a want-have with a want-block.
    max_block_size_replace_has_with_block: usize,
    send_dont_haves: bool,
    // pending_gauge -> iroh-metrics
    // active_guage -> iroh-metrics
    metrics_update_counter: Mutex<usize>, // ?? atomic
    peer_block_request_filter: Option<Box<dyn PeerBlockRequestFilter>>,
    /// List of handles to worker threads.
    workers: Vec<(oneshot::Sender<()>, JoinHandle<()>)>,
    work_signal: Arc<Notify>,
}

impl<S: Store> Engine<S> {
    pub async fn new(store: S, _self_id: PeerId, config: Config) -> Self {
        // TODO: insert options for peertaskqueue

        // TODO: limit?
        let outbox = async_channel::bounded(1024);
        let work_signal = Arc::new(Notify::new());

        let task_merger = TaskMerger::default();
        let peer_task_queue = PeerTaskQueue::new(
            task_merger,
            PTQConfig {
                max_outstanding_work_per_peer: config.max_outstanding_bytes_per_peer,
                ignore_freezing: true,
            },
        );
        let peer_task_hook = peer_task_queue.add_hook(64).await;
        let blockstore_manager = Arc::new(RwLock::new(
            BlockstoreManager::new(store, config.engine_blockstore_worker_count).await,
        ));
        let score_ledger = DefaultScoreLedger::new(Box::new(|_peer, _score| {
            // if score == 0 {
            //     // untag peer("useful")
            // } else {
            //     // tag peer("useful", score)
            // }
        }))
        .await;
        let target_message_size = config.target_message_size;
        let task_worker_count = config.engine_task_worker_count;
        let mut workers = Vec::with_capacity(task_worker_count);

        let rt = tokio::runtime::Handle::current();
        for i in 0..task_worker_count {
            let outbox = outbox.0.clone();
            let (closer_s, mut closer_r) = oneshot::channel();

            let peer_task_queue = peer_task_queue.clone();
            let mut ticker = tokio::time::interval(Duration::from_millis(100));
            let work_signal = work_signal.clone();
            let blockstore_manager = blockstore_manager.clone();
            let peer_task_hook = peer_task_hook.clone();

            let handle = rt.spawn(async move {
                loop {
                    inc!(BitswapMetrics::EngineLoopTick);
                    tokio::select! {
                        biased;
                        _ = &mut closer_r => {
                            break;
                        }
                        event = peer_task_hook.recv() => {
                            debug!("peer queue event: {:?}", event);
                            // TODO: tag/untag peer
                        }
                        _ = work_signal.notified() => {
                            // not needed anymore?
                        }
                        _ = ticker.tick() => {
                            // TODO: remove thaw_round is not used atm
                            // When a task is cancelled, the qeue may be "frozen"
                            // for a period of time. We periodically "thaw" the queue
                            // to make sure it doesn't get suck in a frozen state.
                            // peer_task_queue.thaw_round().await;
                            if let Some((peer, next_tasks, pending_bytes)) = peer_task_queue.pop_tasks(target_message_size).await {
                                if next_tasks.is_empty() {
                                    continue;
                                }
                                debug!("engine:{} next envelope:tick tasks: {}", i, next_tasks.len());

                                // create a new message
                                let mut msg = BitswapMessage::new(false);
                                msg.set_pending_bytes(pending_bytes as _);

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
                                let mut blocks = match blockstore_manager
                                    .read()
                                    .await
                                    .get_blocks(&block_cids)
                                    .await {
                                        Ok(blocks) => blocks,
                                        Err(err) => {
                                            warn!("failed to load blocks: {:?}", err);
                                            continue;
                                        }
                                    };

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
                                    peer_task_queue.tasks_done(peer, &next_tasks).await;
                                    continue;
                                }

                                let envelope = Ok(Envelope {
                                    peer,
                                    message: msg,
                                    sent_tasks: next_tasks,
                                    queue: peer_task_queue.clone(),
                                    work_signal: work_signal.clone(),
                                });
                                if let Err(err) = outbox.send(envelope).await {
                                    error!("failed to deliver envelope: {:?}", err);
                                }
                            }
                        }
                    }
                }
            });
            workers.push((closer_s, handle));
        }

        Engine {
            peer_task_queue,
            outbox: outbox.1,
            blockstore_manager,
            ledger_map: Default::default(),
            peer_ledger: Mutex::new(PeerLedger::default()),
            score_ledger,
            max_block_size_replace_has_with_block: config.max_replace_size,
            send_dont_haves: config.send_dont_haves,
            metrics_update_counter: Default::default(),
            peer_block_request_filter: config.peer_block_request_filter,
            workers,
            work_signal,
        }
    }

    async fn update_metrics(&self) {
        let mut counter = self.metrics_update_counter.lock().await;
        *counter += 1;

        if *counter % 100 == 0 {
            let stats = self.peer_task_queue.stats().await;
            record!(BitswapMetrics::EnginePendingTasks, stats.num_pending as u64);
            record!(BitswapMetrics::EngineActiveTasks, stats.num_active as u64);
        }
    }

    pub fn outbox(&self) -> async_channel::Receiver<Result<Envelope>> {
        self.outbox.clone()
    }

    /// Shuts down.
    pub async fn stop(mut self) -> Result<()> {
        Arc::try_unwrap(self.blockstore_manager)
            .map_err(|_| anyhow!("blockstore manager refs not shutdown"))?
            .into_inner()
            .stop()
            .await?;
        self.score_ledger.stop().await?;

        while let Some((closer, handle)) = self.workers.pop() {
            closer
                .send(())
                .map_err(|e| anyhow!("failed to send close {:?}", e))?;
            handle.await.map_err(|e| anyhow!("{:?}", e))?;
        }

        Ok(())
    }

    pub async fn wantlist_for_peer(&self, peer: &PeerId) -> Vec<wantlist::Entry> {
        let p = self.find_or_create(peer).await;
        let mut partner = p.lock().await;
        partner.wantlist_mut().entries().collect()
    }

    /// Returns the aggregated data communication for the given peer.
    pub async fn ledger_for_peer(&self, peer: &PeerId) -> Option<Receipt> {
        self.score_ledger.receipt(peer).await
    }

    /// Returns a list of peers with whom the local node has active sessions.
    pub async fn peers(&self) -> AHashSet<PeerId> {
        // TODO: can this avoid the allocation?
        self.ledger_map.read().await.keys().copied().collect()
    }

    /// MessageReceived is called when a message is received from a remote peer.
    /// For each item in the wantlist, add a want-have or want-block entry to the
    /// request queue (this is later popped off by the workerTasks)
    pub async fn message_received(&self, peer: &PeerId, message: &BitswapMessage) {
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
            .await
            .get_block_sizes(&want_ks)
            .await
        {
            Ok(s) => s,
            Err(err) => {
                warn!("failed to fetch block sizes: {:?}", err);
                return;
            }
        };

        {
            let mut peer_ledger = self.peer_ledger.lock().await;
            for want in &wants {
                peer_ledger.wants(*peer, want.cid);
            }
            for canel in &cancels {
                peer_ledger.cancel_want(peer, &canel.cid);
            }
        }

        // get the ledger for the peer
        let l = self.find_or_create(peer).await;
        let mut ledger = l.lock().await;

        // if the peer sent a full wantlist, clear the existing wantlist.
        if message.full() {
            ledger.clear_wantlist();
        }
        let mut active_entries = Vec::new();
        for entry in &cancels {
            if ledger.cancel_want(&entry.cid).is_some() {
                self.peer_task_queue.remove(&entry.cid, *peer).await;
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
            self.peer_task_queue.push_tasks(*peer, active_entries).await;
            self.update_metrics().await;
        }

        if new_work_exists {
            self.signal_new_work();
        }
    }

    pub async fn message_sent(&self, peer: &PeerId, message: &BitswapMessage) {
        let l = self.find_or_create(peer).await;
        let mut ledger = l.lock().await;

        // remove sent blocks from the want list for the peer
        for block in message.blocks() {
            self.score_ledger
                .add_to_sent_bytes(ledger.partner(), block.data().len())
                .await;
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
            } else if let Some(ref filter) = self.peer_block_request_filter {
                if (filter)(peer, &entry.cid) {
                    wants.push(entry);
                } else {
                    denials.push(entry);
                }
            } else {
                wants.push(entry);
            }
        }

        (wants, cancels, denials)
    }

    pub async fn received_blocks(&self, from: PeerId, blocks: Vec<Block>) {
        if blocks.is_empty() {
            return;
        }

        let l = self.find_or_create(&from).await;
        let ledger = l.lock().await;
        for block in blocks {
            self.score_ledger
                .add_to_recv_bytes(ledger.partner(), block.data().len())
                .await;
        }
    }

    pub async fn notify_new_blocks(&self, blocks: &[Block]) {
        if blocks.is_empty() {
            return;
        }

        // get the sizes of each block
        let block_sizes: AHashMap<_, _> = blocks
            .iter()
            .map(|block| (block.cid(), block.data().len()))
            .collect();

        let mut work = false;
        let mut missing_wants: AHashMap<PeerId, Vec<Cid>> = AHashMap::new();
        for block in blocks {
            let cid = block.cid();
            let peer_ledger = self.peer_ledger.lock().await;
            let peers = peer_ledger.peers(cid);
            if peers.is_none() {
                continue;
            }
            for peer in peers.unwrap() {
                let l = self.ledger_map.read().await.get(peer).cloned();
                if l.is_none() {
                    missing_wants.entry(*peer).or_default().push(*cid);
                    continue;
                }
                let l = l.unwrap();
                let ledger = l.lock().await;
                let entry = ledger.wantlist_get(cid);
                if entry.is_none() {
                    missing_wants.entry(*peer).or_default().push(*cid);
                    continue;
                }
                let entry = entry.unwrap();

                work = true;
                let block_size = block_sizes.get(cid).copied().unwrap_or_default();
                let is_want_block = self.send_as_block(entry.want_type, block_size);
                let entry_size = if is_want_block {
                    block_size
                } else {
                    BlockPresence::encoded_len_for_cid(*cid)
                };

                self.peer_task_queue
                    .push_task(
                        *peer,
                        Task {
                            topic: entry.cid,
                            priority: entry.priority as isize,
                            work: entry_size,
                            data: TaskData {
                                block_size,
                                have_block: true,
                                is_want_block,
                                send_dont_have: false,
                            },
                        },
                    )
                    .await;
                self.update_metrics().await;
            }
        }

        // If we found missing wants remove them from the list
        if !missing_wants.is_empty() {
            let ledger_map = self.ledger_map.read().await;
            let mut peer_ledger = self.peer_ledger.lock().await;
            for (peer, wants) in missing_wants.into_iter() {
                if let Some(l) = ledger_map.get(&peer) {
                    let ledger = l.lock().await;
                    for cid in wants {
                        if ledger.wantlist_get(&cid).is_some() {
                            continue;
                        }
                        peer_ledger.cancel_want(&peer, &cid);
                    }
                } else {
                    for cid in wants {
                        peer_ledger.cancel_want(&peer, &cid);
                    }
                }
            }
        }

        if work {
            self.signal_new_work();
        }
    }

    /// Called when a new peer connects, which means we will start sending blocks to this peer.
    pub async fn peer_connected(&self, peer: &PeerId) {
        let mut ledger_map = self.ledger_map.write().await;
        let _ = ledger_map
            .entry(*peer)
            .or_insert_with(|| Arc::new(Mutex::new(Ledger::new(*peer))));

        self.score_ledger.peer_connected(peer).await;
    }

    /// Called when a peer is disconnected.
    pub async fn peer_disconnected(&self, peer: &PeerId) {
        let mut ledger_map = self.ledger_map.write().await;
        if let Some(e) = ledger_map.remove(peer) {
            let mut entry = e.lock().await;
            let mut peer_ledger = self.peer_ledger.lock().await;
            for want in entry.entries() {
                peer_ledger.cancel_want(peer, &want.cid);
            }
        }

        self.score_ledger.peer_disconnected(peer).await;
    }

    fn signal_new_work(&self) {
        debug!("signal_new_work");
        self.work_signal.notify_one();
    }

    fn send_as_block(&self, want_type: WantType, block_size: usize) -> bool {
        let is_want_block = want_type == WantType::Block;
        is_want_block || block_size <= self.max_block_size_replace_has_with_block
    }

    async fn find_or_create(&self, peer: &PeerId) -> Arc<Mutex<Ledger>> {
        self.ledger_map
            .write()
            .await
            .entry(*peer)
            .or_insert_with(|| Arc::new(Mutex::new(Ledger::new(*peer))))
            .clone()
    }
}

/// Contains a message for a specific peer.
#[derive(Debug)]
pub struct Envelope {
    pub peer: PeerId,
    pub message: BitswapMessage,
    pub sent_tasks: Vec<Task<Cid, TaskData>>,
    pub queue: PeerTaskQueue<Cid, TaskData, TaskMerger>,
    pub work_signal: Arc<Notify>,
}
