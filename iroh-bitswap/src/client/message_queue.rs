use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use anyhow::{anyhow, Result};
use cid::Cid;
use futures::Future;
use libp2p::PeerId;
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};
use tracing::{error, info, warn};

use crate::{
    message::{BitswapMessage, Entry, WantType},
    network::{MessageSender, MessageSenderConfig, Network},
    Priority,
};

use self::dont_have_timeout_manager::DontHaveTimeoutManager;

use super::{peer_manager::DontHaveTimeout, wantlist::Wantlist};

mod dont_have_timeout_manager;

#[derive(Debug, Clone)]
pub struct MessageQueue {
    inner: Arc<Inner>,
    dh_timeout_manager: DontHaveTimeoutManager,
    pub(crate) wants: Arc<Mutex<Wants>>,
}

#[derive(Debug)]
struct Inner {
    responses: mpsc::Sender<Vec<Cid>>,
    closer: mpsc::Sender<()>,
    worker: Option<JoinHandle<anyhow::Result<()>>>,
    outgoing_work_sender: mpsc::Sender<Instant>,
}

#[derive(Debug, Clone)]
pub(crate) struct Wants {
    pub(crate) bcst_wants: RecallWantlist,
    pub(crate) peer_wants: RecallWantlist,
    pub(crate) cancels: AHashSet<Cid>,
    pub(crate) priority: i32,
}

impl Wants {
    /// Wether there is work to be processed.
    fn has_pending_work(&self) -> bool {
        self.pending_work_count() > 0
    }

    /// The amount of work that is waiting to be processed.
    fn pending_work_count(&self) -> usize {
        self.bcst_wants.pending.len() + self.peer_wants.pending.len() + self.cancels.len()
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct RecallWantlist {
    /// List of wants that have not yet been sent.
    pub(crate) pending: Wantlist,
    /// The list of wants that have been sent.
    pub(crate) sent: Wantlist,
    /// The time at which each want was sent.
    pub(crate) sent_at: AHashMap<Cid, Instant>,
}

impl RecallWantlist {
    /// Adds a want to the pending list.
    fn add(&mut self, cid: Cid, priority: Priority, want_type: WantType) {
        self.pending.add(cid, priority, want_type);
    }

    /// Removes wants from both pending and sent list.
    fn remove(&mut self, cid: &Cid) {
        self.pending.remove(cid);
        self.sent.remove(cid);
        self.sent_at.remove(cid);
    }

    /// Removes wants from both pending and sent list, by type.
    fn remove_type(&mut self, cid: &Cid, want_type: WantType) {
        self.pending.remove_type(cid, want_type);
        if self.sent.remove_type(cid, want_type).is_some() {
            self.sent_at.remove(cid);
        }
    }

    /// Moves the want from pending to sent.
    ///
    /// Returns true if the want was marked as sent, false if the want wasn't
    /// pending to begin with.
    fn mark_sent(&mut self, e: &crate::client::wantlist::Entry) -> bool {
        if self.pending.remove_type(&e.cid, e.want_type).is_none() {
            return false;
        }
        self.sent.add(e.cid, e.priority, e.want_type);
        true
    }

    /// Clears out the recorded sent time.
    fn clear_sent_at(&mut self, cid: &Cid) {
        self.sent_at.remove(cid);
    }

    fn sent_at(&mut self, cid: Cid, at: Instant) {
        if !self.sent.contains(&cid) {
            self.sent_at.insert(cid, at);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// The time to w ait before retrying to connect after an error,
    /// when trying to send a message.
    pub send_error_backof: Duration,
    /// Maximum amount of time in which to accept a response as being valid
    /// for latency calculation (as opposed to discarding it as an outlier).
    pub max_valid_latency: Duration,
    /// Maximum priority allowed in the network.
    pub max_priority: i32,
    pub rebroadcast_interval: Duration,
    pub send_message_max_delay: Duration,
    pub send_message_cutoff: usize,
    pub send_message_debounce: Duration,
    pub send_timeout: Duration,
    pub max_retries: usize,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_message_size: 1024 * 1024 * 2,
            send_error_backof: Duration::from_millis(100),
            max_valid_latency: Duration::from_secs(30),
            max_priority: i32::MAX,
            rebroadcast_interval: Duration::from_secs(30),
            send_message_max_delay: Duration::from_millis(20),
            send_message_cutoff: 256,
            send_message_debounce: Duration::from_millis(1),
            send_timeout: Duration::from_secs(30),
            max_retries: 3,
        }
    }
}

impl MessageQueue {
    pub async fn new(
        peer: PeerId,
        network: Network,
        on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
    ) -> Self {
        Self::with_config(peer, network, Config::default(), on_dont_have_timeout).await
    }

    pub async fn with_config(
        peer: PeerId,
        network: Network,
        config: Config,
        on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
    ) -> Self {
        let (closer_sender, mut closer_receiver) = mpsc::channel(1);
        let (responses_sender, mut responses_receiver) = mpsc::channel(8);
        let (outgoing_work_sender, mut outgoing_work_receiver) = mpsc::channel(4);
        let wants = Arc::new(Mutex::new(Wants {
            bcst_wants: Default::default(),
            peer_wants: Default::default(),
            cancels: Default::default(),
            priority: config.max_priority,
        }));
        let send_message_max_delay = config.send_message_max_delay;
        let send_message_cutoff = config.send_message_cutoff;
        let send_message_debounce = config.send_message_debounce;
        let max_valid_latency = config.max_valid_latency;
        let dh_timeout_manager =
            DontHaveTimeoutManager::new(peer, network.clone(), on_dont_have_timeout).await;
        let max_retries = config.max_retries;
        let max_message_size = config.max_message_size;
        let send_timeout = config.send_timeout;
        let send_error_backoff = config.send_error_backof;
        let closer = closer_sender.clone();

        let dhtm = dh_timeout_manager.clone();
        let wants_thread = wants.clone();
        let nt = network.clone();
        let outgoing_work_sender_thread = outgoing_work_sender.clone();

        let rt = tokio::runtime::Handle::current();
        let worker = rt.spawn(async move {
            let mut work_scheduled: Option<Instant> = None;
            let mut rebroadcast_timer = tokio::time::interval(config.rebroadcast_interval);
            let schedule_work = tokio::time::sleep(Duration::from_secs(0));
            tokio::pin!(schedule_work);
            let wants = wants_thread;
            let dh_timeout_manager = dhtm;
            let network = nt;
            let outgoing_work_sender = outgoing_work_sender_thread;
            let mut sender = None;
            let msg_sender_config = MessageSenderConfig {
                max_retries,
                send_timeout,
                send_error_backoff,
            };

            loop {
                tokio::select! {
                    _ = rebroadcast_timer.tick() => {
                        rebroadcast_wantlist(
                            &wants,
                            &closer,
                            &dh_timeout_manager,
                            max_message_size,
                            &outgoing_work_sender,
                            &mut sender,
                            &network,
                            &msg_sender_config,
                            peer,
                        ).await;
                    }
                    when = outgoing_work_receiver.recv() => {
                        if work_scheduled.is_none() {
                            work_scheduled = when;
                        }

                        let pending_work_count = wants.lock().await.pending_work_count();
                        if pending_work_count > send_message_cutoff
                            || work_scheduled.unwrap().elapsed() >= send_message_max_delay {
                                send_if_ready(
                                    &wants,
                                    &closer,
                                    &dh_timeout_manager,
                                    max_message_size,
                                    &outgoing_work_sender,
                                    &mut sender,
                                    &network,
                                    &msg_sender_config,
                                    peer,
                                ).await;
                                work_scheduled = None;
                            } else {
                                // Extend the timer
                                Pin::set(&mut schedule_work, tokio::time::sleep(send_message_debounce));
                            }
                    }
                    _ = &mut schedule_work => {
                        work_scheduled = None;
                        send_if_ready(
                            &wants,
                            &closer,
                            &dh_timeout_manager,
                            max_message_size,
                            &outgoing_work_sender,
                            &mut sender,
                            &network,
                            &msg_sender_config,
                            peer,
                        ).await;
                    }
                    response = responses_receiver.recv() => {
                        match response {
                            Some(response) => {
                                // Received a response from the peer, calculate latency.
                                handle_response(&wants, max_valid_latency, &dh_timeout_manager,  response).await;
                            }
                            None => {
                                error!("shutting down, repsonse receiver error");
                                break;
                            }
                        }
                    }
                    _ = closer_receiver.recv() => {
                        info!("shutting down, close received");
                        break;
                    }
                }
            }
            Ok(())
        });

        MessageQueue {
            inner: Arc::new(Inner {
                responses: responses_sender,
                closer: closer_sender,
                worker: Some(worker),
                outgoing_work_sender,
            }),
            dh_timeout_manager,
            wants,
        }
    }

    /// Add want-haves that are part of a broadcast to all connected peers.
    pub async fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        if want_haves.is_empty() {
            return;
        }
        let wants = &mut *self.wants.lock().await;
        for cid in want_haves {
            wants.bcst_wants.add(*cid, wants.priority, WantType::Have);
            wants.priority -= 1;

            // Adding a want-have for the cid, so clear any pending cancels.
            wants.cancels.remove(cid);
        }

        if let Err(err) = self.inner.outgoing_work_sender.send(Instant::now()).await {
            warn!("unable to send outgoing work: {:?}", err);
        }
    }

    /// Add want-haves and want-blocks for the peer for this queue.
    pub async fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        if want_blocks.is_empty() && want_haves.is_empty() {
            return;
        }

        let wants = &mut *self.wants.lock().await;
        for cid in want_haves {
            wants.peer_wants.add(*cid, wants.priority, WantType::Have);
            wants.priority -= 1;

            // Adding a want-have for the cid, so clear any pending cancels.
            wants.cancels.remove(cid);
        }

        for cid in want_blocks {
            wants.peer_wants.add(*cid, wants.priority, WantType::Block);
            wants.priority -= 1;

            // Adding a want-block for the cid, so clear any pending cancels.
            wants.cancels.remove(cid);
        }
    }

    /// Add cancel messages for the given keys.
    pub async fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        if cancels.is_empty() {
            return;
        }

        // Cancel any outstanding DONT_HAVE timers
        self.dh_timeout_manager.cancel_pending(cancels).await;

        let mut work_ready = false;
        {
            let wants = &mut *self.wants.lock().await;

            // Remove keys from broadcast and peer wants, and add to cancels.
            for cid in cancels {
                // Check if a want for the key was sent
                let was_sent_bcst = wants.bcst_wants.sent.contains(cid);
                let was_sent_peer = wants.peer_wants.sent.contains(cid);

                // Remove the want from tracking wantlist
                wants.bcst_wants.remove(cid);
                wants.peer_wants.remove(cid);

                // Only send a cancel if a want was sent
                if was_sent_bcst || was_sent_peer {
                    wants.cancels.insert(*cid);
                    work_ready = true;
                }
            }
        }

        // Schedule a message send
        if work_ready {
            if let Err(err) = self.inner.outgoing_work_sender.send(Instant::now()).await {
                warn!("unable to send outgoing work: {:?}", err);
            }
        }
    }

    /// Called when a message is received from the network.
    /// `cids` is the set of blocks, HAVEs and DONT_HAVEs in the message.
    /// Note: this is only use to calculate latency currently.
    pub async fn response_received(&self, cids: Vec<Cid>) {
        if cids.is_empty() {
            return;
        }

        if let Err(err) = self.inner.responses.send(cids).await {
            warn!("unable to send responses: {:?}", err);
        }
    }

    pub async fn stop(self) -> Result<()> {
        println!("stopping message queue");
        match self.inner.closer.send(()).await {
            Ok(_) => {
                println!("waiting for worker");
                Arc::try_unwrap(self.inner)
                    .map_err(|_| anyhow!("message queue refs not shutdown"))?
                    .worker
                    .take()
                    .ok_or_else(|| anyhow!("missing worker"))?
                    .await??;
                self.dh_timeout_manager.stop().await?;
            }
            Err(err) => {
                error!("failed to shutdown message queue: {:?}", err);
            }
        }
        Ok(())
    }
}

async fn rebroadcast_wantlist(
    wants: &Arc<Mutex<Wants>>,
    closer: &mpsc::Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    max_message_size: usize,
    outgoing_work_sender: &mpsc::Sender<Instant>,
    sender: &mut Option<MessageSender>,
    network: &Network,
    msg_sender_config: &MessageSenderConfig,
    peer: PeerId,
) {
    if transfer_rebroadcast_wants(wants).await {
        send_message(
            wants,
            closer,
            dh_timeout_manager,
            max_message_size,
            outgoing_work_sender,
            sender,
            network,
            msg_sender_config,
            peer,
        )
        .await;
    }
}

/// Transfer wants from the rebroadcast lists into the pending lists.
async fn transfer_rebroadcast_wants(wants: &Arc<Mutex<Wants>>) -> bool {
    let wants = &mut *wants.lock().await;

    // Check if there are any wants to rebroadcast.
    if wants.bcst_wants.sent.is_empty() && wants.peer_wants.sent.is_empty() {
        return false;
    }

    // Copy sent wants into pending wants lists
    wants.bcst_wants.pending.extend(&wants.bcst_wants.sent);
    wants.peer_wants.pending.extend(&wants.peer_wants.sent);

    true
}

async fn send_message(
    wants: &Arc<Mutex<Wants>>,
    closer: &mpsc::Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    max_message_size: usize,
    outgoing_work_sender: &mpsc::Sender<Instant>,
    sender: &mut Option<MessageSender>,
    network: &Network,
    msg_sender_config: &MessageSenderConfig,
    peer: PeerId,
) {
    if sender.is_none() {
        match network.new_message_sender(peer, msg_sender_config.clone()) {
            Ok(s) => *sender = Some(s),
            Err(err) => {
                error!("failed to dial, unable to send message: {:?}", err);
                return;
            }
        }
    }
    let sender = sender.as_ref().unwrap();
    // Convert want lists to a bitswap message
    let (msg, on_sent) =
        extract_outgoing_message(wants, max_message_size, sender.supports_have()).await;
    if msg.is_empty() {
        return;
    }

    let wantlist: Vec<_> = msg.wantlist().cloned().collect();
    if let Err(err) = sender.send_message(msg) {
        warn!("failed to send message {:?}", err);
        closer.send(()).await.ok();
        return;
    }

    // Record sent time so as to calculate message latency.
    on_sent.await;

    // Set a timer to wait for responses.
    simulate_dont_have_with_timeout(&wantlist, wants, dh_timeout_manager).await;

    // If the message was too big and only a subset of wants could be sent
    // schedule sending the rest of the wants in the next iteration of the event loop.
    if wants.lock().await.has_pending_work() {
        outgoing_work_sender.send(Instant::now()).await.ok();
    }
}

async fn simulate_dont_have_with_timeout(
    wantlist: &[Entry],
    wants: &Arc<Mutex<Wants>>,
    dh_timeout_manager: &DontHaveTimeoutManager,
) {
    let wants = &mut *wants.lock().await;

    // Get the Cid of each want-block that expects a DONT_HAVE reponse.
    let pending_wants: Vec<Cid> = wantlist
        .iter()
        .filter_map(|entry| {
            if entry.want_type == WantType::Block && entry.send_dont_have {
                // check if the block was already sent
                if wants.peer_wants.sent.contains(&entry.cid) {
                    return Some(entry.cid);
                }
            }
            None
        })
        .collect();

    drop(wants);

    // Add wants to DONT_HAVE timeout manger
    dh_timeout_manager.add_pending(&pending_wants).await;
}

async fn send_if_ready(
    wants: &Arc<Mutex<Wants>>,
    closer: &mpsc::Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    max_message_size: usize,
    outgoing_work_sender: &mpsc::Sender<Instant>,
    sender: &mut Option<MessageSender>,
    network: &Network,
    msg_sender_config: &MessageSenderConfig,
    peer: PeerId,
) {
    if wants.lock().await.has_pending_work() {
        send_message(
            wants,
            closer,
            dh_timeout_manager,
            max_message_size,
            outgoing_work_sender,
            sender,
            network,
            msg_sender_config,
            peer,
        )
        .await;
    }
}

async fn handle_response(
    wants: &Arc<Mutex<Wants>>,
    max_valid_latency: Duration,
    dh_timeout_manager: &DontHaveTimeoutManager,
    response: Vec<Cid>,
) {
    let now = Instant::now();
    let wants = &mut *wants.lock().await;

    // Check if the keys in the response correspond to any request that was sent to the peer.
    //
    // - Finde the earliest request so as to calculate the longest latency as we want
    //   to be conservative when setting the timeout.
    // - Ignore latencies that are very long, as these are likely to be outliers caused when
    //   - we send a want to pere A
    //   - peer A does not have the block
    //   - peer A later receives the block from peer B
    //   - peer A sends us HAVE/block

    let mut earliest = None;
    for cid in response {
        if let Some(at) = wants.bcst_wants.sent_at.get(&cid) {
            if (earliest.is_none() || at < earliest.as_ref().unwrap())
                && now - *at < max_valid_latency
            {
                earliest = Some(*at);
            }
            wants.bcst_wants.clear_sent_at(&cid);
        }
        if let Some(at) = wants.peer_wants.sent_at.get(&cid) {
            if (earliest.is_none() || at < earliest.as_ref().unwrap())
                && now - *at < max_valid_latency
            {
                earliest = Some(*at);
                // Clear out the sent time, as we want to only record the latency
                // between the request and the first response.
                wants.peer_wants.clear_sent_at(&cid);
            }
        }
    }

    drop(wants);

    if let Some(earliest) = earliest {
        dh_timeout_manager
            .update_message_latency(now - earliest)
            .await;
    }
}

/// Convert the lists of wants into a bitswap message
async fn extract_outgoing_message(
    wants: &Arc<Mutex<Wants>>,
    max_message_size: usize,
    supports_have: bool,
) -> (BitswapMessage, impl Future<Output = ()>) {
    let (mut peer_entries, mut bcst_entries, mut cancels) = {
        let wants = &mut *wants.lock().await;
        let mut peer_entries: Vec<_> = wants.peer_wants.pending.entries().collect();
        if !supports_have {
            // Remove want haves
            peer_entries.retain(|entry| {
                if entry.want_type == WantType::Have {
                    wants.peer_wants.remove_type(&entry.cid, WantType::Have);
                    false
                } else {
                    true
                }
            });
        }
        let bcst_entries: Vec<_> = wants.bcst_wants.pending.entries().collect();
        let cancels: Vec<_> = wants.cancels.iter().cloned().collect();
        (peer_entries, bcst_entries, cancels)
    };

    // We prioritize cancels, then regular wants, then broadcast wants.

    let mut msg_size = 0;
    let mut sent_cancels = 0;
    let mut sent_peer_entries = 0;
    let mut sent_bcst_entries = 0;
    let mut done = false;

    let mut msg = BitswapMessage::default();

    // add cancels
    for c in &cancels {
        msg_size += msg.cancel(*c);
        sent_cancels += 1;

        if msg_size >= max_message_size {
            done = true;
            break;
        }
    }

    if !done {
        // add wants, if there are too many entires for a single message, sort by
        // by priority.
        for entry in &peer_entries {
            msg_size += msg.add_entry(entry.cid, entry.priority, entry.want_type, true);
            sent_peer_entries += 1;

            if msg_size >= max_message_size {
                done = true;
                break;
            }
        }
    }

    if !done {
        // add each broadcast want-have to the message

        for entry in &bcst_entries {
            // Broadcast wants are sent as want-have
            let want_type = if supports_have {
                WantType::Have
            } else {
                WantType::Block
            };

            msg_size += msg.add_entry(entry.cid, entry.priority, want_type, false);
            sent_bcst_entries += 1;

            if msg_size >= max_message_size {
                break;
            }
        }
    }

    // Finally  retake the lock, makr sent and remove any entries from our message
    // that we've decided to cancel at the last minute.
    {
        let wants = &mut *wants.lock().await;

        // shorten to actually sent
        peer_entries.truncate(sent_peer_entries);
        peer_entries.retain(|entry| {
            if !wants.peer_wants.mark_sent(entry) {
                // It changed
                msg.remove(&entry.cid);
                false
            } else {
                true
            }
        });

        // shorten to actually sent
        bcst_entries.truncate(sent_bcst_entries);
        bcst_entries.retain(|entry| {
            if !wants.bcst_wants.mark_sent(entry) {
                // It changed
                msg.remove(&entry.cid);
                false
            } else {
                true
            }
        });

        // shorten to actually sent
        cancels.truncate(sent_cancels);
        for cancel in &cancels {
            if !wants.cancels.contains(cancel) {
                msg.remove(&cancel);
            } else {
                wants.cancels.remove(cancel);
            }
        }
    }

    // Update state after the message has been sent.
    let wants = wants.clone();
    let on_sent = async move {
        let now = Instant::now();
        let wants = &mut *wants.lock().await;

        for e in peer_entries {
            wants.peer_wants.sent_at(e.cid, now);
        }
        for e in bcst_entries {
            wants.bcst_wants.sent_at(e.cid, now);
        }
    };
    (msg, on_sent)
}
