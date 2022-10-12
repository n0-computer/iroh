use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use anyhow::{ensure, Result};
use cid::Cid;
use libp2p::PeerId;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

use crate::{
    message::{BitswapMessage, Entry, WantType},
    network::{MessageSender, MessageSenderConfig, Network},
    Priority,
};

use self::dont_have_timeout_manager::DontHaveTimeoutManager;

use super::{
    peer_manager::DontHaveTimeout,
    wantlist::{self, Wantlist},
};

mod dont_have_timeout_manager;

#[derive(Debug)]
pub struct MessageQueue {
    peer: PeerId,
    running: Arc<AtomicBool>,
    responses: mpsc::Sender<Vec<Cid>>,
    closer: oneshot::Sender<()>,
    worker: JoinHandle<()>,
    wants_sender: mpsc::Sender<WantsUpdate>,
}

#[derive(Debug)]
enum WantsUpdate {
    AddBroadcastWantHaves(AHashSet<Cid>),
    AddWants {
        want_blocks: Vec<Cid>,
        want_haves: Vec<Cid>,
    },
    AddCancels(AHashSet<Cid>),
    #[cfg(test)]
    GetWants(tokio::sync::oneshot::Sender<Wants>),
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
        let (closer_s, mut closer_r) = oneshot::channel();
        let (responses_sender, mut responses_receiver) = mpsc::channel(8);
        let (outgoing_work_sender, mut outgoing_work_receiver) = mpsc::channel(4);
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
        let running = Arc::new(AtomicBool::new(true));

        let nt = network.clone();
        let wants = Wants {
            bcst_wants: Default::default(),
            peer_wants: Default::default(),
            cancels: Default::default(),
            priority: config.max_priority,
        };

        let (wants_s, mut wants_r) = mpsc::channel(64);

        let running_thread = running.clone();
        let worker = tokio::task::spawn(async move {
            let mut work_scheduled: Option<Instant> = None;
            let mut rebroadcast_timer = tokio::time::interval(config.rebroadcast_interval);
            let schedule_work = tokio::time::sleep(Duration::from_secs(0));
            tokio::pin!(schedule_work);
            let running = running_thread;

            let mut loop_state = LoopState::new(
                wants,
                dh_timeout_manager,
                max_message_size,
                max_valid_latency,
                outgoing_work_sender,
                nt,
                MessageSenderConfig {
                    max_retries,
                    send_timeout,
                    send_error_backoff,
                },
                peer,
            );

            loop {
                tokio::select! {
                    biased;
                    _ = &mut closer_r => {
                        info!("message_queue:{}: shutting down, close received", peer);
                        break;
                    }
                    wants_update = wants_r.recv() => {
                        match wants_update {
                            Some(wants_update) => {
                                loop_state.handle_wants_update(wants_update).await;
                            }
                            None => {
                                // shutting down
                                break;
                            }
                        }
                    }
                    _ = rebroadcast_timer.tick() => {
                        debug!("message_queue:{}: rebroadcast wantlist", peer);
                        if loop_state.rebroadcast_wantlist().await {
                            // fatal error
                            break;
                        }
                    }
                    when = outgoing_work_receiver.recv() => {
                        if work_scheduled.is_none() {
                            work_scheduled = when;
                        }

                        let pending_work_count = loop_state.wants.pending_work_count();
                        debug!("message_queue:{}: outgoing work receiver: {:?} {} {:?}", peer, work_scheduled.unwrap().elapsed(), pending_work_count, send_message_max_delay);

                        if pending_work_count > send_message_cutoff
                            || work_scheduled.unwrap().elapsed() >= send_message_max_delay {
                                if loop_state.send_if_ready().await {
                                    // fatal error
                                    break;
                                }
                                work_scheduled = None;
                            } else {
                                // Extend the timer
                                schedule_work.as_mut().reset(tokio::time::Instant::now() + send_message_debounce);
                            }
                    }
                    _ = &mut schedule_work, if work_scheduled.is_some() => {
                        debug!("message_queue:{}: schedule work", peer);
                        work_scheduled = None;
                        if loop_state.send_if_ready().await {
                            // fatal error
                            break;
                        }
                    }
                    response = responses_receiver.recv() => {
                        match response {
                            Some(response) => {
                                // Received a response from the peer, calculate latency.
                                loop_state.handle_response(response).await;
                            }
                            None => {
                                error!("message_queue:{}: shutting down, repsonse receiver error", peer);
                                break;
                            }
                        }
                    }
                }
            }

            running.store(false, Ordering::Relaxed);
            if let Err(err) = loop_state.stop().await {
                error!(
                    "message_queue:{}: failed to stop message queue loop: {:?}",
                    peer, err
                );
            }
        });

        MessageQueue {
            peer,
            running,
            responses: responses_sender,
            worker,
            wants_sender: wants_s,
            closer: closer_s,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) async fn wants(&self) -> Result<Wants> {
        let (s, r) = tokio::sync::oneshot::channel();
        self.wants_sender.send(WantsUpdate::GetWants(s)).await?;
        let wants = r.await?;
        Ok(wants)
    }

    /// Add want-haves that are part of a broadcast to all connected peers.
    pub async fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        debug!(
            "message_queue:{}: adding broadcast wants to message queue {:?}",
            self.peer, want_haves
        );
        if want_haves.is_empty() {
            return;
        }
        self.send_wants_update(WantsUpdate::AddBroadcastWantHaves(want_haves.to_owned()))
            .await;
    }

    /// Add want-haves and want-blocks for the peer for this queue.
    pub async fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        if want_blocks.is_empty() && want_haves.is_empty() {
            return;
        }

        self.send_wants_update(WantsUpdate::AddWants {
            want_blocks: want_blocks.to_vec(),
            want_haves: want_haves.to_vec(),
        })
        .await;
    }

    /// Add cancel messages for the given keys.
    pub async fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        if cancels.is_empty() {
            return;
        }

        self.send_wants_update(WantsUpdate::AddCancels(cancels.to_owned()))
            .await;
    }

    async fn send_wants_update(&self, update: WantsUpdate) {
        if self.is_running() {
            if let Err(err) = self.wants_sender.send(update).await {
                warn!(
                    "message_queue:{}: failed to send wants update (is_running: {}): {:?}",
                    self.peer,
                    self.is_running(),
                    err
                );
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

        if let Err(err) = self.responses.send(cids).await {
            warn!(
                "message_queue:{}: unable to send responses: {:?}",
                self.peer, err
            );
        }
    }

    pub async fn stop(self) -> Result<()> {
        debug!("message_queue:{}: stopping message queue", self.peer);
        if self.closer.send(()).is_ok() {
            self.worker.await?;
        }
        ensure!(
            self.running.load(Ordering::Relaxed) == false,
            "failed to shutdown"
        );
        Ok(())
    }
}

struct LoopState {
    wants: Wants,
    dh_timeout_manager: DontHaveTimeoutManager,
    max_message_size: usize,
    max_valid_latency: Duration,
    outgoing_work_sender: mpsc::Sender<Instant>,
    sender: Option<MessageSender>,
    network: Network,
    msg_sender_config: MessageSenderConfig,
    peer: PeerId,
}

impl LoopState {
    fn new(
        wants: Wants,
        dh_timeout_manager: DontHaveTimeoutManager,
        max_message_size: usize,
        max_valid_latency: Duration,
        outgoing_work_sender: mpsc::Sender<Instant>,
        network: Network,
        msg_sender_config: MessageSenderConfig,
        peer: PeerId,
    ) -> Self {
        Self {
            wants,
            dh_timeout_manager,
            max_message_size,
            max_valid_latency,
            outgoing_work_sender,
            sender: None,
            network,
            msg_sender_config,
            peer,
        }
    }

    async fn stop(self) -> Result<()> {
        self.dh_timeout_manager.stop().await?;
        Ok(())
    }

    async fn handle_wants_update(&mut self, wants_update: WantsUpdate) {
        match wants_update {
            WantsUpdate::AddBroadcastWantHaves(want_haves) => {
                for cid in want_haves {
                    self.wants
                        .bcst_wants
                        .add(cid, self.wants.priority, WantType::Have);
                    self.wants.priority -= 1;

                    // Adding a want-have for the cid, so clear any pending cancels.
                    self.wants.cancels.remove(&cid);
                }

                if let Err(err) = self.outgoing_work_sender.try_send(Instant::now()) {
                    warn!("unable to send outgoing work: {:?}", err);
                }
            }
            WantsUpdate::AddWants {
                want_blocks,
                want_haves,
            } => {
                for cid in want_haves {
                    self.wants
                        .peer_wants
                        .add(cid, self.wants.priority, WantType::Have);
                    self.wants.priority -= 1;

                    // Adding a want-have for the cid, so clear any pending cancels.
                    self.wants.cancels.remove(&cid);
                }

                for cid in want_blocks {
                    self.wants
                        .peer_wants
                        .add(cid, self.wants.priority, WantType::Block);
                    self.wants.priority -= 1;

                    // Adding a want-block for the cid, so clear any pending cancels.
                    self.wants.cancels.remove(&cid);
                }
            }
            WantsUpdate::AddCancels(cancels) => {
                // Cancel any outstanding DONT_HAVE timers
                self.dh_timeout_manager.cancel_pending(&cancels).await;

                let mut work_ready = false;
                {
                    // Remove keys from broadcast and peer wants, and add to cancels.
                    for cid in cancels {
                        // Check if a want for the key was sent
                        let was_sent_bcst = self.wants.bcst_wants.sent.contains(&cid);
                        let was_sent_peer = self.wants.peer_wants.sent.contains(&cid);

                        // Remove the want from tracking wantlist
                        self.wants.bcst_wants.remove(&cid);
                        self.wants.peer_wants.remove(&cid);

                        // Only send a cancel if a want was sent
                        if was_sent_bcst || was_sent_peer {
                            self.wants.cancels.insert(cid);
                            work_ready = true;
                        }
                    }
                }

                // Schedule a message send
                if work_ready {
                    if let Err(err) = self.outgoing_work_sender.try_send(Instant::now()) {
                        warn!("unable to send outgoing work: {:?}", err);
                    }
                }
            }
            #[cfg(test)]
            WantsUpdate::GetWants(r) => r.send(self.wants.clone()).unwrap(),
        }
    }

    async fn rebroadcast_wantlist(&mut self) -> bool {
        if self.transfer_rebroadcast_wants().await {
            return self.send_message().await;
        }
        false
    }

    /// Transfer wants from the rebroadcast lists into the pending lists.
    async fn transfer_rebroadcast_wants(&mut self) -> bool {
        // Check if there are any wants to rebroadcast.
        if self.wants.bcst_wants.sent.is_empty() && self.wants.peer_wants.sent.is_empty() {
            return false;
        }

        // Copy sent wants into pending wants lists
        self.wants
            .bcst_wants
            .pending
            .extend(self.wants.bcst_wants.sent.clone());
        self.wants
            .peer_wants
            .pending
            .extend(self.wants.peer_wants.sent.clone());

        true
    }

    async fn send_message(&mut self) -> bool {
        // Convert want lists to a bitswap message
        let (msg, sender, peer_entries, bcst_entries) = match self.extract_outgoing_message().await
        {
            Ok(res) => res,
            Err(err) => {
                error!(
                    "message_queue:{}: failed to prepare message: {:?}",
                    self.peer, err
                );
                return true;
            }
        };
        if msg.is_empty() {
            return false;
        }

        let wantlist: Vec<_> = msg.wantlist().cloned().collect();
        if let Err(err) = sender.send_message(msg).await {
            error!(
                "message_queue:{}: failed to send message {:?}",
                self.peer, err
            );
            return true;
        }

        // Record sent time so as to calculate message latency.
        // Update state after the message has been sent.
        {
            let now = Instant::now();
            for e in peer_entries {
                self.wants.peer_wants.sent_at(e.cid, now);
            }
            for e in bcst_entries {
                self.wants.bcst_wants.sent_at(e.cid, now);
            }
        };

        // Set a timer to wait for responses.
        self.simulate_dont_have_with_timeout(wantlist).await;

        // If the message was too big and only a subset of wants could be sent
        // schedule sending the rest of the wants in the next iteration of the event loop.
        if self.wants.has_pending_work() {
            if let Err(err) = self.outgoing_work_sender.try_send(Instant::now()) {
                warn!(
                    "message_queue:{}: unable to send outgoing work: {:?}",
                    self.peer, err
                );
            }
        }
        false
    }

    async fn simulate_dont_have_with_timeout(&mut self, wantlist: Vec<Entry>) {
        // Get the Cid of each want-block that expects a DONT_HAVE reponse.
        let pending_wants: Vec<Cid> = wantlist
            .iter()
            .filter_map(|entry| {
                if entry.want_type == WantType::Block && entry.send_dont_have {
                    // check if the block was already sent
                    if self.wants.peer_wants.sent.contains(&entry.cid) {
                        return Some(entry.cid);
                    }
                }
                None
            })
            .collect();

        // Add wants to DONT_HAVE timeout manger
        self.dh_timeout_manager.add_pending(&pending_wants).await;
    }

    async fn send_if_ready(&mut self) -> bool {
        debug!("message_queue:{}: send if ready", self.peer);
        if self.wants.has_pending_work() {
            return self.send_message().await;
        }
        false
    }

    async fn handle_response(&mut self, response: Vec<Cid>) {
        let now = Instant::now();
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
            if let Some(at) = self.wants.bcst_wants.sent_at.get(&cid) {
                if (earliest.is_none() || at < earliest.as_ref().unwrap())
                    && now - *at < self.max_valid_latency
                {
                    earliest = Some(*at);
                }
                self.wants.bcst_wants.clear_sent_at(&cid);
            }
            if let Some(at) = self.wants.peer_wants.sent_at.get(&cid) {
                if (earliest.is_none() || at < earliest.as_ref().unwrap())
                    && now - *at < self.max_valid_latency
                {
                    earliest = Some(*at);
                    // Clear out the sent time, as we want to only record the latency
                    // between the request and the first response.
                    self.wants.peer_wants.clear_sent_at(&cid);
                }
            }
        }

        if let Some(earliest) = earliest {
            self.dh_timeout_manager
                .update_message_latency(now - earliest)
                .await;
        }
    }

    /// Convert the lists of wants into a bitswap message
    async fn extract_outgoing_message(
        &mut self,
    ) -> Result<(
        BitswapMessage,
        &MessageSender,
        Vec<wantlist::Entry>,
        Vec<wantlist::Entry>,
    )> {
        if self.sender.is_none() {
            let sender = self
                .network
                .new_message_sender(self.peer, self.msg_sender_config.clone())
                .await?;
            self.sender = Some(sender);
        }
        let sender = self.sender.as_ref().unwrap();

        let supports_have = sender.supports_have();

        let (mut peer_entries, mut bcst_entries, mut cancels) = {
            let mut peer_entries: Vec<_> = self.wants.peer_wants.pending.entries().collect();
            if !supports_have {
                // Remove want haves
                peer_entries.retain(|entry| {
                    if entry.want_type == WantType::Have {
                        self.wants
                            .peer_wants
                            .remove_type(&entry.cid, WantType::Have);
                        false
                    } else {
                        true
                    }
                });
            }
            let bcst_entries: Vec<_> = self.wants.bcst_wants.pending.entries().collect();
            let cancels: Vec<_> = self.wants.cancels.iter().cloned().collect();
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

            if msg_size >= self.max_message_size {
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

                if msg_size >= self.max_message_size {
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

                if msg_size >= self.max_message_size {
                    break;
                }
            }
        }

        // Finally  retake the lock, makr sent and remove any entries from our message
        // that we've decided to cancel at the last minute.
        {
            // shorten to actually sent
            peer_entries.truncate(sent_peer_entries);
            peer_entries.retain(|entry| {
                if !self.wants.peer_wants.mark_sent(entry) {
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
                if !self.wants.bcst_wants.mark_sent(entry) {
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
                if !self.wants.cancels.contains(cancel) {
                    msg.remove(&cancel);
                } else {
                    self.wants.cancels.remove(cancel);
                }
            }
        }

        Ok((msg, sender, peer_entries, bcst_entries))
    }
}
