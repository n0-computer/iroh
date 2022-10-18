use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use ahash::AHashSet;
use anyhow::{ensure, Result};
use cid::Cid;
use iroh_metrics::core::MRecorder;
use iroh_metrics::{bitswap::BitswapMetrics, inc};
use libp2p::PeerId;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, warn};

use crate::{
    message::{BitswapMessage, Entry, WantType},
    network::{MessageSender, MessageSenderConfig, Network},
};

use self::{dont_have_timeout_manager::DontHaveTimeoutManager, wantlist::Wants};

use super::peer_manager::DontHaveTimeout;

mod dont_have_timeout_manager;
mod wantlist;

#[derive(Debug)]
pub struct MessageQueue {
    peer: PeerId,
    sender_responses: Option<mpsc::Sender<Vec<Cid>>>,
    sender_wants: Option<mpsc::Sender<WantsUpdate>>,
    worker: JoinHandle<()>,
}

#[derive(Debug)]
enum WantsUpdate {
    BroadcastWantHaves(AHashSet<Cid>),
    Wants {
        want_blocks: Vec<Cid>,
        want_haves: Vec<Cid>,
    },
    Cancels(AHashSet<Cid>),
    #[cfg(test)]
    #[allow(dead_code)]
    GetWants(tokio::sync::oneshot::Sender<Wants>),
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
        let (sender_responses, receiver_responses) = mpsc::channel(64);
        let (sender_wants, receiver_wants) = mpsc::channel(2048);

        let actor = MessageQueueActor::new(
            config,
            network,
            peer,
            receiver_responses,
            receiver_wants,
            on_dont_have_timeout,
        )
        .await;

        let worker = tokio::task::spawn(async move { run(actor).await });

        MessageQueue {
            peer,
            sender_responses: Some(sender_responses),
            sender_wants: Some(sender_wants),
            worker,
        }
    }

    pub fn is_running(&self) -> bool {
        if let Some(ref sender) = self.sender_wants {
            !sender.is_closed()
        } else {
            false
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) async fn wants(&self) -> Result<Wants> {
        let (s, r) = tokio::sync::oneshot::channel();
        self.send_wants_update(WantsUpdate::GetWants(s)).await;
        let wants = r.await?;
        Ok(wants)
    }

    /// Add want-haves that are part of a broadcast to all connected peers.
    pub async fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        if want_haves.is_empty() || !self.is_running() {
            return;
        }
        self.send_wants_update(WantsUpdate::BroadcastWantHaves(want_haves.to_owned()))
            .await;
    }

    /// Add want-haves and want-blocks for the peer for this queue.
    pub async fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        debug!("add_wants: {} {}", want_blocks.len(), want_haves.len());
        if (want_blocks.is_empty() && want_haves.is_empty()) || !self.is_running() {
            return;
        }

        self.send_wants_update(WantsUpdate::Wants {
            want_blocks: want_blocks.to_vec(),
            want_haves: want_haves.to_vec(),
        })
        .await;
    }

    /// Add cancel messages for the given keys.
    pub async fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        if cancels.is_empty() || !self.is_running() {
            return;
        }

        self.send_wants_update(WantsUpdate::Cancels(cancels.to_owned()))
            .await;
    }

    async fn send_wants_update(&self, update: WantsUpdate) {
        if let Some(ref sender) = self.sender_wants {
            if let Err(err) = sender.send(update).await {
                warn!(
                    "message_queue:{}: failed to send wants update: {:?}",
                    self.peer, err
                );
            }
        } else {
            warn!(
                "message_queue:{}: failed to send message: not running",
                self.peer
            );
        }
    }

    /// Called when a message is received from the network.
    /// `cids` is the set of blocks, HAVEs and DONT_HAVEs in the message.
    /// Note: this is only use to calculate latency currently.
    pub async fn response_received(&self, cids: Vec<Cid>) {
        if cids.is_empty() || !self.is_running() {
            return;
        }

        // Best effort only
        if let Some(ref sender) = self.sender_responses {
            let _ = sender.try_send(cids);
        }
    }

    /// Shuts down this message queue.
    pub async fn stop(mut self) -> Result<()> {
        ensure!(
            self.sender_responses.is_some(),
            "message queue {} already stopped",
            self.peer
        );
        inc!(BitswapMetrics::MessageQueuesStopped);

        let _ = self.sender_wants.take();
        let _ = self.sender_responses.take();
        // just kill it
        self.worker.abort();
        // self.worker.await?;

        Ok(())
    }
}

async fn run(mut actor: MessageQueueActor) {
    let mut work_scheduled: Option<Instant> = None;
    let mut rebroadcast_timer = tokio::time::interval_at(
        tokio::time::Instant::now() + actor.config.rebroadcast_interval,
        actor.config.rebroadcast_interval,
    );

    let schedule_work = tokio::time::sleep(Duration::from_secs(100));
    tokio::pin!(schedule_work);
    let mut schedule_work_enabled = false;

    loop {
        inc!(BitswapMetrics::MessageQueueWorkerLoopTick);
        tokio::select! {
            biased;

            message = actor.receiver_wants.recv() => {
                debug!("{}: {:?}", actor.peer, message);
                match message {
                    Some(wants_update) => {
                        actor.handle_wants_update(wants_update).await;
                    }
                    None => {
                        // Shutdown
                        break;
                    }
                }
            }
            message = actor.receiver_responses.recv() => {
                debug!("{}: {:?}", actor.peer, message);
                match message {
                    Some(responses) => {
                        actor.handle_response(responses).await;
                    }
                    None => {
                        // Shutdown
                        break;
                    }
                }
            }
            _ = rebroadcast_timer.tick() => {
                if actor.rebroadcast_wantlist().await {
                    // fatal error
                    break;
                }
            }
            Some(when) = actor.outgoing_work.1.recv() => {
                if work_scheduled.is_none() {
                    // No work, record when the work was scheduled.
                    work_scheduled = Some(when);
                } else {
                    // If work is scheduled, make sure timer is cancelled.
                    schedule_work_enabled = false;
                }

                // We have so much work, schedule it immeditately
                let pending_work_count = actor.wants.pending_work_count();
                if pending_work_count > actor.config.send_message_cutoff ||
                    work_scheduled.unwrap().elapsed() >= actor.config.send_message_max_delay {
                        debug!("{}: outgoing work sending", actor.peer);
                        if actor.send_if_ready().await {
                            // fatal error
                            break;
                        }
                        work_scheduled = None;
                    } else {
                        debug!("{}: outgoing work extend timer", actor.peer);
                        // Extend the timer
                        schedule_work.as_mut().reset(tokio::time::Instant::now() + actor.config.send_message_debounce);
                        schedule_work_enabled = true;
                    }
            }
            _ = &mut schedule_work, if schedule_work_enabled => {
                debug!("{}: schedule work", actor.peer);
                work_scheduled = None;
                schedule_work_enabled = false;
                if actor.send_if_ready().await {
                    // fatal error
                    break;
                }
            }
        }
    }

    debug!("{}: message loop shutting down", actor.peer);
    if let Err(err) = actor.stop().await {
        error!(
            "message_queue: failed to stop message queue loop: {:?}",
            err
        );
    }
}

struct MessageQueueActor {
    peer: PeerId,
    config: Config,
    wants: Wants,
    dh_timeout_manager: DontHaveTimeoutManager,
    outgoing_work: (mpsc::Sender<Instant>, mpsc::Receiver<Instant>),
    sender: Option<MessageSender>,
    network: Network,
    msg_sender_config: MessageSenderConfig,
    receiver_responses: mpsc::Receiver<Vec<Cid>>,
    receiver_wants: mpsc::Receiver<WantsUpdate>,
}

impl MessageQueueActor {
    async fn new(
        config: Config,
        network: Network,
        peer: PeerId,
        receiver_responses: mpsc::Receiver<Vec<Cid>>,
        receiver_wants: mpsc::Receiver<WantsUpdate>,
        on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
    ) -> Self {
        let outgoing_work = mpsc::channel(2);
        let wants = Wants {
            bcst_wants: Default::default(),
            peer_wants: Default::default(),
            cancels: Default::default(),
            priority: config.max_priority,
        };

        let dh_timeout_manager = DontHaveTimeoutManager::new(peer, on_dont_have_timeout).await;

        let msg_sender_config = MessageSenderConfig {
            max_retries: config.max_retries,
            send_timeout: config.send_timeout,
            send_error_backoff: config.send_error_backof,
        };
        Self {
            config,
            wants,
            dh_timeout_manager,
            outgoing_work,
            sender: None,
            network,
            msg_sender_config,
            peer,
            receiver_responses,
            receiver_wants,
        }
    }

    async fn stop(self) -> Result<()> {
        self.dh_timeout_manager.stop().await?;
        Ok(())
    }

    async fn handle_wants_update(&mut self, wants_update: WantsUpdate) {
        match wants_update {
            WantsUpdate::BroadcastWantHaves(want_haves) => {
                for cid in want_haves {
                    self.wants
                        .bcst_wants
                        .add(cid, self.wants.priority, WantType::Have);
                    self.wants.priority -= 1;

                    // Adding a want-have for the cid, so clear any pending cancels.
                    self.wants.cancels.remove(&cid);
                }

                self.signal_work();
            }
            WantsUpdate::Wants {
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
                self.signal_work();
            }
            WantsUpdate::Cancels(cancels) => {
                // Cancel any outstanding DONT_HAVE timers
                self.dh_timeout_manager.cancel_pending(&cancels).await;

                let mut work_ready = false;
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

                // Schedule a message send
                if work_ready {
                    self.signal_work();
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
        self.dh_timeout_manager.start(self.network.clone()).await;
        // Convert want lists to a bitswap message
        let (msg, sender, peer_entries, bcst_entries) = match self.extract_outgoing_message().await
        {
            Ok(res) => res,
            Err(err) => {
                debug!(
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
            debug!(
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
            self.signal_work();
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
                    && now - *at < self.config.max_valid_latency
                {
                    earliest = Some(*at);
                }
                self.wants.bcst_wants.clear_sent_at(&cid);
            }
            if let Some(at) = self.wants.peer_wants.sent_at.get(&cid) {
                if (earliest.is_none() || at < earliest.as_ref().unwrap())
                    && now - *at < self.config.max_valid_latency
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
        Vec<super::wantlist::Entry>,
        Vec<super::wantlist::Entry>,
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

        debug!("pending bcst: {:?}", bcst_entries);
        debug!("pending peer: {:?}", peer_entries);
        debug!(
            "pending cancels: {:?}",
            cancels.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
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

            if msg_size >= self.config.max_message_size {
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

                if msg_size >= self.config.max_message_size {
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

                if msg_size >= self.config.max_message_size {
                    break;
                }
            }
        }

        // Finally mark sent and remove any entries from our message that we've decided to cancel at the last minute.
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
                    msg.remove(cancel);
                } else {
                    self.wants.cancels.remove(cancel);
                }
            }
        }
        debug!("got done {}", done);

        Ok((msg, sender, peer_entries, bcst_entries))
    }

    /// Signal the event loop that there is new work.
    fn signal_work(&self) {
        // Ignore error, we only want to make sure the loop is aware that there is work to be done.
        let _ = self.outgoing_work.0.try_send(Instant::now());
    }
}
