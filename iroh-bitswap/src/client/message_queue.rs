use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use crossbeam::channel::Sender;
use libp2p::{ping::PingResult, PeerId};

use crate::{
    message::{BitswapMessage, Entry, WantType},
    network::{MessageSender, MessageSenderConfig, Network},
    Priority,
};

use self::dont_have_timeout_manager::DontHaveTimeoutManager;

use super::wantlist::Wantlist;

mod dont_have_timeout_manager;

#[derive(Debug, Clone)]
pub struct MessageQueue {
    // TODO: likely need an Arc<lock>
    peer: PeerId,
    network: Network,
    send_error_backoff: Duration,
    max_valid_latency: Duration,
    responses: Sender<Vec<Cid>>,
    closer: Sender<()>,
    wants: Arc<Mutex<Wants>>,

    dh_timeout_manager: DontHaveTimeoutManager,
}

#[derive(Debug, Clone)]
struct Wants {
    bcst_wants: RecallWantlist,
    peer_wants: RecallWantlist,
    cancels: AHashSet<Cid>,
    priority: i32,
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
struct RecallWantlist {
    /// List of wants that have not yet been sent.
    pending: Wantlist,
    /// The list of wants that have been sent.
    sent: Wantlist,
    /// The time at which each want was sent.
    sent_at: AHashMap<Cid, Instant>,
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
    fn mark_sent(&mut self, e: Entry) -> bool {
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
}

#[derive(Debug)]
struct PeerConn {
    peer: PeerId,
    network: Network,
}

impl PeerConn {
    fn new(peer: PeerId, network: Network) -> Self {
        PeerConn { peer, network }
    }

    fn ping(&self) -> PingResult {
        self.network.ping(&self.peer)
    }

    fn latency(&self) -> Duration {
        self.network.latency(&self.peer)
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
    pub fn new(peer: PeerId, network: Network) -> Self {
        // TODO: register on_donthave_timeout
        Self::with_config(peer, network, Config::default())
    }

    pub fn with_config(peer: PeerId, network: Network, config: Config) -> Self {
        let (closer_sender, closer_receiver) = crossbeam::channel::bounded(1);
        let (responses_sender, responses_receiver) = crossbeam::channel::bounded(8);
        let (outgoing_work_sender, outgoing_work_receiver) = crossbeam::channel::bounded(1);
        let wants = Arc::new(Mutex::new(Wants {
            bcst_wants: Default::default(),
            peer_wants: Default::default(),
            cancels: Default::default(),
            priority: config.max_priority,
        }));
        let send_message_max_delay = config.send_message_max_delay;
        let send_message_cutoff = config.send_message_cutoff;
        let send_message_debounce = config.send_message_debounce;
        let dh_timeout_manager = DontHaveTimeoutManager::new();
        let max_retries = config.max_retries;
        let send_timeout = config.send_timeout;
        let send_error_backoff = config.send_error_backof;
        let closer = closer_sender.clone();

        let dhtm = dh_timeout_manager.clone();
        let wants_thread = wants.clone();
        let nt = network.clone();

        let handle: JoinHandle<anyhow::Result<()>> = std::thread::spawn(move || {
            let mut work_scheduled: Option<Instant> = None;
            let rebroadcast_timer = crossbeam::channel::tick(config.rebroadcast_interval);
            let mut schedule_work = crossbeam::channel::after(Duration::from_secs(0));
            let wants = wants_thread;
            let dh_timeout_manager = dhtm;
            let network = nt;
            let sender = network.new_message_sender(
                peer,
                MessageSenderConfig {
                    max_retries,
                    send_timeout,
                    send_error_backoff,
                },
            )?;

            loop {
                crossbeam::channel::select! {
                    recv(rebroadcast_timer) -> _ => {
                        rebroadcast_wantlist(&wants, &closer, &dh_timeout_manager, &sender);
                    }
                    recv(outgoing_work_receiver) -> when => {
                        if work_scheduled.is_none() {
                            work_scheduled = when.ok();
                        }

                        let pending_work_count = wants.lock().unwrap().pending_work_count();
                        if pending_work_count > send_message_cutoff
                            || work_scheduled.unwrap().elapsed() >= send_message_max_delay {
                                send_if_ready(&wants, &closer, &dh_timeout_manager, &sender);
                                work_scheduled = None;
                            } else {
                                // Extend the timer
                                schedule_work = crossbeam::channel::after(send_message_debounce);
                            }
                    }
                    recv(schedule_work) -> _ => {
                        work_scheduled = None;
                        send_if_ready(&wants, &closer, &dh_timeout_manager, &sender);
                    }
                    recv(responses_receiver) -> response => {
                        // Received a response from the peer, calculate latency.
                        handle_response(response.unwrap());
                    }
                    recv(closer_receiver) -> _ => {
                        break;
                    }
                }
            }
            Ok(())
        });

        // TODO: track thread

        MessageQueue {
            peer,
            network,
            send_error_backoff: config.send_error_backof,
            max_valid_latency: config.max_valid_latency,
            responses: responses_sender,
            wants,
            closer: closer_sender,
            dh_timeout_manager,
        }
    }

    /// Add want-haves that are part of a broadcast to all connected peers.
    pub fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        if want_haves.is_empty() {
            return;
        }
        let wants = &mut *self.wants.lock().unwrap();
        for cid in want_haves {
            wants.bcst_wants.add(*cid, wants.priority, WantType::Have);
            wants.priority -= 1;

            // Adding a want-have for the cid, so clear any pending cancels.
            wants.cancels.remove(cid);
        }

        signal_work_ready()
    }

    /// Add want-haves and want-blocks for the peer for this queue.
    pub fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        if want_blocks.is_empty() && want_haves.is_empty() {
            return;
        }

        let wants = &mut *self.wants.lock().unwrap();
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
    pub fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        if cancels.is_empty() {
            return;
        }

        // Cancel any outstanding DONT_HAVE timers
        self.dh_timeout_manager.cancel_pending(cancels);

        let mut work_ready = false;
        let wants = &mut *self.wants.lock().unwrap();

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
        drop(wants);

        // Schedule a message send
        if work_ready {
            signal_work_ready();
        }
    }

    /// Called when a message is received from the network.
    /// `cids` is the set of blocks, HAVEs and DONT_HAVEs in the message.
    /// Note: this is only use to calculate latency currently.
    pub fn response_received(&self, cids: Vec<Cid>) {
        if cids.is_empty() {
            return;
        }

        self.responses.send(cids).ok();
    }

    pub fn shutdown(self) {
        self.closer.send(()).ok();
    }
}

fn rebroadcast_wantlist(
    wants: &Arc<Mutex<Wants>>,
    closer: &Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    sender: &MessageSender,
) {
    if transfer_rebroadcast_wants(wants) {
        send_message(wants, closer, dh_timeout_manager, sender);
    }
}

/// Transfer wants from the rebroadcast lists into the pending lists.
fn transfer_rebroadcast_wants(wants: &Arc<Mutex<Wants>>) -> bool {
    let wants = &mut *wants.lock().unwrap();

    // Check if there are any wants to rebroadcast.
    if wants.bcst_wants.sent.is_empty() && wants.peer_wants.sent.is_empty() {
        return false;
    }

    // Copy sent wants into pending wants lists
    wants.bcst_wants.pending.extend(&wants.bcst_wants.sent);
    wants.peer_wants.pending.extend(&wants.peer_wants.sent);

    true
}

fn send_message(
    wants: &Arc<Mutex<Wants>>,
    closer: &Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    sender: &MessageSender,
) {
    // TODO: check donthave timeout manager is running

    // Convert want lists to a bitswap message
    let (msg, on_sent) = extract_outgoing_message(sender.supports_have());
    if msg.is_empty() {
        return;
    }

    let wantlist: Vec<_> = msg.wantlist().cloned().collect();
    if let Err(err) = sender.send_message(msg) {
        closer.send(()).ok();
        return;
    }

    // Record sent time so as to calculate message latency.
    on_sent();

    // Set a timer to wait for responses.
    simulate_dont_have_with_timeout(&wantlist, wants, dh_timeout_manager);

    // If the message was too big and only a subset of wants could be sent
    // schedule sending the rest of the wants in the next iteration of the event loop.
    if wants.lock().unwrap().has_pending_work() {
        signal_work_ready();
    }
}

fn simulate_dont_have_with_timeout(
    wantlist: &[Entry],
    wants: &Arc<Mutex<Wants>>,
    dh_timeout_manager: &DontHaveTimeoutManager,
) {
    let wants = &mut *wants.lock().unwrap();

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
    dh_timeout_manager.add_pending(&pending_wants);
}

fn send_if_ready(
    wants: &Arc<Mutex<Wants>>,
    closer: &Sender<()>,
    dh_timeout_manager: &DontHaveTimeoutManager,
    sender: &MessageSender,
) {
    if wants.lock().unwrap().has_pending_work() {
        send_message(wants, closer, dh_timeout_manager, sender);
    }
}

fn handle_response(response: Vec<Cid>) {
    todo!()
}

fn extract_outgoing_message(supports_have: bool) -> (BitswapMessage, impl Fn() -> ()) {
    let mut msg = BitswapMessage::default();
    // TODO

    (msg, || {})
}

fn signal_work_ready() {
    todo!()
}
