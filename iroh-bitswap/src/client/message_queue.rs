use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::{ping::PingResult, PeerId};

use crate::{
    message::{BitswapMessage, Entry, WantType},
    network::Network,
    Priority,
};

use self::dont_have_timeout_manager::DontHaveTimeoutManager;

use super::wantlist::Wantlist;

mod dont_have_timeout_manager;

#[derive(Debug, Clone)]
pub struct MessageQueue {
    // TODO: likely need an Arc<lock>
    self_id: PeerId,
    network: Network,
    send_error_backoff: Duration,
    max_valid_latency: Duration,
    wants: Arc<Mutex<Wants>>,

    /// Cached message to reuse memory
    msg: BitswapMessage,

    dh_timeout_manager: DontHaveTimeoutManager,
}

#[derive(Debug, Clone)]
struct Wants {
    bcst_wants: RecallWantlist,
    peer_wants: RecallWantlist,
    cancels: AHashSet<Cid>,
    priority: i32,
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_message_size: 1024 * 1024 * 2,
            send_error_backof: Duration::from_millis(100),
            max_valid_latency: Duration::from_secs(30),
            max_priority: i32::MAX,
        }
    }
}

impl MessageQueue {
    pub fn new(self_id: PeerId, network: Network) -> Self {
        // TODO: register on_donthave_timeout
        Self::with_config(self_id, network, Config::default())
    }

    pub fn with_config(self_id: PeerId, network: Network, config: Config) -> Self {
        MessageQueue {
            self_id,
            network,
            send_error_backoff: config.send_error_backof,
            max_valid_latency: config.max_valid_latency,
            wants: Arc::new(Mutex::new(Wants {
                bcst_wants: Default::default(),
                peer_wants: Default::default(),
                cancels: Default::default(),
                priority: config.max_priority,
            })),
            msg: Default::default(),
            dh_timeout_manager: DontHaveTimeoutManager::new(),
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

        self.signal_work_ready()
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

        // TODO
    }

    // TODO: merge into new
    pub fn startup(&mut self) {
        // TODO
    }

    pub fn response_received(&self, cids: &[Cid]) {
        // TODO
    }

    pub fn shutdown(self) {
        // TODO
    }

    fn signal_work_ready(&self) {
        todo!()
    }
}
