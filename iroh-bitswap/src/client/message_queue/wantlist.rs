use std::time::Instant;

use ahash::{AHashMap, AHashSet};
use cid::Cid;

use crate::{
    client::wantlist::Wantlist,
    message::{Priority, WantType},
};

#[derive(Debug, Clone)]
pub struct Wants {
    pub bcst_wants: RecallWantlist,
    pub peer_wants: RecallWantlist,
    pub cancels: AHashSet<Cid>,
    pub priority: i32,
}

impl Wants {
    /// Wether there is work to be processed.
    pub fn has_pending_work(&self) -> bool {
        self.pending_work_count() > 0
    }

    /// The amount of work that is waiting to be processed.
    pub fn pending_work_count(&self) -> usize {
        self.bcst_wants.pending.len() + self.peer_wants.pending.len() + self.cancels.len()
    }
}

#[derive(Debug, Default, Clone)]
pub struct RecallWantlist {
    /// List of wants that have not yet been sent.
    pub pending: Wantlist,
    /// The list of wants that have been sent.
    pub sent: Wantlist,
    /// The time at which each want was sent.
    pub sent_at: AHashMap<Cid, Instant>,
}

impl RecallWantlist {
    /// Adds a want to the pending list.
    pub fn add(&mut self, cid: Cid, priority: Priority, want_type: WantType) {
        self.pending.add(cid, priority, want_type);
    }

    /// Removes wants from both pending and sent list.
    pub fn remove(&mut self, cid: &Cid) {
        self.pending.remove(cid);
        self.sent.remove(cid);
        self.sent_at.remove(cid);
    }

    /// Removes wants from both pending and sent list, by type.
    pub fn remove_type(&mut self, cid: &Cid, want_type: WantType) {
        self.pending.remove_type(cid, want_type);
        if self.sent.remove_type(cid, want_type).is_some() {
            self.sent_at.remove(cid);
        }
    }

    /// Moves the want from pending to sent.
    ///
    /// Returns true if the want was marked as sent, false if the want wasn't
    /// pending to begin with.
    pub fn mark_sent(&mut self, e: &crate::client::wantlist::Entry) -> bool {
        if self.pending.remove_type(&e.cid, e.want_type).is_none() {
            return false;
        }
        self.sent.add(e.cid, e.priority, e.want_type);
        true
    }

    /// Clears out the recorded sent time.
    pub fn clear_sent_at(&mut self, cid: &Cid) {
        self.sent_at.remove(cid);
    }

    pub fn sent_at(&mut self, cid: Cid, at: Instant) {
        if !self.sent.contains(&cid) {
            self.sent_at.insert(cid, at);
        }
    }
}
