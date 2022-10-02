use std::sync::{Arc, RwLock};

use ahash::{AHashMap, AHashSet};
use cid::Cid;

use crate::Block;

#[derive(Debug, Clone)]
pub struct SessionInterestManager {
    /// Map of cids -> sessions -> bool
    ///
    /// The boolean indicates whether the session still wants the block
    /// or is just interested in receiving messages about it.
    ///
    /// Note: Once the block is received the session no longer wants
    /// the block, but still wants to receive messages from peers who have
    /// the block as they may have other blocks the session is interested in.
    wants: Arc<RwLock<AHashMap<Cid, AHashMap<u64, bool>>>>,
}

impl SessionInterestManager {
    pub fn new() -> Self {
        SessionInterestManager {
            wants: Default::default(),
        }
    }

    /// When the client asks the session for blocks, the session calls this methods.
    pub fn record_session_interest(&self, session: u64, keys: &[Cid]) {
        let wants = &mut *self.wants.write().unwrap();

        for key in keys {
            // Record that the session wants the block.
            wants.entry(*key).or_default().insert(session, true);
        }
    }

    /// When the session shuts down, this is called.
    /// Returns the keys that no session is interested in anymore.
    pub fn remove_session(&self, session: u64) -> Vec<Cid> {
        let wants = &mut *self.wants.write().unwrap();

        let mut deleted_keys = Vec::new();
        for (key, wants) in wants.iter_mut() {
            wants.remove(&session);

            if wants.is_empty() {
                deleted_keys.push(*key);
            }
        }
        // cleanup memory
        for key in &deleted_keys {
            wants.remove(key);
        }

        deleted_keys
    }

    /// Called when the session receives blocks.
    pub fn remove_session_wants(&self, session: u64, keys: &[Cid]) {
        let wants = &mut *self.wants.write().unwrap();

        for key in keys {
            if let Some(wants) = wants.get_mut(key) {
                if let Some(wanted) = wants.get_mut(&session) {
                    if *wanted {
                        // Mark as unwanted
                        *wanted = false;
                    }
                }
            }
        }
    }

    /// Called when a request is cancelled.
    /// Retuns the keys taht no session is interested in anymore.
    pub fn remove_session_interested(&self, session: u64, keys: &[Cid]) -> Vec<Cid> {
        let wants = &mut *self.wants.write().unwrap();

        let mut deleted_keys = Vec::new();

        for key in keys {
            if let Some(wants) = wants.get_mut(key) {
                wants.remove(&session);

                if wants.is_empty() {
                    deleted_keys.push(*key);
                }
            }
        }

        // cleanup
        for key in &deleted_keys {
            wants.remove(key);
        }

        deleted_keys
    }

    /// Called to filter the sets of keys for those that the session is interested in.
    pub fn filter_session_interested(&self, session: u64, key_sets: &[&[Cid]]) -> Vec<Vec<Cid>> {
        let mut results = Vec::with_capacity(key_sets.len());
        let wants = &*self.wants.read().unwrap();

        for key_set in key_sets {
            let mut has = Vec::new();

            for key in *key_set {
                if let Some(wants) = wants.get(key) {
                    if wants.get(&session).copied().unwrap_or_default() {
                        has.push(*key);
                    }
                }
            }

            results.push(has);
        }

        results
    }

    /// Splits the list of blocks into wanted and unwanted blocks.
    pub fn split_wanted_unwanted<'a>(
        &self,
        blocks: &'a [Block],
    ) -> (Vec<&'a Block>, Vec<&'a Block>) {
        let wants = &*self.wants.read().unwrap();

        // Get the wanted bock keys as a set
        let mut wanted_keys = AHashSet::new();
        for block in blocks {
            let cid = block.cid();
            if let Some(wants) = wants.get(cid) {
                for wanted in wants.values() {
                    if *wanted {
                        wanted_keys.insert(*cid);
                    }
                }
            }
        }

        let mut wanted_blocks = Vec::new();
        let mut not_wanted_blocks = Vec::new();

        for block in blocks {
            if wanted_keys.contains(block.cid()) {
                wanted_blocks.push(block);
            } else {
                not_wanted_blocks.push(block);
            }
        }

        (wanted_blocks, not_wanted_blocks)
    }

    /// Returns a list of interested sessions given the message.
    pub fn interested_sessions(
        &self,
        blocks: &[Cid],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) -> AHashSet<u64> {
        let wants = &*self.wants.read().unwrap();

        let mut session_keys = AHashSet::new();
        let keys = blocks.iter().chain(haves.iter()).chain(dont_haves.iter());
        for key in keys {
            if let Some(wants) = wants.get(key) {
                for session in wants.keys() {
                    session_keys.insert(*session);
                }
            }
        }

        session_keys
    }
}
