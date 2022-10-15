use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use tokio::sync::RwLock;
use tracing::debug;

use crate::Block;

#[derive(Default, Debug, Clone)]
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
    /// When the client asks the session for blocks, the session calls this methods.
    pub async fn record_session_interest(&self, session: u64, keys: &[Cid]) {
        debug!("session:{} record_session_interest: {:?}", session, keys);
        let wants = &mut *self.wants.write().await;

        for key in keys {
            // Record that the session wants the block.
            wants.entry(*key).or_default().insert(session, true);
        }
    }

    /// When the session shuts down, this is called.
    /// Returns the keys that no session is interested in anymore.
    pub async fn remove_session(&self, session: u64) -> Vec<Cid> {
        debug!("session:{}: remove_session", session);
        let wants = &mut *self.wants.write().await;

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
    pub async fn remove_session_wants(&self, session: u64, keys: &[Cid]) {
        debug!(
            "session:{}: remove_session_wants: {:?}",
            session,
            keys.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        let wants = &mut *self.wants.write().await;

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
    /// Retuns the keys that no session is interested in anymore.
    pub async fn remove_session_interested(&self, session: u64, keys: &[Cid]) -> Vec<Cid> {
        debug!(
            "session:{}: remove_session_interested: {:?}",
            session,
            keys.iter().map(|s| s.to_string()).collect::<Vec<_>>()
        );
        let wants = &mut *self.wants.write().await;

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
    pub async fn filter_session_interested(
        &self,
        session: u64,
        key_sets: &[&[Cid]],
    ) -> Vec<Vec<Cid>> {
        debug!("filter_session_interested",);

        let mut results = Vec::with_capacity(key_sets.len());
        let wants = &*self.wants.read().await;

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
    pub async fn split_wanted_unwanted<'a>(
        &self,
        blocks: &'a [Block],
    ) -> (Vec<&'a Block>, Vec<&'a Block>) {
        debug!("split_wanted_unwantedn",);

        let wants = &*self.wants.read().await;

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
    pub async fn interested_sessions(
        &self,
        blocks: &[Cid],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) -> AHashSet<u64> {
        debug!("interested sessions");
        let wants = &*self.wants.read().await;

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
