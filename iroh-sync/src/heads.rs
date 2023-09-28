//! State vector

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::AuthorId;

/// Timestamps of the latest entry for each author.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct AuthorHeads {
    heads: BTreeMap<AuthorId, u64>,
}

impl AuthorHeads {
    /// Insert a new timestamp.
    pub fn insert(&mut self, author: AuthorId, timestamp: u64) {
        self.heads
            .entry(author)
            .and_modify(|t| *t = (*t).max(timestamp))
            .or_insert(timestamp);
    }
}

impl AuthorHeads {
    /// Can this state offer newer stuff to `other`?
    pub fn has_news_for(&self, other: &Self) -> bool {
        for (a, t) in self.heads.iter() {
            match other.heads.get(a) {
                None => return true,
                Some(ot) => {
                    if t > ot {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Merge another author head state into this one.
    pub fn merge(&mut self, other: &Self) {
        for (a, t) in other.iter() {
            self.insert(*a, *t);
        }
    }

    /// Create an iterator over the entries in this state.
    pub fn iter(&self) -> std::collections::btree_map::Iter<AuthorId, u64> {
        self.heads.iter()
    }
}

/// Outcome of a sync operation.
#[derive(Debug, Clone, Default)]
pub struct SyncOutcome {
    /// Timestamp of the latest entry for each author in the set we received.
    pub heads_received: AuthorHeads,
    /// Number of entries we received.
    pub num_recv: usize,
    /// Number of entries we sent.
    pub num_sent: usize,
}
