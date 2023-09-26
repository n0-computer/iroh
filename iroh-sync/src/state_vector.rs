//! State vector

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::AuthorId;

/// State vector for a replica
///
/// Contains the timestamp for the latest entry for each author.
///
// TODO: compressed binary storage if many authors, eg by hashing "old" authors.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Default)]
pub struct StateVector {
    heads: BTreeMap<AuthorId, u64>,
}

impl StateVector {
    /// Insert a new timestamp.
    pub fn insert(&mut self, author: AuthorId, timestamp: u64) {
        self.heads
            .entry(author)
            .and_modify(|t| *t = (*t).max(timestamp))
            .or_insert(timestamp);
    }
}

impl StateVector {
    /// Can this state vector offer newer stuff to `other`?
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

    /// Merge another state vector into this one.
    pub fn merge(&mut self, other: &Self) {
        for (a, t) in other.iter() {
            self.insert(*a, *t);
        }
    }

    /// Create an iterator over the entries in this state vector.
    pub fn iter(&self) -> std::collections::btree_map::Iter<AuthorId, u64> {
        self.heads.iter()
    }
}

/// Progress tracker for sync runs.
#[derive(Debug, Clone, Default)]
pub struct SyncProgress {
    ///
    pub state_vector: StateVector,
    ///
    pub entries_recv: usize,
    ///
    pub entries_sent: usize,
}
