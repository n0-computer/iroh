use std::{
    fmt::Display,
    time::{Duration, Instant},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use rand::{thread_rng, Rng};

use super::cid_queue::CidQueue;

/// `live_wants_order` and `live_wants` will get out of sync as blocks are received.
/// This constant is the maximum amount to allow them to be out of sync before
/// cleaning up the ordering array.
const LIVE_WANTS_ORDER_GC_LIMIT: usize = 32;

#[derive(Debug)]
/// Keeps track of which cids are waiting to be sent out, and which
///peers are "live" - ie, we've sent a request but haven't received a block yet.
pub struct SessionWants {
    /// The wants that have not yet been sent out.
    to_fetch: CidQueue,
    /// Wants that have been sent but have not received a response.
    live_wants: AHashMap<Cid, Instant>,
    /// The order in which wants were requested
    live_wants_order: Vec<Cid>,
    /// The maximum number of want-haves to send in a broadcast
    broadcast_limit: usize,
}

impl Display for SessionWants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pending / {} live",
            self.to_fetch.len(),
            self.live_wants.len()
        )
    }
}

impl SessionWants {
    pub fn new(broadcast_limit: usize) -> Self {
        SessionWants {
            to_fetch: Default::default(),
            live_wants: Default::default(),
            live_wants_order: Default::default(),
            broadcast_limit,
        }
    }

    /// Called when the client makes a request for blocks
    pub fn blocks_requested(&mut self, new_wants: &[Cid]) {
        for cid in new_wants {
            self.to_fetch.push(*cid);
        }
    }

    /// Called when the session has not yet discovered peers with
    /// the blocks that it wants. It moves as many CIDs from the fetch queue to
    /// the live wants queue as possible (given the broadcast limit).
    ///
    /// Returns the newly live wants.
    pub fn get_next_wants(&mut self) -> AHashSet<Cid> {
        let now = Instant::now();

        // Move cids from fetch queue to the live wants queue (up to the broadcast limit)
        let current_live_count = self.live_wants.len();
        let to_add = self.broadcast_limit - current_live_count;

        let mut live = AHashSet::new();

        for _ in 0..to_add {
            if let Some(cid) = self.to_fetch.pop() {
                live.insert(cid);
                self.live_wants_order.push(cid);
                self.live_wants.insert(cid, now);
            } else {
                // no more available
                break;
            }
        }

        live
    }

    /// Called when wants are sent to a peer.
    pub fn wants_sent(&mut self, keys: &[Cid]) {
        let now = Instant::now();
        for key in keys {
            if !self.live_wants.contains_key(key) && self.to_fetch.has(key) {
                self.to_fetch.remove(key);
                self.live_wants_order.push(*key);
                self.live_wants.insert(*key, now);
            }
        }
    }

    /// Removes received block CIDs from the live wants list and
    /// measures latency. It returns the CIDs of blocks that were actually
    /// wanted (as opposed to duplicates) and the total latency for all incoming blocks.
    pub fn blocks_received(&mut self, keys: &[Cid]) -> (Vec<Cid>, Duration) {
        let mut wanted = Vec::with_capacity(keys.len());
        let mut total_latency = Duration::default();

        // Filter for blocks that were actually wanted (as opposed to duplicates)
        let now = Instant::now();
        for key in keys {
            if self.is_wanted(key) {
                wanted.push(*key);

                // Measure latency
                if let Some(sent_at) = self.live_wants.get(key) {
                    total_latency += now - *sent_at;
                }

                // Remove the CID from the live wants / toFetch queue
                self.live_wants.remove(key);
                self.to_fetch.remove(key);
            }
        }

        // If the live wants ordering array is a long way out of sync with the
        // live wants map, clean up the ordering array
        if self.live_wants_order.len() - self.live_wants.len() > LIVE_WANTS_ORDER_GC_LIMIT {
            self.live_wants_order
                .retain(|key| self.live_wants.contains_key(key));
        }

        (wanted, total_latency)
    }

    /// Saves the current time for each live want and returns the live want cids up
    /// to the broadcast limit.
    pub fn prepare_broadcast(&mut self) -> AHashSet<Cid> {
        let now = Instant::now();
        let mut live = AHashSet::with_capacity(self.live_wants.len());
        for key in &self.live_wants_order {
            if let Some(want) = self.live_wants.get_mut(key) {
                // No response was received for the want, so reset the sent time
                // to now as we're about to broadcast
                *want = now;
                live.insert(*key);
                if live.len() == self.broadcast_limit {
                    break;
                }
            }
        }

        live
    }

    /// Removes the given CIDs from the fetch queue.
    pub fn cancel_pending(&mut self, keys: &[Cid]) {
        for key in keys {
            self.to_fetch.remove(key);
        }
    }

    /// Returns a randomly selected live want
    pub fn random_live_want(&self) -> Option<Cid> {
        if self.live_wants.is_empty() {
            return None;
        }

        // Picking a random live want
        let mut rng = thread_rng();
        let i = rng.gen_range(0..self.live_wants.len());
        self.live_wants.keys().nth(i).copied()
    }

    /// Has live wants indicates if there are any live wants.
    pub fn has_live_wants(&self) -> bool {
        !self.live_wants.is_empty()
    }

    /// Indicates whether the want is in either of the fetch or live queues.
    fn is_wanted(&self, key: &Cid) -> bool {
        if !self.live_wants.contains_key(key) {
            self.to_fetch.has(key)
        } else {
            true
        }
    }
}
