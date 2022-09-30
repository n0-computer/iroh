use std::sync::{Arc, RwLock};

use ahash::AHashMap;
use libp2p::PeerId;
use rand::{thread_rng, Rng};

/// Keeps track of how many times each peer was the first to send us a block for a
/// given cid (used to rank peers)
#[derive(Default, Debug, Clone)]
pub struct PeerResponseTracker {
    first_responder: Arc<RwLock<AHashMap<PeerId, usize>>>,
}

impl PeerResponseTracker {
    /// Ccalled when a block is received from a peer (only called first time block is received)
    pub fn received_block_from(&self, from: &PeerId) {
        *self
            .first_responder
            .write()
            .unwrap()
            .entry(*from)
            .or_default() += 1;
    }

    // Picks a peer from the list of candidate peers, favouring those peers
    // that were first to send us previous blocks.
    pub fn choose(&self, peers: &[PeerId]) -> Option<PeerId> {
        if peers.is_empty() {
            return None;
        }

        let mut rng = thread_rng();
        let rnd: f64 = rng.gen();

        // Find the total received blocks for all candidate peers
        let total: f64 = peers.iter().map(|p| self.get_peer_count(p) as f64).sum();

        // Choose one of the peers with a chance proportional to the number
        // of blocks received from that peer
        let mut counted = 0.0;
        for peer in peers {
            counted += self.get_peer_count(peer) as f64 / total;
            if counted > rnd {
                return Some(*peer);
            }
        }

        // We shouldn't get here unless there is some weirdness with floating point
        // math that doesn't quite cover the whole range of peers in the for loop
        // so just choose the last peer.
        peers.iter().last().copied()
    }

    /// Returns the number of times the peer was first to send us a block.
    pub fn get_peer_count(&self, peer: &PeerId) -> usize {
        // Make sure there is always at least a small chance a new peer
        // will be chosen
        self.first_responder
            .read()
            .unwrap()
            .get(peer)
            .copied()
            .unwrap_or(1)
    }
}
