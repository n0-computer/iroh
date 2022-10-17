use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::PeerId;
use tracing::{debug, error};

use super::message_queue::MessageQueue;
use super::peer_manager::PeerState;

/// Keeps track of which want-haves and want-blocks have been sent to each peer,
/// in order to avoid the `PeerManager` sending duplicates.
#[derive(Debug, Default)]
pub struct PeerWantManager {
    /// Maps peers to outstanding wants.
    /// A peers wants is the _union_ of the broadcast wants and the wants in this list.
    peer_wants: AHashMap<PeerId, PeerWant>,
    /// Reverse index of all wants in the `peer_wants`.
    want_peers: AHashMap<Cid, AHashSet<PeerId>>,
    /// Current broadcast wants.
    broadcast_wants: AHashSet<Cid>,
}

#[derive(Debug)]
struct PeerWant {
    want_blocks: AHashSet<Cid>,
    want_haves: AHashSet<Cid>,
}

impl PeerWantManager {
    /// Adds a peer whose wants we need to keep track of.
    /// Sends the current list of broadcasts to this peer.
    pub async fn add_peer(&mut self, peer_queue: &MessageQueue, peer: &PeerId) {
        if self.peer_wants.contains_key(peer) {
            return;
        }

        self.peer_wants.insert(
            *peer,
            PeerWant {
                want_blocks: Default::default(),
                want_haves: Default::default(),
            },
        );

        // Broadcast any live want-haves to the newly connected peer.
        if !self.broadcast_wants.is_empty() {
            let wants = &self.broadcast_wants;
            peer_queue.add_broadcast_want_haves(wants).await;
        }
    }

    /// Removes a peer and its associated wants from tracking.
    pub fn remove_peer(&mut self, peer: &PeerId) {
        if let Some(peer_wants) = self.peer_wants.remove(peer) {
            // Clean up want-block
            for cid in peer_wants.want_blocks {
                self.reverse_index_remove(&cid, peer);
                let peer_counts = self.want_peer_counts(&cid);
                if peer_counts.want_block == 0 {
                    // TODO: wantBlockGauge dec
                }
                if !peer_counts.wanted() {
                    // TODO: wantGauge dec
                }
            }

            // Clean up want-haves
            for cid in peer_wants.want_haves {
                self.reverse_index_remove(&cid, peer);
                let peer_counts = self.want_peer_counts(&cid);
                if !peer_counts.wanted() {
                    // TODO: wantGauge dec
                }
            }
        }
    }

    /// Sends want-haves to any peers that have not yet been sent them.
    pub(super) async fn broadcast_want_haves(
        &mut self,
        want_haves: &AHashSet<Cid>,
        peer_queues: &AHashMap<PeerId, PeerState>,
    ) {
        debug!("pwm: broadcast_want_haves: {:?}", want_haves);
        // want_haves - self.broadcast_wants
        let unsent: AHashSet<_> = want_haves
            .difference(&self.broadcast_wants)
            .copied()
            .collect();
        self.broadcast_wants.extend(unsent.clone());

        let mut peer_unsent = AHashSet::new();
        for (peer, peer_wants) in self.peer_wants.iter() {
            for cid in &unsent {
                // Skip if already sent to this peer
                if !peer_wants.want_blocks.contains(cid) && !peer_wants.want_haves.contains(cid) {
                    peer_unsent.insert(*cid);
                }
            }

            if !peer_unsent.is_empty() {
                if let Some(peer_state) = peer_queues.get(peer) {
                    peer_state
                        .message_queue
                        .add_broadcast_want_haves(&peer_unsent)
                        .await;
                }
            }

            // clear for reuse
            peer_unsent.clear();
        }
    }

    /// Only sends the peer the want-blocks and want-haves that have not already been sent to it.
    pub(super) async fn send_wants(
        &mut self,
        peer: &PeerId,
        want_blocks: &[Cid],
        want_haves: &[Cid],
        message_queue: &MessageQueue,
    ) {
        let mut flt_want_blocks = Vec::with_capacity(want_blocks.len());
        let mut flt_want_haves = Vec::with_capacity(want_haves.len());

        // get the existing want-blocks and want-haves for the peer
        if let Some(peer_wants) = self.peer_wants.get_mut(peer) {
            // iterate over the requested want-blocks
            for cid in want_blocks {
                //  if the want-block hasn't been sent to the peer
                if peer_wants.want_blocks.contains(cid) {
                    continue;
                }

                // make sure the cid is no longer recorded as want-have
                peer_wants.want_haves.remove(cid);
                // record that the cid was sent as a want-block
                peer_wants.want_blocks.insert(*cid);
                // add to the results
                flt_want_blocks.push(*cid);
                // update reverse index
                self.want_peers.entry(*cid).or_default().insert(*peer);
            }

            // iterate over the requested want-haves
            for cid in want_haves {
                //  if already broadcasted, ignore
                if self.broadcast_wants.contains(cid) {
                    continue;
                }

                // Onliy if the cid has not been sent as want-block or want-have
                if !peer_wants.want_blocks.contains(cid) && !peer_wants.want_haves.contains(cid) {
                    // record that the cid was sent as a want-have
                    peer_wants.want_haves.insert(*cid);
                    // add to the results
                    flt_want_haves.push(*cid);
                    // update reverse index
                    self.want_peers.entry(*cid).or_default().insert(*peer);
                }
            }

            // send out want-blocks and want-haves
            if !flt_want_blocks.is_empty() || !flt_want_haves.is_empty() {
                message_queue
                    .add_wants(&flt_want_blocks, &flt_want_haves)
                    .await;
            }
        } else {
            error!("send_wants called with peer {}, but peer not found", peer);
        }
    }

    /// Sends out cancels to each peer which has a corresponding want sent to.
    pub(super) async fn send_cancels(
        &mut self,
        cancels: &[Cid],
        peer_queues: &AHashMap<PeerId, PeerState>,
    ) {
        if cancels.is_empty() {
            return;
        }

        // record how many peers have a pending want-block and wan-thave for each key to
        // be cancelled
        // TODO: for gauges
        let _peer_counts: AHashMap<Cid, WantPeerCounts> = cancels
            .iter()
            .map(|cid| (*cid, self.want_peer_counts(cid)))
            .collect();

        let broadcast_cancels: AHashSet<Cid> = cancels
            .iter()
            .filter(|cid| self.broadcast_wants.contains(cid))
            .copied()
            .collect();

        macro_rules! send {
            ($peer:expr, $peer_wants:expr) => {
                // start from the broadcast cancels
                let mut to_cancel = broadcast_cancels.clone();
                // for each key to cancel
                for cid in cancels {
                    // check if a want was sent for the eky
                    if !$peer_wants.want_blocks.contains(cid)
                        && !$peer_wants.want_haves.contains(cid)
                    {
                        continue;
                    }

                    // unconditionally remove from the want lists
                    $peer_wants.want_blocks.remove(cid);
                    $peer_wants.want_haves.remove(cid);

                    // If it's a broadcast want, we've already added it
                    if !self.broadcast_wants.contains(cid) {
                        to_cancel.insert(*cid);
                    }
                }

                if !to_cancel.is_empty() {
                    if let Some(peer_state) = peer_queues.get($peer) {
                        peer_state.message_queue.add_cancels(&to_cancel).await;
                    }
                }
            };
        }

        if broadcast_cancels.is_empty() {
            // Only send cancels ot peers that received a corresponding want
            let cancel_peers: AHashSet<PeerId> = cancels
                .iter()
                .filter_map(|cid| self.want_peers.get(cid))
                .flatten()
                .copied()
                .collect();
            for peer in cancel_peers {
                if let Some(peer_wants) = self.peer_wants.get_mut(&peer) {
                    send!(&peer, peer_wants);
                } else {
                    error!("index missing for peer {}", peer);
                    continue;
                }
            }
        } else {
            // if a broadcast want is being cancelled, send the cancel to all peers
            for (peer, peer_wants) in &mut self.peer_wants {
                send!(peer, peer_wants);
            }
        }

        // remove cancelled broadcast wants
        self.broadcast_wants = &self.broadcast_wants - &broadcast_cancels;

        // batch remove the reverse-index
        for cancel in cancels {
            self.want_peers.remove(cancel);

            let peer_counts = self.want_peer_counts(cancel);
            if peer_counts.want_block == 0 {
                // TODO: wantBlockGauge dec
            }
            if !peer_counts.wanted() {
                // TODO: wantGauge dec
            }
        }
    }

    /// Counts how many peers have a pendinng want-block and want-have for the given cid.
    fn want_peer_counts(&self, cid: &Cid) -> WantPeerCounts {
        let mut counts = WantPeerCounts {
            is_broadcast: self.broadcast_wants.contains(cid),
            ..Default::default()
        };

        if let Some(peers) = self.want_peers.get(cid) {
            for peer in peers {
                if let Some(peer_wants) = self.peer_wants.get(peer) {
                    if peer_wants.want_blocks.contains(cid) {
                        counts.want_block += 1;
                    } else if peer_wants.want_haves.contains(cid) {
                        counts.want_have += 1;
                    }
                } else {
                    error!(
                        "missing entry in the reverse index for peer {} for key {}",
                        peer, cid
                    );
                }
            }
        }

        counts
    }

    /// Remove the peer from the list of peers that have sent a want with the cid.
    fn reverse_index_remove(&mut self, cid: &Cid, peer: &PeerId) {
        if let Some(peers) = self.want_peers.get_mut(cid) {
            peers.remove(peer);
            if peers.is_empty() {
                self.want_peers.remove(cid);
            }
        }
    }

    /// Returns the set of all want-blocks sent to all peers.
    pub fn get_want_blocks(&self) -> AHashSet<Cid> {
        self.peer_wants
            .values()
            .flat_map(|peer_wants| peer_wants.want_blocks.iter())
            .copied()
            .collect()
    }

    /// Returns the set of all want-haves sent to all peers.
    pub fn get_want_haves(&self) -> AHashSet<Cid> {
        self.peer_wants
            .values()
            .flat_map(|peer_wants| peer_wants.want_haves.iter())
            .chain(self.broadcast_wants.iter())
            .copied()
            .collect()
    }

    /// Returns the set of all wants (both want-blocks and want-haves).
    pub fn get_wants(&self) -> AHashSet<Cid> {
        self.broadcast_wants
            .iter()
            .chain(self.want_peers.keys())
            .copied()
            .collect()
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct WantPeerCounts {
    /// Number of peers that have a pending want-block for this cid.
    want_block: usize,
    /// Number of peers that have a pending want-have for this cid.
    want_have: usize,
    /// Is this a broadcast want?
    is_broadcast: bool,
}

impl WantPeerCounts {
    /// Returns true if any peer wants this cid or it is a broadcast want.
    fn wanted(&self) -> bool {
        self.want_block > 0 || self.want_have > 0 || self.is_broadcast
    }
}
