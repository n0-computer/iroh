use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::PeerId;

/// Keeps track of which peers we've sent a want-block to.
#[derive(Debug, Default)]
pub struct SentWantBlocksTracker {
    sent_want_blocks: AHashMap<PeerId, AHashSet<Cid>>,
}

impl SentWantBlocksTracker {
    pub fn add_sent_want_blocks_to(&mut self, peer: &PeerId, keys: &[Cid]) {
        let entry = self.sent_want_blocks.entry(*peer).or_default();
        for key in keys {
            entry.insert(*key);
        }
    }

    pub fn have_sent_want_block_to(&self, peer: &PeerId, cid: &Cid) -> bool {
        self.sent_want_blocks
            .get(peer)
            .map(|cids| cids.contains(cid))
            .unwrap_or_default()
    }
}
