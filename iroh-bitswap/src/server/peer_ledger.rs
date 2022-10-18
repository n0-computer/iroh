use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::PeerId;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PeerLedger {
    cids: AHashMap<Cid, AHashSet<PeerId>>,
}

impl PeerLedger {
    pub fn wants(&mut self, peer: PeerId, cid: Cid) {
        self.cids.entry(cid).or_default().insert(peer);
    }

    pub fn cancel_want(&mut self, peer: &PeerId, cid: &Cid) {
        if let Some(peers) = self.cids.get_mut(cid) {
            peers.remove(peer);
        }
    }

    pub fn peers(&self, cid: &Cid) -> Option<&AHashSet<PeerId>> {
        self.cids.get(cid)
    }
}
