use std::sync::RwLock;

use ahash::AHashMap;
use cid::Cid;
use libp2p::PeerId;

#[derive(Debug)]
pub struct BlockPresenceManager {
    presence: RwLock<AHashMap<Cid, AHashMap<PeerId, bool>>>,
}

impl BlockPresenceManager {
    pub fn new() -> Self {
        BlockPresenceManager {
            presence: Default::default(),
        }
    }

    /// Called when a peer sends us information about which blocks it has and does not have.
    pub fn receive_from(&self, peer: &PeerId, haves: &[Cid], dont_haves: &[Cid]) {
        let presence = &mut *self.presence.write().unwrap();

        for key in haves {
            update_block_presence(presence, peer, key, true);
        }
        for key in dont_haves {
            update_block_presence(presence, peer, key, false);
        }
    }

    /// Indicates wether the given peer has sent a `HAVE` for the given `cid`.
    pub fn peer_has_block(&self, peer: &PeerId, cid: &Cid) -> bool {
        let presence = self.presence.read().unwrap();
        presence
            .get(cid)
            .and_then(|l| l.get(peer))
            .copied()
            .unwrap_or_default()
    }

    /// Indicates wether the given peer has sent a `DONT_HAVE` for the given `cid`.
    pub fn peer_does_not_have_block(&self, peer: &PeerId, cid: &Cid) -> bool {
        let presence = self.presence.read().unwrap();
        presence
            .get(cid)
            .and_then(|l| l.get(peer).map(|have| !*have))
            .unwrap_or_default()
    }

    /// Filters the keys such that all the given peers have received a DONT_HAVE
    /// for a key.
    ///
    /// This allows us to know if we've exhauseed all possibilities of finding the key
    /// with the peers we know about.
    pub fn all_peers_do_not_have_block(&self, peers: &[PeerId], keys: &[Cid]) -> Vec<Cid> {
        let presence = &*self.presence.read().unwrap();
        let mut res = Vec::new();
        for key in keys {
            if all_dont_have(presence, peers, key) {
                res.push(*key);
            }
        }

        res
    }

    /// Cleans up the given keys.
    pub fn remove_keys(&self, keys: &[Cid]) {
        let presence = &mut *self.presence.write().unwrap();
        for key in keys {
            presence.remove(key);
        }
    }

    /// Indicates whether we are trackin this key.
    pub fn has_key(&self, cid: &Cid) -> bool {
        let presence = &*self.presence.read().unwrap();
        presence.contains_key(cid)
    }
}

fn update_block_presence(
    presence: &mut AHashMap<Cid, AHashMap<PeerId, bool>>,
    peer: &PeerId,
    key: &Cid,
    present: bool,
) {
    let entry = presence.entry(*key).or_default();

    // Make sure not to change HAVE to DONT_HAVE
    if let Some(has) = entry.get(peer) {
        if *has {
            return;
        }
    }

    entry.insert(*peer, present);
}

fn all_dont_have(
    presence: &AHashMap<Cid, AHashMap<PeerId, bool>>,
    peers: &[PeerId],
    key: &Cid,
) -> bool {
    if let Some(ps) = presence.get(key) {
        // Check if we explicitly know that all the given peers do not have the cid.
        for peer in peers {
            if let Some(has) = ps.get(peer) {
                if !has {
                    return false;
                }
            } else {
                return false;
            }
        }
        true
    } else {
        false
    }
}
