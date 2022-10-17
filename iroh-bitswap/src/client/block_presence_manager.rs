use std::sync::Arc;

use ahash::AHashMap;
use cid::Cid;
use libp2p::PeerId;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default)]
pub struct BlockPresenceManager {
    presence: Arc<RwLock<AHashMap<Cid, AHashMap<PeerId, bool>>>>,
}

impl BlockPresenceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called when a peer sends us information about which blocks it has and does not have.
    pub async fn receive_from(&self, peer: &PeerId, haves: &[Cid], dont_haves: &[Cid]) {
        let presence = &mut *self.presence.write().await;

        for key in haves {
            update_block_presence(presence, peer, key, true);
        }
        for key in dont_haves {
            update_block_presence(presence, peer, key, false);
        }
    }

    /// Indicates wether the given peer has sent a `HAVE` for the given `cid`.
    pub async fn peer_has_block(&self, peer: &PeerId, cid: &Cid) -> bool {
        let presence = self.presence.read().await;

        if let Some(list) = presence.get(cid) {
            if let Some(have) = list.get(peer) {
                return *have;
            }
        }
        false
    }

    /// Indicates wether the given peer has sent a `DONT_HAVE` for the given `cid`.
    pub async fn peer_does_not_have_block(&self, peer: &PeerId, cid: &Cid) -> bool {
        let presence = self.presence.read().await;
        if let Some(list) = presence.get(cid) {
            if let Some(have) = list.get(peer) {
                !have
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Filters the keys such that all the given peers have received a DONT_HAVE
    /// for a key.
    ///
    /// This allows us to know if we've exhauseed all possibilities of finding the key
    /// with the peers we know about.
    pub async fn all_peers_do_not_have_block(
        &self,
        peers: &[PeerId],
        keys: impl IntoIterator<Item = Cid>,
    ) -> Vec<Cid> {
        let presence = &*self.presence.read().await;
        let mut res = Vec::new();
        for key in keys.into_iter() {
            if all_dont_have(presence, peers, &key) {
                res.push(key);
            }
        }

        res
    }

    /// Cleans up the given keys.
    pub async fn remove_keys(&self, keys: &[Cid]) {
        let presence = &mut *self.presence.write().await;
        for key in keys {
            presence.remove(key);
        }
    }

    /// Indicates whether we are trackin this key.
    pub async fn has_key(&self, cid: &Cid) -> bool {
        let presence = &*self.presence.read().await;
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
                if *has {
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

#[cfg(test)]
mod tests {
    use crate::block::tests::create_random_block_v1;

    use super::*;

    #[tokio::test]
    async fn test_block_presence_manager() {
        let bpm = BlockPresenceManager::new();

        let p = PeerId::random();
        let cids = gen_cids(2);
        let c0 = cids[0];
        let c1 = cids[1];

        // Nothing stored yet, both peer_has_block and peer_does_not_have_block should
        // return false
        assert!(!bpm.peer_has_block(&p, &c0).await);

        assert!(!bpm.peer_does_not_have_block(&p, &c0).await);

        // HAVE cid0 / DONT_HAVE cid1
        bpm.receive_from(&p, &[c0][..], &[c1][..]).await;

        // Peer has received HAVE for cid0
        assert!(bpm.peer_has_block(&p, &c0).await);
        assert!(!bpm.peer_does_not_have_block(&p, &c0).await);

        // Peer has received DONT_HAVE for cid1
        assert!(!bpm.peer_has_block(&p, &c1).await);
        assert!(bpm.peer_does_not_have_block(&p, &c1).await);

        // HAVE cid1 / DONT_HAVE cid0
        bpm.receive_from(&p, &[c1][..], &[c0][..]).await;

        // DONT_HAVE cid0 should NOT over-write earlier HAVE cid0
        assert!(bpm.peer_has_block(&p, &c0).await);
        assert!(!bpm.peer_does_not_have_block(&p, &c0).await);

        // HAVE cid1 should over-write earlier DONT_HAVE cid1
        assert!(bpm.peer_has_block(&p, &c1).await);
        assert!(!bpm.peer_does_not_have_block(&p, &c1).await);

        // Remove cid0
        bpm.remove_keys(&[c0][..]).await;

        // Nothing stored, both peer_has_block and peer_does_not_have_block should
        // return false
        assert!(!bpm.peer_has_block(&p, &c0).await);
        assert!(!bpm.peer_does_not_have_block(&p, &c0).await);

        // Remove cid1
        bpm.remove_keys(&[c1][..]).await;

        // Nothing stored, both peer_has_block and peer_does_not_have_block should
        // return false
        assert!(!bpm.peer_has_block(&p, &c1).await);
        assert!(!bpm.peer_does_not_have_block(&p, &c1).await);
    }

    #[tokio::test]
    async fn test_add_remove_multi() {
        let bpm = BlockPresenceManager::new();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let cids = gen_cids(3);
        let c0 = cids[0];
        let c1 = cids[1];
        let c2 = cids[2];

        // p0: HAVE cid0, cid1 / DONT_HAVE cid1, cid2
        // p1: HAVE cid1, cid2 / DONT_HAVE cid0
        bpm.receive_from(&p0, &[c0, c1][..], &[c1, c2][..]).await;
        bpm.receive_from(&p1, &[c1, c2][..], &[c0][..]).await;

        // Peer 0 should end up with
        // - HAVE cid0
        // - HAVE cid1
        // - DONT_HAVE cid2
        assert!(bpm.peer_has_block(&p0, &c0).await);
        assert!(bpm.peer_has_block(&p0, &c1).await);
        assert!(bpm.peer_does_not_have_block(&p0, &c2).await);

        // Peer 1 should end up with
        // - HAVE cid1
        // - HAVE cid2
        // - DONT_HAVE cid0
        assert!(bpm.peer_has_block(&p1, &c1).await);
        assert!(bpm.peer_has_block(&p1, &c2).await);
        assert!(bpm.peer_does_not_have_block(&p1, &c0).await);

        // Remove cid1 and cid2. Should end up with
        // Peer 0: HAVE cid0
        // Peer 1: DONT_HAVE cid0
        bpm.remove_keys(&[c1, c2][..]).await;
        assert!(bpm.peer_has_block(&p0, &c0).await);
        assert!(bpm.peer_does_not_have_block(&p1, &c0).await);

        // The other keys should have been cleared, so both HasBlock() and
        // DoesNotHaveBlock() should return false
        assert!(!bpm.peer_has_block(&p0, &c1).await);
        assert!(!bpm.peer_does_not_have_block(&p0, &c1).await);

        assert!(!bpm.peer_has_block(&p0, &c2).await);
        assert!(!bpm.peer_does_not_have_block(&p0, &c2).await);
        assert!(!bpm.peer_has_block(&p1, &c1).await);
        assert!(!bpm.peer_does_not_have_block(&p1, &c1).await);
        assert!(!bpm.peer_has_block(&p1, &c2).await);
        assert!(!bpm.peer_does_not_have_block(&p1, &c2).await);
    }

    #[tokio::test]
    async fn test_all_peers_do_not_have_block() {
        let bpm = BlockPresenceManager::new();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        let cids = gen_cids(3);
        let c0 = cids[0];
        let c1 = cids[1];
        let c2 = cids[2];

        //      c0  c1  c2
        //  p0   ?  N   N
        //  p1   N  Y   ?
        //  p2   Y  Y   N
        bpm.receive_from(&p0, &[][..], &[c1, c2][..]).await;
        bpm.receive_from(&p1, &[c1][..], &[c0][..]).await;
        bpm.receive_from(&p2, &[c0, c1][..], &[c2][..]).await;

        struct TestCase {
            peers: Vec<PeerId>,
            ks: Vec<Cid>,
            exp: Vec<Cid>,
        }

        let testcases = [
            TestCase {
                peers: vec![p0],
                ks: vec![c0],
                exp: vec![],
            },
            TestCase {
                peers: vec![p1],
                ks: vec![c0],
                exp: vec![c0],
            },
            TestCase {
                peers: vec![p2],
                ks: vec![c0],
                exp: vec![],
            },
            TestCase {
                peers: vec![p0],
                ks: vec![c1],
                exp: vec![c1],
            },
            TestCase {
                peers: vec![p1],
                ks: vec![c1],
                exp: vec![],
            },
            TestCase {
                peers: vec![p2],
                ks: vec![c1],
                exp: vec![],
            },
            TestCase {
                peers: vec![p0],
                ks: vec![c2],
                exp: vec![c2],
            },
            TestCase {
                peers: vec![p1],
                ks: vec![c2],
                exp: vec![],
            },
            TestCase {
                peers: vec![p2],
                ks: vec![c2],
                exp: vec![c2],
            },
            // p0 recieved DONT_HAVE for c1 & c2 (but not for c0)
            TestCase {
                peers: vec![p0],
                ks: vec![c0, c1, c2],
                exp: vec![c1, c2],
            },
            TestCase {
                peers: vec![p0, p1],
                ks: vec![c0, c1, c2],
                exp: vec![],
            },
            // Both p0 and p2 received DONT_HAVE for c2
            TestCase {
                peers: vec![p0, p2],
                ks: vec![c0, c1, c2],
                exp: vec![c2],
            },
            TestCase {
                peers: vec![p0, p1, p2],
                ks: vec![c0, c1, c2],
                exp: vec![],
            },
        ];

        for (i, mut tc) in testcases.into_iter().enumerate() {
            let mut peers = bpm.all_peers_do_not_have_block(&tc.peers, tc.ks).await;
            peers.sort();
            tc.exp.sort();
            assert_eq!(
                peers, tc.exp,
                "test case {i} failed: expected matching keys"
            );
        }
    }

    fn gen_cids(n: usize) -> Vec<Cid> {
        (0..n).map(|_| *create_random_block_v1().cid()).collect()
    }
}
