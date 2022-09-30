use std::{
    fmt::Debug,
    sync::{Arc, RwLock},
};

use ahash::{AHashMap, AHashSet};
use cid::Cid;
use libp2p::PeerId;

use crate::network::Network;

use super::{message_queue::MessageQueue, peer_want_manager::PeerWantManager, session::Signaler};

#[derive(Debug, Clone)]
pub struct PeerManager {
    inner: Arc<Inner>,
}

struct Inner {
    peers: RwLock<(AHashMap<PeerId, MessageQueue>, PeerWantManager)>,
    sessions: RwLock<(AHashMap<u64, Signaler>, AHashMap<PeerId, AHashSet<u64>>)>,
    self_id: PeerId,
    network: Network,
    on_dont_have_timeout: Arc<dyn DontHaveTimeout>,
}

impl Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("peers", &self.peers)
            .field("sessions", &self.sessions)
            .field("self_id", &self.self_id)
            .field("network", &self.network)
            .field("on_dont_have_timeout", &"Box<Fn>")
            .finish()
    }
}

pub trait DontHaveTimeout: Fn(&PeerId, &[Cid]) + 'static + Sync + Send {}

impl<F: Fn(&PeerId, &[Cid]) + 'static + Sync + Send> DontHaveTimeout for F {}

impl PeerManager {
    pub fn new(self_id: PeerId, network: Network) -> Self {
        Self::with_cb(self_id, network, |_: &PeerId, _: &[Cid]| {})
    }

    pub fn with_cb<F>(self_id: PeerId, network: Network, on_dont_have_timeout: F) -> Self
    where
        F: DontHaveTimeout,
    {
        PeerManager {
            inner: Arc::new(Inner {
                peers: Default::default(),
                sessions: Default::default(),
                self_id,
                network,
                on_dont_have_timeout: Arc::new(on_dont_have_timeout),
            }),
        }
    }

    pub fn available_peers(&self) -> Vec<PeerId> {
        self.connected_peers()
    }

    /// Returns a list of peers this peer manager is managing.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.inner.peers.read().unwrap().0.keys().copied().collect()
    }

    /// Called to a new peer to the pool, and send it an initial set of wants.
    pub fn connected(&self, peer: &PeerId) {
        let (peer_queues, peer_want_manager) = &mut *self.inner.peers.write().unwrap();

        let peer_queue = peer_queues.entry(*peer).or_insert_with(|| {
            MessageQueue::new(
                *peer,
                self.inner.network.clone(),
                self.inner.on_dont_have_timeout.clone(),
            )
        });

        // Inform the peer want manager that there's a new peer.
        peer_want_manager.add_peer(&peer_queue, peer);

        // Inform the session that the peer has connected
        self.signal_availability(peer, true);
    }

    /// Called to remove a peer from the pool.
    pub fn disconnected(&self, peer: &PeerId) {
        let (peer_queues, peer_want_manager) = &mut *self.inner.peers.write().unwrap();
        if let Some(_peer_queue) = peer_queues.remove(peer) {
            // inform the sessions that the peer has disconnected
            self.signal_availability(peer, false);
            peer_want_manager.remove_peer(peer);
        }
    }

    /// Called when a message is received from the network.
    /// The set of blocks, HAVEs and DONT_HAVEs, is `cids`.
    /// Currently only used to calculate latency.
    pub fn response_received(&self, peer: &PeerId, cids: &[Cid]) {
        let peer_queues = &*self.inner.peers.read().unwrap().0;
        if let Some(peer_queue) = peer_queues.get(peer) {
            peer_queue.response_received(cids.to_vec());
        }
    }

    /// Broadcasts want-haves to all peers
    /// (used by the session to discover seeds).
    /// For each peer it filters out want-haves that have previously been sent to the peer.
    pub fn broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        self.inner
            .peers
            .write()
            .unwrap()
            .1
            .broadcast_want_haves(want_haves);
    }

    /// Sends the given want-blocks and want-haves to the given peer.
    /// It filters out wants that have been previously sent to the peer.
    pub fn send_wants(&self, peer: &PeerId, want_blocks: &[Cid], want_haves: &[Cid]) {
        let (peer_queues, peer_want_manager) = &mut *self.inner.peers.write().unwrap();
        if peer_queues.contains_key(peer) {
            peer_want_manager.send_wants(peer, want_blocks, want_haves);
        }
    }

    /// Sends cancels for the given keys to all peers who had previously received a want for those keys.
    pub fn send_cancels(&self, cancels: &[Cid]) {
        self.inner.peers.write().unwrap().1.send_cancels(cancels);
    }

    /// Returns a list of pending wants (both want-haves and want-blocks).
    pub fn current_wants(&self) -> AHashSet<Cid> {
        self.inner.peers.read().unwrap().1.get_wants()
    }

    /// Returns a list of pending want-blocks.
    pub fn current_want_blocks(&self) -> AHashSet<Cid> {
        self.inner.peers.read().unwrap().1.get_want_blocks()
    }

    /// Returns a list of pending want-haves
    pub fn current_want_haves(&self) -> AHashSet<Cid> {
        self.inner.peers.read().unwrap().1.get_want_haves()
    }

    /// Informst the `PeerManager` that the given session is interested in events about the given peer.
    pub fn register_session(&self, peer: &PeerId, session: Signaler) {
        let (sessions, peer_sessions) = &mut *self.inner.sessions.write().unwrap();
        let id = session.id();
        if !sessions.contains_key(&id) {
            sessions.insert(session.id(), session);
        }

        peer_sessions.entry(*peer).or_default().insert(id);
    }

    pub fn unregister_session(&self, session_id: u64) {
        let (sessions, peer_sessions) = &mut *self.inner.sessions.write().unwrap();
        let mut to_remove = Vec::new();
        for (peer_id, session_ids) in peer_sessions.iter_mut() {
            session_ids.remove(&session_id);
            if session_ids.is_empty() {
                to_remove.push(*peer_id);
            }
        }

        for peer in to_remove {
            peer_sessions.remove(&peer);
        }

        sessions.remove(&session_id);
    }

    /// Called when a peers connectivity changes, informs the interested sessions.
    fn signal_availability(&self, peer: &PeerId, is_connected: bool) {
        let (sessions, peer_sessions) = &*self.inner.sessions.read().unwrap();
        if let Some(session_ids) = peer_sessions.get(peer) {
            for session_id in session_ids {
                if let Some(session) = sessions.get(session_id) {
                    session.signal_availability(*peer, is_connected);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{block::tests::create_random_block_v1, message::WantType};

    use super::*;

    #[test]
    fn test_adding_removing_peers() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();
        let peer5 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network);
        peer_manager.connected(&peer1);
        peer_manager.connected(&peer2);
        peer_manager.connected(&peer3);

        let connected_peers = peer_manager.connected_peers();
        assert!(connected_peers.contains(&peer1));
        assert!(connected_peers.contains(&peer2));
        assert!(connected_peers.contains(&peer3));

        assert!(!connected_peers.contains(&peer4));
        assert!(!connected_peers.contains(&peer5));

        // disconnect
        peer_manager.disconnected(&peer1);
        let connected_peers = peer_manager.connected_peers();
        assert!(!connected_peers.contains(&peer1));

        // reconnect
        peer_manager.connected(&peer1);
        let connected_peers = peer_manager.connected_peers();
        assert!(connected_peers.contains(&peer1));
    }

    #[test]
    fn test_broadcast_on_connect() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network);
        let cids: AHashSet<_> = gen_cids(2).into_iter().collect();

        peer_manager.broadcast_want_haves(&cids);

        // connect with peer, which should send out the broadcast
        peer_manager.connected(&peer1);

        // check messages in MessageQueue
        let peers = peer_manager.inner.peers.read().unwrap();
        let mq = peers.0.get(&peer1).unwrap();
        let mq = &*mq.wants.lock().unwrap();
        assert_eq!(mq.bcst_wants.pending.len(), 2);
        for cid in &cids {
            assert!(mq.bcst_wants.pending.get(cid).is_some());
        }
    }

    #[test]
    fn test_broadcast_want_haves() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network);
        let cids = gen_cids(3);

        // broadcast 2
        peer_manager.broadcast_want_haves(&cids[..2].into_iter().copied().collect::<AHashSet<_>>());

        peer_manager.connected(&peer1);

        {
            let peers = peer_manager.inner.peers.read().unwrap();
            let mq = peers.0.get(&peer1).unwrap();
            let mq = &*mq.wants.lock().unwrap();
            assert_eq!(mq.bcst_wants.pending.len(), 2);
            for cid in &cids[..2] {
                assert!(mq.bcst_wants.pending.get(cid).is_some());
            }
        }

        // second peer
        peer_manager.connected(&peer2);

        // broadcast to all peers, including an already sent cid
        peer_manager.broadcast_want_haves(&[cids[0], cids[2]].into_iter().collect::<AHashSet<_>>());

        {
            let peers = peer_manager.inner.peers.read().unwrap();
            // peer 1 now has all three
            {
                let mq = peers.0.get(&peer1).unwrap();
                let mq = &*mq.wants.lock().unwrap();
                assert_eq!(mq.bcst_wants.pending.len(), 3);
                for cid in &cids {
                    assert!(mq.bcst_wants.pending.get(cid).is_some());
                }
            }
            // peer 2 now has all three
            {
                let mq = peers.0.get(&peer2).unwrap();
                let mq = &*mq.wants.lock().unwrap();
                assert_eq!(mq.bcst_wants.pending.len(), 3);
                for cid in &cids {
                    assert!(mq.bcst_wants.pending.get(cid).is_some());
                }
            }
        }
    }

    #[test]
    fn test_send_wants() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network);
        let cids = gen_cids(4);

        peer_manager.connected(&peer1);
        peer_manager.send_wants(&peer1, &[cids[0]][..], &[cids[2]][..]);

        {
            let peers = peer_manager.inner.peers.read().unwrap();
            let mq = peers.0.get(&peer1).unwrap();
            let mq = &*mq.wants.lock().unwrap();
            assert!(mq.bcst_wants.pending.is_empty());
            assert_eq!(mq.peer_wants.pending.len(), 2);
            assert_eq!(
                mq.peer_wants.pending.get(&cids[0]).unwrap().want_type,
                WantType::Block
            );
            assert_eq!(
                mq.peer_wants.pending.get(&cids[2]).unwrap().want_type,
                WantType::Have
            );
        }

        peer_manager.send_wants(&peer1, &[cids[0], cids[1]][..], &[cids[2], cids[3]][..]);

        {
            let peers = peer_manager.inner.peers.read().unwrap();
            let mq = peers.0.get(&peer1).unwrap();
            let mq = &*mq.wants.lock().unwrap();
            assert!(mq.bcst_wants.pending.is_empty());
            assert_eq!(mq.peer_wants.pending.len(), 4);
            assert_eq!(
                mq.peer_wants.pending.get(&cids[0]).unwrap().want_type,
                WantType::Block
            );
            assert_eq!(
                mq.peer_wants.pending.get(&cids[1]).unwrap().want_type,
                WantType::Block
            );
            assert_eq!(
                mq.peer_wants.pending.get(&cids[2]).unwrap().want_type,
                WantType::Have
            );
            assert_eq!(
                mq.peer_wants.pending.get(&cids[3]).unwrap().want_type,
                WantType::Have
            );
        }
    }

    #[test]
    fn test_send_cancels() {
        let this = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let network = Network::new(this);

        let peer_manager = PeerManager::new(this, network);
        let cids = gen_cids(4);

        peer_manager.connected(&peer1);
        peer_manager.connected(&peer2);

        peer_manager.send_wants(&peer1, &[cids[0], cids[1]][..], &[cids[2]][..]);
        std::thread::sleep(Duration::from_millis(100));

        {
            let peers = peer_manager.inner.peers.read().unwrap();
            let mq = peers.0.get(&peer1).unwrap();
            let mq = &*mq.wants.lock().unwrap();
            assert!(mq.bcst_wants.pending.is_empty());
            assert!(mq.bcst_wants.sent.is_empty());
            // TODO: doesn't work because dialing fails
            // assert!(mq.peer_wants.pending.is_empty());
            // assert_eq!(mq.peer_wants.sent.len(), 3);
            assert!(mq.cancels.is_empty());
        }

        peer_manager.send_cancels(&[cids[0], cids[2]][..]);
        std::thread::sleep(Duration::from_millis(100));
        {
            let peers = peer_manager.inner.peers.read().unwrap();

            // check that no cancels went to peer2
            {
                let mq = peers.0.get(&peer2).unwrap();
                let mq = &*mq.wants.lock().unwrap();
                assert!(mq.cancels.is_empty());
            }

            // TODO: doesn't work because dialing fails
            // {
            //     let mq = peers.0.get(&peer1).unwrap();
            //     let mq = &*mq.wants.lock().unwrap();
            //     assert!(mq.bcst_wants.pending.is_empty());
            //     assert_eq!(mq.peer_wants.pending.len(), 1);
            //     assert_eq!(mq.cancels.len(), 2);
            // }
        }
    }

    fn gen_cids(n: usize) -> Vec<Cid> {
        (0..n).map(|_| *create_random_block_v1().cid()).collect()
    }
}
