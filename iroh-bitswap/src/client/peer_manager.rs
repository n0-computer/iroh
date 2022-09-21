use std::sync::RwLock;

use ahash::{AHashMap, AHashSet};
use libp2p::PeerId;

use super::{message_queue::MessageQueue, peer_want_manager::PeerWantManager, session::Session};

#[derive(Debug)]
pub struct PeerManager {
    peer_queues: RwLock<AHashMap<PeerId, MessageQueue>>,
    peer_want_manager: PeerWantManager,
    sessions: AHashMap<u64, Session>,
    peer_sessions: AHashMap<PeerId, AHashSet<u64>>,
    self_id: PeerId,
}

impl PeerManager {
    pub fn new(self_id: PeerId) -> Self {
        PeerManager {
            peer_queues: Default::default(),
            peer_want_manager: PeerWantManager::new(),
            sessions: Default::default(),
            peer_sessions: Default::default(),
            self_id,
        }
    }
}
