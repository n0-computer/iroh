use std::sync::{Arc, RwLock};

use ahash::AHashSet;
use anyhow::Result;
use libp2p::PeerId;

use crate::network::Network;

#[derive(Debug, Clone)]
pub struct SessionPeerManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    network: Network,
    id: u64,
    tag: String,
    peers: RwLock<(AHashSet<PeerId>, bool)>,
}

/// Tag to indicate the connection should be kept open.
const SESSION_PEER_TAG_VALUE: usize = 5;

impl SessionPeerManager {
    pub fn new(id: u64, network: Network) -> Self {
        SessionPeerManager {
            inner: Arc::new(Inner {
                network,
                id,
                tag: format!("bs-ses-{}", id),
                peers: Default::default(),
            }),
        }
    }

    pub fn stop(self) -> Result<()> {
        let this = &self.inner;
        let (peers, _) = &*this.peers.read().unwrap();
        for peer in peers.iter() {
            this.network.untag_peer(peer, &this.tag);
            this.network.unprotect_peer(peer, &this.tag);
        }
        Ok(())
    }

    /// Adds the peer.
    /// Returns true if the peer is new.
    pub fn add_peer(&self, peer: &PeerId) -> bool {
        let (peers, peers_discovered) = &mut *self.inner.peers.write().unwrap();

        if peers.contains(peer) {
            return false;
        }

        peers.insert(*peer);
        *peers_discovered = true;

        // Tag the peer
        self.inner
            .network
            .tag_peer(peer, &self.inner.tag, SESSION_PEER_TAG_VALUE);
        true
    }

    /// Protects this connection.
    pub fn protect_connection(&self, peer: &PeerId) {
        let (peers, _) = &*self.inner.peers.read().unwrap();

        if !peers.contains(peer) {
            return;
        }
        self.inner.network.protect_peer(peer, &self.inner.tag);
    }

    /// Removes the peer.
    /// Returns true if the peer existed
    pub fn remove_peer(&self, peer: &PeerId) -> bool {
        let (peers, _) = &mut *self.inner.peers.write().unwrap();

        if peers.contains(peer) {
            return false;
        }

        peers.remove(peer);

        self.inner.network.untag_peer(peer, &self.inner.tag);
        self.inner.network.unprotect_peer(peer, &self.inner.tag);
        true
    }

    /// Indicates wether peers have been discovered yet.
    pub fn peers_discovered(&self) -> bool {
        self.inner.peers.read().unwrap().1
    }

    pub fn peers(&self) -> Vec<PeerId> {
        let (peers, _) = &*self.inner.peers.read().unwrap();
        peers.iter().copied().collect()
    }

    pub fn has_peers(&self) -> bool {
        let (peers, _) = &*self.inner.peers.read().unwrap();
        peers.is_empty()
    }

    pub fn has_peer(&self, peer: &PeerId) -> bool {
        let (peers, _) = &*self.inner.peers.read().unwrap();
        peers.contains(peer)
    }
}
