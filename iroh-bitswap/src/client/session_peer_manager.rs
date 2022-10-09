use std::sync::Arc;

use ahash::AHashSet;
use anyhow::{anyhow, Result};
use libp2p::PeerId;
use tokio::sync::RwLock;
use tracing::debug;

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

    pub async fn stop(self) -> Result<()> {
        debug!(
            "shutting down SessionPeerManager ({})",
            Arc::strong_count(&self.inner)
        );
        let inner = Arc::try_unwrap(self.inner)
            .map_err(|_| anyhow!("session peer manager refs not shutdown"))?;

        let (peers, _) = RwLock::into_inner(inner.peers);
        for peer in peers.iter() {
            inner.network.untag_peer(peer, &inner.tag);
            inner.network.unprotect_peer(peer, &inner.tag);
        }
        Ok(())
    }

    /// Adds the peer.
    /// Returns true if the peer is new.
    pub async fn add_peer(&self, peer: &PeerId) -> bool {
        let (peers, peers_discovered) = &mut *self.inner.peers.write().await;

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
    pub async fn protect_connection(&self, peer: &PeerId) {
        let (peers, _) = &*self.inner.peers.read().await;

        if !peers.contains(peer) {
            return;
        }
        self.inner.network.protect_peer(peer, &self.inner.tag);
    }

    /// Removes the peer.
    /// Returns true if the peer existed
    pub async fn remove_peer(&self, peer: &PeerId) -> bool {
        let (peers, _) = &mut *self.inner.peers.write().await;

        if peers.contains(peer) {
            return false;
        }

        peers.remove(peer);

        self.inner.network.untag_peer(peer, &self.inner.tag);
        self.inner.network.unprotect_peer(peer, &self.inner.tag);
        true
    }

    /// Indicates wether peers have been discovered yet.
    pub async fn peers_discovered(&self) -> bool {
        self.inner.peers.read().await.1
    }

    pub async fn peers(&self) -> Vec<PeerId> {
        let (peers, _) = &*self.inner.peers.read().await;
        peers.iter().copied().collect()
    }

    pub async fn has_peers(&self) -> bool {
        let (peers, _) = &*self.inner.peers.read().await;
        peers.is_empty()
    }

    pub async fn has_peer(&self, peer: &PeerId) -> bool {
        let (peers, _) = &*self.inner.peers.read().await;
        peers.contains(peer)
    }
}
