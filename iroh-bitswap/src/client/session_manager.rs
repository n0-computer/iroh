use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use ahash::AHashMap;
use anyhow::{anyhow, Result};
use cid::Cid;
use libp2p::PeerId;
use tokio::sync::{broadcast, RwLock};

use crate::{network::Network, Block};

use super::{
    block_presence_manager::BlockPresenceManager, peer_manager::PeerManager,
    provider_query_manager::ProviderQueryManager, session::Session,
    session_interest_manager::SessionInterestManager, session_peer_manager::SessionPeerManager,
};

#[derive(Debug, Clone)]
pub struct SessionManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    self_id: PeerId,
    session_interest_manager: SessionInterestManager,
    block_presence_manager: BlockPresenceManager,
    peer_manager: PeerManager,
    provider_finder: ProviderQueryManager,
    sessions: RwLock<AHashMap<u64, Session>>,
    session_index: AtomicU64,
    network: Network,
    notify: broadcast::Sender<Block>,
}

impl SessionManager {
    pub fn new(
        self_id: PeerId,
        session_interest_manager: SessionInterestManager,
        block_presence_manager: BlockPresenceManager,
        peer_manager: PeerManager,
        provider_finder: ProviderQueryManager,
        network: Network,
        notify: broadcast::Sender<Block>,
    ) -> Self {
        SessionManager {
            inner: Arc::new(Inner {
                self_id,
                session_interest_manager,
                block_presence_manager,
                peer_manager,
                provider_finder,
                sessions: Default::default(),
                session_index: Default::default(),
                network,
                notify,
            }),
        }
    }

    pub async fn stop(self) -> Result<()> {
        let inner = Arc::try_unwrap(self.inner)
            .map_err(|_| anyhow!("session manager refs not shutdown"))?;

        let sessions = RwLock::into_inner(inner.sessions);
        let results = futures::future::join_all(
            sessions
                .into_iter()
                .map(|(_, session)| async move { session.stop().await }),
        )
        .await;

        for r in results {
            r?;
        }

        Ok(())
    }

    /// Initializes a new session and starts tracking it.
    pub async fn new_session(
        &self,
        provider_search_delay: Duration,
        rebroadcast_delay: Duration,
    ) -> Session {
        let id = self.get_next_session_id();
        let session_peer_manager = SessionPeerManager::new(id, self.inner.network.clone());

        let session = Session::new(
            self.inner.self_id,
            id,
            self.clone(),
            self.inner.peer_manager.clone(),
            session_peer_manager,
            self.inner.provider_finder.clone(),
            self.inner.session_interest_manager.clone(),
            self.inner.block_presence_manager.clone(),
            self.inner.provider_finder.clone(),
            self.inner.notify.clone(),
            provider_search_delay,
            rebroadcast_delay,
        )
        .await;

        self.inner
            .sessions
            .write()
            .await
            .insert(id, session.clone());
        session
    }

    pub async fn remove_session(&self, session_id: u64) {
        let cancels = self
            .inner
            .session_interest_manager
            .remove_session(session_id)
            .await;
        self.cancel_wants(&cancels).await;
        self.inner.sessions.write().await.remove(&session_id);
    }

    /// Returns the next sequential identifier for a session.
    pub fn get_next_session_id(&self) -> u64 {
        self.inner.session_index.fetch_add(1, Ordering::SeqCst)
    }

    pub async fn receive_from(
        &self,
        peer: Option<PeerId>,
        blocks: &[Cid],
        haves: &[Cid],
        dont_haves: &[Cid],
    ) {
        // Record block presence for HAVE/DONT_HAVE.
        if let Some(ref peer) = peer {
            self.inner
                .block_presence_manager
                .receive_from(peer, haves, dont_haves)
                .await;
        }

        for id in &self
            .inner
            .session_interest_manager
            .interested_sessions(blocks, haves, dont_haves)
            .await
        {
            let sessions = &*self.inner.sessions.read().await;
            if let Some(session) = sessions.get(id) {
                session.receive_from(peer, blocks, haves, dont_haves).await;
            }
        }

        // Send CANCELs to all peers with want-have/want-block
        self.inner.peer_manager.send_cancels(blocks).await;
    }

    pub async fn cancel_session_wants(&self, session_id: u64, wants: &[Cid]) {
        // Remove session's interest in the given blocks - returns the keys taht
        // no session is interested in anymore.
        let cancels = self
            .inner
            .session_interest_manager
            .remove_session_interested(session_id, wants)
            .await;
        self.cancel_wants(&cancels).await;
    }

    async fn cancel_wants(&self, wants: &[Cid]) {
        // Free up block presence tracking
        self.inner.block_presence_manager.remove_keys(wants).await;

        // Send CANCEL to all peers for blocks that no session is interested anymore.
        self.inner.peer_manager.send_cancels(wants).await;
    }
}
