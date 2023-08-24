//! Handlers and actors to for live syncing [`iroh_sync`] replicas.
//!
//! [`iroh_sync::Replica`] is also called documents here.

use std::{collections::HashSet, sync::Arc};

use anyhow::anyhow;
use iroh_bytes::{baomap::Store as BaoStore, util::runtime::Handle};
use iroh_gossip::net::Gossip;
use iroh_net::MagicEndpoint;
use iroh_sync::{
    store::Store,
    sync::{Author, AuthorId, NamespaceId, Replica},
};
use parking_lot::RwLock;

use crate::download::Downloader;

mod live;
pub mod rpc;

pub use iroh_sync::net::SYNC_ALPN;
pub use live::*;

/// The SyncEngine contains the [`LiveSync`] handle, and keeps a copy of the store and endpoint.
///
/// The RPC methods dealing with documents and sync operate on the `SyncEngine`, with method
/// implementations in [rpc].
#[derive(Debug, Clone)]
pub struct SyncEngine<S: Store> {
    pub(crate) rt: Handle,
    pub(crate) store: S,
    pub(crate) endpoint: MagicEndpoint,
    pub(crate) live: LiveSync<S>,
    active: Arc<RwLock<HashSet<NamespaceId>>>,
}

impl<S: Store> SyncEngine<S> {
    /// Start the sync engine.
    ///
    /// This will spawn a background task for the [`LiveSync`]. When documents are added to the
    /// engine with [`Self::start_sync`], then new entries inserted locally will be sent to peers
    /// through iroh-gossip.
    ///
    /// The engine will also register for [`Replica::subscribe`] events to download content for new
    /// entries from peers.
    pub fn spawn<B: BaoStore>(
        rt: Handle,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        store: S,
        bao_store: B,
        downloader: Downloader,
    ) -> Self {
        let live = LiveSync::spawn(rt.clone(), endpoint.clone(), gossip, bao_store, downloader);
        Self {
            live,
            store,
            rt,
            endpoint,
            active: Default::default(),
        }
    }

    /// Start to sync a document.
    ///
    /// If `peers` is non-empty, it will both do an initial set-reconciliation sync with each peer,
    /// and join an iroh-gossip swarm with these peers to receive and broadcast document updates.
    pub async fn start_sync(
        &self,
        namespace: NamespaceId,
        peers: Vec<PeerSource>,
    ) -> anyhow::Result<()> {
        if !self.active.read().contains(&namespace) {
            let replica = self.get_replica(&namespace)?;
            self.live.start_sync(replica, peers).await?;
            self.active.write().insert(namespace);
        } else if !peers.is_empty() {
            self.live.join_peers(namespace, peers).await?;
        }
        Ok(())
    }

    /// Stop syncing a document.
    pub async fn stop_sync(&self, namespace: NamespaceId) -> anyhow::Result<()> {
        let replica = self.get_replica(&namespace)?;
        self.active.write().remove(&replica.namespace());
        self.live.stop_sync(namespace).await?;
        Ok(())
    }

    /// Shutdown the sync engine.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        self.live.shutdown().await?;
        Ok(())
    }

    /// Get a [`Replica`] from the store, returning an error if the replica does not exist.
    pub fn get_replica(&self, id: &NamespaceId) -> anyhow::Result<Replica<S::Instance>> {
        self.store
            .open_replica(id)?
            .ok_or_else(|| anyhow!("doc not found"))
    }

    /// Get an [`Author`] from the store, returning an error if the replica does not exist.
    pub fn get_author(&self, id: &AuthorId) -> anyhow::Result<Author> {
        self.store
            .get_author(id)?
            .ok_or_else(|| anyhow!("author not found"))
    }
}
