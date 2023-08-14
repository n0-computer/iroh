use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use futures::FutureExt;
use iroh_bytes::util::runtime::Handle;
use iroh_gossip::net::Gossip;
use iroh_net::MagicEndpoint;
use iroh_sync::{
    store::Store,
    sync::{Author, AuthorId, NamespaceId, Replica},
};
use parking_lot::RwLock;

use crate::download::Downloader;

use super::{LiveEvent, LiveSync, OnLiveEventCallback, PeerSource, RemovalToken};

/// The SyncEngine combines the [`LiveSync`] actor with the Iroh bytes database and [`Downloader`].
///
#[derive(Debug, Clone)]
pub struct SyncEngine<S: Store> {
    pub(crate) rt: Handle,
    pub(crate) store: S,
    pub(crate) endpoint: MagicEndpoint,
    downloader: Downloader,
    pub(crate) live: LiveSync<S>,
    active: Arc<RwLock<HashMap<NamespaceId, RemovalToken>>>,
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
    pub fn spawn(
        rt: Handle,
        endpoint: MagicEndpoint,
        gossip: Gossip,
        store: S,
        downloader: Downloader,
    ) -> Self {
        let live = LiveSync::spawn(rt.clone(), endpoint.clone(), gossip);
        Self {
            live,
            downloader,
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
        let replica = self.get_replica(&namespace)?;
        if !self.active.read().contains_key(&namespace) {
            // start to gossip updates
            self.live.start_sync(replica, peers).await?;
            // add download listener
            let removal_token = self
                .live
                .subscribe(namespace, on_insert_download(self.downloader.clone()))
                .await?;

            self.active.write().insert(namespace, removal_token);
        } else if !peers.is_empty() {
            self.live.join_peers(namespace, peers).await?;
        }
        Ok(())
    }

    /// Stop syncing a document.
    pub async fn stop_sync(&self, namespace: NamespaceId) -> anyhow::Result<()> {
        let replica = self.get_replica(&namespace)?;
        self.active.write().remove(&replica.namespace());
        // `stop_sync` removes all callback listeners automatically
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

fn on_insert_download(downloader: Downloader) -> OnLiveEventCallback {
    Box::new(move |event: LiveEvent| {
        let downloader = downloader.clone();
        async move {
            if let LiveEvent::InsertRemote {
                from: Some(peer_id),
                entry,
            } = event
            {
                let hash = *entry.record().content_hash();
                downloader.push(hash, vec![peer_id]).await;
            }
        }
        .boxed()
    })
}
