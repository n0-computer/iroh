use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use iroh_bytes::util::runtime::Handle;
use iroh_gossip::net::Gossip;
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::{
    store::Store,
    sync::{Author, AuthorId, InsertOrigin, NamespaceId, OnInsertCallback, RemovalToken, Replica},
};
use parking_lot::RwLock;

use crate::download::Downloader;

use super::{LiveSync, PeerSource};

/// The SyncEngine combines the [`LiveSync`] actor with the Iroh bytes database and [`Downloader`].
///
#[derive(Debug, Clone)]
pub struct SyncEngine<S: Store> {
    pub(crate) rt: Handle,
    pub(crate) store: S,
    pub(crate) endpoint: MagicEndpoint,
    downloader: Downloader,
    live: LiveSync<S>,
    active: Arc<RwLock<HashMap<NamespaceId, RemovalToken>>>,
}

impl<S: Store> SyncEngine<S> {
    /// Start the sync engine.
    ///
    /// This will spawn a background task for the [`LiveSync`]. When documents are added to the
    /// engine with [`Self::start_sync`], then new entries inserted locally will be sent to peers
    /// through iroh-gossip.
    ///
    /// The engine will also register [`Replica::on_insert`] callbacks to download content for new
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
            // add download listener
            let removal_token = replica.on_insert(on_insert_download(self.downloader.clone()));
            self.active
                .write()
                .insert(replica.namespace(), removal_token);
            // start to gossip updates
            self.live.start_sync(replica.clone(), peers).await?;
        } else if !peers.is_empty() {
            self.live.join_peers(namespace, peers).await?;
        }
        Ok(())
    }

    /// Stop syncing a document.
    pub async fn stop_sync(&self, namespace: NamespaceId) -> anyhow::Result<()> {
        let replica = self.get_replica(&namespace)?;
        let token = self.active.write().remove(&replica.namespace());
        if let Some(token) = token {
            replica.remove_on_insert(token);
            self.live.stop_sync(namespace).await?;
        }
        Ok(())
    }

    /// Shutdown the sync engine.
    pub async fn shutdown(&self) -> anyhow::Result<()> {
        for (namespace, token) in self.active.write().drain() {
            if let Ok(Some(replica)) = self.store.open_replica(&namespace) {
                replica.remove_on_insert(token);
            }
        }
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

fn on_insert_download(downloader: Downloader) -> OnInsertCallback {
    Box::new(move |origin, entry| {
        if let InsertOrigin::Sync(Some(peer_id)) = origin {
            let peer_id = PeerId::from_bytes(&peer_id).unwrap();
            let hash = *entry.entry().record().content_hash();
            downloader.push(hash, vec![peer_id]);
        }
    })
}
