// use std::collections::HashMap;

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, bail};
use futures::Stream;
use genawaiter::sync::Gen;
use iroh_bytes::util::runtime::Handle;
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::{
    store::Store,
    sync::{InsertOrigin, Namespace, NamespaceId, Replica},
};
use rand::rngs::OsRng;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
    DocSetRequest, DocSetResponse, DocShareRequest, DocShareResponse, DocsCreateRequest,
    DocsCreateResponse, DocsImportRequest, DocsImportResponse, RpcResult, ShareMode,
};

use super::{BlobStore, Doc, DownloadMode, LiveSync, PeerSource};

/// Document synchronization engine
#[derive(Debug, Clone)]
pub struct SyncNode<S: Store> {
    endpoint: MagicEndpoint,
    store: S,
    live: LiveSync<S>,
    blobs: BlobStore,
    // open_docs: Arc<HashSet<NamespaceId>>
}

impl<S: Store> SyncNode<S> {
    /// todo
    pub fn spawn(
        rt: Handle,
        store: S,
        endpoint: MagicEndpoint,
        gossip: iroh_gossip::net::GossipHandle,
        blobs: BlobStore,
    ) -> Self {
        let live = LiveSync::spawn(rt, endpoint.clone(), gossip);
        Self {
            store,
            live,
            blobs,
            endpoint, // open_docs: Default::default(),
        }
    }

    /// todo
    pub fn author_create(&self, _req: AuthorCreateRequest) -> anyhow::Result<AuthorCreateResponse> {
        // TODO: pass rng
        let author = self.store.new_author(&mut rand::rngs::OsRng {})?;
        Ok(AuthorCreateResponse {
            author_id: author.id(),
        })
    }

    /// todo
    pub fn author_list(
        &self,
        _req: AuthorListRequest,
    ) -> impl Stream<Item = RpcResult<AuthorListResponse>> {
        let store = self.store.clone();
        Gen::new(|co| async move {
            match store.list_authors() {
                Ok(authors) => {
                    for author in authors {
                        let author = AuthorListResponse {
                            author_id: author.id(),
                            writable: true,
                        };
                        co.yield_(Ok(author)).await;
                    }
                }
                Err(err) => {
                    co.yield_(Err(err.into())).await;
                }
            }
        })
    }

    fn get_replica(&self, id: &NamespaceId) -> anyhow::Result<Replica<S::Instance>> {
        self.store
            .get_replica(id)?
            .ok_or_else(|| anyhow!("doc not found"))
    }

    pub async fn doc_open(&self, id: &NamespaceId, peers: Vec<PeerSource>) -> anyhow::Result<()> {
        let replica = self.get_replica(id)?;

        let download_mode = DownloadMode::Always;

        // If download mode is set to always download:
        // setup on_insert callback to trigger download on remote insert
        if let DownloadMode::Always = download_mode {
            let replica = replica.clone();
            let blobs = self.blobs.clone();
            replica.on_insert(Box::new(move |origin, entry| {
                if matches!(origin, InsertOrigin::Sync) {
                    let hash = *entry.entry().record().content_hash();
                    let peer_id = PeerId::from_bytes(entry.entry().id().author().as_bytes())
                        .expect("failed to convert author to peer id");
                    blobs.start_download(hash, peer_id);
                }
            }));
        }

        self.live.add(replica, peers).await?;

        // Collect metrics
        // replica.on_insert(Box::new(move |origin, entry| {
        //     let size = entry.entry().record().content_len();
        //     match origin {
        //         InsertOrigin::Local => {
        //             inc!(Metrics, new_entries_local);
        //             inc_by!(Metrics, new_entries_local_size, size);
        //         }
        //         InsertOrigin::Sync => {
        //             inc!(Metrics, new_entries_remote);
        //             inc_by!(Metrics, new_entries_remote_size, size);
        //         }
        //     }
        // }));

        Ok(())
    }

    pub fn docs_create(&self, req: DocsCreateRequest) -> RpcResult<DocsCreateResponse> {
        let doc = self.store.new_replica(Namespace::new(&mut OsRng {}))?;
        Ok(DocsCreateResponse {
            id: doc.namespace(),
        })
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        let replica = self.get_replica(&req.doc_id)?;
        let key = match req.mode {
            ShareMode::Read => *replica.namespace().as_bytes(),
            ShareMode::Write => replica.secret_key(),
        };
        let me = PeerSource {
            peer_id: self.endpoint.peer_id(),
            derp_region: self.endpoint.my_derp().await,
            addrs: self
                .endpoint
                .local_endpoints()
                .await?
                .into_iter()
                .map(|ep| ep.addr)
                .collect(),
        };
        Ok(DocShareResponse { key, me })
    }

    pub fn doc_import(&self, req: DocsImportRequest) -> anyhow::Result<DocsImportResponse> {
        let doc = match NamespaceId::from_bytes(&req.key) {
            Ok(id) => bail!("importing read-only replicas is not yet supported"),
            Err(_err) => {
                let namespace = Namespace::from_bytes(&req.key);
                self.store.new_replica(namespace)?;
                todo!()
            }
        };
    }

    pub fn doc_set(&self, req: DocSetRequest) -> RpcResult<DocSetResponse> {
        todo!()
    }

    // PeerAdd(PeerAddRequest),
    // PeerList(PeerListRequest),
    //
    // AuthorImport(AuthorImportRequest),
    // AuthorShare(AuthorShareRequest),
    //
    // DocsList(DocsListRequest),
    // DocsCreate(DocsCreateRequest),
    // DocsImport(DocsImportRequest),
    //
    // DocSet(DocSetRequest),
    // DocGet(DocGetRequest),
    // DocList(DocListRequest),
    // DocJoin(DocJoinRequest),
    // DocShare(DocShareRequest),
}
