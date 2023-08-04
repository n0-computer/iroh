// use std::collections::HashMap;

use futures::Stream;
use genawaiter::sync::Gen;
use iroh_bytes::util::runtime::Handle;
use iroh_net::MagicEndpoint;
use iroh_sync::store::Store;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse, RpcResult,
};

// use super::{BlobStore, Doc, LiveSync};

/// Document synchronization engine
#[derive(Debug, Clone)]
pub struct SyncNode<S: Store> {
    // rt: Handle,
    // endpoint: MagicEndpoint,
    store: S,
    // live: LiveSync<S>,
    // blobs: BlobStore,
    // open_docs: HashMap<NamespaceId, Doc<S>>,
}

impl<S: Store> SyncNode<S> {
    /// todo
    pub fn spawn(
        _rt: Handle,
        store: S,
        _endpoint: MagicEndpoint,
        _gossip: iroh_gossip::net::GossipHandle,
        // blobs: BlobStore,
    ) -> Self {
        // let live = LiveSync::spawn(rt, endpoint, gossip);
        Self {
            store,
            // live,
            // blobs,
            // open_docs: Default::default(),
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
}
