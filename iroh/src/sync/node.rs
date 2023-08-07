use std::{collections::HashSet, sync::Arc};

use anyhow::anyhow;
use futures::Stream;
use genawaiter::sync::Gen;
use iroh_bytes::util::runtime::Handle;
use iroh_net::{tls::PeerId, MagicEndpoint};
use iroh_sync::{
    store::Store,
    sync::{Author, AuthorId, InsertOrigin, Namespace, NamespaceId, Replica, SignedEntry},
};
use parking_lot::Mutex;
use rand::rngs::OsRng;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
    DocGetRequest, DocGetResponse, DocJoinRequest, DocJoinResponse, DocListRequest,
    DocListResponse, DocSetRequest, DocSetResponse, DocShareRequest, DocShareResponse,
    DocsCreateRequest, DocsCreateResponse, DocsImportRequest, DocsImportResponse, DocsListRequest,
    DocsListResponse, RpcResult, ShareMode,
};

use super::{BlobStore, DownloadMode, LiveSync, PeerSource};

/// Document synchronization engine
#[derive(Debug, Clone)]
pub struct SyncNode<S: Store> {
    endpoint: MagicEndpoint,
    pub(crate) store: S,
    pub(crate) live: LiveSync<S>,
    blobs: BlobStore,
    open_docs: Arc<Mutex<HashSet<NamespaceId>>>,
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
            endpoint,
            open_docs: Default::default(),
        }
    }

    /// todo
    pub fn author_create(&self, _req: AuthorCreateRequest) -> RpcResult<AuthorCreateResponse> {
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
                        let res = AuthorListResponse {
                            author_id: author.id(),
                            writable: true,
                        };
                        co.yield_(Ok(res)).await;
                    }
                }
                Err(err) => co.yield_(Err(err.into())).await,
            }
        })
    }

    fn get_replica(&self, id: &NamespaceId) -> anyhow::Result<Replica<S::Instance>> {
        self.store
            .get_replica(id)?
            .ok_or_else(|| anyhow!("doc not found"))
    }

    fn get_author(&self, id: &AuthorId) -> anyhow::Result<Author> {
        self.store
            .get_author(id)?
            .ok_or_else(|| anyhow!("author not found"))
    }

    pub async fn doc_open(&self, id: &NamespaceId, peers: Vec<PeerSource>) -> anyhow::Result<()> {
        let replica = self.get_replica(id)?;

        {
            let mut open_docs = self.open_docs.lock();
            if open_docs.contains(id) {
                return Ok(());
            } else {
                open_docs.insert(id.clone());
            }
        }

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

    pub fn docs_create(&self, _req: DocsCreateRequest) -> RpcResult<DocsCreateResponse> {
        let doc = self.store.new_replica(Namespace::new(&mut OsRng {}))?;
        Ok(DocsCreateResponse {
            id: doc.namespace(),
        })
    }

    pub fn docs_list(
        &self,
        _req: DocsListRequest,
    ) -> impl Stream<Item = RpcResult<DocsListResponse>> {
        let store = self.store.clone();
        Gen::new(|co| async move {
            match store.list_replicas() {
                Ok(namespaces) => {
                    for id in namespaces {
                        co.yield_(Ok(DocsListResponse { id })).await;
                    }
                }
                Err(err) => co.yield_(Err(err.into())).await,
            }
        })
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        let replica = self.get_replica(&req.doc_id)?;
        self.doc_open(&replica.namespace(), vec![]).await?;
        let key = match req.mode {
            // ShareMode::Read => *replica.namespace().as_bytes(),
            ShareMode::Read => {
                return Err(anyhow!("creating read-only shares is not yet supported").into())
            }
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

    pub async fn docs_import(&self, req: DocsImportRequest) -> RpcResult<DocsImportResponse> {
        let DocsImportRequest { key, peers } = req;
        // let namespace = match NamespaceId::from_bytes(&key) {
        //     Ok(id) => {
        //         return Err(anyhow!("importing read-only replicas is not yet supported").into())
        //     }
        //     Err(_err) => Namespace::from_bytes(&key),
        // };
        let namespace = Namespace::from_bytes(&key);
        let id = namespace.id();
        let replica = self.store.new_replica(namespace)?;
        self.doc_open(&id, peers.clone()).await?;
        self.live.add(replica, peers).await?;
        Ok(DocsImportResponse { doc_id: id })
    }

    pub async fn doc_join(&self, req: DocJoinRequest) -> RpcResult<DocJoinResponse> {
        let DocJoinRequest { doc_id, peers } = req;
        let replica = self.get_replica(&doc_id)?;
        self.doc_open(&doc_id, vec![]).await?;
        self.live.add(replica, peers).await?;
        Ok(DocJoinResponse {})
    }

    pub async fn doc_set(&self, req: DocSetRequest) -> RpcResult<DocSetResponse> {
        let DocSetRequest {
            doc_id,
            author_id,
            key,
            value,
        } = req;
        let replica = self.get_replica(&doc_id)?;
        let author = self.get_author(&author_id)?;
        let (hash, len) = self.blobs.put_bytes(value.into()).await?;
        replica
            .insert(&key, &author, hash, len)
            .map_err(|err| anyhow!(err))?;
        let entry = self
            .store
            .get_latest_by_key_and_author(replica.namespace(), author.id(), &key)?
            .expect("inserted successfully");
        Ok(DocSetResponse { entry })
    }

    pub fn doc_get(&self, req: DocGetRequest) -> impl Stream<Item = RpcResult<DocGetResponse>> {
        let namespace = req.doc_id;
        let latest = req.latest;
        let filter = ListFilter::from(req);
        let ite = DocIter::new(&self.store, namespace, filter, latest);
        let ite = inline_error(ite);
        let ite = ite.map(|entry| entry.map(|entry| DocGetResponse { entry }));
        // TODO: avoid collect? but the iterator is not Send and has a lifetime on the store.
        let entries = ite.collect::<Vec<_>>();
        futures::stream::iter(entries.into_iter())
    }

    pub fn doc_list(&self, req: DocListRequest) -> impl Stream<Item = RpcResult<DocListResponse>> {
        let namespace = req.doc_id;
        let latest = req.latest;
        let filter = ListFilter::from(req);
        let ite = DocIter::new(&self.store, namespace, filter, latest);
        let ite = inline_error(ite);
        let ite = ite.map(|entry| entry.map(|entry| DocListResponse { entry }));
        // TODO: avoid collect? but the iterator is not Send and has a lifetime on the store.
        let entries = ite.collect::<Vec<_>>();
        futures::stream::iter(entries.into_iter())
    }
}

// TODO: Move to iroh-sync
#[derive(Debug)]
enum ListFilter {
    All,
    Prefix(Vec<u8>),
    Key(Vec<u8>),
    KeyAndAuthor(Vec<u8>, AuthorId),
}
impl From<DocListRequest> for ListFilter {
    fn from(_req: DocListRequest) -> Self {
        ListFilter::All
    }
}
impl From<DocGetRequest> for ListFilter {
    fn from(req: DocGetRequest) -> Self {
        match (req.prefix, req.author_id) {
            (true, None) => ListFilter::Prefix(req.key),
            (false, None) => ListFilter::Key(req.key),
            (false, Some(author)) => ListFilter::KeyAndAuthor(req.key, author),
            // TODO: support get_all|latest_by_prefix_and_author
            (true, Some(_author)) => {
                unimplemented!("get by prefix and author is not yet implemented")
            }
        }
    }
}

// TODO: Move to iroh-sync
enum DocIter<'s, S: Store> {
    All(S::GetAllIter<'s>),
    Latest(S::GetLatestIter<'s>),
    Single(std::option::IntoIter<anyhow::Result<SignedEntry>>),
}

impl<'s, S: Store> Iterator for DocIter<'s, S> {
    type Item = anyhow::Result<SignedEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            DocIter::All(iter) => iter.next().map(|x| x.map(|(_id, entry)| entry)),
            DocIter::Latest(iter) => iter.next().map(|x| x.map(|(_id, entry)| entry)),
            DocIter::Single(iter) => iter.next(),
        }
    }
}

impl<'s, S: Store> DocIter<'s, S> {
    pub fn new(
        store: &'s S,
        namespace: NamespaceId,
        filter: ListFilter,
        latest: bool,
    ) -> anyhow::Result<Self> {
        Ok(match latest {
            false => match filter {
                ListFilter::All => Self::All(store.get_all(namespace)?),
                ListFilter::Prefix(prefix) => {
                    Self::All(store.get_all_by_prefix(namespace, &prefix)?)
                }
                ListFilter::Key(key) => Self::All(store.get_all_by_key(namespace, key)?),
                ListFilter::KeyAndAuthor(key, author) => {
                    Self::All(store.get_all_by_key_and_author(namespace, author, key)?)
                }
            },
            true => match filter {
                ListFilter::All => Self::Latest(store.get_latest(namespace)?),
                ListFilter::Prefix(prefix) => {
                    Self::Latest(store.get_latest_by_prefix(namespace, &prefix)?)
                }
                ListFilter::Key(key) => Self::Latest(store.get_latest_by_key(namespace, key)?),
                ListFilter::KeyAndAuthor(key, author) => Self::Single(
                    store
                        .get_latest_by_key_and_author(namespace, author, key)?
                        .map(|entry| Ok(entry))
                        .into_iter(),
                ),
            },
        })
    }
}

fn inline_error<T>(
    ite: anyhow::Result<impl Iterator<Item = anyhow::Result<T>>>,
) -> impl Iterator<Item = RpcResult<T>> {
    match ite {
        Ok(ite) => itertools::Either::Left(ite.map(|item| item.map_err(|err| err.into()))),
        Err(err) => itertools::Either::Right(Some(Err(err.into())).into_iter()),
    }
}
