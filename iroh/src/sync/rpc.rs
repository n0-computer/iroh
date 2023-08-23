//! This module contains an impl block on [`SyncEngine`] with handlers for RPC requests

use anyhow::anyhow;
use futures::{FutureExt, Stream};
use iroh_bytes::{baomap::Store as BaoStore, util::RpcError};
use iroh_sync::{store::Store, sync::Namespace};
use itertools::Itertools;
use rand::rngs::OsRng;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
    DocCreateRequest, DocCreateResponse, DocGetRequest, DocGetResponse, DocImportRequest,
    DocImportResponse, DocInfoRequest, DocInfoResponse, DocListRequest, DocListResponse,
    DocSetRequest, DocSetResponse, DocShareRequest, DocShareResponse, DocStartSyncRequest,
    DocStartSyncResponse, DocStopSyncRequest, DocStopSyncResponse, DocSubscribeRequest,
    DocSubscribeResponse, DocTicket, RpcResult, ShareMode,
};

use super::{engine::SyncEngine, PeerSource};

/// Capacity for the flume channels to forward sync store iterators to async RPC streams.
const ITER_CHANNEL_CAP: usize = 64;

#[allow(missing_docs)]
impl<S: Store> SyncEngine<S> {
    pub fn author_create(&self, _req: AuthorCreateRequest) -> RpcResult<AuthorCreateResponse> {
        // TODO: pass rng
        let author = self.store.new_author(&mut rand::rngs::OsRng {})?;
        Ok(AuthorCreateResponse {
            author_id: author.id(),
        })
    }

    pub fn author_list(
        &self,
        _req: AuthorListRequest,
    ) -> impl Stream<Item = RpcResult<AuthorListResponse>> {
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let store = self.store.clone();
        self.rt.main().spawn_blocking(move || {
            let ite = store.list_authors();
            let ite = inline_result(ite).map_ok(|author| AuthorListResponse {
                author_id: author.id(),
            });
            for entry in ite {
                if let Err(_err) = tx.send(entry) {
                    break;
                }
            }
        });
        rx.into_stream()
    }

    pub fn doc_create(&self, _req: DocCreateRequest) -> RpcResult<DocCreateResponse> {
        let doc = self.store.new_replica(Namespace::new(&mut OsRng {}))?;
        Ok(DocCreateResponse {
            id: doc.namespace(),
        })
    }

    pub fn doc_list(
        &self,
        _req: DocListRequest,
    ) -> impl Stream<Item = RpcResult<DocListResponse>> {
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let store = self.store.clone();
        self.rt.main().spawn_blocking(move || {
            let ite = store.list_namespaces();
            let ite = inline_result(ite).map_ok(|id| DocListResponse { id });
            for entry in ite {
                if let Err(_err) = tx.send(entry) {
                    break;
                }
            }
        });
        rx.into_stream()
    }

    pub async fn doc_info(&self, req: DocInfoRequest) -> RpcResult<DocInfoResponse> {
        let replica = self.get_replica(&req.doc_id)?;
        self.start_sync(replica.namespace(), vec![]).await?;
        Ok(DocInfoResponse {})
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        let replica = self.get_replica(&req.doc_id)?;
        let key = match req.mode {
            ShareMode::Read => {
                // TODO: support readonly docs
                // *replica.namespace().as_bytes()
                return Err(anyhow!("creating read-only shares is not yet supported").into());
            }
            ShareMode::Write => replica.secret_key(),
        };
        let me = PeerSource::from_endpoint(&self.endpoint).await?;
        self.start_sync(replica.namespace(), vec![]).await?;
        Ok(DocShareResponse(DocTicket {
            key,
            peers: vec![me],
        }))
    }

    pub async fn doc_subscribe(
        &self,
        req: DocSubscribeRequest,
    ) -> impl Stream<Item = DocSubscribeResponse> {
        let (s, r) = flume::bounded(64);
        self.live
            .subscribe(req.doc_id, move |event| {
                let s = s.clone();
                async move {
                    s.send_async(DocSubscribeResponse { event }).await.ok();
                }
                .boxed()
            })
            .await
            .unwrap(); // TODO: handle error

        r.into_stream()
    }

    pub async fn doc_import(&self, req: DocImportRequest) -> RpcResult<DocImportResponse> {
        let DocImportRequest(DocTicket { key, peers }) = req;
        // TODO: support read-only docs
        // if let Ok(namespace) = match NamespaceId::from_bytes(&key) {};
        let namespace = Namespace::from_bytes(&key);
        let id = namespace.id();
        let replica = self.store.new_replica(namespace)?;
        self.start_sync(replica.namespace(), peers).await?;
        Ok(DocImportResponse { doc_id: id })
    }

    pub async fn doc_start_sync(
        &self,
        req: DocStartSyncRequest,
    ) -> RpcResult<DocStartSyncResponse> {
        let DocStartSyncRequest { doc_id, peers } = req;
        let replica = self.get_replica(&doc_id)?;
        self.start_sync(replica.namespace(), peers).await?;
        Ok(DocStartSyncResponse {})
    }

    pub async fn doc_stop_sync(&self, req: DocStopSyncRequest) -> RpcResult<DocStopSyncResponse> {
        let DocStopSyncRequest { doc_id } = req;
        let replica = self.get_replica(&doc_id)?;
        self.stop_sync(replica.namespace()).await?;
        Ok(DocStopSyncResponse {})
    }

    pub async fn doc_set<B: BaoStore>(
        &self,
        bao_store: &B,
        req: DocSetRequest,
    ) -> RpcResult<DocSetResponse> {
        let DocSetRequest {
            doc_id,
            author_id,
            key,
            value,
        } = req;
        let replica = self.get_replica(&doc_id)?;
        let author = self.get_author(&author_id)?;
        let len = value.len();
        let hash = bao_store.import_bytes(value.into()).await?;
        replica
            .insert(&key, &author, hash, len as u64)
            .map_err(Into::into)?;
        let entry = self
            .store
            .get_latest_by_key_and_author(replica.namespace(), author.id(), &key)?
            .ok_or_else(|| anyhow!("failed to get entry after insertion"))?;
        Ok(DocSetResponse { entry })
    }

    pub fn doc_get(&self, req: DocGetRequest) -> impl Stream<Item = RpcResult<DocGetResponse>> {
        let DocGetRequest { doc_id, filter } = req;
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let store = self.store.clone();
        self.rt.main().spawn_blocking(move || {
            let ite = store.get(doc_id, filter);
            let ite = inline_result(ite).map_ok(|entry| DocGetResponse { entry });
            for entry in ite {
                if let Err(_err) = tx.send(entry) {
                    break;
                }
            }
        });
        rx.into_stream()
    }
}

fn inline_result<T>(
    ite: Result<impl Iterator<Item = Result<T, impl Into<RpcError>>>, impl Into<RpcError>>,
) -> impl Iterator<Item = RpcResult<T>> {
    match ite {
        Ok(ite) => itertools::Either::Left(ite.map(|item| item.map_err(|err| err.into()))),
        Err(err) => itertools::Either::Right(Some(Err(err.into())).into_iter()),
    }
}
