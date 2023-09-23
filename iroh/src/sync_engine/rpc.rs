//! This module contains an impl block on [`SyncEngine`] with handlers for RPC requests

use anyhow::anyhow;
use futures::{FutureExt, Stream};
use iroh_bytes::{
    baomap::Store as BaoStore,
    util::{BlobFormat, RpcError},
};
use iroh_sync::{store::Store, sync::Namespace};
use itertools::Itertools;
use rand::rngs::OsRng;

use crate::{
    rpc_protocol::{
        AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
        DocCreateRequest, DocCreateResponse, DocGetManyRequest, DocGetManyResponse,
        DocGetOneRequest, DocGetOneResponse, DocImportRequest, DocImportResponse, DocInfoRequest,
        DocInfoResponse, DocListRequest, DocListResponse, DocSetRequest, DocSetResponse,
        DocShareRequest, DocShareResponse, DocStartSyncRequest, DocStartSyncResponse,
        DocStopSyncRequest, DocStopSyncResponse, DocSubscribeRequest, DocSubscribeResponse,
        DocTicket, RpcResult, ShareMode,
    },
    sync_engine::{KeepCallback, LiveStatus, SyncEngine},
};

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

    pub fn doc_list(&self, _req: DocListRequest) -> impl Stream<Item = RpcResult<DocListResponse>> {
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
        let _replica = self.get_replica(&req.doc_id)?;
        let status = self.live.status(req.doc_id).await?;
        let status = status.unwrap_or(LiveStatus {
            active: false,
            subscriptions: 0,
        });
        Ok(DocInfoResponse { status })
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        self.start_sync(req.doc_id, vec![]).await?;
        let me = self.endpoint.my_addr().await?;
        let replica = self.get_replica(&req.doc_id)?;
        let key = match req.mode {
            ShareMode::Read => {
                // TODO: support readonly docs
                // *replica.namespace().as_bytes()
                return Err(anyhow!("creating read-only shares is not yet supported").into());
            }
            ShareMode::Write => replica.secret_key(),
        };
        Ok(DocShareResponse(DocTicket {
            key,
            peers: vec![me],
        }))
    }

    pub async fn doc_subscribe(
        &self,
        req: DocSubscribeRequest,
    ) -> impl Stream<Item = RpcResult<DocSubscribeResponse>> {
        let (s, r) = flume::bounded(64);
        let res = self
            .live
            .subscribe(req.doc_id, {
                let s = s.clone();
                move |event| {
                    let s = s.clone();
                    async move {
                        // Send event over the channel, unsubscribe if the channel is closed.
                        match s.send_async(Ok(DocSubscribeResponse { event })).await {
                            Err(_err) => KeepCallback::Drop,
                            Ok(()) => KeepCallback::Keep,
                        }
                    }
                    .boxed()
                }
            })
            .await;
        match res {
            Err(err) => {
                s.send_async(Err(err.into())).await.ok();
            }
            Ok(_token) => {}
        };
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
        self.start_sync(doc_id, peers).await?;
        Ok(DocStartSyncResponse {})
    }

    pub async fn doc_stop_sync(&self, req: DocStopSyncRequest) -> RpcResult<DocStopSyncResponse> {
        let DocStopSyncRequest { doc_id } = req;
        self.stop_sync(doc_id).await?;
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
        let tag = bao_store
            .import_bytes(value.into(), BlobFormat::RAW)
            .await?;
        replica
            .insert(&key, &author, *tag.hash(), len as u64)
            .map_err(anyhow::Error::from)?;
        let entry = self
            .store
            .get_one(replica.namespace(), author.id(), &key)?
            .ok_or_else(|| anyhow!("failed to get entry after insertion"))?;
        Ok(DocSetResponse { entry })
    }

    pub fn doc_get_many(
        &self,
        req: DocGetManyRequest,
    ) -> impl Stream<Item = RpcResult<DocGetManyResponse>> {
        let DocGetManyRequest { doc_id, filter } = req;
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let store = self.store.clone();
        self.rt.main().spawn_blocking(move || {
            let ite = store.get_many(doc_id, filter);
            let ite = inline_result(ite).map_ok(|entry| DocGetManyResponse { entry });
            for entry in ite {
                if let Err(_err) = tx.send(entry) {
                    break;
                }
            }
        });
        rx.into_stream()
    }

    pub async fn doc_get_one(&self, req: DocGetOneRequest) -> RpcResult<DocGetOneResponse> {
        let DocGetOneRequest {
            doc_id,
            author,
            key,
        } = req;
        let replica = self.get_replica(&doc_id)?;
        let entry = self.store.get_one(replica.namespace(), author, key)?;
        Ok(DocGetOneResponse { entry })
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
