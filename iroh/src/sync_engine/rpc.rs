//! This module contains an impl block on [`SyncEngine`] with handlers for RPC requests

use anyhow::anyhow;
use futures::{FutureExt, Stream};
use iroh_bytes::{baomap::Store as BaoStore, util::BlobFormat};
use iroh_sync::{store::Store, sync::Namespace, Author};
use tokio_stream::StreamExt;

use crate::{
    rpc_protocol::{
        AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
        DocCreateRequest, DocCreateResponse, DocDelRequest, DocDelResponse, DocDropRequest,
        DocDropResponse, DocGetManyRequest, DocGetManyResponse, DocGetOneRequest,
        DocGetOneResponse, DocImportRequest, DocImportResponse, DocInfoRequest, DocInfoResponse,
        DocLeaveRequest, DocLeaveResponse, DocListRequest, DocListResponse, DocSetHashRequest,
        DocSetHashResponse, DocSetRequest, DocSetResponse, DocShareRequest, DocShareResponse,
        DocStartSyncRequest, DocStartSyncResponse, DocSubscribeRequest, DocSubscribeResponse,
        DocTicket, RpcResult, ShareMode,
    },
    sync_engine::{KeepCallback, LiveStatus, SyncEngine},
};

/// Capacity for the flume channels to forward sync store iterators to async RPC streams.
const ITER_CHANNEL_CAP: usize = 64;

#[allow(missing_docs)]
impl<S: Store> SyncEngine<S> {
    pub async fn author_create(
        &self,
        _req: AuthorCreateRequest,
    ) -> RpcResult<AuthorCreateResponse> {
        // TODO: pass rng
        let author = Author::new(&mut rand::rngs::OsRng {});
        self.sync.import_author(author.clone()).await?;
        Ok(AuthorCreateResponse {
            author_id: author.id(),
        })
    }

    pub fn author_list(
        &self,
        _req: AuthorListRequest,
    ) -> impl Stream<Item = RpcResult<AuthorListResponse>> {
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        self.rt.main().spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.list_authors(tx).await {
                tx2.send_async(Err(err)).await.ok();
            }
        });
        rx.into_stream().map(|r| {
            r.map(|author_id| AuthorListResponse { author_id })
                .map_err(Into::into)
        })
    }

    pub async fn doc_create(&self, _req: DocCreateRequest) -> RpcResult<DocCreateResponse> {
        let namespace = Namespace::new(&mut rand::rngs::OsRng {});
        self.sync.import_replica(namespace.clone()).await?;
        Ok(DocCreateResponse { id: namespace.id() })
    }

    pub async fn doc_drop(&self, req: DocDropRequest) -> RpcResult<DocDropResponse> {
        let DocDropRequest { doc_id } = req;
        self.leave(doc_id, true).await?;
        self.sync.drop_replica(doc_id).await?;
        Ok(DocDropResponse {})
    }

    pub fn doc_list(&self, _req: DocListRequest) -> impl Stream<Item = RpcResult<DocListResponse>> {
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        self.rt.main().spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.list_replicas(tx).await {
                tx2.send_async(Err(err)).await.ok();
            }
        });
        rx.into_stream()
            .map(|r| r.map(|id| DocListResponse { id }).map_err(Into::into))
    }

    pub async fn doc_info(&self, req: DocInfoRequest) -> RpcResult<DocInfoResponse> {
        let status = self.status(req.doc_id).await?;
        let status = status.unwrap_or(LiveStatus {
            state: Default::default(),
            subscriptions: 0,
        });
        Ok(DocInfoResponse { status })
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        let me = self.endpoint.my_addr().await?;
        let key = match req.mode {
            ShareMode::Read => {
                // TODO: support readonly docs
                // *replica.namespace().as_bytes()
                return Err(anyhow!("creating read-only shares is not yet supported").into());
            }
            ShareMode::Write => self.sync.export_secret_key(req.doc_id).await?.to_bytes(),
        };
        self.start_sync(req.doc_id, vec![]).await?;
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
        let s2 = s.clone();
        let res = self
            .subscribe(req.doc_id, {
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
                s2.send_async(Err(err.into())).await.ok();
            }
            Ok(_token) => {}
        };
        r.into_stream()
    }

    pub async fn doc_import(&self, req: DocImportRequest) -> RpcResult<DocImportResponse> {
        let DocImportRequest(DocTicket { key, peers }) = req;
        let namespace = Namespace::from_bytes(&key);
        let doc_id = self.sync.import_replica(namespace).await?;
        self.start_sync(doc_id, peers).await?;
        Ok(DocImportResponse { doc_id })
    }

    pub async fn doc_start_sync(
        &self,
        req: DocStartSyncRequest,
    ) -> RpcResult<DocStartSyncResponse> {
        let DocStartSyncRequest { doc_id, peers } = req;
        self.start_sync(doc_id, peers).await?;
        Ok(DocStartSyncResponse {})
    }

    pub async fn doc_leave(&self, req: DocLeaveRequest) -> RpcResult<DocLeaveResponse> {
        let DocLeaveRequest { doc_id } = req;
        self.leave(doc_id, false).await?;
        Ok(DocLeaveResponse {})
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
        let len = value.len();
        let tag = bao_store.import_bytes(value, BlobFormat::Raw).await?;
        self.sync
            .insert_local(doc_id, author_id, key.clone(), *tag.hash(), len as u64)
            .await?;
        let entry = self
            .sync
            .get_one(doc_id, author_id, key)
            .await?
            .ok_or_else(|| anyhow!("failed to get entry after insertion"))?;
        Ok(DocSetResponse { entry })
    }

    pub async fn doc_del(&self, req: DocDelRequest) -> RpcResult<DocDelResponse> {
        let DocDelRequest {
            doc_id,
            author_id,
            prefix,
        } = req;
        let removed = self.sync.delete_prefix(doc_id, author_id, prefix).await?;
        Ok(DocDelResponse { removed })
    }

    pub async fn doc_set_hash(&self, req: DocSetHashRequest) -> RpcResult<DocSetHashResponse> {
        let DocSetHashRequest {
            doc_id,
            author_id,
            key,
            hash,
            size,
        } = req;
        self.sync
            .insert_local(doc_id, author_id, key.clone(), hash, size)
            .await?;
        Ok(DocSetHashResponse {})
    }

    pub fn doc_get_many(
        &self,
        req: DocGetManyRequest,
    ) -> impl Stream<Item = RpcResult<DocGetManyResponse>> {
        let DocGetManyRequest { doc_id, filter } = req;
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        self.rt.main().spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.get_many(doc_id, filter, tx).await {
                tx2.send_async(Err(err)).await.ok();
            }
        });
        rx.into_stream().map(|r| {
            r.map(|entry| DocGetManyResponse { entry })
                .map_err(Into::into)
        })
    }

    pub async fn doc_get_one(&self, req: DocGetOneRequest) -> RpcResult<DocGetOneResponse> {
        let DocGetOneRequest {
            doc_id,
            author,
            key,
        } = req;
        let entry = self.sync.get_one(doc_id, author, key).await?;
        // let replica = self.get_replica(&doc_id)?;
        // let entry = self.store.get_one(replica.namespace(), author, key)?;
        Ok(DocGetOneResponse { entry })
    }
}
