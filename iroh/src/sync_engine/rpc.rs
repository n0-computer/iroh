//! This module contains an impl block on [`SyncEngine`] with handlers for RPC requests

use anyhow::anyhow;
use futures::Stream;
use iroh_bytes::{store::Store as BaoStore, BlobFormat};
use iroh_sync::{Author, NamespaceSecret};
use tokio_stream::StreamExt;

use crate::rpc_protocol::{
    AuthorDeleteRequest, AuthorDeleteResponse, AuthorExportRequest, AuthorExportResponse,
    AuthorImportRequest, AuthorImportResponse, DocGetSyncPeersRequest, DocGetSyncPeersResponse,
};
use crate::{
    rpc_protocol::{
        AuthorCreateRequest, AuthorCreateResponse, AuthorListRequest, AuthorListResponse,
        DocCloseRequest, DocCloseResponse, DocCreateRequest, DocCreateResponse, DocDelRequest,
        DocDelResponse, DocDropRequest, DocDropResponse, DocGetDownloadPolicyRequest,
        DocGetDownloadPolicyResponse, DocGetExactRequest, DocGetExactResponse, DocGetManyRequest,
        DocGetManyResponse, DocImportRequest, DocImportResponse, DocLeaveRequest, DocLeaveResponse,
        DocListRequest, DocListResponse, DocOpenRequest, DocOpenResponse,
        DocSetDownloadPolicyRequest, DocSetDownloadPolicyResponse, DocSetHashRequest,
        DocSetHashResponse, DocSetRequest, DocSetResponse, DocShareRequest, DocShareResponse,
        DocStartSyncRequest, DocStartSyncResponse, DocStatusRequest, DocStatusResponse,
        DocSubscribeRequest, DocSubscribeResponse, DocTicket, RpcResult, ShareMode,
    },
    sync_engine::SyncEngine,
};

/// Capacity for the flume channels to forward sync store iterators to async RPC streams.
const ITER_CHANNEL_CAP: usize = 64;

#[allow(missing_docs)]
impl SyncEngine {
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
        tokio::task::spawn(async move {
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

    pub async fn author_import(&self, req: AuthorImportRequest) -> RpcResult<AuthorImportResponse> {
        let author_id = self.sync.import_author(req.author).await?;
        Ok(AuthorImportResponse { author_id })
    }

    pub async fn author_export(&self, req: AuthorExportRequest) -> RpcResult<AuthorExportResponse> {
        let author = self.sync.export_author(req.author).await?;

        Ok(AuthorExportResponse { author })
    }

    pub async fn author_delete(&self, req: AuthorDeleteRequest) -> RpcResult<AuthorDeleteResponse> {
        self.sync.delete_author(req.author).await?;
        Ok(AuthorDeleteResponse)
    }

    pub async fn doc_create(&self, _req: DocCreateRequest) -> RpcResult<DocCreateResponse> {
        let namespace = NamespaceSecret::new(&mut rand::rngs::OsRng {});
        let id = namespace.id();
        self.sync.import_namespace(namespace.into()).await?;
        self.sync.open(id, Default::default()).await?;
        Ok(DocCreateResponse { id })
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
        tokio::task::spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.list_replicas(tx).await {
                tx2.send_async(Err(err)).await.ok();
            }
        });
        rx.into_stream().map(|r| {
            r.map(|(id, capability)| DocListResponse { id, capability })
                .map_err(Into::into)
        })
    }

    pub async fn doc_open(&self, req: DocOpenRequest) -> RpcResult<DocOpenResponse> {
        self.sync.open(req.doc_id, Default::default()).await?;
        Ok(DocOpenResponse {})
    }

    pub async fn doc_close(&self, req: DocCloseRequest) -> RpcResult<DocCloseResponse> {
        self.sync.close(req.doc_id).await?;
        Ok(DocCloseResponse {})
    }

    pub async fn doc_status(&self, req: DocStatusRequest) -> RpcResult<DocStatusResponse> {
        let status = self.sync.get_state(req.doc_id).await?;
        Ok(DocStatusResponse { status })
    }

    pub async fn doc_share(&self, req: DocShareRequest) -> RpcResult<DocShareResponse> {
        let me = self.endpoint.my_addr().await?;
        let capability = match req.mode {
            ShareMode::Read => iroh_sync::Capability::Read(req.doc_id),
            ShareMode::Write => {
                let secret = self.sync.export_secret_key(req.doc_id).await?;
                iroh_sync::Capability::Write(secret)
            }
        };
        self.start_sync(req.doc_id, vec![]).await?;
        Ok(DocShareResponse(DocTicket {
            capability,
            nodes: vec![me],
        }))
    }

    pub fn doc_subscribe(
        &self,
        req: DocSubscribeRequest,
    ) -> impl Stream<Item = RpcResult<DocSubscribeResponse>> {
        let stream = self.subscribe(req.doc_id);
        stream.map(|res| {
            res.map(|event| DocSubscribeResponse { event })
                .map_err(Into::into)
        })
    }

    pub async fn doc_import(&self, req: DocImportRequest) -> RpcResult<DocImportResponse> {
        let DocImportRequest(DocTicket {
            capability,
            nodes: peers,
        }) = req;
        let doc_id = self.sync.import_namespace(capability).await?;
        self.sync.open(doc_id, Default::default()).await?;
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
            .get_exact(doc_id, author_id, key, false)
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
        let DocGetManyRequest { doc_id, query } = req;
        let (tx, rx) = flume::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        tokio::task::spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.get_many(doc_id, query, tx).await {
                tx2.send_async(Err(err)).await.ok();
            }
        });
        rx.into_stream().map(|r| {
            r.map(|entry| DocGetManyResponse { entry })
                .map_err(Into::into)
        })
    }

    pub async fn doc_get_exact(&self, req: DocGetExactRequest) -> RpcResult<DocGetExactResponse> {
        let DocGetExactRequest {
            doc_id,
            author,
            key,
            include_empty,
        } = req;
        let entry = self
            .sync
            .get_exact(doc_id, author, key, include_empty)
            .await?;
        Ok(DocGetExactResponse { entry })
    }

    pub async fn doc_set_download_policy(
        &self,
        req: DocSetDownloadPolicyRequest,
    ) -> RpcResult<DocSetDownloadPolicyResponse> {
        self.sync
            .set_download_policy(req.doc_id, req.policy)
            .await?;
        Ok(DocSetDownloadPolicyResponse {})
    }
    pub async fn doc_get_download_policy(
        &self,
        req: DocGetDownloadPolicyRequest,
    ) -> RpcResult<DocGetDownloadPolicyResponse> {
        let policy = self.sync.get_download_policy(req.doc_id).await?;
        Ok(DocGetDownloadPolicyResponse { policy })
    }

    pub async fn doc_get_sync_peers(
        &self,
        req: DocGetSyncPeersRequest,
    ) -> RpcResult<DocGetSyncPeersResponse> {
        let peers = self.sync.get_sync_peers(req.doc_id).await?;
        Ok(DocGetSyncPeersResponse { peers })
    }
}
