//! This module contains an impl block on [`DocsProtocol`] with handlers for RPC requests

use anyhow::anyhow;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::{store::Store as BaoStore, BlobFormat};
use iroh_docs::{Author, DocTicket, NamespaceSecret};

use super::{RpcError, RpcResult};
use crate::{
    client::docs::ShareMode,
    node::protocol::docs::DocsProtocol,
    rpc_protocol::{
        authors::{
            CreateRequest, CreateResponse, DeleteRequest, DeleteResponse, ExportRequest,
            ExportResponse, GetDefaultRequest, GetDefaultResponse, ImportRequest, ImportResponse,
            ListRequest as AuthorListRequest, ListResponse as AuthorListResponse,
            SetDefaultRequest, SetDefaultResponse,
        },
        docs::{
            CloseRequest, CloseResponse, CreateRequest as DocCreateRequest,
            CreateResponse as DocCreateResponse, DelRequest, DelResponse, DocListRequest,
            DocSubscribeRequest, DocSubscribeResponse, DropRequest, DropResponse,
            GetDownloadPolicyRequest, GetDownloadPolicyResponse, GetExactRequest, GetExactResponse,
            GetManyRequest, GetManyResponse, GetSyncPeersRequest, GetSyncPeersResponse,
            ImportRequest as DocImportRequest, ImportResponse as DocImportResponse, LeaveRequest,
            LeaveResponse, ListResponse as DocListResponse, OpenRequest, OpenResponse,
            SetDownloadPolicyRequest, SetDownloadPolicyResponse, SetHashRequest, SetHashResponse,
            SetRequest, SetResponse, ShareRequest, ShareResponse, StartSyncRequest,
            StartSyncResponse, StatusRequest, StatusResponse,
        },
    },
};

/// Capacity for the flume channels to forward sync store iterators to async RPC streams.
const ITER_CHANNEL_CAP: usize = 64;

#[allow(missing_docs)]
impl DocsProtocol {
    pub async fn author_create(&self, _req: CreateRequest) -> RpcResult<CreateResponse> {
        // TODO: pass rng
        let author = Author::new(&mut rand::rngs::OsRng {});
        self.sync
            .import_author(author.clone())
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(CreateResponse {
            author_id: author.id(),
        })
    }

    pub fn author_default(&self, _req: GetDefaultRequest) -> GetDefaultResponse {
        let author_id = self.default_author.get();
        GetDefaultResponse { author_id }
    }

    pub async fn author_set_default(
        &self,
        req: SetDefaultRequest,
    ) -> RpcResult<SetDefaultResponse> {
        self.default_author
            .set(req.author_id, &self.sync)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(SetDefaultResponse)
    }

    pub fn author_list(
        &self,
        _req: AuthorListRequest,
    ) -> impl Stream<Item = RpcResult<AuthorListResponse>> + Unpin {
        let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        tokio::task::spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.list_authors(tx).await {
                tx2.send(Err(err)).await.ok();
            }
        });
        rx.boxed().map(|r| {
            r.map(|author_id| AuthorListResponse { author_id })
                .map_err(|e| RpcError::new(&*e))
        })
    }

    pub async fn author_import(&self, req: ImportRequest) -> RpcResult<ImportResponse> {
        let author_id = self
            .sync
            .import_author(req.author)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(ImportResponse { author_id })
    }

    pub async fn author_export(&self, req: ExportRequest) -> RpcResult<ExportResponse> {
        let author = self
            .sync
            .export_author(req.author)
            .await
            .map_err(|e| RpcError::new(&*e))?;

        Ok(ExportResponse { author })
    }

    pub async fn author_delete(&self, req: DeleteRequest) -> RpcResult<DeleteResponse> {
        if req.author == self.default_author.get() {
            return Err(RpcError::new(&*anyhow!(
                "Deleting the default author is not supported"
            )));
        }
        self.sync
            .delete_author(req.author)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(DeleteResponse)
    }

    pub async fn doc_create(&self, _req: DocCreateRequest) -> RpcResult<DocCreateResponse> {
        let namespace = NamespaceSecret::new(&mut rand::rngs::OsRng {});
        let id = namespace.id();
        self.sync
            .import_namespace(namespace.into())
            .await
            .map_err(|e| RpcError::new(&*e))?;
        self.sync
            .open(id, Default::default())
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(DocCreateResponse { id })
    }

    pub async fn doc_drop(&self, req: DropRequest) -> RpcResult<DropResponse> {
        let DropRequest { doc_id } = req;
        self.leave(doc_id, true)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        self.sync
            .drop_replica(doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(DropResponse {})
    }

    pub fn doc_list(
        &self,
        _req: DocListRequest,
    ) -> impl Stream<Item = RpcResult<DocListResponse>> + Unpin {
        let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        tokio::task::spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.list_replicas(tx).await {
                tx2.send(Err(err)).await.ok();
            }
        });
        rx.boxed().map(|r| {
            r.map(|(id, capability)| DocListResponse { id, capability })
                .map_err(|e| RpcError::new(&*e))
        })
    }

    pub async fn doc_open(&self, req: OpenRequest) -> RpcResult<OpenResponse> {
        self.sync
            .open(req.doc_id, Default::default())
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(OpenResponse {})
    }

    pub async fn doc_close(&self, req: CloseRequest) -> RpcResult<CloseResponse> {
        self.sync
            .close(req.doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(CloseResponse {})
    }

    pub async fn doc_status(&self, req: StatusRequest) -> RpcResult<StatusResponse> {
        let status = self
            .sync
            .get_state(req.doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(StatusResponse { status })
    }

    pub async fn doc_share(&self, req: ShareRequest) -> RpcResult<ShareResponse> {
        let ShareRequest {
            doc_id,
            mode,
            addr_options,
        } = req;
        let mut me = self
            .endpoint
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        me.apply_options(addr_options);

        let capability = match mode {
            ShareMode::Read => iroh_docs::Capability::Read(doc_id),
            ShareMode::Write => {
                let secret = self
                    .sync
                    .export_secret_key(doc_id)
                    .await
                    .map_err(|e| RpcError::new(&*e))?;
                iroh_docs::Capability::Write(secret)
            }
        };
        self.start_sync(doc_id, vec![])
            .await
            .map_err(|e| RpcError::new(&*e))?;

        Ok(ShareResponse(DocTicket {
            capability,
            nodes: vec![me],
        }))
    }

    pub async fn doc_subscribe(
        &self,
        req: DocSubscribeRequest,
    ) -> RpcResult<impl Stream<Item = RpcResult<DocSubscribeResponse>>> {
        let stream = self
            .subscribe(req.doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;

        Ok(stream.map(|el| {
            el.map(|event| DocSubscribeResponse { event })
                .map_err(|e| RpcError::new(&*e))
        }))
    }

    pub async fn doc_import(&self, req: DocImportRequest) -> RpcResult<DocImportResponse> {
        let DocImportRequest { capability } = req;
        let doc_id = self
            .sync
            .import_namespace(capability)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        self.sync
            .open(doc_id, Default::default())
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(DocImportResponse { doc_id })
    }

    pub async fn doc_start_sync(&self, req: StartSyncRequest) -> RpcResult<StartSyncResponse> {
        let StartSyncRequest { doc_id, peers } = req;
        self.start_sync(doc_id, peers)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(StartSyncResponse {})
    }

    pub async fn doc_leave(&self, req: LeaveRequest) -> RpcResult<LeaveResponse> {
        let LeaveRequest { doc_id } = req;
        self.leave(doc_id, false)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(LeaveResponse {})
    }

    pub async fn doc_set<B: BaoStore>(
        &self,
        bao_store: &B,
        req: SetRequest,
    ) -> RpcResult<SetResponse> {
        let SetRequest {
            doc_id,
            author_id,
            key,
            value,
        } = req;
        let len = value.len();
        let tag = bao_store
            .import_bytes(value, BlobFormat::Raw)
            .await
            .map_err(|e| RpcError::new(&e))?;
        self.sync
            .insert_local(doc_id, author_id, key.clone(), *tag.hash(), len as u64)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        let entry = self
            .sync
            .get_exact(doc_id, author_id, key, false)
            .await
            .map_err(|e| RpcError::new(&*e))?
            .ok_or_else(|| RpcError::new(&*anyhow!("failed to get entry after insertion")))?;
        Ok(SetResponse { entry })
    }

    pub async fn doc_del(&self, req: DelRequest) -> RpcResult<DelResponse> {
        let DelRequest {
            doc_id,
            author_id,
            prefix,
        } = req;
        let removed = self
            .sync
            .delete_prefix(doc_id, author_id, prefix)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(DelResponse { removed })
    }

    pub async fn doc_set_hash(&self, req: SetHashRequest) -> RpcResult<SetHashResponse> {
        let SetHashRequest {
            doc_id,
            author_id,
            key,
            hash,
            size,
        } = req;
        self.sync
            .insert_local(doc_id, author_id, key.clone(), hash, size)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(SetHashResponse {})
    }

    pub fn doc_get_many(
        &self,
        req: GetManyRequest,
    ) -> impl Stream<Item = RpcResult<GetManyResponse>> + Unpin {
        let GetManyRequest { doc_id, query } = req;
        let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
        let sync = self.sync.clone();
        // we need to spawn a task to send our request to the sync handle, because the method
        // itself must be sync.
        tokio::task::spawn(async move {
            let tx2 = tx.clone();
            if let Err(err) = sync.get_many(doc_id, query, tx).await {
                tx2.send(Err(err)).await.ok();
            }
        });
        rx.boxed().map(|r| {
            r.map(|entry| GetManyResponse { entry })
                .map_err(|e| RpcError::new(&*e))
        })
    }

    pub async fn doc_get_exact(&self, req: GetExactRequest) -> RpcResult<GetExactResponse> {
        let GetExactRequest {
            doc_id,
            author,
            key,
            include_empty,
        } = req;
        let entry = self
            .sync
            .get_exact(doc_id, author, key, include_empty)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(GetExactResponse { entry })
    }

    pub async fn doc_set_download_policy(
        &self,
        req: SetDownloadPolicyRequest,
    ) -> RpcResult<SetDownloadPolicyResponse> {
        self.sync
            .set_download_policy(req.doc_id, req.policy)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(SetDownloadPolicyResponse {})
    }
    pub async fn doc_get_download_policy(
        &self,
        req: GetDownloadPolicyRequest,
    ) -> RpcResult<GetDownloadPolicyResponse> {
        let policy = self
            .sync
            .get_download_policy(req.doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(GetDownloadPolicyResponse { policy })
    }

    pub async fn doc_get_sync_peers(
        &self,
        req: GetSyncPeersRequest,
    ) -> RpcResult<GetSyncPeersResponse> {
        let peers = self
            .sync
            .get_sync_peers(req.doc_id)
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(GetSyncPeersResponse { peers })
    }
}
