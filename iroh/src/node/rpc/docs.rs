//! This module contains an impl block on [`Handler`] to handle docs related requests.

use anyhow::anyhow;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::{store::Store as BaoStore, BlobFormat};
use iroh_docs::{Author, DocTicket, NamespaceSecret};

use super::{Handler, RpcError, RpcResult};
use crate::{
    client::docs::ShareMode,
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

impl<D: BaoStore> Handler<D> {
    pub(super) async fn author_create(self, _req: CreateRequest) -> RpcResult<CreateResponse> {
        self.with_docs(|docs| async move {
            // TODO: pass rng
            let author = Author::new(&mut rand::rngs::OsRng {});
            docs.sync
                .import_author(author.clone())
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(CreateResponse {
                author_id: author.id(),
            })
        })
        .await
    }

    pub(super) async fn author_default(
        self,
        _req: GetDefaultRequest,
    ) -> RpcResult<GetDefaultResponse> {
        self.with_docs(|docs| async move {
            let author_id = docs.default_author.get();
            Ok(GetDefaultResponse { author_id })
        })
        .await
    }

    pub(super) async fn author_set_default(
        self,
        req: SetDefaultRequest,
    ) -> RpcResult<SetDefaultResponse> {
        self.with_docs(|docs| async move {
            docs.default_author
                .set(req.author_id, &docs.sync)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(SetDefaultResponse)
        })
        .await
    }

    pub(super) fn author_list(
        self,
        _req: AuthorListRequest,
    ) -> impl Stream<Item = RpcResult<AuthorListResponse>> + Unpin {
        self.with_docs_stream(|docs| {
            let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
            let sync = docs.sync.clone();
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
        })
    }

    pub(super) async fn author_import(self, req: ImportRequest) -> RpcResult<ImportResponse> {
        self.with_docs(|docs| async move {
            let author_id = docs
                .sync
                .import_author(req.author)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(ImportResponse { author_id })
        })
        .await
    }

    pub(super) async fn author_export(self, req: ExportRequest) -> RpcResult<ExportResponse> {
        self.with_docs(|docs| async move {
            let author = docs
                .sync
                .export_author(req.author)
                .await
                .map_err(|e| RpcError::new(&*e))?;

            Ok(ExportResponse { author })
        })
        .await
    }

    pub(super) async fn author_delete(self, req: DeleteRequest) -> RpcResult<DeleteResponse> {
        self.with_docs(|docs| async move {
            if req.author == docs.default_author.get() {
                return Err(RpcError::new(&*anyhow!(
                    "Deleting the default author is not supported"
                )));
            }
            docs.sync
                .delete_author(req.author)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(DeleteResponse)
        })
        .await
    }

    pub(super) async fn doc_create(self, _req: DocCreateRequest) -> RpcResult<DocCreateResponse> {
        self.with_docs(|docs| async move {
            let namespace = NamespaceSecret::new(&mut rand::rngs::OsRng {});
            let id = namespace.id();
            docs.sync
                .import_namespace(namespace.into())
                .await
                .map_err(|e| RpcError::new(&*e))?;
            docs.sync
                .open(id, Default::default())
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(DocCreateResponse { id })
        })
        .await
    }

    pub(super) async fn doc_drop(self, req: DropRequest) -> RpcResult<DropResponse> {
        self.with_docs(|docs| async move {
            let DropRequest { doc_id } = req;
            docs.leave(doc_id, true)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            docs.sync
                .drop_replica(doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(DropResponse {})
        })
        .await
    }

    pub(super) fn doc_list(
        self,
        _req: DocListRequest,
    ) -> impl Stream<Item = RpcResult<DocListResponse>> + Unpin {
        self.with_docs_stream(|docs| {
            let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
            let sync = docs.sync.clone();
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
        })
    }

    pub(super) async fn doc_open(self, req: OpenRequest) -> RpcResult<OpenResponse> {
        self.with_docs(|docs| async move {
            docs.sync
                .open(req.doc_id, Default::default())
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(OpenResponse {})
        })
        .await
    }

    pub(super) async fn doc_close(self, req: CloseRequest) -> RpcResult<CloseResponse> {
        self.with_docs(|docs| async move {
            docs.sync
                .close(req.doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(CloseResponse {})
        })
        .await
    }

    pub(super) async fn doc_status(self, req: StatusRequest) -> RpcResult<StatusResponse> {
        self.with_docs(|docs| async move {
            let status = docs
                .sync
                .get_state(req.doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(StatusResponse { status })
        })
        .await
    }

    pub(super) async fn doc_share(self, req: ShareRequest) -> RpcResult<ShareResponse> {
        self.with_docs(|docs| async move {
            let ShareRequest {
                doc_id,
                mode,
                addr_options,
            } = req;
            let mut me = docs
                .endpoint
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?;
            me.apply_options(addr_options);

            let capability = match mode {
                ShareMode::Read => iroh_docs::Capability::Read(doc_id),
                ShareMode::Write => {
                    let secret = docs
                        .sync
                        .export_secret_key(doc_id)
                        .await
                        .map_err(|e| RpcError::new(&*e))?;
                    iroh_docs::Capability::Write(secret)
                }
            };
            docs.start_sync(doc_id, vec![])
                .await
                .map_err(|e| RpcError::new(&*e))?;

            Ok(ShareResponse(DocTicket {
                capability,
                nodes: vec![me],
            }))
        })
        .await
    }

    pub(super) async fn doc_subscribe(
        self,
        req: DocSubscribeRequest,
    ) -> RpcResult<impl Stream<Item = RpcResult<DocSubscribeResponse>>> {
        self.with_docs(|docs| async move {
            let stream = docs
                .subscribe(req.doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;

            Ok(stream.map(|el| {
                el.map(|event| DocSubscribeResponse { event })
                    .map_err(|e| RpcError::new(&*e))
            }))
        })
        .await
    }

    pub(super) async fn doc_import(self, req: DocImportRequest) -> RpcResult<DocImportResponse> {
        self.with_docs(|docs| async move {
            let DocImportRequest { capability } = req;
            let doc_id = docs
                .sync
                .import_namespace(capability)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            docs.sync
                .open(doc_id, Default::default())
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(DocImportResponse { doc_id })
        })
        .await
    }

    pub(super) async fn doc_start_sync(
        self,
        req: StartSyncRequest,
    ) -> RpcResult<StartSyncResponse> {
        self.with_docs(|docs| async move {
            let StartSyncRequest { doc_id, peers } = req;
            docs.start_sync(doc_id, peers)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(StartSyncResponse {})
        })
        .await
    }

    pub(super) async fn doc_leave(self, req: LeaveRequest) -> RpcResult<LeaveResponse> {
        self.with_docs(|docs| async move {
            let LeaveRequest { doc_id } = req;
            docs.leave(doc_id, false)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(LeaveResponse {})
        })
        .await
    }

    pub(super) async fn doc_set(self, req: SetRequest) -> RpcResult<SetResponse> {
        let blobs_store = self.blobs_store();
        self.with_docs(|docs| async move {
            let SetRequest {
                doc_id,
                author_id,
                key,
                value,
            } = req;
            let len = value.len();
            let tag = blobs_store
                .import_bytes(value, BlobFormat::Raw)
                .await
                .map_err(|e| RpcError::new(&e))?;
            docs.sync
                .insert_local(doc_id, author_id, key.clone(), *tag.hash(), len as u64)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            let entry = docs
                .sync
                .get_exact(doc_id, author_id, key, false)
                .await
                .map_err(|e| RpcError::new(&*e))?
                .ok_or_else(|| RpcError::new(&*anyhow!("failed to get entry after insertion")))?;
            Ok(SetResponse { entry })
        })
        .await
    }

    pub(super) async fn doc_del(self, req: DelRequest) -> RpcResult<DelResponse> {
        self.with_docs(|docs| async move {
            let DelRequest {
                doc_id,
                author_id,
                prefix,
            } = req;
            let removed = docs
                .sync
                .delete_prefix(doc_id, author_id, prefix)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(DelResponse { removed })
        })
        .await
    }

    pub(super) async fn doc_set_hash(self, req: SetHashRequest) -> RpcResult<SetHashResponse> {
        self.with_docs(|docs| async move {
            let SetHashRequest {
                doc_id,
                author_id,
                key,
                hash,
                size,
            } = req;
            docs.sync
                .insert_local(doc_id, author_id, key.clone(), hash, size)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(SetHashResponse {})
        })
        .await
    }

    pub(super) fn doc_get_many(
        self,
        req: GetManyRequest,
    ) -> impl Stream<Item = RpcResult<GetManyResponse>> + Unpin {
        let GetManyRequest { doc_id, query } = req;
        self.with_docs_stream(move |docs| {
            let (tx, rx) = async_channel::bounded(ITER_CHANNEL_CAP);
            let sync = docs.sync.clone();
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
        })
    }

    pub(super) async fn doc_get_exact(self, req: GetExactRequest) -> RpcResult<GetExactResponse> {
        self.with_docs(|docs| async move {
            let GetExactRequest {
                doc_id,
                author,
                key,
                include_empty,
            } = req;
            let entry = docs
                .sync
                .get_exact(doc_id, author, key, include_empty)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(GetExactResponse { entry })
        })
        .await
    }

    pub(super) async fn doc_set_download_policy(
        self,
        req: SetDownloadPolicyRequest,
    ) -> RpcResult<SetDownloadPolicyResponse> {
        self.with_docs(|docs| async move {
            docs.sync
                .set_download_policy(req.doc_id, req.policy)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(SetDownloadPolicyResponse {})
        })
        .await
    }

    pub(super) async fn doc_get_download_policy(
        self,
        req: GetDownloadPolicyRequest,
    ) -> RpcResult<GetDownloadPolicyResponse> {
        self.with_docs(|docs| async move {
            let policy = docs
                .sync
                .get_download_policy(req.doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(GetDownloadPolicyResponse { policy })
        })
        .await
    }

    pub(super) async fn doc_get_sync_peers(
        self,
        req: GetSyncPeersRequest,
    ) -> RpcResult<GetSyncPeersResponse> {
        self.with_docs(|docs| async move {
            let peers = docs
                .sync
                .get_sync_peers(req.doc_id)
                .await
                .map_err(|e| RpcError::new(&*e))?;
            Ok(GetSyncPeersResponse { peers })
        })
        .await
    }
}
