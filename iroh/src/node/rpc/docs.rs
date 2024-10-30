//! This module contains an impl block on [`Handler`] to handle docs related requests.

use anyhow::anyhow;
use futures_lite::{Stream, StreamExt};
use iroh_blobs::store::Store as BaoStore;
use iroh_docs::Author;

use super::{Handler, RpcError, RpcResult};
use crate::rpc_protocol::authors::{
    CreateRequest, CreateResponse, DeleteRequest, DeleteResponse, ExportRequest, ExportResponse,
    GetDefaultRequest, GetDefaultResponse, ImportRequest, ImportResponse,
    ListRequest as AuthorListRequest, ListResponse as AuthorListResponse, SetDefaultRequest,
    SetDefaultResponse,
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
}
