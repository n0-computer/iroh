//! Client to an iroh node. Is generic over the connection (in-memory or RPC).
//!
//! TODO: Contains only iroh sync related methods. Add other methods.

// TODO: fill out docs
#![allow(missing_docs)]

use std::collections::HashMap;
use std::result::Result as StdResult;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::{Stream, StreamExt, TryStreamExt};
use iroh_bytes::Hash;
use iroh_sync::store::{GetFilter, KeyFilter};
use iroh_sync::sync::{AuthorId, NamespaceId, SignedEntry};
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorListRequest, BytesGetRequest, CounterStats, DocGetRequest,
    DocImportRequest, DocSetRequest, DocShareRequest, DocStartSyncRequest, DocSubscribeRequest,
    DocTicket, DocsCreateRequest, DocsListRequest, ProviderService, ShareMode, StatsGetRequest,
};
use crate::sync::{LiveEvent, PeerSource};

pub mod mem;
#[cfg(feature = "cli")]
pub mod quic;

/// Iroh client
pub struct Iroh<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> Iroh<C>
where
    C: ServiceConnection<ProviderService>,
{
    pub fn new(rpc: RpcClient<ProviderService, C>) -> Self {
        Self { rpc }
    }
    pub async fn create_author(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorCreateRequest).await??;
        Ok(res.author_id)
    }

    pub async fn list_authors(&self) -> Result<impl Stream<Item = Result<AuthorId>>> {
        let stream = self.rpc.server_streaming(AuthorListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.author_id))
    }

    pub async fn create_doc(&self) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocsCreateRequest {}).await??;
        let doc = Doc {
            id: res.id,
            rpc: self.rpc.clone(),
        };
        Ok(doc)
    }

    pub async fn import_doc(&self, ticket: DocTicket) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocImportRequest(ticket)).await??;
        let doc = Doc {
            id: res.doc_id,
            rpc: self.rpc.clone(),
        };
        Ok(doc)
    }

    pub async fn list_docs(&self) -> Result<impl Stream<Item = Result<NamespaceId>>> {
        let stream = self.rpc.server_streaming(DocsListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.id))
    }

    pub fn get_doc(&self, id: NamespaceId) -> Result<Doc<C>> {
        // TODO: Check if doc exists?
        let doc = Doc {
            id,
            rpc: self.rpc.clone(),
        };
        Ok(doc)
    }

    // TODO: add get_reader for streaming gets
    pub async fn get_bytes(&self, hash: Hash) -> Result<Bytes> {
        let res = self.rpc.rpc(BytesGetRequest { hash }).await??;
        Ok(res.data)
    }

    pub async fn stats(&self) -> Result<HashMap<String, CounterStats>> {
        let res = self.rpc.rpc(StatsGetRequest {}).await??;
        Ok(res.stats)
    }
}

/// Document handle
pub struct Doc<C> {
    id: NamespaceId,
    rpc: RpcClient<ProviderService, C>,
}

impl<C> Doc<C>
where
    C: ServiceConnection<ProviderService>,
{
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    pub async fn set_bytes(
        &self,
        author_id: AuthorId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<SignedEntry> {
        let res = self
            .rpc
            .rpc(DocSetRequest {
                doc_id: self.id,
                author_id,
                key,
                value,
            })
            .await??;
        Ok(res.entry)
    }

    // TODO: add get_content_reader
    pub async fn get_content_bytes(&self, entry: &SignedEntry) -> Result<Bytes> {
        let hash = *entry.content_hash();
        let bytes = self.rpc.rpc(BytesGetRequest { hash }).await??;
        Ok(bytes.data)
    }

    pub async fn get_latest(&self, author_id: AuthorId, key: Vec<u8>) -> Result<SignedEntry> {
        let filter = GetFilter {
            key: KeyFilter::Key(key),
            author: Some(author_id),
            latest: true,
        };
        let mut stream = self.get(filter).await?;
        let entry = stream
            .next()
            .await
            .unwrap_or_else(|| Err(anyhow!("not found")))?;
        Ok(entry)
    }

    pub async fn get(&self, filter: GetFilter) -> Result<impl Stream<Item = Result<SignedEntry>>> {
        let stream = self
            .rpc
            .server_streaming(DocGetRequest {
                doc_id: self.id,
                filter,
            })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.entry))
    }

    pub async fn share(&self, mode: ShareMode) -> anyhow::Result<DocTicket> {
        let res = self
            .rpc
            .rpc(DocShareRequest {
                doc_id: self.id,
                mode,
            })
            .await??;
        Ok(res.0)
    }

    pub async fn start_sync(&self, peers: Vec<PeerSource>) -> Result<()> {
        let _res = self
            .rpc
            .rpc(DocStartSyncRequest {
                doc_id: self.id,
                peers,
            })
            .await??;
        Ok(())
    }

    // TODO: add stop_sync

    pub async fn subscribe(&self) -> anyhow::Result<impl Stream<Item = anyhow::Result<LiveEvent>>> {
        let stream = self
            .rpc
            .server_streaming(DocSubscribeRequest { doc_id: self.id })
            .await?;
        Ok(stream.map_ok(|res| res.event).map_err(Into::into))
    }
}

fn flatten<T, E1, E2>(
    s: impl Stream<Item = StdResult<StdResult<T, E1>, E2>>,
) -> impl Stream<Item = Result<T>>
where
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
    s.map(|res| match res {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    })
}
