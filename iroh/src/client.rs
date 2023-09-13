//! Client to an iroh node. Is generic over the connection (in-memory or RPC).
//!
//! TODO: Contains only iroh sync related methods. Add other methods.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures::stream::BoxStream;
use futures::{Stream, StreamExt, TryStreamExt};
use iroh_bytes::Hash;
use iroh_net::{key::PublicKey, magic_endpoint::ConnectionInfo};
use iroh_sync::{store::GetFilter, AuthorId, Entry, NamespaceId};
use quic_rpc::{RpcClient, ServiceConnection};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};
use tokio_util::io::StreamReader;

use crate::rpc_protocol::{
    AuthorCreateRequest, AuthorListRequest, BytesGetRequest, BytesGetResponse,
    ConnectionInfoRequest, ConnectionInfoResponse, ConnectionsRequest, CounterStats,
    DocCreateRequest, DocGetManyRequest, DocGetOneRequest, DocImportRequest, DocInfoRequest,
    DocListRequest, DocSetRequest, DocShareRequest, DocStartSyncRequest, DocStopSyncRequest,
    DocSubscribeRequest, DocTicket, ProviderService, ShareMode, StatsGetRequest,
};
use crate::sync_engine::{LiveEvent, LiveStatus, PeerSource};

pub mod mem;
#[cfg(feature = "cli")]
pub mod quic;

/// Iroh client
#[derive(Debug, Clone)]
pub struct Iroh<C> {
    rpc: RpcClient<ProviderService, C>,
}

impl<C> Iroh<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Create a new high-level client to a Iroh node from the low-level RPC client.
    pub fn new(rpc: RpcClient<ProviderService, C>) -> Self {
        Self { rpc }
    }

    /// Create a new document author.
    pub async fn create_author(&self) -> Result<AuthorId> {
        let res = self.rpc.rpc(AuthorCreateRequest).await??;
        Ok(res.author_id)
    }

    /// List document authors for which we have a secret key.
    pub async fn list_authors(&self) -> Result<impl Stream<Item = Result<AuthorId>>> {
        let stream = self.rpc.server_streaming(AuthorListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.author_id))
    }

    /// Create a new document.
    pub async fn create_doc(&self) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocCreateRequest {}).await??;
        let doc = Doc {
            id: res.id,
            rpc: self.rpc.clone(),
        };
        Ok(doc)
    }

    /// Import a document from a ticket and join all peers in the ticket.
    pub async fn import_doc(&self, ticket: DocTicket) -> Result<Doc<C>> {
        let res = self.rpc.rpc(DocImportRequest(ticket)).await??;
        let doc = Doc {
            id: res.doc_id,
            rpc: self.rpc.clone(),
        };
        Ok(doc)
    }

    /// List all documents.
    pub async fn list_docs(&self) -> Result<impl Stream<Item = Result<NamespaceId>>> {
        let stream = self.rpc.server_streaming(DocListRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.id))
    }

    /// Get a [`Doc`] client for a single document. Return an error if the document cannot be found.
    pub async fn get_doc(&self, id: NamespaceId) -> Result<Doc<C>> {
        match self.try_get_doc(id).await? {
            Some(doc) => Ok(doc),
            None => Err(anyhow!("Document not found")),
        }
    }

    /// Get a [`Doc`] client for a single document. Return None if the document cannot be found.
    pub async fn try_get_doc(&self, id: NamespaceId) -> Result<Option<Doc<C>>> {
        if let Err(_err) = self.rpc.rpc(DocInfoRequest { doc_id: id }).await? {
            return Ok(None);
        }
        let doc = Doc {
            id,
            rpc: self.rpc.clone(),
        };
        Ok(Some(doc))
    }

    /// Get the bytes for a hash.
    ///
    /// Note: This reads the full blob into memory.
    pub async fn get_bytes(&self, hash: Hash) -> Result<Bytes> {
        let mut stream = self.get_bytes_stream(hash).await?;
        stream.read_to_end().await
    }

    /// Get the bytes for a hash.
    pub async fn get_bytes_stream(&self, hash: Hash) -> Result<BlobReader> {
        BlobReader::from_rpc(&self.rpc, hash).await
    }

    /// Get statistics of the running node.
    pub async fn stats(&self) -> Result<HashMap<String, CounterStats>> {
        let res = self.rpc.rpc(StatsGetRequest {}).await??;
        Ok(res.stats)
    }

    /// Get information about the different connections we have made
    pub async fn connections(&self) -> Result<impl Stream<Item = Result<ConnectionInfo>>> {
        let stream = self.rpc.server_streaming(ConnectionsRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.conn_info))
    }

    /// Get connection information about a node
    pub async fn connection_info(&self, node_id: PublicKey) -> Result<Option<ConnectionInfo>> {
        let ConnectionInfoResponse { conn_info } =
            self.rpc.rpc(ConnectionInfoRequest { node_id }).await??;
        Ok(conn_info)
    }
}

/// Data reader for a single blob.
///
/// Implements [`AsyncRead`].
pub struct BlobReader {
    size: u64,
    is_complete: bool,
    stream: tokio_util::io::StreamReader<BoxStream<'static, io::Result<Bytes>>, Bytes>,
}
impl BlobReader {
    fn new(size: u64, is_complete: bool, stream: BoxStream<'static, io::Result<Bytes>>) -> Self {
        Self {
            size,
            is_complete,
            stream: StreamReader::new(stream),
        }
    }

    async fn from_rpc<C: ServiceConnection<ProviderService>>(
        rpc: &RpcClient<ProviderService, C>,
        hash: Hash,
    ) -> anyhow::Result<Self> {
        let stream = rpc.server_streaming(BytesGetRequest { hash }).await?;
        let mut stream = flatten(stream);

        let (size, is_complete) = match stream.next().await {
            Some(Ok(BytesGetResponse::Entry { size, is_complete })) => (size, is_complete),
            Some(Err(err)) => return Err(err),
            None | Some(Ok(_)) => return Err(anyhow!("Expected header frame")),
        };

        let stream = stream.map(|item| match item {
            Ok(BytesGetResponse::Data { chunk }) => Ok(chunk),
            Ok(_) => Err(io::Error::new(io::ErrorKind::Other, "Expected data frame")),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, format!("{err}"))),
        });
        Ok(Self::new(size, is_complete, stream.boxed()))
    }

    /// Total size of this blob.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether this blob has been downloaded completely.
    ///
    /// Returns false for partial blobs for which some chunks are missing.
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Read all bytes of the blob.
    pub async fn read_to_end(&mut self) -> anyhow::Result<Bytes> {
        let mut buf = Vec::with_capacity(self.size() as usize);
        AsyncReadExt::read_to_end(self, &mut buf).await?;
        Ok(buf.into())
    }
}

impl AsyncRead for BlobReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

/// Document handle
#[derive(Debug, Clone)]
pub struct Doc<C> {
    id: NamespaceId,
    rpc: RpcClient<ProviderService, C>,
}

impl<C> Doc<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Get the document id of this doc.
    pub fn id(&self) -> NamespaceId {
        self.id
    }

    /// Set the content of a key to a byte array.
    pub async fn set_bytes(
        &self,
        author_id: AuthorId,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<Hash> {
        let res = self
            .rpc
            .rpc(DocSetRequest {
                doc_id: self.id,
                author_id,
                key,
                value,
            })
            .await??;
        Ok(res.entry.content_hash())
    }

    /// Get the contents of an entry as a byte array.
    pub async fn get_content_bytes(&self, hash: Hash) -> Result<Bytes> {
        let mut stream = BlobReader::from_rpc(&self.rpc, hash).await?;
        stream.read_to_end().await
    }

    /// Get the contents of an entry as a [`BlobReader`].
    pub async fn get_content_reader(&self, hash: Hash) -> Result<BlobReader> {
        BlobReader::from_rpc(&self.rpc, hash).await
    }

    /// Get the latest entry for a key and author.
    pub async fn get_one(&self, author: AuthorId, key: Vec<u8>) -> Result<Option<Entry>> {
        let res = self
            .rpc
            .rpc(DocGetOneRequest {
                author,
                key,
                doc_id: self.id,
            })
            .await??;
        Ok(res.entry.map(|entry| entry.into()))
    }

    /// Get entries.
    pub async fn get_many(&self, filter: GetFilter) -> Result<impl Stream<Item = Result<Entry>>> {
        let stream = self
            .rpc
            .server_streaming(DocGetManyRequest {
                doc_id: self.id,
                filter,
            })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.entry.into()))
    }

    /// Share this document with peers over a ticket.
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

    /// Start to sync this document with a list of peers.
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

    /// Stop the live sync for this document.
    pub async fn stop_sync(&self) -> Result<()> {
        let _res = self
            .rpc
            .rpc(DocStopSyncRequest { doc_id: self.id })
            .await??;
        Ok(())
    }

    /// Subscribe to events for this document.
    pub async fn subscribe(&self) -> anyhow::Result<impl Stream<Item = anyhow::Result<LiveEvent>>> {
        let stream = self
            .rpc
            .server_streaming(DocSubscribeRequest { doc_id: self.id })
            .await?;
        Ok(flatten(stream).map_ok(|res| res.event).map_err(Into::into))
    }

    /// Get status info for this document
    pub async fn status(&self) -> anyhow::Result<LiveStatus> {
        let res = self.rpc.rpc(DocInfoRequest { doc_id: self.id }).await??;
        Ok(res.status)
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
