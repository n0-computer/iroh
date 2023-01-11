//! In-memory store for iroh.
//!
//! This is an in-memory store for iroh, it implements the internal RPC interface for a
//! store and thus can be used as a drop-in replacement for the store.  It is not optimised
//! at all.
//!
//! This store has no concurrency at all, all RPC requests are handled sequentially.

use ahash::AHashMap;
use anyhow::{Context, Result};
use bytes::Bytes;
use cid::Cid;
use futures::{SinkExt, StreamExt};
use iroh_rpc_client::{create_server_channel, HEALTH_POLL_WAIT};
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, GetSizeRequest, GetSizeResponse,
    HasRequest, HasResponse, PutManyRequest, PutRequest, StoreAddr, StoreRequest, StoreResponse,
    StoreService,
};
use iroh_rpc_types::{VersionResponse, WatchResponse};
use quic_rpc::transport::{combined, Http2ChannelTypes, MemChannelTypes};
use quic_rpc::ServerChannel;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The [`futures::Sink`] to send store RPC responses.
type StoreSink = combined::SendSink<Http2ChannelTypes, MemChannelTypes, StoreResponse>;

/// The [`futures::Stream`] to receive store RPC requests.
type StoreSource = combined::RecvStream<Http2ChannelTypes, MemChannelTypes, StoreRequest>;

/// Handle to the store task.
///
/// The [`MemStore`] is run as a tokio task running an iRPC server.  This handle allows you
/// to gracefully shut this task down.
#[derive(Debug)]
pub struct MemStoreHandle {
    shutdown_tx: oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

impl MemStoreHandle {
    /// Shuts the the [`MemStore`] task gracefully.
    ///
    /// The returned [`JoinHandle`] can be awaited to wait for completion of the server.
    pub fn shutdown(self) -> JoinHandle<()> {
        // Failing to send the shutdown signal means the task already died somehow.  We can
        // still return the JoinHandle which should complete when awaited.
        self.shutdown_tx.send(()).ok();
        self.handle
    }
}

/// A single block to be stored.
#[derive(Debug, Default, Clone)]
struct StoreBlock {
    blob: Bytes,
    links: Vec<Cid>,
}

/// An in-memory store for iroh.
///
/// To use this store use [`MemStore::spawn`] which will spawn a tokio task running the
/// [`StoreService`] iRPC server.
#[derive(Debug, Default, Clone)]
pub struct MemStore {
    blocks: AHashMap<Cid, StoreBlock>,
}

impl MemStore {
    /// Spawns a new tokio task running the iRPC server for the [`StoreService`].
    pub async fn spawn(addr: StoreAddr) -> Result<MemStoreHandle> {
        let accept_channel = create_server_channel::<StoreService>(addr).await?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let mut store = MemStore::default();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => {
                        info!("Shutting down MemStore");
                        break;
                    }
                    res = accept_channel.accept_bi() => {
                        match res {
                            Ok((sink, stream)) => {
                                if let Err(err) = store.dispatch(sink, stream).await {
                                    error!("Error handling request: {err:#}");
                                }
                            }
                            Err(_) => debug!("Remote closed connection during accept"),
                        }
                    }
                }
            }
            // TODO: Make this return a Result.
            // Ok(())
        });
        Ok(MemStoreHandle {
            shutdown_tx,
            handle,
        })
    }

    async fn dispatch(&mut self, sink: StoreSink, mut source: StoreSource) -> Result<()> {
        let Some(request) = source.next().await else {
            debug!("Remote closed connection before first request");
            return Ok(());
    };
        let request = request.context("Failed to read request")?;
        match request {
            StoreRequest::Watch(_) => self.handle_watch(sink, source)?,
            StoreRequest::Version(_) => self.handle_version(sink, source).await?,
            StoreRequest::Put(req) => self.handle_put(req, sink, source).await?,
            StoreRequest::PutMany(req) => self.handle_put_many(req, sink, source).await?,
            StoreRequest::Get(req) => self.handle_get(req, sink, source).await?,
            StoreRequest::Has(req) => self.handle_has(req, sink, source).await?,
            StoreRequest::GetLinks(req) => self.handle_get_links(req, sink, source).await?,
            StoreRequest::GetSize(req) => self.handle_get_size(req, sink, source).await?,
        }
        Ok(())
    }

    /// Spawns a task regularly sending [`WatchResponse`] messages to the sink.
    fn handle_watch(&self, mut sink: StoreSink, mut source: StoreSource) -> Result<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEALTH_POLL_WAIT);
            loop {
                // TODO: I really want to close the source half here instead of this select.
                tokio::select! {
                    biased;
                    _ = source.next() => {
                        error!("WatchRequest request received second message");
                        break;
                    }
                    _ = interval.tick() => {
                        let msg = WatchResponse { version: VERSION.to_string() };
                        if sink.send(msg.into()).await.is_err() {
                            trace!("WatchRequest response stream closed");
                        }
                    }
                };
            }
        });
        Ok(())
    }

    async fn handle_version(&self, mut sink: StoreSink, _source: StoreSource) -> Result<()> {
        // TODO: Generally it would be nice to close the source half before responding.
        let response = VersionResponse {
            version: VERSION.to_string(),
        };
        sink.send(response.into()).await?;
        Ok(())
    }

    // async fn handle_rpc<S, M>(request: M, sink: )

    async fn handle_put(
        &mut self,
        request: PutRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        let PutRequest { cid, blob, links } = request;
        let block = StoreBlock { blob, links };
        self.blocks.insert(cid, block);

        let response = Ok(());
        sink.send(response.into()).await?;
        Ok(())
    }

    async fn handle_put_many(
        &mut self,
        request: PutManyRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        for req in request.blocks {
            let PutRequest { cid, blob, links } = req;
            let block = StoreBlock { blob, links };
            self.blocks.insert(cid, block);
        }

        let response = Ok(());
        sink.send(response.into()).await?;
        Ok(())
    }

    async fn handle_get(
        &mut self,
        request: GetRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        let block = self.blocks.get(&request.cid);

        let response = Ok(GetResponse {
            data: block.map(|b| b.blob.clone()),
        });
        sink.send(response.into()).await?;
        Ok(())
    }

    async fn handle_has(
        &mut self,
        request: HasRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        let has = self.blocks.get(&request.cid).is_some();

        let response = Ok(HasResponse { has });
        sink.send(response.into()).await?;
        Ok(())
    }

    async fn handle_get_links(
        &mut self,
        request: GetLinksRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        let block = self.blocks.get(&request.cid);
        let links = block.map(|b| b.links.clone());

        let response = Ok(GetLinksResponse { links });
        sink.send(response.into()).await?;
        Ok(())
    }

    async fn handle_get_size(
        &mut self,
        request: GetSizeRequest,
        mut sink: StoreSink,
        _source: StoreSource,
    ) -> Result<()> {
        let block = self.blocks.get(&request.cid);
        let size: Option<u64> = block.map(|b| b.blob.len().try_into().unwrap());

        let response = Ok(GetSizeResponse { size });
        sink.send(response.into()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cid::multihash::{Code, MultihashDigest};
    use cid::Version;
    use iroh_rpc_client::StoreClient;
    use libipld::raw::RawCodec;

    use super::*;

    #[tokio::test]
    async fn test_in_mem() {
        let addr = StoreAddr::new_mem();
        let handle = MemStore::spawn(addr.clone()).await.unwrap();

        let client = StoreClient::new(addr).await.unwrap();

        let version = client.version().await.unwrap();
        assert_eq!(version, VERSION);

        let blob0 = Bytes::from(&b"hello"[..]);
        let hash0 = Code::Sha2_256.digest(&blob0);
        let cid0 = Cid::new(Version::V1, RawCodec.into(), hash0).unwrap();
        let blob1 = Bytes::from(&b"world"[..]);
        let hash1 = Code::Sha2_256.digest(&blob1);
        let cid1 = Cid::new(Version::V1, RawCodec.into(), hash1).unwrap();

        client.put(cid0, blob0.clone(), vec![cid1]).await.unwrap();
        client.put(cid1, blob1, vec![]).await.unwrap();

        let blob = client.get(cid0).await.unwrap();
        assert_eq!(blob.unwrap(), blob0);

        let has = client.has(cid1).await.unwrap();
        assert!(has);

        handle.shutdown().await.unwrap();
    }
}
