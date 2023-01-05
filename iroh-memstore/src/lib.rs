//! In-memory store for iroh.
//!
//! This is an in-memory store for iroh, it implements the internal RPC interface for a
//! store and thus can be used as a drop-in replacement for the store.  It is not optimised
//! at all.
//!
//! This store has no concurrency at all, all RPC requests are handled sequentially.

use std::sync::{Arc, Mutex};

use ahash::AHashMap;
use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use futures::stream::Stream;
use iroh_rpc_client::{ChannelTypes, ServerSocket, StoreServer, HEALTH_POLL_WAIT};
use iroh_rpc_types::store::{
    GetLinksRequest, GetLinksResponse, GetRequest, GetResponse, GetSizeRequest, GetSizeResponse,
    HasRequest, HasResponse, PutManyRequest, PutRequest, StoreAddr, StoreRequest, StoreService,
};
use iroh_rpc_types::{VersionRequest, VersionResponse, WatchRequest, WatchResponse};
use quic_rpc::server::RpcServerError;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub struct MemStoreHandle {
    shutdown_tx: oneshot::Sender<()>,
    handle: JoinHandle<()>,
}

impl MemStoreHandle {
    pub fn shutdown(self) -> JoinHandle<()> {
        // Failing to send the shutdown signal means the task already died somehow.  We can
        // still return the JoinHandle which should complete when awaited.
        self.shutdown_tx.send(()).ok();
        self.handle
    }
}

pub async fn spawn(addr: StoreAddr) -> Result<MemStoreHandle> {
    let server = iroh_rpc_client::create_server::<StoreService>(addr).await?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let mut store = MemStore::new();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => {
                    info!("Shutting down MemStore");
                    break
                },
                req = server.accept_one() => store.dispatch_request(&server, req).await,
            };
        }
        // TODO: The quick-rpc RpcServer needs to be improved so it can be shut down without
        // dropping and we can await the completion.
    });
    Ok(MemStoreHandle {
        shutdown_tx,
        handle,
    })
}

#[derive(Debug, Default, Clone)]
struct MemStore {
    inner: Arc<Mutex<InnerMemStore>>,
}

#[derive(Debug, Default)]
struct InnerMemStore {
    data: AHashMap<Cid, Bytes>,
    links: AHashMap<Cid, Vec<Cid>>,
}

impl MemStore {
    fn new() -> Self {
        Self::default()
    }

    async fn dispatch_request(
        &mut self,
        server: &StoreServer,
        request: Result<(StoreRequest, ServerSocket<StoreService>), RpcServerError<ChannelTypes>>,
    ) {
        let res = match request {
            Ok((req, chan)) => match req {
                StoreRequest::Watch(req) => {
                    server
                        .server_streaming(req, chan, self.clone(), MemStore::watch)
                        .await
                }
                StoreRequest::Version(req) => {
                    server.rpc(req, chan, self.clone(), MemStore::version).await
                }
                StoreRequest::Put(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::put)
                        .await
                }
                StoreRequest::PutMany(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::put_many)
                        .await
                }
                StoreRequest::Get(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::get)
                        .await
                }
                StoreRequest::Has(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::has)
                        .await
                }
                StoreRequest::GetLinks(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::get_links)
                        .await
                }
                StoreRequest::GetSize(req) => {
                    server
                        .rpc_map_err(req, chan, self.clone(), MemStore::get_size)
                        .await
                }
            },
            Err(err) => {
                // Errors happen, e.g. when the client drops the request.
                debug!("Store rpc accept error: {err}");
                Err(RpcServerError::EarlyClose)
            }
        };
        if let Err(err) = res {
            // TODO: what should we do here?
            error!("Failed processing MemStore request: {err}");
        }
    }

    #[tracing::instrument(skip(self))]
    fn watch(self, _: WatchRequest) -> impl Stream<Item = WatchResponse> {
        async_stream::stream! {
            loop {
                yield WatchResponse { version: VERSION.to_string() };
                tokio::time::sleep(HEALTH_POLL_WAIT).await;
            }
        }
    }

    #[tracing::instrument(skip(self))]
    async fn version(self, _: VersionRequest) -> VersionResponse {
        VersionResponse {
            version: VERSION.to_string(),
        }
    }

    #[tracing::instrument(skip(self, req))]
    async fn put(self, req: PutRequest) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.data.insert(req.cid, req.blob);
        inner.links.insert(req.cid, req.links);
        Ok(())
    }

    #[tracing::instrument(skip(self, req))]
    async fn put_many(self, req: PutManyRequest) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for single_req in req.blocks {
            inner.data.insert(single_req.cid, single_req.blob);
            inner.links.insert(single_req.cid, single_req.links);
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get(self, req: GetRequest) -> Result<GetResponse> {
        let inner = self.inner.lock().unwrap();
        let data = inner.data.get(&req.cid);
        Ok(GetResponse {
            data: data.cloned(),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn has(self, req: HasRequest) -> Result<HasResponse> {
        let inner = self.inner.lock().unwrap();
        let has = inner.data.get(&req.cid).is_some();
        Ok(HasResponse { has })
    }

    #[tracing::instrument(skip(self))]
    async fn get_links(self, req: GetLinksRequest) -> Result<GetLinksResponse> {
        let inner = self.inner.lock().unwrap();
        let links = inner.links.get(&req.cid);
        Ok(GetLinksResponse {
            links: links.cloned(),
        })
    }

    #[tracing::instrument(skip(self))]
    async fn get_size(self, req: GetSizeRequest) -> Result<GetSizeResponse> {
        let inner = self.inner.lock().unwrap();
        let size = inner.data.get(&req.cid).map(|b| b.len());
        Ok(GetSizeResponse {
            size: size.map(|s| s.try_into().unwrap()),
        })
    }
}
