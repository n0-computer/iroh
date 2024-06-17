use anyhow::Result;
use futures_lite::future;
use iroh_net::endpoint::Connecting;
use std::ops::Deref;
use tracing::warn;

use super::{DocsEngine, Protocol};

#[derive(Debug)]
pub(crate) struct BlobsProtocol<S> {
    rt: tokio_util::task::LocalPoolHandle,
    store: S,
}

impl<S: iroh_blobs::store::Store> BlobsProtocol<S> {
    pub fn new(store: S, rt: tokio_util::task::LocalPoolHandle) -> Self {
        Self { rt, store }
    }
}

impl<S: iroh_blobs::store::Store> Protocol for BlobsProtocol<S> {
    fn accept(&self, conn: Connecting) -> future::Boxed<Result<()>> {
        let store = self.store.clone();
        let rt = self.rt.clone();
        Box::pin(async move {
            iroh_blobs::provider::handle_connection(conn.await?, store, MockEventSender, rt).await;
            Ok(())
        })
    }

    fn shutdown(&self) -> future::Boxed<()> {
        let store = self.store.clone();
        Box::pin(async move {
            store.shutdown().await;
        })
    }
}

#[derive(Debug, Clone)]
struct MockEventSender;

impl iroh_blobs::provider::EventSender for MockEventSender {
    fn send(&self, _event: iroh_blobs::provider::Event) -> futures_lite::future::Boxed<()> {
        Box::pin(std::future::ready(()))
    }
}

impl Protocol for iroh_gossip::net::Gossip {
    fn accept(&self, conn: Connecting) -> future::Boxed<Result<()>> {
        let this = self.clone();
        Box::pin(async move { this.handle_connection(conn.await?).await })
    }
}

impl Protocol for DocsEngine {
    fn accept(&self, conn: Connecting) -> future::Boxed<Result<()>> {
        let this = self.clone();
        Box::pin(async move { this.handle_connection(conn).await })
    }

    fn shutdown(&self) -> future::Boxed<()> {
        let this = self.clone();
        Box::pin(async move {
            if let Err(err) = this.deref().shutdown().await {
                warn!("Error while shutting down docs engine: {err:?}");
            }
        })
    }
}
