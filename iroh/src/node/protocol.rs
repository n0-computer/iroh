use std::{
    any::Any,
    collections::HashMap,
    fmt,
    ops::Deref,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh_net::endpoint::Connecting;
use tracing::warn;

use crate::node::{DocsEngine, Node};

/// Handler for incoming connections.
pub trait Protocol: Send + Sync + IntoArcAny + fmt::Debug + 'static {
    /// Handle an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>>;

    /// Called when the node shuts down.
    fn shutdown(self: Arc<Self>) -> BoxedFuture<()> {
        Box::pin(async move {})
    }
}

/// Helper trait to facilite casting from `Arc<dyn T>` to `Arc<dyn Any>`.
///
/// This trait has a blanket implementation so there is no need to implement this yourself.
pub trait IntoArcAny {
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<T: Send + Sync + 'static> IntoArcAny for T {
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

#[derive(Debug, Clone, Default)]
#[allow(clippy::type_complexity)]
pub struct ProtocolMap(Arc<RwLock<HashMap<&'static [u8], Arc<dyn Protocol>>>>);

pub type ProtocolBuilders<D> = Vec<(
    &'static [u8],
    Box<dyn FnOnce(Node<D>) -> BoxedFuture<Result<Arc<dyn Protocol>>> + Send + 'static>,
)>;

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a concrete type.
    pub fn get<P: Protocol>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        let protocols = self.0.read().unwrap();
        let protocol: Arc<dyn Protocol> = protocols.get(alpn)?.clone();
        let protocol_any: Arc<dyn Any + Send + Sync> = protocol.into_arc_any();
        let protocol_ref = Arc::downcast(protocol_any).ok()?;
        Some(protocol_ref)
    }

    /// Returns the registered protocol handler for an ALPN as a `dyn Protocol`.
    pub fn get_any(&self, alpn: &[u8]) -> Option<Arc<dyn Protocol>> {
        let protocols = self.0.read().unwrap();
        let protocol: Arc<dyn Protocol> = protocols.get(alpn)?.clone();
        Some(protocol)
    }

    pub(super) fn insert(&self, alpn: &'static [u8], protocol: Arc<dyn Protocol>) {
        self.0.write().unwrap().insert(alpn, protocol);
    }

    pub(super) fn read(
        &self,
    ) -> std::sync::RwLockReadGuard<HashMap<&'static [u8], Arc<dyn Protocol>>> {
        self.0.read().unwrap()
    }

    /// Build the protocols from a list of builders.
    pub(super) async fn build<S: iroh_blobs::store::Store>(
        &self,
        node: Node<S>,
        builders: ProtocolBuilders<S>,
    ) -> Result<()> {
        for (alpn, builder) in builders {
            let protocol = builder(node.clone()).await;
            match protocol {
                Ok(protocol) => self.insert(alpn, protocol),
                Err(err) => {
                    // Shutdown the protocols that were already built before returning the error.
                    self.shutdown().await;
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Shutdown the protocol handlers.
    pub(super) async fn shutdown(&self) {
        // We cannot hold the RwLockReadGuard over an await point,
        // so we have to manually loop, clone each protocol, and drop the read guard
        // before awaiting shutdown.
        let mut i = 0;
        loop {
            let protocol = {
                let protocols = self.read();
                if let Some(protocol) = protocols.values().nth(i) {
                    protocol.clone()
                } else {
                    break;
                }
            };
            protocol.shutdown().await;
            i += 1;
        }
    }
}

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
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move {
            iroh_blobs::provider::handle_connection(
                conn.await?,
                self.store.clone(),
                MockEventSender,
                self.rt.clone(),
            )
            .await;
            Ok(())
        })
    }

    fn shutdown(self: Arc<Self>) -> BoxedFuture<()> {
        Box::pin(async move {
            self.store.shutdown().await;
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
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move { self.handle_connection(conn.await?).await })
    }
}

impl Protocol for DocsEngine {
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move { self.handle_connection(conn).await })
    }
    fn shutdown(self: Arc<Self>) -> BoxedFuture<()> {
        Box::pin(async move {
            if let Err(err) = self.deref().shutdown().await {
                warn!("Error while shutting down docs engine: {err:?}");
            }
        })
    }
}
