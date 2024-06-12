use std::{
    any::Any,
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh_net::endpoint::Connecting;

use crate::node::DocsEngine;

/// Trait for iroh protocol handlers.
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
}
