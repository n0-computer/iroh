//! Custom protocols

use std::{any::Any, collections::BTreeMap, fmt, sync::Arc};

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use futures_util::future::join_all;

use crate::endpoint::Connecting;

/// Handler for incoming connections.
///
/// An iroh node can accept connections for arbitrary ALPN protocols. By default, the iroh node
/// only accepts connections for the ALPNs of the core iroh protocols (blobs, gossip, docs).
///
/// With this trait, you can handle incoming connections for custom protocols.
///
/// Implement this trait on a struct that should handle incoming connections.
/// The protocol handler must then be registered on the node for an ALPN protocol with
/// [`crate::node::builder::ProtocolBuilder::accept`].
pub trait ProtocolHandler: Send + Sync + IntoArcAny + fmt::Debug + 'static {
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
    /// Conversion
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;
}

impl<T: Send + Sync + 'static> IntoArcAny for T {
    fn into_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

/// List of custom protocols.
#[derive(Debug, Clone, Default)]
pub struct ProtocolMap(BTreeMap<Vec<u8>, Arc<dyn ProtocolHandler>>);

impl ProtocolMap {
    /// Returns the registered protocol handler for an ALPN as a concrete type.
    pub fn get_typed<P: ProtocolHandler>(&self, alpn: &[u8]) -> Option<Arc<P>> {
        let protocol: Arc<dyn ProtocolHandler> = self.0.get(alpn)?.clone();
        let protocol_any: Arc<dyn Any + Send + Sync> = protocol.into_arc_any();
        let protocol_ref = Arc::downcast(protocol_any).ok()?;
        Some(protocol_ref)
    }

    /// Returns the registered protocol handler for an ALPN as a [`Arc<dyn ProtocolHandler>`].
    pub fn get(&self, alpn: &[u8]) -> Option<Arc<dyn ProtocolHandler>> {
        self.0.get(alpn).cloned()
    }

    /// Inserts a protocol handler.
    pub fn insert(&mut self, alpn: Vec<u8>, handler: Arc<dyn ProtocolHandler>) {
        self.0.insert(alpn, handler);
    }

    /// Returns an iterator of all registered ALPN protocol identifiers.
    pub fn alpns(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.0.keys()
    }

    /// Shuts down all protocol handlers.
    ///
    /// Calls and awaits [`ProtocolHandler::shutdown`] for all registered handlers concurrently.
    pub async fn shutdown(&self) {
        let handlers = self.0.values().cloned().map(ProtocolHandler::shutdown);
        join_all(handlers).await;
    }
}
