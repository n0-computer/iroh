use std::{
    any::Any,
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh_net::endpoint::Connecting;

/// Trait for iroh protocol handlers.
pub trait Protocol: Send + Sync + IntoArcAny + fmt::Debug + 'static {
    /// Handle an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>>;
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

/// Map of registered protocol handlers.
#[allow(clippy::type_complexity)]
#[derive(Debug, Clone, Default)]
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
}
