use std::{any::Any, fmt, future::Future, pin::Pin, sync::Arc};

use iroh_net::endpoint::Connection;

/// Trait for iroh protocol handlers.
pub trait Protocol: Sync + Send + Any + fmt::Debug + 'static {
    /// Return `self` as `dyn Any`.
    ///
    /// Implementations can simply return `self` here.
    fn as_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;

    /// Accept an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(
        &self,
        conn: Connection,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<()>> + 'static + Send + Sync>>;
}
