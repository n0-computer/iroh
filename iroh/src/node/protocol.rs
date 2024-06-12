use std::{any::Any, fmt, sync::Arc};

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh_net::endpoint::Connecting;

/// Trait for iroh protocol handlers.
pub trait Protocol: Send + Sync + Any + fmt::Debug + 'static {
    /// Return `self` as `dyn Any`.
    ///
    /// Implementations can simply return `self` here.
    fn as_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;

    /// Handle an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn handle_connection(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>>;
}
