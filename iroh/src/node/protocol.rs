use std::{any::Any, fmt, sync::Arc};

use anyhow::Result;
use futures_lite::future::Boxed;
use iroh_net::endpoint::Connection;

/// Trait for iroh protocol handlers.
pub trait Protocol: Send + Sync + Any + fmt::Debug + 'static {
    /// Return `self` as `dyn Any`.
    ///
    /// Implementations can simply return `self` here.
    fn as_arc_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync>;

    /// Accept an incoming connection.
    ///
    /// This runs on a freshly spawned tokio task so this can be long-running.
    fn accept(self: Arc<Self>, conn: Connection) -> Boxed<Result<()>>;
}
