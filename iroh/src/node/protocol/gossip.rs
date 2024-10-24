use std::sync::Arc;

use anyhow::Result;
use futures_lite::future::Boxed as BoxedFuture;
use iroh_net::endpoint::Connecting;
use iroh_router::ProtocolHandler;

/// [`ProtocolHandler`] implementation for `iroh_gossip`.
#[derive(Debug)]
pub(crate) struct GossipProtocol(pub(crate) iroh_gossip::net::Gossip);

impl std::ops::Deref for GossipProtocol {
    type Target = iroh_gossip::net::Gossip;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ProtocolHandler for GossipProtocol {
    fn accept(self: Arc<Self>, conn: Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move { self.handle_connection(conn.await?).await })
    }
}
