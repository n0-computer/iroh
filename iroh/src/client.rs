//! Client to an Iroh node.

use futures_lite::{Stream, StreamExt};
use quic_rpc::{RpcClient, ServiceConnection};

#[doc(inline)]
pub use crate::rpc_protocol::RpcService;

mod mem;
mod quic;

pub use self::mem::{Doc as MemDoc, Iroh as MemIroh, RpcClient as MemRpcClient};
pub use self::node::NodeStatus;
pub use self::quic::{Doc as QuicDoc, Iroh as QuicIroh, RpcClient as QuicRpcClient};

pub(crate) use self::quic::{connect_raw as quic_connect_raw, RPC_ALPN};

pub mod authors;
pub mod blobs;
pub mod docs;
pub mod tags;

mod node;

/// Iroh client.
#[derive(Debug, Clone)]
pub struct Iroh<C> {
    /// Client for blobs operations.
    blobs: blobs::Client<C>,
    /// Client for docs operations.
    docs: docs::Client<C>,
    /// Client for author operations.
    authors: authors::Client<C>,
    /// Client for tags operations.
    tags: tags::Client<C>,

    rpc: RpcClient<RpcService, C>,
}

impl<C> Iroh<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Create a new high-level client to a Iroh node from the low-level RPC client.
    pub fn new(rpc: RpcClient<RpcService, C>) -> Self {
        Self {
            blobs: blobs::Client { rpc: rpc.clone() },
            docs: docs::Client { rpc: rpc.clone() },
            authors: authors::Client { rpc: rpc.clone() },
            tags: tags::Client { rpc: rpc.clone() },
            rpc,
        }
    }

    ///
    pub fn blobs(&self) -> &blobs::Client<C> {
        &self.blobs
    }

    ///
    pub fn docs(&self) -> &docs::Client<C> {
        &self.docs
    }

    ///
    pub fn authors(&self) -> &authors::Client<C> {
        &self.authors
    }

    ///
    pub fn tags(&self) -> &tags::Client<C> {
        &self.tags
    }
}

fn flatten<T, E1, E2>(
    s: impl Stream<Item = Result<Result<T, E1>, E2>>,
) -> impl Stream<Item = anyhow::Result<T>>
where
    E1: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
{
    s.map(|res| match res {
        Ok(Ok(res)) => Ok(res),
        Ok(Err(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    })
}
