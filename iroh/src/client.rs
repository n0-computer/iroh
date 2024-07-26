//! Client to an Iroh node.
//!
//! See the documentation for [`Iroh`] for more information.

use futures_lite::{Stream, StreamExt};
use ref_cast::RefCast;
use std::ops::Deref;

#[doc(inline)]
pub use crate::rpc_protocol::RpcService;

mod quic;

pub use self::docs::Doc;
pub use self::node::NodeStatus;

pub(crate) use self::quic::{connect_raw as quic_connect_raw, RPC_ALPN};

pub mod authors;
pub mod blobs;
pub mod docs;
pub mod gossip;
pub mod node;
pub mod tags;

// Keep this type exposed, otherwise every occurrence of `RpcClient` in the API
// will show up as `RpcClient<RpcService, Connection<RpcService>>` in the docs.
/// Iroh rpc client - boxed so that we can have a concrete type.
pub type RpcClient =
    quic_rpc::RpcClient<RpcService, quic_rpc::transport::boxed::Connection<RpcService>>;

/// An iroh client.
///
/// There are three ways to obtain this client, depending on which context
/// you're running in relative to the main [`Node`](crate::node::Node):
///
/// 1. If you just spawned the client in rust the same process and have a reference to it:
///    Use [`Node::client()`](crate::node::Node::client).
/// 2. If the main node wasn't spawned in the same process, but on the same machine:
///    Use [`Iroh::connect_path`].
/// 3. If the main node was spawned somewhere else and has been made accessible via IP:
///    Use [`Iroh::connect_addr`].
#[derive(Debug, Clone)]
pub struct Iroh {
    rpc: RpcClient,
}

impl Deref for Iroh {
    type Target = node::Client;

    fn deref(&self) -> &Self::Target {
        self.node()
    }
}

impl Iroh {
    /// Creates a new high-level client to a Iroh node from the low-level RPC client.
    ///
    /// Prefer using [`Node::client()`](crate::node::Node::client), [`Iroh::connect_path`]
    /// or [`Iroh::connect_addr`] instead of calling this function.
    ///
    /// See also the [`Iroh`] struct documentation.
    pub fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }

    /// Returns the blobs client.
    pub fn blobs(&self) -> &blobs::Client {
        blobs::Client::ref_cast(&self.rpc)
    }

    /// Returns the docs client.
    pub fn docs(&self) -> &docs::Client {
        docs::Client::ref_cast(&self.rpc)
    }

    /// Returns the authors client.
    pub fn authors(&self) -> &authors::Client {
        authors::Client::ref_cast(&self.rpc)
    }

    /// Returns the tags client.
    pub fn tags(&self) -> &tags::Client {
        tags::Client::ref_cast(&self.rpc)
    }

    /// Returns the gossip client.
    pub fn gossip(&self) -> &gossip::Client {
        gossip::Client::ref_cast(&self.rpc)
    }

    /// Returns the node client.
    pub fn node(&self) -> &node::Client {
        node::Client::ref_cast(&self.rpc)
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
