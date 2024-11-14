//! Client to an Iroh node.
//!
//! See the documentation for [`Iroh`] for more information.

use std::collections::BTreeMap;

use anyhow::Result;
use iroh_node_util::rpc::{client::net::NodeStatus, proto::node::CounterStats};

#[doc(inline)]
pub use crate::rpc_protocol::RpcService;

mod quic;

pub use iroh_blobs::rpc::client::{blobs, tags};
pub use iroh_docs::rpc::client::{authors, docs, docs::Doc};
pub use iroh_gossip::rpc::client as gossip;
pub use iroh_node_util::rpc::client::{net, node};

pub(crate) use self::quic::{connect_raw as quic_connect_raw, RPC_ALPN};

// Keep this type exposed, otherwise every occurrence of `RpcClient` in the API
// will show up as `RpcClient<RpcService, Connection<RpcService>>` in the docs.
/// Iroh rpc client - boxed so that we can have a concrete type.
pub type RpcClient = quic_rpc::RpcClient<RpcService>;

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
    pub fn blobs(&self) -> blobs::Client {
        blobs::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the docs client.
    pub fn docs(&self) -> iroh_docs::rpc::client::docs::Client {
        iroh_docs::rpc::client::docs::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the docs client.
    pub fn authors(&self) -> iroh_docs::rpc::client::authors::Client {
        iroh_docs::rpc::client::authors::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the tags client.
    pub fn tags(&self) -> tags::Client {
        tags::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the gossip client.
    pub fn gossip(&self) -> gossip::Client {
        gossip::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the net client.
    pub fn net(&self) -> net::Client {
        net::Client::new(self.rpc.clone().map().boxed())
    }

    /// Returns the net client.
    pub fn node(&self) -> node::Client {
        node::Client::new(self.rpc.clone().map().boxed())
    }

    /// Shuts down the node.
    ///
    /// If `force` is true, the node will be shut down instantly without
    /// waiting for things to stop gracefully.
    pub async fn shutdown(&self, force: bool) -> Result<()> {
        self.node().shutdown(force).await
    }

    /// Fetches statistics of the running node.
    pub async fn stats(&self) -> Result<BTreeMap<String, CounterStats>> {
        self.node().stats().await
    }

    /// Fetches status information about this node.
    pub async fn status(&self) -> Result<NodeStatus> {
        self.node().status().await
    }
}
