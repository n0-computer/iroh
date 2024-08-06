//! API to manage the iroh node itself.
//!
//! The main entry point is the [`Client`].
//!
//! You obtain a [`Client`] via [`Iroh::node()`](crate::client::Iroh::node),
//! or just use [`Iroh`](crate::client::Iroh) directly,
//! as it has a `Deref` implementation for this [`Client`].
//!
//! The client can be used to get information about the node, such as the
//! [status](Client::status), [node id](Client::node_id) or
//! [node address](Client::node_addr).
//!
//! It can also be used to provide additional information to the node, e.g.
//! using the [add_node_addr](Client::add_node_addr) method.
//!
//! It provides a way to [shutdown](Client::shutdown) the entire node.
use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_net::{endpoint::ConnectionInfo, relay::RelayUrl, NodeAddr, NodeId};
use ref_cast::RefCast;
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::node::{
    AddAddrRequest, AddrRequest, ConnectionInfoRequest, ConnectionInfoResponse, ConnectionsRequest,
    CounterStats, IdRequest, RelayRequest, ShutdownRequest, StatsRequest, StatusRequest,
};

use super::{flatten, RpcClient};

/// Iroh node Client.
///
/// Cheaply clonable and threadsafe. Use the iroh `node::Client` to access the
/// iroh node methods from a different thread, process, or remote machine.
/// The [`Iroh`](crate::client::Iroh) client dereferences to a `node::Client`,
/// so you have access to this api from the [`Iroh`](crate::client::Iroh) client itself.
///
/// The `node::Client` api allows you to get information *about* the iroh node,
/// its status, and connection status to other nodes. It also allows you to
/// provide address information about *other* nodes to your node.
///
/// Obtain an iroh `node::Client` via [`Iroh::node()`](crate::client::Iroh::node).
///
/// It also provides a way to [shutdown](Client::shutdown) the entire iroh node.
///
/// # Examples
/// ```
/// use std::str::FromStr;
/// use iroh_base::{key::NodeId, node_addr::{RelayUrl, NodeAddr}};
/// use url::Url;
///
/// # async fn run() -> anyhow::Result<()> {
/// // Create an iroh node:
/// let iroh = iroh::node::Node::memory().spawn().await?;
/// // Create a node client, a client that gives you access to `node` subsystem
/// let node_client = iroh.client().node();
/// // Get the node status, including its node id, addresses, the version of iroh
/// // it is running, and more.
/// let status = node_client.status().await?;
/// println!("Node status: {status:?}");
/// // Provide your node an address for another node
/// let relay_url = RelayUrl::from(Url::parse("https://example.com").unwrap());
/// let addr = NodeAddr::from_parts(
///   // the node_id
///   NodeId::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6").unwrap(),
///   // the home relay
///   Some(relay_url),
///   // the direct addresses
///   vec!["120.0.0.1:0".parse().unwrap()],
/// );
/// node_client.add_node_addr(addr).await?;
/// // Shut down the node. Passing `true` will force the shutdown, passing in
/// // `false` will allow the node to shut down gracefully.
/// node_client.shutdown(false).await?;
/// # Ok(())
/// # }
/// ```
/// You can also use the `node::Client` methods from the `Iroh` client:
///
/// ```
/// use std::str::FromStr;
/// use iroh_base::{key::NodeId, node_addr::{RelayUrl, NodeAddr}};
/// use url::Url;
///
/// # async fn run() -> anyhow::Result<()> {
/// // Create an iroh node:
/// let iroh = iroh::node::Node::memory().spawn().await?;
/// // Create a client:
/// let client = iroh.client();
/// // Get the node status, including its node id, addresses, the version of iroh
/// // it is running, and more.
/// let status = client.status().await?;
/// println!("Node status: {status:?}");
/// // Provide your node an address for another node
/// let relay_url = RelayUrl::from(Url::parse("https://example.com").unwrap());
/// let addr = NodeAddr::from_parts(
///   // the node_id
///   NodeId::from_str("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6").unwrap(),
///   // the home relay
///   Some(relay_url),
///   // the direct addresses
///   vec!["120.0.0.1:0".parse().unwrap()],
/// );
/// client.add_node_addr(addr).await?;
/// // Shut down the node. Passing `true` will force the shutdown, passing in
/// // `false` will allow the node to shut down gracefully.
/// client.shutdown(false).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

impl Client {
    /// Fetches statistics of the running node.
    pub async fn stats(&self) -> Result<BTreeMap<String, CounterStats>> {
        let res = self.rpc.rpc(StatsRequest {}).await??;
        Ok(res.stats)
    }

    /// Fetches information about currently known connections.
    ///
    /// This streams a *current snapshot*. It does not keep the stream open after finishing
    /// transferring the snapshot.
    ///
    /// See also [`Endpoint::connection_infos`](crate::net::Endpoint::connection_infos).
    pub async fn connections(&self) -> Result<impl Stream<Item = Result<ConnectionInfo>>> {
        let stream = self.rpc.server_streaming(ConnectionsRequest {}).await?;
        Ok(flatten(stream).map(|res| res.map(|res| res.conn_info)))
    }

    /// Fetches connection information about a connection to another node identified by its [`NodeId`].
    ///
    /// See also [`Endpoint::connection_info`](crate::net::Endpoint::connection_info).
    pub async fn connection_info(&self, node_id: NodeId) -> Result<Option<ConnectionInfo>> {
        let ConnectionInfoResponse { conn_info } =
            self.rpc.rpc(ConnectionInfoRequest { node_id }).await??;
        Ok(conn_info)
    }

    /// Fetches status information about this node.
    pub async fn status(&self) -> Result<NodeStatus> {
        let response = self.rpc.rpc(StatusRequest).await??;
        Ok(response)
    }

    /// Fetches the node id of this node.
    ///
    /// See also [`Endpoint::node_id`](crate::net::Endpoint::node_id).
    pub async fn node_id(&self) -> Result<NodeId> {
        let id = self.rpc.rpc(IdRequest).await??;
        Ok(id)
    }

    /// Fetches the [`NodeAddr`] for this node.
    ///
    /// See also [`Endpoint::node_addr`](crate::net::Endpoint::node_addr).
    pub async fn node_addr(&self) -> Result<NodeAddr> {
        let addr = self.rpc.rpc(AddrRequest).await??;
        Ok(addr)
    }

    /// Adds a known node address to this node.
    ///
    /// See also [`Endpoint::add_node_addr`](crate::net::Endpoint::add_node_addr).
    pub async fn add_node_addr(&self, addr: NodeAddr) -> Result<()> {
        self.rpc.rpc(AddAddrRequest { addr }).await??;
        Ok(())
    }

    /// Returns the relay server we are connected to.
    ///
    /// See also [`Endpoint::home_relay`](crate::net::Endpoint::home_relay).
    pub async fn home_relay(&self) -> Result<Option<RelayUrl>> {
        let relay = self.rpc.rpc(RelayRequest).await??;
        Ok(relay)
    }

    /// Shuts down the node.
    ///
    /// If `force` is true, the node will be shut down instantly without
    /// waiting for things to stop gracefully.
    pub async fn shutdown(&self, force: bool) -> Result<()> {
        self.rpc.rpc(ShutdownRequest { force }).await?;
        Ok(())
    }
}

/// The response to a version request
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    /// The node id and socket addresses of this node.
    pub addr: NodeAddr,
    /// The bound listening addresses of the node
    pub listen_addrs: Vec<SocketAddr>,
    /// The version of the node
    pub version: String,
    /// RPC address, if currently listening.
    pub rpc_addr: Option<SocketAddr>,
}
