//! API to manage the iroh node itself.
//!
//! The main entry point is the [Client].
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

/// Iroh node client.
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
