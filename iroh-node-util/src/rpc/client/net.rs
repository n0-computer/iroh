//! API to manage the iroh networking stack.
//!
//! The main entry point is the [`Client`].
//!
//! The client can be used to get information about the node, such as the
//! [node id](Client::node_id) or [node address](Client::node_addr).
//!
//! It can also be used to provide additional information to the node, e.g.
//! using the [add_node_addr](Client::add_node_addr) method.
use std::net::SocketAddr;

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_net::{endpoint::RemoteInfo, relay::RelayUrl, NodeAddr, NodeId};
use quic_rpc::RpcClient;
use serde::{Deserialize, Serialize};

use super::flatten;
use crate::rpc::proto::{
    net::{
        AddAddrRequest, AddrRequest, IdRequest, RelayRequest, RemoteInfoRequest,
        RemoteInfoResponse, RemoteInfosIterRequest,
    },
    RpcService,
};

/// Iroh net Client.
///
/// Cheaply clonable and threadsafe. Use the iroh `net::Client` to access the
/// iroh net methods from a different thread, process, or remote machine.
///
/// The `node::Client` api allows you to get information *about* the iroh node,
/// its status, and connection status to other nodes. It also allows you to
/// provide address information about *other* nodes to your node.
#[derive(Debug, Clone)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient<RpcService>,
}

impl Client {
    /// Creates a new net client
    pub fn new(rpc: RpcClient<RpcService>) -> Self {
        Self { rpc }
    }

    /// Fetches information about currently known remote nodes.
    ///
    /// This streams a *current snapshot*. It does not keep the stream open after finishing
    /// transferring the snapshot.
    ///
    /// See also [`Endpoint::remote_info_iter`](iroh_net::Endpoint::remote_info_iter).
    pub async fn remote_info_iter(&self) -> Result<impl Stream<Item = Result<RemoteInfo>>> {
        let stream = self.rpc.server_streaming(RemoteInfosIterRequest {}).await?;
        Ok(flatten(stream).map(|res| res.map(|res| res.info)))
    }

    /// Fetches node information about a remote iroh node identified by its [`NodeId`].
    ///
    /// See also [`Endpoint::remote_info`](iroh_net::Endpoint::remote_info).
    pub async fn remote_info(&self, node_id: NodeId) -> Result<Option<RemoteInfo>> {
        let RemoteInfoResponse { info } = self.rpc.rpc(RemoteInfoRequest { node_id }).await??;
        Ok(info)
    }

    /// Fetches the node id of this node.
    ///
    /// See also [`Endpoint::node_id`](iroh_net::Endpoint::node_id).
    pub async fn node_id(&self) -> Result<NodeId> {
        let id = self.rpc.rpc(IdRequest).await??;
        Ok(id)
    }

    /// Fetches the [`NodeAddr`] for this node.
    ///
    /// See also [`Endpoint::node_addr`](iroh_net::Endpoint::node_addr).
    pub async fn node_addr(&self) -> Result<NodeAddr> {
        let addr = self.rpc.rpc(AddrRequest).await??;
        Ok(addr)
    }

    /// Adds a known node address to this node.
    ///
    /// See also [`Endpoint::add_node_addr`](iroh_net::Endpoint::add_node_addr).
    pub async fn add_node_addr(&self, addr: NodeAddr) -> Result<()> {
        self.rpc.rpc(AddAddrRequest { addr }).await??;
        Ok(())
    }

    /// Returns the relay server we are connected to.
    ///
    /// See also [`Endpoint::home_relay`](iroh_net::Endpoint::home_relay).
    pub async fn home_relay(&self) -> Result<Option<RelayUrl>> {
        let relay = self.rpc.rpc(RelayRequest).await??;
        Ok(relay)
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
