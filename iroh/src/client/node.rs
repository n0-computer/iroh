//! API to manage the iroh node itself.

use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_base::key::PublicKey;
use iroh_net::{magic_endpoint::ConnectionInfo, NodeAddr, NodeId};
use quic_rpc::{RpcClient, ServiceConnection};
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::{
    CounterStats, NodeConnectionInfoRequest, NodeConnectionInfoResponse, NodeConnectionsRequest,
    NodeIdRequest, NodeShutdownRequest, NodeStatsRequest, NodeStatusRequest, RpcService,
};

use super::flatten;

/// Iroh node client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<RpcService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Get statistics of the running node.
    pub async fn stats(&self) -> Result<BTreeMap<String, CounterStats>> {
        let res = self.rpc.rpc(NodeStatsRequest {}).await??;
        Ok(res.stats)
    }

    /// Get information about the different connections we have made
    pub async fn connections(&self) -> Result<impl Stream<Item = Result<ConnectionInfo>>> {
        let stream = self.rpc.server_streaming(NodeConnectionsRequest {}).await?;
        Ok(flatten(stream).map(|res| res.map(|res| res.conn_info)))
    }

    /// Get connection information about a node
    pub async fn connection_info(&self, node_id: PublicKey) -> Result<Option<ConnectionInfo>> {
        let NodeConnectionInfoResponse { conn_info } = self
            .rpc
            .rpc(NodeConnectionInfoRequest { node_id })
            .await??;
        Ok(conn_info)
    }

    /// Get status information about a node.
    pub async fn status(&self) -> Result<NodeStatus> {
        let response = self.rpc.rpc(NodeStatusRequest).await??;
        Ok(response)
    }

    /// Get the id of this node.
    pub async fn id(&self) -> Result<NodeId> {
        let id = self.rpc.rpc(NodeIdRequest).await??;
        Ok(id)
    }

    /// Shutdown the node.
    ///
    /// If `force` is true, the node will be killed instantly without waiting for things to
    /// shutdown gracefully.
    pub async fn shutdown(&self, force: bool) -> Result<()> {
        self.rpc.rpc(NodeShutdownRequest { force }).await?;
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
}
