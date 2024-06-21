//! API to manage the iroh node itself.

use std::{collections::BTreeMap, net::SocketAddr};

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use iroh_base::key::PublicKey;
use iroh_net::{endpoint::ConnectionInfo, relay::RelayUrl, NodeAddr, NodeId};
use serde::{Deserialize, Serialize};

use crate::rpc_protocol::{
    CounterStats, NodeAddrRequest, NodeConnectionInfoRequest, NodeConnectionInfoResponse,
    NodeConnectionsRequest, NodeIdRequest, NodeRelayRequest, NodeShutdownRequest, NodeStatsRequest,
    NodeStatusRequest,
};

use super::{flatten, Iroh};

impl Iroh {
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
    pub async fn node_id(&self) -> Result<NodeId> {
        let id = self.rpc.rpc(NodeIdRequest).await??;
        Ok(id)
    }

    /// Return the [`NodeAddr`] for this node.
    pub async fn my_addr(&self) -> Result<NodeAddr> {
        let addr = self.rpc.rpc(NodeAddrRequest).await??;
        Ok(addr)
    }

    /// Get the relay server we are connected to.
    pub async fn my_relay(&self) -> Result<Option<RelayUrl>> {
        let relay = self.rpc.rpc(NodeRelayRequest).await??;
        Ok(relay)
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
