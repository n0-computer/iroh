use std::collections::BTreeMap;

use anyhow::Result;
use futures::{Stream, TryStreamExt};
use iroh_base::key::PublicKey;
use iroh_net::magic_endpoint::ConnectionInfo;
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{
    CounterStats, NodeConnectionInfoRequest, NodeConnectionInfoResponse, NodeConnectionsRequest,
    NodeShutdownRequest, NodeStatsRequest, NodeStatusRequest, NodeStatusResponse, ProviderService,
};

use super::flatten;

/// Iroh node client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Get statistics of the running node.
    pub async fn stats(&self) -> Result<BTreeMap<String, CounterStats>> {
        let res = self.rpc.rpc(NodeStatsRequest {}).await??;
        Ok(res.stats)
    }

    /// Get information about the different connections we have made
    pub async fn connections(&self) -> Result<impl Stream<Item = Result<ConnectionInfo>>> {
        let stream = self.rpc.server_streaming(NodeConnectionsRequest {}).await?;
        Ok(flatten(stream).map_ok(|res| res.conn_info))
    }

    /// Get connection information about a node
    pub async fn connection_info(&self, node_id: PublicKey) -> Result<Option<ConnectionInfo>> {
        let NodeConnectionInfoResponse { conn_info } = self
            .rpc
            .rpc(NodeConnectionInfoRequest { node_id })
            .await??;
        Ok(conn_info)
    }

    /// Get status information about a node
    pub async fn status(&self) -> Result<NodeStatusResponse> {
        let response = self.rpc.rpc(NodeStatusRequest).await??;
        Ok(response)
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
