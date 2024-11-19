//! Server implementation to handle node and net rpc requests
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};
use futures_lite::{Stream, StreamExt};
use iroh_net::{Endpoint, NodeAddr, NodeId, RelayUrl};
use quic_rpc::server::{ChannelTypes, RpcChannel, RpcServerError};
use tracing::{debug, info};

use super::proto::{net, node::CounterStats, Request};
use crate::rpc::{
    client::net::NodeStatus,
    proto::{
        node::{self, ShutdownRequest, StatsRequest, StatsResponse, StatusRequest},
        RpcError, RpcResult, RpcService,
    },
};

/// Trait that provides fields used by the rpc handler for the net and node requests.
pub trait AbstractNode: Send + Sync + 'static {
    /// Get the endpoint of the node
    fn endpoint(&self) -> &Endpoint;

    /// Shutdown the node, used by the node shutdown rpc call
    fn shutdown(&self);

    /// Rpc address of the node, used by the node status rpc call
    fn rpc_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Stats for the node stats rpc call
    fn stats(&self) -> anyhow::Result<BTreeMap<String, CounterStats>> {
        anyhow::bail!("metrics are disabled");
    }
}

struct Handler(Arc<dyn AbstractNode>);

/// Handle rpc requests for the node and net services
pub async fn handle_rpc_request<C: ChannelTypes<RpcService>>(
    node: Arc<dyn AbstractNode>,
    msg: Request,
    chan: RpcChannel<RpcService, C>,
) -> Result<(), RpcServerError<C>> {
    use Request::*;
    match msg {
        Node(msg) => Handler(node).handle_node_request(msg, chan).await,
        Net(msg) => Handler(node).handle_net_request(msg, chan).await,
    }
}

impl Handler {
    fn endpoint(&self) -> &Endpoint {
        self.0.endpoint()
    }

    async fn handle_node_request<C: ChannelTypes<RpcService>>(
        self,
        msg: node::Request,
        chan: RpcChannel<RpcService, C>,
    ) -> Result<(), RpcServerError<C>> {
        use node::Request::*;
        debug!("handling node request: {msg}");
        match msg {
            Status(msg) => chan.rpc(msg, self, Self::node_status).await,
            Shutdown(msg) => chan.rpc(msg, self, Self::node_shutdown).await,
            Stats(msg) => chan.rpc(msg, self, Self::node_stats).await,
        }
    }

    async fn handle_net_request<C: ChannelTypes<RpcService>>(
        self,
        msg: net::Request,
        chan: RpcChannel<RpcService, C>,
    ) -> Result<(), RpcServerError<C>> {
        use net::Request::*;
        debug!("handling net request: {msg}");
        match msg {
            Watch(msg) => chan.server_streaming(msg, self, Self::node_watch).await,
            Id(msg) => chan.rpc(msg, self, Self::node_id).await,
            Addr(msg) => chan.rpc(msg, self, Self::node_addr).await,
            Relay(msg) => chan.rpc(msg, self, Self::node_relay).await,
            RemoteInfosIter(msg) => {
                chan.server_streaming(msg, self, Self::remote_infos_iter)
                    .await
            }
            RemoteInfo(msg) => chan.rpc(msg, self, Self::remote_info).await,
            AddAddr(msg) => chan.rpc(msg, self, Self::node_add_addr).await,
        }
    }

    #[allow(clippy::unused_async)]
    async fn node_shutdown(self, request: ShutdownRequest) {
        if request.force {
            info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            info!("graceful shutdown requested");
            self.0.shutdown();
        }
    }

    #[allow(clippy::unused_async)]
    async fn node_stats(self, _req: StatsRequest) -> RpcResult<StatsResponse> {
        Ok(StatsResponse {
            stats: self.0.stats().map_err(|e| RpcError::new(&*e))?,
        })
    }

    async fn node_status(self, _: StatusRequest) -> RpcResult<NodeStatus> {
        Ok(NodeStatus {
            addr: self
                .endpoint()
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?,
            listen_addrs: self.local_endpoint_addresses().await.unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_addr: self.0.rpc_addr(),
        })
    }

    async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        let endpoints = self
            .endpoint()
            .direct_addresses()
            .next()
            .await
            .ok_or(anyhow!("no endpoints found"))?;
        Ok(endpoints.into_iter().map(|x| x.addr).collect())
    }

    async fn node_addr(self, _: net::AddrRequest) -> RpcResult<NodeAddr> {
        let addr = self
            .endpoint()
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(addr)
    }

    fn remote_infos_iter(
        self,
        _: net::RemoteInfosIterRequest,
    ) -> impl Stream<Item = RpcResult<net::RemoteInfosIterResponse>> + Send + 'static {
        let mut infos: Vec<_> = self.endpoint().remote_info_iter().collect();
        infos.sort_by_key(|n| n.node_id.to_string());
        futures_lite::stream::iter(
            infos
                .into_iter()
                .map(|info| Ok(net::RemoteInfosIterResponse { info })),
        )
    }

    #[allow(clippy::unused_async)]
    async fn node_id(self, _: net::IdRequest) -> RpcResult<NodeId> {
        Ok(self.endpoint().secret_key().public())
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn remote_info(self, req: net::RemoteInfoRequest) -> RpcResult<net::RemoteInfoResponse> {
        let net::RemoteInfoRequest { node_id } = req;
        let info = self.endpoint().remote_info(node_id);
        Ok(net::RemoteInfoResponse { info })
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_add_addr(self, req: net::AddAddrRequest) -> RpcResult<()> {
        let net::AddAddrRequest { addr } = req;
        self.endpoint()
            .add_node_addr(addr)
            .map_err(|e| RpcError::new(&*e))?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_relay(self, _: net::RelayRequest) -> RpcResult<Option<RelayUrl>> {
        Ok(self.endpoint().home_relay())
    }

    fn node_watch(self, _: net::NodeWatchRequest) -> impl Stream<Item = net::WatchResponse> + Send {
        futures_lite::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                net::WatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }
}

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
