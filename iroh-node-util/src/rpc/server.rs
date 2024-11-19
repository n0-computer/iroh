use std::{net::SocketAddr, time::Duration};

use anyhow::{anyhow, Result};
use futures_lite::{Stream, StreamExt};
use iroh_net::{Endpoint, NodeAddr, NodeId, RelayUrl};
use quic_rpc::server::{ChannelTypes, RpcChannel, RpcServerError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use super::proto::{net, Request};
use crate::rpc::{
    client::net::NodeStatus,
    proto::{
        node::{self, ShutdownRequest, StatsRequest, StatsResponse, StatusRequest},
        RpcError, RpcResult, RpcService,
    },
};

#[derive(Debug)]
pub struct Node {
    endpoint: Endpoint,
    cancel_token: CancellationToken,
    rpc_addr: Option<SocketAddr>,
}

impl Node {
    pub fn new(
        endpoint: Endpoint,
        cancel_token: CancellationToken,
        rpc_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            endpoint,
            cancel_token,
            rpc_addr,
        }
    }

    pub async fn handle_rpc_request<C: ChannelTypes<RpcService>>(
        self,
        msg: Request,
        chan: RpcChannel<RpcService, C>,
    ) -> Result<(), RpcServerError<C>> {
        use Request::*;
        match msg {
            Node(msg) => self.handle_node_request(msg, chan).await,
            Net(msg) => self.handle_net_request(msg, chan).await,
        }
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
            self.cancel_token.cancel();
        }
    }

    #[allow(clippy::unused_async)]
    async fn node_stats(self, _req: StatsRequest) -> RpcResult<StatsResponse> {
        // TODO
        Err(RpcError::new(&*anyhow::anyhow!("metrics are disabled")))
    }

    async fn node_status(self, _: StatusRequest) -> RpcResult<NodeStatus> {
        Ok(NodeStatus {
            addr: self
                .endpoint
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?,
            listen_addrs: self.local_endpoint_addresses().await.unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_addr: self.rpc_addr,
        })
    }

    async fn local_endpoint_addresses(&self) -> Result<Vec<SocketAddr>> {
        let endpoints = self
            .endpoint
            .direct_addresses()
            .next()
            .await
            .ok_or(anyhow!("no endpoints found"))?;
        Ok(endpoints.into_iter().map(|x| x.addr).collect())
    }

    async fn node_addr(self, _: net::AddrRequest) -> RpcResult<NodeAddr> {
        let addr = self
            .endpoint
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(addr)
    }

    fn remote_infos_iter(
        self,
        _: net::RemoteInfosIterRequest,
    ) -> impl Stream<Item = RpcResult<net::RemoteInfosIterResponse>> + Send + 'static {
        let mut infos: Vec<_> = self.endpoint.remote_info_iter().collect();
        infos.sort_by_key(|n| n.node_id.to_string());
        futures_lite::stream::iter(
            infos
                .into_iter()
                .map(|info| Ok(net::RemoteInfosIterResponse { info })),
        )
    }

    #[allow(clippy::unused_async)]
    async fn node_id(self, _: net::IdRequest) -> RpcResult<NodeId> {
        Ok(self.endpoint.secret_key().public())
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn remote_info(self, req: net::RemoteInfoRequest) -> RpcResult<net::RemoteInfoResponse> {
        let net::RemoteInfoRequest { node_id } = req;
        let info = self.endpoint.remote_info(node_id);
        Ok(net::RemoteInfoResponse { info })
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_add_addr(self, req: net::AddAddrRequest) -> RpcResult<()> {
        let net::AddAddrRequest { addr } = req;
        self.endpoint
            .add_node_addr(addr)
            .map_err(|e| RpcError::new(&*e))?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_relay(self, _: net::RelayRequest) -> RpcResult<Option<RelayUrl>> {
        Ok(self.endpoint.home_relay())
    }

    fn node_watch(self, _: net::NodeWatchRequest) -> impl Stream<Item = net::WatchResponse> {
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
