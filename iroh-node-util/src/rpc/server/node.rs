use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use futures_lite::StreamExt;
use iroh_net::Endpoint;
use quic_rpc::server::{ChannelTypes, RpcChannel, RpcServerError};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::rpc::{client::net::NodeStatus, proto::{node::{self, ShutdownRequest, StatsRequest, StatsResponse, StatusRequest}, RpcError, RpcResult, RpcService}};

struct Node {
    endpoint: Endpoint,
    cancel_token: CancellationToken,
    rpc_addr: Option<SocketAddr>,
}

impl Node {

    async fn handle_rpc_request<C: ChannelTypes<RpcService>>(
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
        #[cfg(feature = "metrics")]
        let res = Ok(StatsResponse {
            stats: crate::metrics::get_metrics().map_err(|e| RpcError::new(&*e))?,
        });

        #[cfg(not(feature = "metrics"))]
        let res = Err(RpcError::new(&*anyhow::anyhow!("metrics are disabled")));

        res
    }


    async fn node_status(self, _: StatusRequest) -> RpcResult<NodeStatus> {
        Ok(NodeStatus {
            addr: self
                .endpoint
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?,
            listen_addrs: self
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
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
}