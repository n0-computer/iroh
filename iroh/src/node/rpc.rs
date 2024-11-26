use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

use anyhow::Result;
use iroh_node_util::rpc::proto::node::CounterStats;
use iroh_router::Router;
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::task::JoinSet;
use tracing::{debug, warn};

use super::IrohServerEndpoint;
use crate::{
    node::NodeInner,
    rpc_protocol::{Request, RpcService},
};

#[derive(Debug, Clone)]
pub(crate) struct Handler {
    pub(crate) inner: Arc<NodeInner>,
    pub(crate) _router: Router,
}

impl Handler {
    pub fn new(inner: Arc<NodeInner>, router: Router) -> Self {
        Self {
            inner,
            _router: router,
        }
    }
}

impl iroh_node_util::rpc::server::AbstractNode for NodeInner {
    fn endpoint(&self) -> &iroh_net::Endpoint {
        &self.endpoint
    }

    fn shutdown(&self) {
        self.cancel_token.cancel();
    }

    fn rpc_addr(&self) -> Option<std::net::SocketAddr> {
        self.rpc_addr
    }

    fn stats(&self) -> anyhow::Result<BTreeMap<String, CounterStats>> {
        #[cfg(feature = "metrics")]
        return crate::metrics::get_metrics();

        #[cfg(not(feature = "metrics"))]
        anyhow::bail!("metrics are disabled")
    }
}

impl Handler {
    pub(crate) fn spawn_rpc_request(
        inner: Arc<NodeInner>,
        join_set: &mut JoinSet<anyhow::Result<()>>,
        accepting: quic_rpc::server::Accepting<RpcService, IrohServerEndpoint>,
        router: Router,
    ) {
        let handler = Self::new(inner, router);
        join_set.spawn(async move {
            let (msg, chan) = accepting.read_first().await?;
            if let Err(err) = handler.handle_rpc_request(msg, chan).await {
                warn!("rpc request handler error: {err:?}");
            }
            Ok(())
        });
    }

    async fn handle_node_request(
        self,
        msg: iroh_node_util::rpc::proto::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        debug!("handling node request: {msg:?}");
        iroh_node_util::rpc::server::handle_rpc_request(self.inner, msg, chan.map().boxed())
            .await
            .map_err(|e| e.errors_into())
    }

    pub(crate) async fn handle_rpc_request(
        self,
        msg: Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use Request::*;
        debug!("handling rpc request: {msg}");
        match msg {
            Node(msg) => self.handle_node_request(msg, chan).await,
        }
    }
}
