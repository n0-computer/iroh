use std::{collections::BTreeMap, fmt::Debug, sync::Arc};

use anyhow::Result;
use futures_lite::Stream;
use iroh_blobs::{net_protocol::Blobs as BlobsProtocol, store::Store as BaoStore};
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
pub(crate) struct Handler<D> {
    pub(crate) inner: Arc<NodeInner<D>>,
    pub(crate) router: Router,
}

impl<D> Handler<D> {
    pub fn new(inner: Arc<NodeInner<D>>, router: Router) -> Self {
        Self { inner, router }
    }
}

impl<D: BaoStore> iroh_node_util::rpc::server::AbstractNode for NodeInner<D> {
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

impl<D: BaoStore> Handler<D> {
    fn blobs(&self) -> Arc<BlobsProtocol<D>> {
        self.router
            .get_protocol::<BlobsProtocol<D>>(iroh_blobs::protocol::ALPN)
            .expect("missing blobs")
    }

    pub(crate) fn spawn_rpc_request(
        inner: Arc<NodeInner<D>>,
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

    async fn handle_blobs_request(
        self,
        msg: iroh_blobs::rpc::proto::Request,
        chan: RpcChannel<iroh_blobs::rpc::proto::RpcService>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        self.blobs()
            .handle_rpc_request(msg, chan)
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
            BlobsAndTags(msg) => self.handle_blobs_request(msg, chan.map().boxed()).await,
        }
    }
}
