use std::{fmt::Debug, sync::Arc, time::Duration};

use anyhow::Result;
use futures_lite::Stream;
use iroh_blobs::{
    net_protocol::Blobs as BlobsProtocol, store::Store as BaoStore,
    util::local_pool::LocalPoolHandle,
};
use iroh_docs::net::DOCS_ALPN;
use iroh_gossip::net::{Gossip, GOSSIP_ALPN};
use iroh_net::{NodeAddr, NodeId};
use iroh_router::Router;
use quic_rpc::server::{RpcChannel, RpcServerError};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use super::IrohServerEndpoint;
use crate::{
    base::node_addr::RelayUrl,
    client::NodeStatus,
    node::NodeInner,
    rpc_protocol::{
        net::{
            self, AddAddrRequest, AddrRequest, IdRequest, NodeWatchRequest, RelayRequest,
            RemoteInfoRequest, RemoteInfoResponse, RemoteInfosIterRequest, RemoteInfosIterResponse,
            WatchResponse,
        },
        node::{self, ShutdownRequest, StatsRequest, StatsResponse, StatusRequest},
        Request, RpcService,
    },
};

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);
pub(crate) type RpcError = serde_error::Error;
pub(crate) type RpcResult<T> = Result<T, RpcError>;

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
        msg: node::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use node::Request::*;
        debug!("handling node request: {msg}");
        match msg {
            Status(msg) => chan.rpc(msg, self, Self::node_status).await,
            Shutdown(msg) => chan.rpc(msg, self, Self::node_shutdown).await,
            Stats(msg) => chan.rpc(msg, self, Self::node_stats).await,
        }
    }

    async fn handle_net_request(
        self,
        msg: net::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use net::Request::*;
        debug!("handling node request: {msg}");
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

    async fn handle_gossip_request(
        self,
        msg: iroh_gossip::RpcRequest,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        let gossip = self
            .router
            .get_protocol::<Gossip>(GOSSIP_ALPN)
            .expect("missing gossip");
        let chan = chan.map::<iroh_gossip::RpcService>();
        gossip
            .handle_rpc_request(msg, chan)
            .await
            .map_err(|e| e.errors_into())
    }

    async fn handle_docs_request(
        self,
        msg: iroh_docs::rpc::proto::Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        if let Some(docs) = self
            .router
            .get_protocol::<iroh_docs::engine::Engine<D>>(DOCS_ALPN)
        {
            let chan = chan.map::<iroh_docs::rpc::proto::RpcService>();
            docs.handle_rpc_request(msg, chan)
                .await
                .map_err(|e| e.errors_into())
        } else {
            Err(RpcServerError::SendError(anyhow::anyhow!(
                "Docs is not enabled"
            )))
        }
    }

    pub(crate) async fn handle_rpc_request(
        self,
        msg: Request,
        chan: RpcChannel<RpcService, IrohServerEndpoint>,
    ) -> Result<(), RpcServerError<IrohServerEndpoint>> {
        use Request::*;
        debug!("handling rpc request: {msg}");
        match msg {
            Net(msg) => self.handle_net_request(msg, chan).await,
            Node(msg) => self.handle_node_request(msg, chan).await,
            BlobsAndTags(msg) => self.handle_blobs_request(msg, chan.map().boxed()).await,
            Docs(msg) => self.handle_docs_request(msg, chan).await,
            Gossip(msg) => self.handle_gossip_request(msg, chan).await,
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
                .inner
                .endpoint
                .node_addr()
                .await
                .map_err(|e| RpcError::new(&*e))?,
            listen_addrs: self
                .inner
                .local_endpoint_addresses()
                .await
                .unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            rpc_addr: self.inner.rpc_addr,
        })
    }

    #[allow(clippy::unused_async)]
    async fn node_id(self, _: IdRequest) -> RpcResult<NodeId> {
        Ok(self.inner.endpoint.secret_key().public())
    }

    async fn node_addr(self, _: AddrRequest) -> RpcResult<NodeAddr> {
        let addr = self
            .inner
            .endpoint
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(addr)
    }

    #[allow(clippy::unused_async)]
    async fn node_relay(self, _: RelayRequest) -> RpcResult<Option<RelayUrl>> {
        Ok(self.inner.endpoint.home_relay())
    }

    #[allow(clippy::unused_async)]
    async fn node_shutdown(self, request: ShutdownRequest) {
        if request.force {
            info!("hard shutdown requested");
            std::process::exit(0);
        } else {
            // trigger a graceful shutdown
            info!("graceful shutdown requested");
            self.inner.cancel_token.cancel();
        }
    }

    fn node_watch(self, _: NodeWatchRequest) -> impl Stream<Item = WatchResponse> {
        futures_lite::stream::unfold((), |()| async move {
            tokio::time::sleep(HEALTH_POLL_WAIT).await;
            Some((
                WatchResponse {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                (),
            ))
        })
    }

    fn local_pool_handle(&self) -> LocalPoolHandle {
        self.inner.local_pool_handle.clone()
    }

    fn remote_infos_iter(
        self,
        _: RemoteInfosIterRequest,
    ) -> impl Stream<Item = RpcResult<RemoteInfosIterResponse>> + Send + 'static {
        // provide a little buffer so that we don't slow down the sender
        let (tx, rx) = async_channel::bounded(32);
        let mut infos: Vec<_> = self.inner.endpoint.remote_info_iter().collect();
        infos.sort_by_key(|n| n.node_id.to_string());
        self.local_pool_handle().spawn_detached(|| async move {
            for info in infos {
                tx.send(Ok(RemoteInfosIterResponse { info })).await.ok();
            }
        });
        rx
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn remote_info(self, req: RemoteInfoRequest) -> RpcResult<RemoteInfoResponse> {
        let RemoteInfoRequest { node_id } = req;
        let info = self.inner.endpoint.remote_info(node_id);
        Ok(RemoteInfoResponse { info })
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_add_addr(self, req: AddAddrRequest) -> RpcResult<()> {
        let AddAddrRequest { addr } = req;
        self.inner
            .endpoint
            .add_node_addr(addr)
            .map_err(|e| RpcError::new(&*e))?;
        Ok(())
    }
}
