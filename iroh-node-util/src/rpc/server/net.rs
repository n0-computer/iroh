use std::time::Duration;

use futures_lite::Stream;
use iroh_net::{relay::RelayUrl, Endpoint, NodeAddr, NodeId};
use quic_rpc::server::{ChannelTypes, RpcChannel, RpcServerError};
use tracing::debug;

use crate::rpc::proto::{
    net::{
        self, AddAddrRequest, AddrRequest, IdRequest, NodeWatchRequest, RelayRequest,
        RemoteInfoRequest, RemoteInfoResponse, RemoteInfosIterRequest, RemoteInfosIterResponse,
        WatchResponse,
    },
    RpcError, RpcResult, RpcService,
};

const HEALTH_POLL_WAIT: Duration = Duration::from_secs(1);

pub struct NetServer {
    endpoint: Endpoint,
}

impl NetServer {
    pub async fn handle_rpc_request<C>(
        self,
        msg: net::Request,
        chan: RpcChannel<RpcService, C>,
    ) -> Result<(), RpcServerError<C>>
    where
        C: ChannelTypes<RpcService>,
    {
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

    async fn node_addr(self, _: AddrRequest) -> RpcResult<NodeAddr> {
        let addr = self
            .endpoint
            .node_addr()
            .await
            .map_err(|e| RpcError::new(&*e))?;
        Ok(addr)
    }

    fn remote_infos_iter(
        self,
        _: RemoteInfosIterRequest,
    ) -> impl Stream<Item = RpcResult<RemoteInfosIterResponse>> + Send + 'static {
        let mut infos: Vec<_> = self.endpoint.remote_info_iter().collect();
        infos.sort_by_key(|n| n.node_id.to_string());
        futures_lite::stream::iter(
            infos
                .into_iter()
                .map(|info| Ok(RemoteInfosIterResponse { info })),
        )
    }

    #[allow(clippy::unused_async)]
    async fn node_id(self, _: IdRequest) -> RpcResult<NodeId> {
        Ok(self.endpoint.secret_key().public())
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn remote_info(self, req: RemoteInfoRequest) -> RpcResult<RemoteInfoResponse> {
        let RemoteInfoRequest { node_id } = req;
        let info = self.endpoint.remote_info(node_id);
        Ok(RemoteInfoResponse { info })
    }

    // This method is called as an RPC method, which have to be async
    #[allow(clippy::unused_async)]
    async fn node_add_addr(self, req: AddAddrRequest) -> RpcResult<()> {
        let AddAddrRequest { addr } = req;
        self.endpoint
            .add_node_addr(addr)
            .map_err(|e| RpcError::new(&*e))?;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn node_relay(self, _: RelayRequest) -> RpcResult<Option<RelayUrl>> {
        Ok(self.endpoint.home_relay())
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
}
