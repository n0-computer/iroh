pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;
pub use self::config::Config;
pub use client::Client;
use futures::{
    stream::{self, BoxStream},
    StreamExt,
};
use iroh_qrpc_types::{gateway::GatewayService, p2p::P2pService, store::StoreService, Addr};
pub use network::{Lookup, P2pClient};
use quic_rpc::{
    transport::{combined, http2, CombinedChannelTypes, Http2ChannelTypes, MemChannelTypes},
    RpcClient, RpcServer, Service,
};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

pub type ChannelTypes = CombinedChannelTypes<Http2ChannelTypes, MemChannelTypes>;

pub type StoreServer = RpcServer<StoreService, ChannelTypes>;
pub type GatewayServer = RpcServer<GatewayService, ChannelTypes>;
pub type P2pServer = RpcServer<P2pService, ChannelTypes>;

pub async fn create_server_stream<S: Service>(
    addr: Addr<S>,
) -> anyhow::Result<
    BoxStream<
        'static,
        Result<
            RpcServer<S, ChannelTypes>,
            combined::AcceptBiError<Http2ChannelTypes, MemChannelTypes>,
        >,
    >,
> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(channel, _) => {
            let channel = combined::ServerChannel::new(None, Some(channel));
            let server = RpcServer::new(channel);
            Ok(stream::repeat(server).map(Ok).boxed())
        }
        Addr::Http2Lookup(_addr) => {
            todo!()
            // Ok(Some(RpcServer::new(combined::Channel::new(Some(addr), None))))
        }
        Addr::Http2(addr) => {
            let (channel, hyper) = quic_rpc::transport::http2::ServerChannel::new(&addr)?;
            tokio::spawn(hyper);
            let channel = combined::ServerChannel::new(Some(channel), None);
            let server = RpcServer::new(channel);
            Ok(stream::repeat(server).map(Ok).boxed())
        }
    }
}

async fn create_http2_client_channel<S: Service>(
    uri: hyper::Uri,
) -> Result<http2::ClientChannel<S::Res, S::Req>, hyper::Error> {
    Ok(http2::ClientChannel::new(uri))
}

pub async fn open_client<S: Service>(addr: Addr<S>) -> anyhow::Result<RpcClient<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(_, client) => Ok(RpcClient::<S, ChannelTypes>::new(
            combined::ClientChannel::new(None, Some(client)),
        )),
        Addr::Http2(uri) => {
            let uri = format!("http://{}", uri).parse()?;
            let channel = create_http2_client_channel::<S>(uri).await?;
            let channel = combined::ClientChannel::new(Some(channel), None);
            Ok(RpcClient::<S, ChannelTypes>::new(channel))
        }
        Addr::Http2Lookup(_addr) => {
            todo!()
        }
    }
}
