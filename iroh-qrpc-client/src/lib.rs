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
    combined::{self, CombinedChannelTypes},
    http2::{self, Http2ChannelTypes},
    mem::MemChannelTypes,
    RpcClient, RpcServer, Service,
};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

pub type ChannelTypes = CombinedChannelTypes<Http2ChannelTypes, MemChannelTypes>;

pub type StoreServer = RpcServer<StoreService, ChannelTypes>;
pub type GatewayServer = RpcServer<GatewayService, ChannelTypes>;
pub type P2pServer = RpcServer<P2pService, ChannelTypes>;

pub async fn create_server_stream<S: Service>(
    addr: Addr<S::Req, S::Res>,
) -> anyhow::Result<
    BoxStream<
        'static,
        Result<
            RpcServer<S, ChannelTypes>,
            combined::CreateChannelError<Http2ChannelTypes, MemChannelTypes>,
        >,
    >,
> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(_addr) => {
            todo!()
            // Ok(Some(RpcServer::new(combined::Channel::new(Some(addr), None))))
        }
        Addr::Http2Lookup(_addr) => {
            todo!()
            // Ok(Some(RpcServer::new(combined::Channel::new(Some(addr), None))))
        }
        Addr::Http2(addr) => {
            let (channel, hyper) = quic_rpc::http2::Channel::server(&addr)?;
            tokio::spawn(hyper);
            let channel = combined::Channel::new(Some(channel), None);
            let server = RpcServer::new(channel);
            Ok(stream::repeat(server).map(Ok).boxed())
        }
    }
}

async fn create_http2_client_channel<S: Service>(
    uri: hyper::Uri,
) -> Result<http2::Channel<S::Res, S::Req>, hyper::Error> {
    Ok(quic_rpc::http2::Channel::client(uri))
}

pub async fn open_client<S: Service>(
    addr: Addr<S::Res, S::Req>,
) -> anyhow::Result<RpcClient<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(_addr) => {
            todo!()
        }
        Addr::Http2(uri) => {
            let uri = format!("http://{}", uri).parse()?;
            let channel = create_http2_client_channel::<S>(uri).await?;
            let channel = combined::Channel::new(Some(channel), None);
            Ok(RpcClient::<S, ChannelTypes>::new(channel))
        }
        Addr::Http2Lookup(_addr) => {
            todo!()
        }
    }
}
