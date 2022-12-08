pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;

pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::http2::Http2ChannelTypes,
    quic_rpc::mem::MemChannelTypes,
>;

pub use self::config::Config;
pub use client::Client;
use futures::{stream::BoxStream, StreamExt};
use iroh_qrpc_types::Addr;
pub use network::{Lookup, P2pClient};
use quic_rpc::{
    combined,
    http2::{self},
    mem::MemChannelTypes,
    RpcClient, RpcServer, Service,
};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

pub async fn create_server_stream<S: Service>(
    addr: Addr<S::Req, S::Res>,
) -> anyhow::Result<
    BoxStream<
        'static,
        Result<
            RpcServer<S, ChannelTypes>,
            combined::CreateChannelError<MemChannelTypes, MemChannelTypes>,
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
            Ok(futures::stream::once(async move { Ok(server) }).boxed())
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
