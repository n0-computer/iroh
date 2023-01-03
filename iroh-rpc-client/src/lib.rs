use iroh_rpc_types::{gateway::GatewayService, p2p::P2pService, store::StoreService, Addr};
use quic_rpc::{
    transport::{combined, http2, CombinedChannelTypes, Http2ChannelTypes, MemChannelTypes},
    RpcClient, RpcServer, Service,
};
use tracing::info;

pub use crate::config::Config;
pub use client::Client;
pub use network::{Lookup, P2pClient};
pub use quic_rpc::LocalAddr;
pub use status::{ClientStatus, ServiceStatus, ServiceType, StatusType, HEALTH_POLL_WAIT};
pub use store::StoreClient;

pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;

/// The types of channels used by the client and server.
pub type ChannelTypes = CombinedChannelTypes<Http2ChannelTypes, MemChannelTypes>;

/// Error when handling an RPC call on the client side.
pub type ClientError = quic_rpc::client::RpcClientError<ChannelTypes>;

/// Error when handling an RPC call on the server side.
pub type ServerError = quic_rpc::server::RpcServerError<ChannelTypes>;

/// A request sink and response stream for a single RPC call on the client side.
#[allow(type_alias_bounds)]
pub type ClientSocket<S: Service, C: quic_rpc::ChannelTypes = ChannelTypes> =
    (C::SendSink<S::Req>, C::RecvStream<S::Res>);

/// A response sink and request stream for a single RPC call on the server side.
#[allow(type_alias_bounds)]
pub type ServerSocket<S: Service, C: quic_rpc::ChannelTypes = ChannelTypes> =
    (C::SendSink<S::Res>, C::RecvStream<S::Req>);

pub type StoreServer = RpcServer<StoreService, ChannelTypes>;
pub type GatewayServer = RpcServer<GatewayService, ChannelTypes>;
pub type P2pServer = RpcServer<P2pService, ChannelTypes>;

pub async fn create_server<S: Service>(
    addr: Addr<S>,
    print_address: bool,
) -> anyhow::Result<RpcServer<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    let server = match addr {
        Addr::Mem(channel, _) => {
            let channel = combined::ServerChannel::new(None, Some(channel));
            RpcServer::new(channel)
        }
        Addr::IrpcLookup(_addr) => {
            todo!()
            // Ok(Some(RpcServer::new(combined::Channel::new(Some(addr), None))))
        }
        Addr::Irpc(addr) => {
            let channel = quic_rpc::transport::http2::ServerChannel::serve(&addr)?;
            let channel = combined::ServerChannel::new(Some(channel), None);
            RpcServer::new(channel)
        }
    };

    // We know there is currently only one real listening address.
    let all_local_addrs: &[LocalAddr] = server.local_addr();
    let local_addr: Option<&LocalAddr> = all_local_addrs
        .iter()
        .find(|a| matches!(a, LocalAddr::Socket(_)))
        .or_else(|| all_local_addrs.get(0));
    if print_address {
        if let Some(local_addr) = local_addr {
            println!("IRPC_LISTENING_ADDR={local_addr}");
        }
    }
    for local_addr in all_local_addrs {
        info!("p2p rpc listening on: {local_addr}");
    }

    Ok(server)
}

pub async fn open_client<S: Service>(addr: Addr<S>) -> anyhow::Result<RpcClient<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(_, client) => Ok(RpcClient::<S, ChannelTypes>::new(
            combined::ClientChannel::new(None, Some(client)),
        )),
        Addr::Irpc(uri) => {
            let uri = format!("http://{uri}").parse()?;
            let channel = http2::ClientChannel::new(uri);
            let channel = combined::ClientChannel::new(Some(channel), None);
            Ok(RpcClient::<S, ChannelTypes>::new(channel))
        }
        Addr::IrpcLookup(_addr) => {
            todo!()
        }
    }
}
