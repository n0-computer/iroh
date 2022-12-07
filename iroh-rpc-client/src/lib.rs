pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;

pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::http2::Http2ChannelTypes,
    quic_rpc::quinn::QuinnChannelTypes,
>;

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

pub use self::config::Config;
use anyhow::Context;
pub use client::Client;
use futures::{stream::BoxStream, StreamExt};
use iroh_rpc_types::Addr;
pub use network::{Lookup, P2pClient};
use quic_rpc::{
    channel_factory::LazyChannelFactory, combined, http2::Http2ChannelTypes, mem::MemChannelTypes,
    quinn::QuinnChannelTypes, RpcClient, RpcServer, Service,
};
use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

pub async fn create_server_stream<S: Service>(
    server_config: ServerConfig,
    addr: Addr<S::Req, S::Res>,
) -> anyhow::Result<
    BoxStream<
        'static,
        Result<
            RpcServer<S, ChannelTypes>,
            quic_rpc::combined::CreateChannelError<MemChannelTypes, QuinnChannelTypes>,
        >,
    >,
> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(_addr) => {
            todo!()
            // Ok(Some(RpcServer::new(combined::Channel::new(Some(addr), None))))
        }
        Addr::Http2(addr) => {
            let addr: SocketAddr = addr.parse()?;
            let (channel, hyper) = quic_rpc::http2::Channel::server(&addr)?;
            tokio::spawn(hyper);
            let channel = combined::Channel::new(Some(channel), None);
            let server = RpcServer::new(channel);
            Ok(futures::stream::once(async move { Ok(server) }).boxed())
        }
        Addr::Qrpc(addr) => {
            println!("Opening server on {}", addr);
            let endpoint = make_server_endpoint(server_config, addr)?;
            Ok(async_stream::stream! {
                while let Some(connecting) = endpoint.accept().await {
                    let conn = connecting.await
                        .map_err(quic_rpc::quinn::CreateChannelError::Connection)
                        .map_err(quic_rpc::combined::CreateChannelError::B)?;
                    let channel = quic_rpc::quinn::Channel::new(conn);
                    yield Ok(RpcServer::new(combined::Channel::new(None, Some(channel))));
                }
            }
            .boxed())
        }
    }
}

async fn create_quinn_client_channel<S: Service>(
    bind_addr: SocketAddr,
    addr: SocketAddr,
) -> Result<quic_rpc::quinn::Channel<S::Res, S::Req>, quic_rpc::quinn::CreateChannelError> {
    let server_name = "localhost";
    println!("Creating insecure client endpoint for {}", bind_addr);
    let endpoint = make_insecure_client_endpoint(bind_addr)?;
    println!("Connecting to {}, server name {}", addr, server_name);
    let connecting = endpoint.connect(addr, server_name)?;
    println!("Awaiting connection");
    let conn = connecting.await?;
    println!("Channel created");
    let channel = quic_rpc::quinn::Channel::new(conn);
    Ok(channel)
}

async fn create_http2_client_channel<S: Service>(
    uri: hyper::Uri,
) -> Result<quic_rpc::http2::Channel<S::Res, S::Req>, hyper::Error> {
    let channel = quic_rpc::http2::Channel::client(uri);
    Ok(channel)
}

pub async fn open_client<S: Service>(
    addr: Addr<S::Res, S::Req>,
) -> anyhow::Result<RpcClient<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    match addr {
        Addr::Mem(addr) => {
            todo!()
            // let channel = combined::Channel::new(Some(addr), None);
            // anyhow::Ok(RpcClient::<S, ChannelTypes>::new(channel))
        }
        Addr::Qrpc(addr) => {
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            let f = move || async move {
                let channel: quic_rpc::quinn::Channel<S::Res, S::Req> =
                    create_quinn_client_channel::<S>(bind_addr, addr)
                        .await
                        .map_err(combined::CreateChannelError::B)?;
                let channel = combined::Channel::new(None, Some(channel));
                Ok(channel)
            };
            let factory = Arc::new(LazyChannelFactory::eager(f).await);
            Ok(RpcClient::<S, ChannelTypes>::from_factory(factory))
        }
        Addr::Http2(uri) => {
            let uri = format!("http://{}", uri).parse()?;
            let channel = create_http2_client_channel::<S>(uri).await?;
            let channel = combined::Channel::new(Some(channel), None);
            Ok(RpcClient::<S, ChannelTypes>::new(channel))
        }
    }
}

pub fn make_insecure_client_endpoint(bind_addr: SocketAddr) -> io::Result<Endpoint> {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let client_cfg = ClientConfig::new(Arc::new(crypto));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(9200)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let mut endpoint = Endpoint::new(
        endpoint_config,
        None,
        std::net::UdpSocket::bind(bind_addr)?,
        TokioRuntime,
    )?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

struct SkipServerVerification;
impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn make_server_endpoint(
    mut server_config: ServerConfig,
    bind_addr: SocketAddr,
) -> io::Result<Endpoint> {
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.initial_max_udp_payload_size(9200);
    server_config.transport_config(Arc::new(transport_config));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config
        .max_udp_payload_size(9200)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let endpoint = Endpoint::new(
        endpoint_config,
        Some(server_config),
        std::net::UdpSocket::bind(bind_addr)?,
        TokioRuntime,
    )?;
    Ok(endpoint)
}

pub fn configure_server() -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}
