pub mod client;
pub mod config;
pub mod gateway;
pub mod network;
pub mod status;
pub mod store;

pub type ChannelTypes = quic_rpc::combined::CombinedChannelTypes<
    quic_rpc::mem::MemChannelTypes,
    quic_rpc::quinn::QuinnChannelTypes,
>;

use std::{io, net::SocketAddr, sync::Arc};

pub use self::config::Config;
pub use client::Client;
use iroh_rpc_types::Addr;
pub use network::{Lookup, P2pClient};
use quic_rpc::{combined, RpcClient, RpcServer, Service};
use quinn::{ClientConfig, Endpoint, ServerConfig};
pub use status::{ServiceStatus, StatusRow, StatusTable};
pub use store::StoreClient;

pub async fn open_server<S: Service>(
    addr: Addr<S::Req, S::Res>,
) -> anyhow::Result<RpcServer<S, ChannelTypes>> {
    // make a channel matching the channel types for this crate
    let channel = match addr {
        Addr::Mem(addr) => anyhow::Ok(combined::Channel::new(Some(addr), None)),
        Addr::Qrpc(addr) => {
            println!("Opening server on {}", addr);
            let (endpoint, _cert) = make_server_endpoint(addr)?;
            let conn = endpoint.accept().await.unwrap().await.unwrap();
            let channel = quic_rpc::quinn::Channel::new(conn);
            Ok(combined::Channel::new(None, Some(channel)))
        }
    }?;
    Ok(RpcServer::new(channel))
}

pub async fn open_client<S: Service>(
    addr: Addr<S::Res, S::Req>,
) -> anyhow::Result<RpcClient<S, ChannelTypes>> {
    println!("open_client: {} {:?}", std::any::type_name::<S>(), addr);
    // make a channel matching the channel types for this crate
    let channel = match addr {
        Addr::Mem(addr) => anyhow::Ok(combined::Channel::new(Some(addr), None)),
        Addr::Qrpc(addr) => {
            let endpoint = make_insecure_client_endpoint("0.0.0.0:0".parse()?)?;
            let conn = endpoint.connect(addr, "localhost")?.await?;
            let channel = quic_rpc::quinn::Channel::new(conn);
            Ok(combined::Channel::new(None, Some(channel)))
        }
    }?;
    Ok(RpcClient::new(channel))
}

pub fn make_insecure_client_endpoint(bind_addr: SocketAddr) -> io::Result<Endpoint> {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    let client_cfg = ClientConfig::new(Arc::new(crypto));
    let mut endpoint = Endpoint::client(bind_addr)?;
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

fn make_server_endpoint(bind_addr: SocketAddr) -> anyhow::Result<(Endpoint, Vec<u8>)> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

fn configure_server() -> anyhow::Result<(ServerConfig, Vec<u8>)> {
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
