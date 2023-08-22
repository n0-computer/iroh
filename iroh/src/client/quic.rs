//! Type declarations and utility functions for an RPC client to an iroh node running in a seperate process.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use quic_rpc::transport::quinn::QuinnConnection;

use crate::rpc_protocol::{ProviderRequest, ProviderResponse, ProviderService, VersionRequest};

/// TODO: Change to "/iroh-rpc/1"
pub const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";

/// RPC client to an iroh node running in a seperate process.
pub type RpcClient =
    quic_rpc::RpcClient<ProviderService, QuinnConnection<ProviderResponse, ProviderRequest>>;

/// Client to an iroh node running in a seperate process.
///
/// This is obtained from [`connect`].
pub type Iroh = super::Iroh<QuinnConnection<ProviderResponse, ProviderRequest>>;

/// RPC document client to an iroh node running in a seperate process.
pub type Doc = super::Doc<QuinnConnection<ProviderResponse, ProviderRequest>>;

/// Connect to an iroh node running on the same computer, but in a different process.
pub async fn connect(rpc_port: u16) -> anyhow::Result<Iroh> {
    let client = connect_raw(rpc_port).await?;
    Ok(Iroh::new(client))
}

/// Create a raw RPC client to an iroh node running on the same computer, but in a different
/// process.
pub async fn connect_raw(rpc_port: u16) -> anyhow::Result<RpcClient> {
    use anyhow::Context;
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let endpoint = create_quinn_client(bind_addr, vec![RPC_ALPN.to_vec()], false)?;
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), rpc_port);
    let server_name = "localhost".to_string();
    let connection = QuinnConnection::new(endpoint, addr, server_name);
    let client = RpcClient::new(connection);
    // Do a version request to check if the server is running.
    let _version = tokio::time::timeout(Duration::from_secs(1), client.rpc(VersionRequest))
        .await
        .context("iroh server is not running")??;
    Ok(client)
}
fn create_quinn_client(
    bind_addr: SocketAddr,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> anyhow::Result<quinn::Endpoint> {
    let secret_key = iroh_net::key::SecretKey::generate();
    let tls_client_config =
        iroh_net::tls::make_client_config(&secret_key, None, alpn_protocols, keylog)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
