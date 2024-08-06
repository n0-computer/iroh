//! Type declarations and utility functions for an RPC client to an iroh node running in a separate process.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context};
use quic_rpc::transport::{boxed::Connection as BoxedConnection, quinn::QuinnConnection};

use super::{Iroh, RpcClient};
use crate::{
    node::RpcStatus,
    rpc_protocol::{node::StatusRequest, RpcService},
};

/// ALPN used by irohs RPC mechanism.
// TODO: Change to "/iroh-rpc/1"
pub(crate) const RPC_ALPN: [u8; 17] = *b"n0/provider-rpc/1";

impl Iroh {
    /// Connects to an iroh node running on the same computer, but in a different process.
    pub async fn connect_path(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let rpc_status = RpcStatus::load(root).await?;
        match rpc_status {
            RpcStatus::Stopped => {
                bail!("iroh is not running, please start it");
            }
            RpcStatus::Running { client, port: _ } => Ok(Iroh::new(client)),
        }
    }

    /// Connects to an iroh node at the given RPC address.
    pub async fn connect_addr(addr: SocketAddr) -> anyhow::Result<Self> {
        let client = connect_raw(addr).await?;
        Ok(Iroh::new(client))
    }
}

/// Create a raw RPC client to an iroh node running on the same computer, but in a different
/// process.
pub(crate) async fn connect_raw(addr: SocketAddr) -> anyhow::Result<RpcClient> {
    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
    let endpoint = create_quinn_client(bind_addr, vec![RPC_ALPN.to_vec()], false)?;

    let server_name = "localhost".to_string();
    let connection = QuinnConnection::<RpcService>::new(endpoint, addr, server_name);
    let connection = BoxedConnection::new(connection);
    let client = RpcClient::new(connection);
    // Do a status request to check if the server is running.
    let _version = tokio::time::timeout(Duration::from_secs(1), client.rpc(StatusRequest))
        .await
        .context("Iroh node is not running")??;
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
