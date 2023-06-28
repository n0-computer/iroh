use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::{
    endpoint::MagicEndpoint,
    hp::derp::DerpMap,
    tls::{self, Keypair, PeerId},
};

/// Connect to a remote endpoint, creating an endpoint on the fly.
///
/// The PeerId and the ALPN protocol are required. If you happen to know dialable addresses of
/// the remote endpoint, they can be specified and will be added to the endpoint's peer map.
/// If no addresses are specified, the endpoint will try to dial the peer through the
/// configured DERP servers.
pub async fn dial_peer(
    known_addrs: &[SocketAddr],
    peer_id: PeerId,
    alpn_protocol: &[u8],
    keylog: bool,
    derp_map: Option<DerpMap>,
) -> Result<quinn::Connection> {
    let bind_addr = if known_addrs.iter().any(|addr| addr.ip().is_ipv6()) {
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into()
    } else {
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let endpoint =
        MagicEndpoint::bind(Keypair::generate(), bind_addr, None, derp_map, None, keylog).await?;
    endpoint
        .connect(peer_id, alpn_protocol, known_addrs)
        .await
        .context("failed to connect to provider")
}

pub fn create_quinn_client(
    bind_addr: SocketAddr,
    peer_id: Option<PeerId>,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
) -> Result<quinn::Endpoint> {
    let keypair = Keypair::generate();

    let tls_client_config = tls::make_client_config(&keypair, peer_id, alpn_protocols, keylog)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
    let mut endpoint = quinn::Endpoint::client(bind_addr)?;
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
