use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tracing::debug;

use crate::{
    hp::{
        self,
        cfg::{self, DERP_MAGIC_IP},
        derp::DerpMap,
        netmap,
    },
    tls::{self, Keypair, PeerId},
};

/// Create a quinn client endpoint
///
/// The *bind_addr* is the address that should be bound locally.  Even though this is an
/// outgoing connection a socket must be bound and this is explicit.  The main choice to
/// make here is the address family: IPv4 or IPv6.  Otherwise you normally bind to the
/// `UNSPECIFIED` address on port `0` thus allowing the kernel to do the right thing.
///
/// If *peer_id* is present it will verify during the TLS connection setup that the remote
/// connected to has the required [`PeerId`], otherwise this will connect to any peer.
///
/// The *alpn_protocols* are the list of Application-Layer Protocol Neotiation identifiers
/// you are happy to accept.
///
/// If *keylog* is `true` and the KEYLOGFILE environment variable is present it will be
/// considered a filename to which the TLS pre-master keys are logged.  This can be useful
/// to be able to decrypt captured traffic for debugging purposes.
///
/// Finally the *derp_map* specifies the DERP servers that can be used to establish this
/// connection.
pub async fn create_endpoint(
    bind_addr: SocketAddr,
    peer_id: PeerId,
    alpn_protocols: Vec<Vec<u8>>,
    keylog: bool,
    derp_map: Option<DerpMap>,
) -> Result<(quinn::Endpoint, hp::magicsock::Conn)> {
    let keypair = Keypair::generate();

    let tls_client_config =
        tls::make_client_config(&keypair, Some(peer_id), alpn_protocols, keylog)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));

    let conn = hp::magicsock::Conn::new(hp::magicsock::Options {
        port: bind_addr.port(),
        private_key: keypair.secret().clone().into(),
        ..Default::default()
    })
    .await?;
    conn.set_derp_map(derp_map).await?;

    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        conn.clone(),
        Arc::new(quinn::TokioRuntime),
    )?;

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);
    Ok((endpoint, conn))
}

/// Establishes a QUIC connection to the provided peer.
pub async fn dial_peer(
    addrs: &[SocketAddr],
    peer_id: PeerId,
    alpn_protocol: &[u8],
    keylog: bool,
    derp_map: Option<DerpMap>,
) -> Result<quinn::Connection> {
    let bind_addr = if addrs.iter().any(|addr| addr.ip().is_ipv6()) {
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0).into()
    } else {
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into()
    };

    let (endpoint, magicsock) = create_endpoint(
        bind_addr,
        peer_id,
        vec![alpn_protocol.to_vec()],
        keylog,
        derp_map,
    )
    .await?;

    // Only a single peer in our network currently.
    let node_key: hp::key::node::PublicKey = peer_id.into();
    const DEFAULT_DERP_REGION: u16 = 1;

    let mut addresses = Vec::new();
    let mut endpoints = Vec::new();

    // Add the provided address as a starting point.
    for addr in addrs {
        addresses.push(addr.ip());
        endpoints.push(*addr);
    }
    magicsock
        .set_network_map(netmap::NetworkMap {
            peers: vec![cfg::Node {
                name: None,
                addresses,
                key: node_key.clone(),
                endpoints,
                derp: Some(SocketAddr::new(DERP_MAGIC_IP, DEFAULT_DERP_REGION)),
            }],
        })
        .await?;

    let addr = magicsock
        .get_mapping_addr(&node_key)
        .await
        .expect("just inserted");
    debug!("connecting to {}: (via {} - {:?})", peer_id, addr, addrs);
    let connect = endpoint.connect(addr, "localhost")?;
    let connection = connect.await.context("failed connecting to provider")?;

    Ok(connection)
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
