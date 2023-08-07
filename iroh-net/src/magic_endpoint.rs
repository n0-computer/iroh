//! An endpoint that leverages a [quinn::Endpoint] backed by a [magicsock::MagicSock].

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{anyhow, Context};
use quinn_proto::VarInt;
use tracing::{debug, trace};

use crate::{
    config,
    derp::DerpMap,
    key,
    magicsock::{self, Callbacks, MagicSock},
    netmap::NetworkMap,
    tls::{self, Keypair, PeerId},
};

/// Builder for [MagicEndpoint]
#[derive(Debug, Default)]
pub struct MagicEndpointBuilder {
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    concurrent_connections: Option<u32>,
    keylog: bool,
    callbacks: Callbacks,
}

impl MagicEndpointBuilder {
    /// Set a keypair to authenticate with other peers.
    ///
    /// This keypair's public key will be the [PeerId] of this endpoint.
    ///
    /// If not set, a new keypair will be generated.
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Set the ALPN protocols that this endpoint will accept on incoming connections.
    pub fn alpns(mut self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        self.alpn_protocols = alpn_protocols;
        self
    }

    /// If *keylog* is `true` and the KEYLOGFILE environment variable is present it will be
    /// considered a filename to which the TLS pre-master keys are logged.  This can be useful
    /// to be able to decrypt captured traffic for debugging purposes.
    pub fn keylog(mut self, keylog: bool) -> Self {
        self.keylog = keylog;
        self
    }

    /// Specify the DERP servers that are used by this endpoint.
    ///
    /// DERP servers are used to discover other peers by [`PeerId`] and also
    /// help establish connections between peers by being an initial relay
    /// for traffic while assisting in holepunching to establish a direct
    /// connection between the peers.
    pub fn derp_map(mut self, derp_map: Option<DerpMap>) -> Self {
        self.derp_map = derp_map;
        self
    }

    /// Set a custom [quinn::TransportConfig] for this endpoint.
    ///
    /// The transport config contains parameters governing the QUIC state machine.
    ///
    /// If unset, the default config is used. Default values should be suitable for most internet
    /// applications. Applications protocols which forbid remotely-initiated streams should set
    /// `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` to zero.
    pub fn transport_config(mut self, transport_config: quinn::TransportConfig) -> Self {
        self.transport_config = Some(transport_config);
        self
    }

    /// Maximum number of simultaneous connections to accept.
    ///
    /// New incoming connections are only accepted if the total number of incoming or outgoing
    /// connections is less than this. Outgoing connections are unaffected.
    pub fn concurrent_connections(mut self, concurrent_connections: u32) -> Self {
        self.concurrent_connections = Some(concurrent_connections);
        self
    }

    /// Optionally set a callback function to be called when endpoints change.
    #[allow(clippy::type_complexity)]
    pub fn on_endpoints(
        mut self,
        on_endpoints: Box<dyn Fn(&[config::Endpoint]) + Send + Sync + 'static>,
    ) -> Self {
        self.callbacks.on_endpoints = Some(on_endpoints);
        self
    }

    /// Optionally set a callback funcion to be called when a connection is made to a DERP server.
    pub fn on_derp_active(mut self, on_derp_active: Box<dyn Fn() + Send + Sync + 'static>) -> Self {
        self.callbacks.on_derp_active = Some(on_derp_active);
        self
    }

    /// Optionally set a callback function that provides a [config::NetInfo] when discovered network conditions change.
    pub fn on_net_info(
        mut self,
        on_net_info: Box<dyn Fn(config::NetInfo) + Send + Sync + 'static>,
    ) -> Self {
        self.callbacks.on_net_info = Some(on_net_info);
        self
    }

    /// Bind the magic endpoint on the specified socket address.
    ///
    /// The *bind_port* is the port that should be bound locally.
    /// The port will be used to bind an IPv4 and, if supported, and IPv6 socket.
    /// You can pass `0` to let the operating system choose a free port for you.
    /// NOTE: This will be improved soon to add support for binding on specific addresses.
    pub async fn bind(self, bind_port: u16) -> anyhow::Result<MagicEndpoint> {
        let keypair = self.keypair.unwrap_or_else(Keypair::generate);
        let mut server_config = make_server_config(
            &keypair,
            self.alpn_protocols,
            self.transport_config,
            self.keylog,
        )?;
        if let Some(c) = self.concurrent_connections {
            server_config.concurrent_connections(c);
        }
        MagicEndpoint::bind(
            keypair,
            bind_port,
            Some(server_config),
            self.derp_map,
            Some(self.callbacks),
            self.keylog,
        )
        .await
    }
}

fn make_server_config(
    keypair: &Keypair,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    keylog: bool,
) -> anyhow::Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(keypair, alpn_protocols, keylog)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    server_config.transport_config(Arc::new(transport_config.unwrap_or_default()));
    Ok(server_config)
}

/// An endpoint that leverages a [quinn::Endpoint] backed by a [magicsock::MagicSock].
#[derive(Clone, Debug)]
pub struct MagicEndpoint {
    keypair: Arc<Keypair>,
    msock: MagicSock,
    endpoint: quinn::Endpoint,
    netmap: Arc<Mutex<NetworkMap>>,
    keylog: bool,
}

impl MagicEndpoint {
    /// Build a MagicEndpoint
    pub fn builder() -> MagicEndpointBuilder {
        MagicEndpointBuilder::default()
    }

    /// Create a quinn endpoint backed by a magicsock.
    ///
    /// This is for internal use, the public interface is the [MagicEndpointBuilder] obtained from
    /// [Self::builder]. See the methods on the builder for documentation of the parameters.
    async fn bind(
        keypair: Keypair,
        bind_port: u16,
        server_config: Option<quinn::ServerConfig>,
        derp_map: Option<DerpMap>,
        callbacks: Option<Callbacks>,
        keylog: bool,
    ) -> anyhow::Result<Self> {
        let msock = magicsock::MagicSock::new(magicsock::Options {
            port: bind_port,
            derp_map: Some(derp_map.unwrap_or_default()),
            private_key: keypair.secret().clone().into(),
            callbacks: callbacks.unwrap_or_default(),
        })
        .await?;
        trace!("created magicsock");

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server_config,
            msock.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        trace!("created quinn endpoint");

        Ok(Self {
            keypair: Arc::new(keypair),
            msock,
            endpoint,
            netmap: Arc::new(Mutex::new(NetworkMap { peers: vec![] })),
            keylog,
        })
    }

    /// Accept an incoming connection on the socket.
    pub fn accept(&self) -> quinn::Accept<'_> {
        self.endpoint.accept()
    }

    /// Get the peer id of this endpoint.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().into()
    }

    /// Get the keypair of this endpoint.
    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    /// Get the local endpoint addresses on which the underlying magic socket is bound.
    ///
    /// Returns a tuple of the IPv4 and the optional IPv6 address.
    pub fn local_addr(&self) -> anyhow::Result<(SocketAddr, Option<SocketAddr>)> {
        self.msock.local_addr()
    }

    /// Get the local and discovered endpoint addresses on which the underlying
    /// magic socket is reachable.
    ///
    /// This list contains both the locally-bound addresses and the endpoint's
    /// publicly-reachable addresses, if they could be discovered through
    /// STUN or port mapping.
    pub async fn local_endpoints(&self) -> anyhow::Result<Vec<config::Endpoint>> {
        self.msock.local_endpoints().await
    }

    /// Get the DERP region we are connected to with the lowest latency.
    ///
    /// Returns `None` if we are not connected to any DERP region.
    pub async fn my_derp(&self) -> Option<u16> {
        self.msock.my_derp().await
    }

    /// Connect to a remote endpoint.
    ///
    /// The PeerId and the ALPN protocol are required. If you happen to know dialable addresses of
    /// the remote endpoint, they can be specified and will be used to try and establish a direct
    /// connection without involving a DERP server. If no addresses are specified, the endpoint
    /// will try to dial the peer through the configured DERP servers.
    ///
    /// If the `derp_region` is not `None` and the configured DERP servers do not include a DERP node from the given `derp_region`, it will error.
    ///
    /// If no UDP addresses and no DERP region is provided, it will error.
    pub async fn connect(
        &self,
        peer_id: PeerId,
        alpn: &[u8],
        derp_region: Option<u16>,
        known_addrs: &[SocketAddr],
    ) -> anyhow::Result<quinn::Connection> {
        if derp_region.is_some() || !known_addrs.is_empty() {
            self.add_known_addrs(peer_id, derp_region, known_addrs)
                .await?;
        }

        let node_key: key::node::PublicKey = peer_id.into();
        let addr = self
            .msock
            .get_mapping_addr(&node_key)
            .await
            .ok_or_else(|| {
                anyhow!("failed to retrieve the mapped address from the magic socket")
            })?;

        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let tls_client_config =
                tls::make_client_config(&self.keypair, Some(peer_id), alpn_protocols, self.keylog)?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

        debug!(
            "connecting to {}: (via {} - {:?})",
            peer_id, addr, known_addrs
        );

        // TODO: We'd eventually want to replace "localhost" with something that makes more sense.
        let connect = self
            .endpoint
            .connect_with(client_config, addr, "localhost")?;

        connect.await.context("failed connecting to provider")
    }

    /// Inform the magic socket about addresses of the peer.
    ///
    /// This updates the magic socket's *netmap* with these addresses, which are used as candidates
    /// when connecting to this peer (in addition to addresses obtained from a derp server).
    ///
    /// If no UDP addresses are added, and `derp_region` is `None`, it will error.
    /// If no UDP addresses are added, and the given `derp_region` cannot be dialed, it will error.
    pub async fn add_known_addrs(
        &self,
        peer_id: PeerId,
        derp_region: Option<u16>,
        endpoints: &[SocketAddr],
    ) -> anyhow::Result<()> {
        match (endpoints.is_empty(), derp_region) {
            (true, None) => {
                anyhow::bail!(
                    "No UDP addresses or DERP region provided. Unable to dial peer {peer_id:?}"
                );
            }
            (true, Some(region)) if !self.msock.has_derp_region(region).await => {
                anyhow::bail!("No UDP addresses provided and we do not have any DERP configuration for DERP region {region}, any hole punching required to establish a connection will not be possible.");
            }
            (false, None) => {
                tracing::warn!("No DERP region provided, any hole punching required to establish a connection will not be possible.");
            }
            (false, Some(region)) if !self.msock.has_derp_region(region).await => {
                tracing::warn!("We do not have any DERP configuration for DERP region {region}, any hole punching required to establish a connection will not be possible.");
            }
            _ => {}
        }

        let node_key: key::node::PublicKey = peer_id.into();
        let netmap = {
            let mut netmap = self.netmap.lock().unwrap();
            let node = netmap.peers.iter_mut().find(|peer| peer.key == node_key);
            if let Some(node) = node {
                for endpoint in endpoints {
                    if !node.endpoints.contains(endpoint) {
                        node.endpoints.push(*endpoint);
                        node.addresses.push(endpoint.ip());
                    }
                }
            } else {
                let endpoints = endpoints.to_vec();
                let addresses = endpoints.iter().map(|ep| ep.ip()).collect();
                let node = config::Node {
                    name: None,
                    addresses,
                    endpoints,
                    key: node_key.clone(),
                    derp: derp_region,
                };
                netmap.peers.push(node)
            }
            netmap.clone()
        };
        self.msock.set_network_map(netmap).await?;
        Ok(())
    }

    /// Close the QUIC endpoint and the magic socket.
    ///
    /// This will close all open QUIC connections with the provided error_code and reason. See
    /// [quinn::Connection] for details on how these are interpreted.
    ///
    /// It will then wait for all connections to actually be shutdown, and afterwards
    /// close the magic socket.
    ///
    /// Returns an error if closing the magic socket failed.
    /// TODO: Document error cases.
    pub async fn close(&self, error_code: VarInt, reason: &[u8]) -> anyhow::Result<()> {
        self.endpoint.close(error_code, reason);
        self.endpoint.wait_idle().await;
        // TODO: Now wait-idle on msock!
        self.msock.close().await?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn magic_sock(&self) -> &MagicSock {
        &self.msock
    }
    #[cfg(test)]
    pub(crate) fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }
}

/// Accept an incoming connection and extract the client-provided [`PeerId`] and ALPN protocol.
pub async fn accept_conn(
    mut conn: quinn::Connecting,
) -> anyhow::Result<(PeerId, String, quinn::Connection)> {
    let alpn = get_alpn(&mut conn).await?;
    let conn = conn.await?;
    let peer_id = get_peer_id(&conn).await?;
    Ok((peer_id, alpn, conn))
}

/// Extract the ALPN protocol from the peer's TLS certificate.
pub async fn get_alpn(connecting: &mut quinn::Connecting) -> anyhow::Result<String> {
    let data = connecting.handshake_data().await?;
    match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
        Ok(data) => match data.protocol {
            Some(protocol) => std::string::String::from_utf8(protocol).map_err(Into::into),
            None => anyhow::bail!("no ALPN protocol available"),
        },
        Err(_) => anyhow::bail!("unknown handshake type"),
    }
}

/// Extract the [`PeerId`] from the peer's TLS certificate.
pub async fn get_peer_id(connection: &quinn::Connection) -> anyhow::Result<PeerId> {
    let data = connection.peer_identity();
    match data {
        None => anyhow::bail!("no peer certificate found"),
        Some(data) => match data.downcast::<Vec<rustls::Certificate>>() {
            Ok(certs) => {
                if certs.len() != 1 {
                    anyhow::bail!(
                        "expected a single peer certificate, but {} found",
                        certs.len()
                    );
                }
                let cert = tls::certificate::parse(&certs[0])?;
                Ok(cert.peer_id())
            }
            Err(_) => anyhow::bail!("invalid peer certificate"),
        },
    }
}

// TODO: These tests could still be flaky, lets fix that:
// https://github.com/n0-computer/iroh/issues/1183
#[cfg(test)]
mod tests {
    use tracing::{info, info_span, Instrument};

    use crate::test_utils::{run_derp_and_stun, setup_logging};

    use super::*;

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[ignore]
    #[tokio::test]
    async fn magic_endpoint_connect_close() {
        let _guard = setup_logging();
        let (derp_map, region_id, _guard) = run_derp_and_stun([127, 0, 0, 1].into()).await.unwrap();
        let server_keypair = Keypair::generate();
        let server_peer_id = PeerId::from(server_keypair.public());

        let server = {
            let derp_map = derp_map.clone();
            tokio::spawn(
                async move {
                    let ep = MagicEndpoint::builder()
                        .keypair(server_keypair)
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .derp_map(Some(derp_map))
                        .bind(0)
                        .await
                        .unwrap();
                    info!("accepting connection");
                    let conn = ep.accept().await.unwrap();
                    let (_peer_id, _alpn, conn) = accept_conn(conn).await.unwrap();
                    let mut stream = conn.accept_uni().await.unwrap();
                    let mut buf = [0u8, 5];
                    stream.read_exact(&mut buf).await.unwrap();
                    info!("Accepted 1 stream, received {buf:?}.  Closing now.");
                    ep.close(7u8.into(), b"bye").await.unwrap();

                    let res = conn.accept_uni().await;
                    assert_eq!(res.unwrap_err(), quinn::ConnectionError::LocallyClosed);

                    let res = stream.read_to_end(10).await;
                    assert_eq!(
                        res.unwrap_err(),
                        quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(
                            quinn::ConnectionError::LocallyClosed
                        ))
                    );
                    info!("server test completed");
                }
                .instrument(info_span!("test-server")),
            )
        };

        let client = tokio::spawn(
            async move {
                let ep = MagicEndpoint::builder()
                    .alpns(vec![TEST_ALPN.to_vec()])
                    .derp_map(Some(derp_map))
                    .bind(0)
                    .await
                    .unwrap();
                info!("client connecting");
                let conn = ep
                    .connect(server_peer_id, TEST_ALPN, region_id, &[])
                    .await
                    .unwrap();
                let mut stream = conn.open_uni().await.unwrap();

                // First write is accepted by server.  We need this bit of synchronisation
                // because if the server closes after simply accepting the connection we can
                // not be sure our .open_uni() call would succeed as it may already receive
                // the error.
                stream.write_all(b"hello").await.unwrap();

                // Remote now closes the connection, we should see an error sometime soon.
                let err = conn.closed().await;
                let expected_err =
                    quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                        error_code: 7u8.into(),
                        reason: b"bye".to_vec().into(),
                    });
                assert_eq!(err, expected_err);

                let res = stream.finish().await;
                assert_eq!(
                    res.unwrap_err(),
                    quinn::WriteError::ConnectionLost(expected_err.clone())
                );

                let res = conn.open_uni().await;
                assert_eq!(res.unwrap_err(), expected_err);
                info!("client test completed");
            }
            .instrument(info_span!("test-client")),
        );

        let (server, client) = tokio::join!(server, client);
        server.unwrap();
        client.unwrap();
    }

    // #[tokio::test]
    // async fn magic_endpoint_bidi_send_recv() {
    //     setup_logging();
    //     let (ep1, ep2, cleanup) = setup_pair().await.unwrap();

    //     let peer_id_1 = ep1.peer_id();
    //     eprintln!("peer id 1 {peer_id_1}");
    //     let peer_id_2 = ep2.peer_id();
    //     eprintln!("peer id 2 {peer_id_2}");

    //     let endpoint = ep2.clone();
    //     let p2_connect = tokio::spawn(async move {
    //         let conn = endpoint.connect(peer_id_1, TEST_ALPN, &[]).await.unwrap();
    //         let (mut send, mut recv) = conn.open_bi().await.unwrap();
    //         send.write_all(b"hello").await.unwrap();
    //         send.finish().await.unwrap();
    //         let m = recv.read_to_end(100).await.unwrap();
    //         assert_eq!(&m, b"world");
    //     });

    //     let endpoint = ep1.clone();
    //     let p1_accept = tokio::spawn(async move {
    //         let conn = endpoint.accept().await.unwrap();
    //         let (peer_id, alpn, conn) = accept_conn(conn).await.unwrap();
    //         assert_eq!(peer_id, peer_id_2);
    //         assert_eq!(alpn.as_bytes(), TEST_ALPN);

    //         let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    //         let m = recv.read_to_end(100).await.unwrap();
    //         assert_eq!(m, b"hello");

    //         send.write_all(b"world").await.unwrap();
    //         send.finish().await.unwrap();
    //     });

    //     let endpoint = ep1.clone();
    //     let p1_connect = tokio::spawn(async move {
    //         let conn = endpoint.connect(peer_id_2, TEST_ALPN, &[]).await.unwrap();
    //         let (mut send, mut recv) = conn.open_bi().await.unwrap();
    //         send.write_all(b"ola").await.unwrap();
    //         send.finish().await.unwrap();
    //         let m = recv.read_to_end(100).await.unwrap();
    //         assert_eq!(&m, b"mundo");
    //     });

    //     let endpoint = ep2.clone();
    //     let p2_accept = tokio::spawn(async move {
    //         let conn = endpoint.accept().await.unwrap();
    //         let (peer_id, alpn, conn) = accept_conn(conn).await.unwrap();
    //         assert_eq!(peer_id, peer_id_1);
    //         assert_eq!(alpn.as_bytes(), TEST_ALPN);

    //         let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    //         let m = recv.read_to_end(100).await.unwrap();
    //         assert_eq!(m, b"ola");

    //         send.write_all(b"mundo").await.unwrap();
    //         send.finish().await.unwrap();
    //     });

    //     p1_accept.await.unwrap();
    //     p2_connect.await.unwrap();

    //     p2_accept.await.unwrap();
    //     p1_connect.await.unwrap();

    //     cleanup().await;
    // }
}
