use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use quinn_proto::VarInt;
use tracing::{debug, trace};

use crate::{
    hp::{
        self,
        cfg::{self, DERP_MAGIC_IP},
        derp::DerpMap,
        magicsock::Conn,
        netmap,
    },
    tls::{self, Keypair, PeerId},
};

/// How long we wait at most for some endpoints to be discovered.
const ENDPOINT_WAIT: Duration = Duration::from_secs(5);

/// Builder for [MagicEndpoint]
#[derive(Debug, Default)]
pub struct MagicEndpointBuilder {
    keypair: Option<Keypair>,
    derp_map: Option<DerpMap>,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    keylog: bool,
}

impl MagicEndpointBuilder {
    /// Set a keypair to authenticate with other peers.
    ///
    /// This keypair's public key will be the [PeerId] of this endpoint.
    ///
    /// If not set, a new keypair will be generated.
    pub fn keypair(self, keypair: Keypair) -> Self {
        Self {
            keypair: Some(keypair),
            ..self
        }
    }

    /// Set the ALPN protocols that this endpoint will accept on incoming connections.
    pub fn alpns(self, alpn_protocols: Vec<Vec<u8>>) -> Self {
        Self {
            alpn_protocols,
            ..self
        }
    }

    /// If *keylog* is `true` and the KEYLOGFILE environment variable is present it will be
    /// considered a filename to which the TLS pre-master keys are logged.  This can be useful
    /// to be able to decrypt captured traffic for debugging purposes.
    pub fn keylog(self, keylog: bool) -> Self {
        Self { keylog, ..self }
    }

    /// Specify the DERP servers that are used by this endpoint.
    pub fn derp_map(self, derp_map: DerpMap) -> Self {
        Self {
            derp_map: Some(derp_map),
            ..self
        }
    }

    /// Set a custom [quinn::TransportConfig] for this endpoint.
    pub fn transport_config(self, transport_config: quinn::TransportConfig) -> Self {
        Self {
            transport_config: Some(transport_config),
            ..self
        }
    }

    /// Bind the magic endpoint on the specified socket address.
    pub async fn bind(self, bind_addr: SocketAddr) -> anyhow::Result<MagicEndpoint> {
        let keypair = self.keypair.unwrap_or_else(Keypair::generate);
        let tls_server_config =
            tls::make_server_config(&keypair, self.alpn_protocols, self.keylog)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
        server_config.transport_config(Arc::new(self.transport_config.unwrap_or_default()));
        MagicEndpoint::bind(
            keypair,
            bind_addr,
            server_config,
            self.derp_map,
            self.keylog,
        )
        .await
    }
}

#[derive(Clone, Debug)]
pub struct MagicEndpoint {
    keypair: Arc<Keypair>,
    conn: Conn,
    endpoint: quinn::Endpoint,
    netmap: Arc<Mutex<netmap::NetworkMap>>,
    keylog: bool,
}

impl MagicEndpoint {
    /// Build a MagicEndpoint
    pub fn builder() -> MagicEndpointBuilder {
        MagicEndpointBuilder::default()
    }

    /// Create a quinn endpoint backed by a magicsock.
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
    pub(crate) async fn bind(
        keypair: Keypair,
        bind_addr: SocketAddr,
        server_config: quinn::ServerConfig,
        derp_map: Option<DerpMap>,
        keylog: bool,
    ) -> anyhow::Result<Self> {
        let (endpoints_update_s, endpoints_update_r) = flume::bounded(1);
        let conn = hp::magicsock::Conn::new(hp::magicsock::Options {
            port: bind_addr.port(),
            private_key: keypair.secret().clone().into(),
            on_endpoints: Some(Box::new(move |eps| {
                if !endpoints_update_s.is_disconnected() && !eps.is_empty() {
                    endpoints_update_s.send(()).ok();
                }
            })),
            ..Default::default()
        })
        .await?;
        trace!("created magicsock");

        let derp_map = derp_map.unwrap_or_default();
        conn.set_derp_map(Some(derp_map))
            .await
            .context("setting derp map")?;

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            conn.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        trace!("created quinn endpoint");

        // Wait for a single endpoint update, to make sure
        // we found some endpoints
        tokio::time::timeout(ENDPOINT_WAIT, async move {
            endpoints_update_r.recv_async().await
        })
        .await
        .context("waiting for endpoint")??;

        Ok(Self {
            keypair: Arc::new(keypair),
            conn,
            endpoint,
            netmap: Arc::new(Mutex::new(netmap::NetworkMap { peers: vec![] })),
            keylog,
        })
    }

    /// Accept a connection on the socket.
    pub fn accept(&self) -> quinn::Accept<'_> {
        self.endpoint.accept()
    }

    /// Get the peer id of this endpoint.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().into()
    }

    /// Get the local addresses on which the underlying magic socket is bound.
    ///
    /// Returns a tuple of the IPv4 and the optional IPv6 address.
    pub fn local_addr(&self) -> anyhow::Result<(SocketAddr, Option<SocketAddr>)> {
        self.conn.local_addr()
    }

    /// Connect to a remote endpoint.
    ///
    /// The PeerId and the ALPN protocol are required. If you happen to know dialable addresses of
    /// the remote endpoint, they can be specified and will be added to the endpoint's peer map.
    /// If no addresses are specified, the endpoint will try to dial the peer through the
    /// configured DERP servers.
    pub async fn connect(
        &self,
        peer_id: PeerId,
        alpn: &[u8],
        known_addrs: &[SocketAddr],
    ) -> anyhow::Result<quinn::Connection> {
        self.add_known_addrs(peer_id, known_addrs).await?;

        let node_key: hp::key::node::PublicKey = peer_id.into();
        let addr = self
            .conn
            .get_mapping_addr(&node_key)
            .await
            .expect("just inserted");

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
        let connect = self
            .endpoint
            .connect_with(client_config, addr, "localhost")?;

        let connection = connect.await.context("failed connecting to provider")?;

        Ok(connection)
    }

    /// Inform the magic socket about addresses of the peer.
    ///
    /// The magic socket will try to connect to these addresses, and if successfull,
    /// prefer them over talking to the peer over the DERP relay.
    pub async fn add_known_addrs(
        &self,
        peer_id: PeerId,
        addrs: &[SocketAddr],
    ) -> anyhow::Result<()> {
        let node_key: hp::key::node::PublicKey = peer_id.into();
        const DEFAULT_DERP_REGION: u16 = 1;

        let peer = {
            let mut addresses = Vec::new();
            let mut endpoints = Vec::new();

            // Add the provided address as a starting point.
            for addr in addrs {
                addresses.push(addr.ip());
                endpoints.push(*addr);
            }
            cfg::Node {
                name: None,
                addresses,
                key: node_key.clone(),
                endpoints,
                derp: Some(SocketAddr::new(DERP_MAGIC_IP, DEFAULT_DERP_REGION)),
                created: Instant::now(),
                hostinfo: hp::hostinfo::Hostinfo::default(),
                keep_alive: false,
                expired: false,
                online: None,
                last_seen: None,
            }
        };

        let netmap = {
            let mut netmap = self.netmap.lock().unwrap();
            netmap.peers.push(peer);
            netmap.clone()
        };
        self.conn.set_network_map(netmap).await?;
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
        self.conn.close().await?;
        Ok(())
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

#[cfg(test)]
mod test {
    use std::net::SocketAddr;

    use futures::future::BoxFuture;

    use crate::{
        endpoint::{accept_conn, MagicEndpoint},
        hp::magicsock::conn_tests::{run_derp_and_stun, setup_logging},
    };

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    async fn setup_pair() -> anyhow::Result<(
        MagicEndpoint,
        MagicEndpoint,
        impl FnOnce() -> BoxFuture<'static, ()>,
    )> {
        let (derp_map, cleanup) = run_derp_and_stun([127, 0, 0, 1].into()).await?;

        let ep1 = MagicEndpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .derp_map(derp_map.clone())
            .bind(SocketAddr::new([127, 0, 0, 1].into(), 0))
            .await?;

        let ep2 = MagicEndpoint::builder()
            .alpns(vec![TEST_ALPN.to_vec()])
            .derp_map(derp_map.clone())
            .bind(SocketAddr::new([127, 0, 0, 1].into(), 0))
            .await?;

        Ok((ep1, ep2, cleanup))
    }

    #[tokio::test]
    async fn magic_endpoint_connect_close() {
        setup_logging();
        let (ep1, ep2, cleanup) = setup_pair().await.unwrap();
        let peer_id_1 = ep1.peer_id();

        let accept = tokio::spawn(async move {
            let conn = ep1.accept().await.unwrap();
            let (_peer_id, _alpn, conn) = accept_conn(conn).await.unwrap();
            let mut stream = conn.accept_uni().await.unwrap();
            ep1.close(23u8.into(), b"badbadnotgood").await.unwrap();
            let res = conn.accept_uni().await;
            assert_eq!(res.unwrap_err(), quinn::ConnectionError::LocallyClosed);

            let res = stream.read_to_end(10).await;
            assert_eq!(
                res.unwrap_err(),
                quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(
                    quinn::ConnectionError::LocallyClosed
                ))
            );
        });

        let conn = ep2.connect(peer_id_1, TEST_ALPN, &[]).await.unwrap();
        // open a first stream - this does not error before we accept one stream before closing
        // on the other peer
        let mut stream = conn.open_uni().await.unwrap();
        // now the other peer closed the connection.
        stream.write_all(b"hi").await.unwrap();
        // now the other peer closed the connection.
        let expected_err = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: 23u8.into(),
            reason: b"badbadnotgood".to_vec().into(),
        });
        let err = conn.closed().await;
        assert_eq!(err, expected_err);

        let res = stream.finish().await;
        assert_eq!(
            res.unwrap_err(),
            quinn::WriteError::ConnectionLost(expected_err.clone())
        );

        let res = conn.open_uni().await;
        assert_eq!(res.unwrap_err(), expected_err);

        accept.await.unwrap();
        cleanup().await;
    }

    #[tokio::test]
    async fn magic_endpoint_bidi_send_recv() {
        setup_logging();
        let (ep1, ep2, cleanup) = setup_pair().await.unwrap();

        let peer_id_1 = ep1.peer_id();
        eprintln!("peer id 1 {peer_id_1}");
        let peer_id_2 = ep2.peer_id();
        eprintln!("peer id 2 {peer_id_2}");

        let endpoint = ep2.clone();
        let p2_connect = tokio::spawn(async move {
            let conn = endpoint.connect(peer_id_1, TEST_ALPN, &[]).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"hello").await.unwrap();
            send.finish().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(&m, b"world");
        });

        let endpoint = ep1.clone();
        let p1_accept = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap();
            let (peer_id, alpn, conn) = accept_conn(conn).await.unwrap();
            assert_eq!(peer_id, peer_id_2);
            assert_eq!(alpn.as_bytes(), TEST_ALPN);

            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"hello");

            send.write_all(b"world").await.unwrap();
            send.finish().await.unwrap();
        });

        let endpoint = ep1.clone();
        let p1_connect = tokio::spawn(async move {
            let conn = endpoint.connect(peer_id_2, TEST_ALPN, &[]).await.unwrap();
            let (mut send, mut recv) = conn.open_bi().await.unwrap();
            send.write_all(b"ola").await.unwrap();
            send.finish().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(&m, b"mundo");
        });

        let endpoint = ep2.clone();
        let p2_accept = tokio::spawn(async move {
            let conn = endpoint.accept().await.unwrap();
            let (peer_id, alpn, conn) = accept_conn(conn).await.unwrap();
            assert_eq!(peer_id, peer_id_1);
            assert_eq!(alpn.as_bytes(), TEST_ALPN);

            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let m = recv.read_to_end(100).await.unwrap();
            assert_eq!(m, b"ola");

            send.write_all(b"mundo").await.unwrap();
            send.finish().await.unwrap();
        });

        p1_accept.await.unwrap();
        p2_connect.await.unwrap();

        p2_accept.await.unwrap();
        p1_connect.await.unwrap();

        cleanup().await;
    }
}
