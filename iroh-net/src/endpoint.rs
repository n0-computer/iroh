use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
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

#[derive(Clone, Debug)]
pub struct MagicEndpoint {
    keypair: Arc<Keypair>,
    conn: Conn,
    endpoint: quinn::Endpoint,
    netmap: Arc<Mutex<netmap::NetworkMap>>,
    keylog: bool,
}

impl MagicEndpoint {
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
    pub async fn bind(
        keypair: Keypair,
        bind_addr: SocketAddr,
        alpn_protocols: Vec<Vec<u8>>,
        transport_config: Option<quinn::TransportConfig>,
        derp_map: Option<DerpMap>,
        keylog: bool,
    ) -> anyhow::Result<Self> {
        let tls_server_config = tls::make_server_config(&keypair, alpn_protocols, keylog)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
        server_config.transport_config(Arc::new(transport_config.unwrap_or_default()));
        Self::bind_with_server_config(keypair, bind_addr, server_config, derp_map, keylog).await
    }

    pub async fn bind_with_server_config(
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
}

/// Fully accept an incoming connection and extract the client-provided [`PeerId`] and ALPN protocol.
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
