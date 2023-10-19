//! An endpoint that leverages a [quinn::Endpoint] backed by a [magicsock::MagicSock].

use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use quinn_proto::VarInt;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};

use crate::{
    config,
    defaults::default_derp_map,
    derp::{DerpMap, DerpMode},
    key::{PublicKey, SecretKey},
    magicsock::{self, Callbacks, MagicSock},
    tls,
};

pub use super::magicsock::EndpointInfo as ConnectionInfo;

/// A peer and it's addressing information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddr {
    /// The node's public key.
    pub peer_id: PublicKey,
    /// Addressing information to connect to [`Self::peer_id`].
    pub info: AddrInfo,
}

impl PeerAddr {
    /// Create a new [`PeerAddr`] with empty [`AddrInfo`].
    pub fn new(peer_id: PublicKey) -> Self {
        PeerAddr {
            peer_id,
            info: Default::default(),
        }
    }

    /// Add a derp region to the peer's [`AddrInfo`].
    pub fn with_derp_region(mut self, derp_region: u16) -> Self {
        self.info.derp_region = Some(derp_region);
        self
    }

    /// Add the given direct addresses to the peer's [`AddrInfo`].
    pub fn with_direct_addresses(
        mut self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        self.info.direct_addresses = addresses.into_iter().collect();
        self
    }

    /// Get the direct addresses of this peer.
    pub fn direct_addresses(&self) -> impl Iterator<Item = &SocketAddr> {
        self.info.direct_addresses.iter()
    }

    /// Get the derp region of this peer.
    pub fn derp_region(&self) -> Option<u16> {
        self.info.derp_region
    }
}

impl From<(PublicKey, Option<u16>, &[SocketAddr])> for PeerAddr {
    fn from(value: (PublicKey, Option<u16>, &[SocketAddr])) -> Self {
        let (peer_id, derp_region, direct_addresses_iter) = value;
        PeerAddr {
            peer_id,
            info: AddrInfo {
                derp_region,
                direct_addresses: direct_addresses_iter.iter().copied().collect(),
            },
        }
    }
}

/// Addressing information to connect to a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AddrInfo {
    /// The peer's home DERP region.
    pub derp_region: Option<u16>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl AddrInfo {
    /// Return whether this addressing information is empty.
    pub fn is_empty(&self) -> bool {
        self.derp_region.is_none() && self.direct_addresses.is_empty()
    }
}

impl PeerAddr {
    /// Create a new [`PeerAddr`] from its parts.
    pub fn from_parts(
        peer_id: PublicKey,
        derp_region: Option<u16>,
        direct_addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            peer_id,
            info: AddrInfo {
                derp_region,
                direct_addresses: direct_addresses.into_iter().collect(),
            },
        }
    }
}

/// Builder for [MagicEndpoint]
#[derive(Debug)]
pub struct MagicEndpointBuilder {
    secret_key: Option<SecretKey>,
    derp_mode: DerpMode,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    concurrent_connections: Option<u32>,
    keylog: bool,
    callbacks: Callbacks,
    /// Path for known peers. See [`MagicEndpointBuilder::peers_data_path`].
    peers_path: Option<PathBuf>,
}

impl Default for MagicEndpointBuilder {
    fn default() -> Self {
        Self {
            secret_key: Default::default(),
            derp_mode: DerpMode::Default,
            alpn_protocols: Default::default(),
            transport_config: Default::default(),
            concurrent_connections: Default::default(),
            keylog: Default::default(),
            callbacks: Default::default(),
            peers_path: None,
        }
    }
}

impl MagicEndpointBuilder {
    /// Set a secret key to authenticate with other peers.
    ///
    /// This secret key's public key will be the [PublicKey] of this endpoint.
    ///
    /// If not set, a new secret key will be generated.
    pub fn secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
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

    /// Sets the DERP servers to assist in establishing connectivity.
    ///
    /// DERP servers are used to discover other peers by [`PublicKey`] and also help
    /// establish connections between peers by being an initial relay for traffic while
    /// assisting in holepunching to establish a direct connection between peers.
    ///
    /// When using [DerpMode::Custom], the provided `derp_map` must contain at least one
    /// region with a configured derp node.  If an invalid [`DerpMap`] is provided [`bind`]
    /// will result in an error.
    ///
    /// [`bind`]: MagicEndpointBuilder::bind
    pub fn derp_mode(mut self, derp_mode: DerpMode) -> Self {
        self.derp_mode = derp_mode;
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

    /// Optionally set the path where peer info should be stored.
    ///
    /// If the file exists, it will be used to populate an initial set of peers. Peers will be
    /// saved periodically and on shutdown to this path.
    pub fn peers_data_path(mut self, path: PathBuf) -> Self {
        self.peers_path = Some(path);
        self
    }

    /// Bind the magic endpoint on the specified socket address.
    ///
    /// The *bind_port* is the port that should be bound locally.
    /// The port will be used to bind an IPv4 and, if supported, and IPv6 socket.
    /// You can pass `0` to let the operating system choose a free port for you.
    /// NOTE: This will be improved soon to add support for binding on specific addresses.
    pub async fn bind(self, bind_port: u16) -> Result<MagicEndpoint> {
        let derp_map = match self.derp_mode {
            DerpMode::Disabled => DerpMap::empty(),
            DerpMode::Default => default_derp_map(),
            DerpMode::Custom(derp_map) => {
                ensure!(!derp_map.is_empty(), "Empty custom Derp server map",);
                derp_map
            }
        };
        let secret_key = self.secret_key.unwrap_or_else(SecretKey::generate);
        let mut server_config = make_server_config(
            &secret_key,
            self.alpn_protocols,
            self.transport_config,
            self.keylog,
        )?;
        if let Some(c) = self.concurrent_connections {
            server_config.concurrent_connections(c);
        }
        let msock_opts = magicsock::Options {
            port: bind_port,
            secret_key,
            derp_map,
            callbacks: self.callbacks,
            peers_path: self.peers_path,
        };
        MagicEndpoint::bind(Some(server_config), msock_opts, self.keylog).await
    }
}

fn make_server_config(
    secret_key: &SecretKey,
    alpn_protocols: Vec<Vec<u8>>,
    transport_config: Option<quinn::TransportConfig>,
    keylog: bool,
) -> Result<quinn::ServerConfig> {
    let tls_server_config = tls::make_server_config(secret_key, alpn_protocols, keylog)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(tls_server_config));
    server_config.transport_config(Arc::new(transport_config.unwrap_or_default()));
    Ok(server_config)
}

/// An endpoint that leverages a [quinn::Endpoint] backed by a [magicsock::MagicSock].
#[derive(Clone, Debug)]
pub struct MagicEndpoint {
    secret_key: Arc<SecretKey>,
    msock: MagicSock,
    endpoint: quinn::Endpoint,
    keylog: bool,
}

impl MagicEndpoint {
    /// Build a MagicEndpoint
    pub fn builder() -> MagicEndpointBuilder {
        MagicEndpointBuilder::default()
    }

    /// Create a quinn endpoint backed by a magicsock.
    ///
    /// This is for internal use, the public interface is the [`MagicEndpointBuilder`] obtained from
    /// [Self::builder]. See the methods on the builder for documentation of the parameters.
    async fn bind(
        server_config: Option<quinn::ServerConfig>,
        msock_opts: magicsock::Options,
        keylog: bool,
    ) -> Result<Self> {
        let secret_key = msock_opts.secret_key.clone();
        let msock = magicsock::MagicSock::new(msock_opts).await?;
        trace!("created magicsock");

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server_config,
            msock.clone(),
            Arc::new(quinn::TokioRuntime),
        )?;
        trace!("created quinn endpoint");

        Ok(Self {
            secret_key: Arc::new(secret_key),
            msock,
            endpoint,
            keylog,
        })
    }

    /// Accept an incoming connection on the socket.
    pub fn accept(&self) -> quinn::Accept<'_> {
        self.endpoint.accept()
    }

    /// Get the peer id of this endpoint.
    pub fn peer_id(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Get the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Get the local endpoint addresses on which the underlying magic socket is bound.
    ///
    /// Returns a tuple of the IPv4 and the optional IPv6 address.
    pub fn local_addr(&self) -> Result<(SocketAddr, Option<SocketAddr>)> {
        self.msock.local_addr()
    }

    /// Get the local and discovered endpoint addresses on which the underlying
    /// magic socket is reachable.
    ///
    /// This list contains both the locally-bound addresses and the endpoint's
    /// publicly-reachable addresses, if they could be discovered through
    /// STUN or port mapping.
    pub async fn local_endpoints(&self) -> Result<Vec<config::Endpoint>> {
        self.msock.local_endpoints().await
    }

    /// Get the DERP region we are connected to with the lowest latency.
    ///
    /// Returns `None` if we are not connected to any DERP region.
    pub async fn my_derp(&self) -> Option<u16> {
        self.msock.my_derp().await
    }

    /// Get the [`PeerAddr`] for this endpoint.
    pub async fn my_addr(&self) -> Result<PeerAddr> {
        let addrs = self.local_endpoints().await?;
        let derp = self.my_derp().await;
        let addrs = addrs.into_iter().map(|x| x.addr).collect();
        Ok(PeerAddr::from_parts(self.peer_id(), derp, addrs))
    }

    /// Get the [`PeerAddr`] for this endpoint, while providing the endpoints.
    pub async fn my_addr_with_endpoints(&self, eps: Vec<config::Endpoint>) -> Result<PeerAddr> {
        let derp = self.my_derp().await;
        let addrs = eps.into_iter().map(|x| x.addr).collect();
        Ok(PeerAddr::from_parts(self.peer_id(), derp, addrs))
    }

    /// Get information on all the nodes we have connection information about.
    ///
    /// Includes the node's [`PublicKey`], potential DERP region, its addresses with any known
    /// latency, and its [`crate::magicsock::ConnectionType`], which let's us know if we are
    /// currently communicating with that node over a `Direct` (UDP) or `Relay` (DERP) connection.
    ///
    /// Connections are currently only pruned on user action (when we explicitly add a new address
    /// to the internal addressbook through [`MagicEndpoint::add_peer_addr`]), so these connections
    /// are not necessarily active connections.
    pub async fn connection_infos(&self) -> anyhow::Result<Vec<ConnectionInfo>> {
        self.msock.tracked_endpoints().await
    }

    /// Get connection information about a specific node.
    ///
    /// Includes the node's [`PublicKey`], potential DERP region, its addresses with any known
    /// latency, and its [`crate::magicsock::ConnectionType`], which let's us know if we are
    /// currently communicating with that node over a `Direct` (UDP) or `Relay` (DERP) connection.
    pub async fn connection_info(
        &self,
        node_id: PublicKey,
    ) -> anyhow::Result<Option<ConnectionInfo>> {
        self.msock.tracked_endpoint(node_id).await
    }

    /// Connect to a remote endpoint.
    ///
    /// The PublicKey and the ALPN protocol are required. If you happen to know dialable addresses of
    /// the remote endpoint, they can be specified and will be used to try and establish a direct
    /// connection without involving a DERP server. If no addresses are specified, the endpoint
    /// will try to dial the peer through the configured DERP servers.
    ///
    /// If the `derp_region` is not `None` and the configured DERP servers do not include a DERP node from the given `derp_region`, it will error.
    ///
    /// If no UDP addresses and no DERP region is provided, it will error.
    pub async fn connect(&self, peer_addr: PeerAddr, alpn: &[u8]) -> Result<quinn::Connection> {
        self.add_peer_addr(peer_addr.clone()).await?;

        let PeerAddr { peer_id, info } = peer_addr;
        let addr = self.msock.get_mapping_addr(&peer_id).await;
        let Some(addr) = addr else {
            return Err(match (info.direct_addresses.is_empty(), info.derp_region) {
                (true, None) => {
                    anyhow!("No UDP addresses or DERP region provided. Unable to dial peer {peer_id:?}")
                }
                (true, Some(region)) if !self.msock.has_derp_region(region).await => {
                    anyhow!("No UDP addresses provided and we do not have any DERP configuration for DERP region {region}. Unable to dial peer {peer_id:?}")
                }
                _ => anyhow!("Failed to retrieve the mapped address from the magic socket. Unable to dial peer {peer_id:?}")
            });
        };

        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let tls_client_config = tls::make_client_config(
                &self.secret_key,
                Some(peer_id),
                alpn_protocols,
                self.keylog,
            )?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

        debug!(
            "connecting to {}: (via {} - {:?})",
            peer_id, addr, info.direct_addresses
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
    /// Note: updating the magic socket's *netmap* will also prune any connections that are *not*
    /// present in the netmap.
    ///
    /// If no UDP addresses are added, and `derp_region` is `None`, it will error.
    /// If no UDP addresses are added, and the given `derp_region` cannot be dialed, it will error.
    pub async fn add_peer_addr(&self, peer_addr: PeerAddr) -> Result<()> {
        self.msock.add_peer_addr(peer_addr).await?;
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
    pub async fn close(&self, error_code: VarInt, reason: &[u8]) -> Result<()> {
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

/// Accept an incoming connection and extract the client-provided [`PublicKey`] and ALPN protocol.
pub async fn accept_conn(
    mut conn: quinn::Connecting,
) -> Result<(PublicKey, String, quinn::Connection)> {
    let alpn = get_alpn(&mut conn).await?;
    let conn = conn.await?;
    let peer_id = get_peer_id(&conn).await?;
    Ok((peer_id, alpn, conn))
}

/// Extract the ALPN protocol from the peer's TLS certificate.
pub async fn get_alpn(connecting: &mut quinn::Connecting) -> Result<String> {
    let data = connecting.handshake_data().await?;
    match data.downcast::<quinn::crypto::rustls::HandshakeData>() {
        Ok(data) => match data.protocol {
            Some(protocol) => std::string::String::from_utf8(protocol).map_err(Into::into),
            None => anyhow::bail!("no ALPN protocol available"),
        },
        Err(_) => anyhow::bail!("unknown handshake type"),
    }
}

/// Extract the [`PublicKey`] from the peer's TLS certificate.
pub async fn get_peer_id(connection: &quinn::Connection) -> Result<PublicKey> {
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

    use crate::test_utils::run_derper;

    use super::*;

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[ignore]
    #[tokio::test]
    async fn magic_endpoint_connect_close() {
        let _guard = iroh_test::logging::setup();
        let (derp_map, region_id, _guard) = run_derper().await.unwrap();
        let server_secret_key = SecretKey::generate();
        let server_peer_id = server_secret_key.public();

        let server = {
            let derp_map = derp_map.clone();
            tokio::spawn(
                async move {
                    let ep = MagicEndpoint::builder()
                        .secret_key(server_secret_key)
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .derp_mode(DerpMode::Custom(derp_map))
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
                    .derp_mode(DerpMode::Custom(derp_map))
                    .bind(0)
                    .await
                    .unwrap();
                info!("client connecting");
                let peer_addr = PeerAddr::new(server_peer_id).with_derp_region(region_id);
                let conn = ep.connect(peer_addr, TEST_ALPN).await.unwrap();
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

    /// Test that peers saved on shutdown are correctly loaded
    #[tokio::test]
    async fn save_load_peers() {
        let _guard = iroh_test::logging::setup();
        let secret_key = SecretKey::generate();
        let tempdir = tempfile::tempdir().unwrap();
        let path: PathBuf = tempdir.path().into();
        let path = path.join("peers");

        /// Create an endpoint for the test.
        async fn new_endpoint(secret_key: SecretKey, peers_path: PathBuf) -> MagicEndpoint {
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.max_idle_timeout(Some(Duration::from_secs(10).try_into().unwrap()));

            MagicEndpoint::builder()
                .secret_key(secret_key.clone())
                .transport_config(transport_config)
                .peers_data_path(peers_path)
                .alpns(vec![TEST_ALPN.to_vec()])
                .bind(0)
                .await
                .unwrap()
        }

        // create the peer that will be added to the peer map
        let peer_id = SecretKey::generate().public();
        let direct_addr: SocketAddr =
            (std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 8758u16).into();
        let peer_addr = PeerAddr::new(peer_id).with_direct_addresses([direct_addr]);

        // first time, create a magic endpoint without peers but a peers file and add adressing
        // information for a peer
        let endpoint = new_endpoint(secret_key.clone(), path.clone()).await;
        assert!(endpoint.connection_infos().await.unwrap().is_empty());
        endpoint.add_peer_addr(peer_addr).await.unwrap();

        // close the endpoint and restart it
        endpoint.close(0u32.into(), b"done").await.unwrap();

        // now restart it and check the addressing info of the peer
        let endpoint = new_endpoint(secret_key, path).await;
        let ConnectionInfo { mut addrs, .. } =
            endpoint.connection_info(peer_id).await.unwrap().unwrap();
        let conn_addr = addrs.pop().unwrap().0;
        assert_eq!(conn_addr, direct_addr);
        drop(tempdir);
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
