//! An endpoint that leverages a [quinn::Endpoint] backed by a [magicsock::MagicSock].

use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{anyhow, ensure, Context, Result};
use derive_more::Debug;
use quinn_proto::VarInt;
use serde::{Deserialize, Serialize};
use tracing::{debug, trace};
use url::Url;

use crate::{
    config,
    defaults::default_derp_map,
    derp::{DerpMap, DerpMode},
    key::{PublicKey, SecretKey},
    magicsock::{self, Discovery, MagicSock},
    tls,
};

pub use super::magicsock::EndpointInfo as ConnectionInfo;

/// A peer and it's addressing information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeAddr {
    /// The node's public key.
    pub node_id: PublicKey,
    /// Addressing information to connect to [`Self::node_id`].
    pub info: AddrInfo,
}

impl NodeAddr {
    /// Create a new [`NodeAddr`] with empty [`AddrInfo`].
    pub fn new(node_id: PublicKey) -> Self {
        NodeAddr {
            node_id,
            info: Default::default(),
        }
    }

    /// Add a derp url to the peer's [`AddrInfo`].
    pub fn with_derp_url(mut self, derp_url: Url) -> Self {
        self.info.derp_url = Some(derp_url);
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

    /// Get the derp url of this peer.
    pub fn derp_url(&self) -> Option<&Url> {
        self.info.derp_url.as_ref()
    }
}

impl From<(PublicKey, Option<Url>, &[SocketAddr])> for NodeAddr {
    fn from(value: (PublicKey, Option<Url>, &[SocketAddr])) -> Self {
        let (node_id, derp_url, direct_addresses_iter) = value;
        NodeAddr {
            node_id,
            info: AddrInfo {
                derp_url,
                direct_addresses: direct_addresses_iter.iter().copied().collect(),
            },
        }
    }
}

/// Addressing information to connect to a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AddrInfo {
    /// The peer's home DERP url.
    pub derp_url: Option<Url>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl AddrInfo {
    /// Return whether this addressing information is empty.
    pub fn is_empty(&self) -> bool {
        self.derp_url.is_none() && self.direct_addresses.is_empty()
    }
}

impl NodeAddr {
    /// Create a new [`NodeAddr`] from its parts.
    pub fn from_parts(
        node_id: PublicKey,
        derp_url: Option<Url>,
        direct_addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            info: AddrInfo {
                derp_url,
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
    discovery: Option<Box<dyn Discovery>>,
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
            discovery: Default::default(),
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
    /// configured derp node.  If an invalid [`DerpMap`] is provided [`bind`]
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

    /// Optionally set the path where peer info should be stored.
    ///
    /// If the file exists, it will be used to populate an initial set of peers. Peers will be
    /// saved periodically and on shutdown to this path.
    pub fn peers_data_path(mut self, path: PathBuf) -> Self {
        self.peers_path = Some(path);
        self
    }

    /// Optionally set a discovery mechanism for this endpoint.
    pub fn discovery(mut self, discovery: Box<dyn Discovery>) -> Self {
        self.discovery = Some(discovery);
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
            nodes_path: self.peers_path,
            discovery: self.discovery,
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

        let mut endpoint_config = quinn::EndpointConfig::default();
        // Setting this to false means that quinn will ignore packets that have the QUIC fixed bit
        // set to 0. The fixed bit is the 3rd bit of the first byte of a packet.
        // For performance reasons and to not rewrite buffers we pass non-QUIC UDP packets straight
        // through to quinn. We set the first byte of the packet to zero, which makes quinn ignore
        // the packet if grease_quic_bit is set to false.
        endpoint_config.grease_quic_bit(false);

        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config,
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

    /// Get the node id of this endpoint.
    pub fn node_id(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Get the secret_key of this endpoint.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Optional reference to the discovery mechanism.
    pub fn discovery(&self) -> Option<&dyn Discovery> {
        self.msock.discovery()
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
    ///
    /// If called before there are any endpoints, waits for the first time there are some.
    pub async fn local_endpoints(&self) -> Result<Vec<config::Endpoint>> {
        self.msock.local_endpoints().await
    }

    /// Waits for local endpoints to change and returns the new ones.
    pub async fn local_endpoints_change(&self) -> Result<Vec<config::Endpoint>> {
        self.msock.local_endpoints_change().await
    }

    /// Get the DERP url we are connected to with the lowest latency.
    ///
    /// Returns `None` if we are not connected to any DERPer.
    pub fn my_derp(&self) -> Option<Url> {
        self.msock.my_derp()
    }

    /// Get the [`NodeAddr`] for this endpoint.
    pub async fn my_addr(&self) -> Result<NodeAddr> {
        let addrs = self.local_endpoints().await?;
        let derp = self.my_derp();
        let addrs = addrs.into_iter().map(|x| x.addr).collect();
        Ok(NodeAddr::from_parts(self.node_id(), derp, addrs))
    }

    /// Get the [`NodeAddr`] for this endpoint, while providing the endpoints.
    pub fn my_addr_with_endpoints(&self, eps: Vec<config::Endpoint>) -> Result<NodeAddr> {
        let derp = self.my_derp();
        let addrs = eps.into_iter().map(|x| x.addr).collect();
        Ok(NodeAddr::from_parts(self.node_id(), derp, addrs))
    }

    /// Get information on all the nodes we have connection information about.
    ///
    /// Includes the node's [`PublicKey`], potential DERP Url, its addresses with any known
    /// latency, and its [`crate::magicsock::ConnectionType`], which let's us know if we are
    /// currently communicating with that node over a `Direct` (UDP) or `Relay` (DERP) connection.
    ///
    /// Connections are currently only pruned on user action (when we explicitly add a new address
    /// to the internal addressbook through [`MagicEndpoint::add_node_addr`]), so these connections
    /// are not necessarily active connections.
    pub async fn connection_infos(&self) -> anyhow::Result<Vec<ConnectionInfo>> {
        self.msock.tracked_endpoints().await
    }

    /// Get connection information about a specific node.
    ///
    /// Includes the node's [`PublicKey`], potential DERP Url, its addresses with any known
    /// latency, and its [`crate::magicsock::ConnectionType`], which let's us know if we are
    /// currently communicating with that node over a `Direct` (UDP) or `Relay` (DERP) connection.
    pub async fn connection_info(
        &self,
        node_id: PublicKey,
    ) -> anyhow::Result<Option<ConnectionInfo>> {
        self.msock.tracked_endpoint(node_id).await
    }

    async fn resolve(&self, node_id: &PublicKey) -> Result<AddrInfo> {
        if let Some(discovery) = self.msock.discovery() {
            debug!("no mapping address for {node_id}, resolving via {discovery:?}");
            discovery.resolve(node_id).await
        } else {
            anyhow::bail!("no discovery mechanism configured");
        }
    }

    /// Connect to a remote endpoint, using just the nodes's [`PublicKey`].
    pub async fn connect_by_node_id(
        &self,
        node_id: &PublicKey,
        alpn: &[u8],
    ) -> Result<quinn::Connection> {
        let addr = match self.msock.get_mapping_addr(node_id).await {
            Some(addr) => addr,
            None => {
                let info = self.resolve(node_id).await?;
                let peer_addr = NodeAddr {
                    node_id: *node_id,
                    info,
                };
                self.add_node_addr(peer_addr)?;
                self.msock.get_mapping_addr(node_id).await.ok_or_else(|| {
                    anyhow!("Failed to retrieve the mapped address from the magic socket. Unable to dial node {node_id:?}")
                })?
            }
        };

        debug!("connecting to {}: (via {})", node_id, addr);
        self.connect_inner(node_id, alpn, addr).await
    }

    /// Connect to a remote endpoint.
    ///
    /// The PublicKey and the ALPN protocol are required. If you happen to know dialable addresses of
    /// the remote endpoint, they can be specified and will be used to try and establish a direct
    /// connection without involving a DERP server. If no addresses are specified, the endpoint
    /// will try to dial the peer through the configured DERP servers.
    ///
    /// If the `derp_url` is not `None` and the configured DERP servers do not include a DERP node from the given `derp_url`, it will error.
    ///
    /// If no UDP addresses and no DERP Url is provided, it will error.
    pub async fn connect(&self, node_addr: NodeAddr, alpn: &[u8]) -> Result<quinn::Connection> {
        self.add_node_addr(node_addr.clone())?;

        let NodeAddr { node_id, info } = node_addr;
        let addr = self.msock.get_mapping_addr(&node_id).await;
        let Some(addr) = addr else {
            return Err(match (info.direct_addresses.is_empty(), info.derp_url) {
                (true, None) => {
                    anyhow!("No UDP addresses or DERP Url provided. Unable to dial node {node_id:?}")
                }
                _ => anyhow!("Failed to retrieve the mapped address from the magic socket. Unable to dial node {node_id:?}")
            });
        };

        debug!(
            "connecting to {}: (via {} - {:?})",
            node_id, addr, info.direct_addresses
        );

        self.connect_inner(&node_id, alpn, addr).await
    }

    async fn connect_inner(
        &self,
        node_id: &PublicKey,
        alpn: &[u8],
        addr: SocketAddr,
    ) -> Result<quinn::Connection> {
        let client_config = {
            let alpn_protocols = vec![alpn.to_vec()];
            let tls_client_config = tls::make_client_config(
                &self.secret_key,
                Some(*node_id),
                alpn_protocols,
                self.keylog,
            )?;
            let mut client_config = quinn::ClientConfig::new(Arc::new(tls_client_config));
            let mut transport_config = quinn::TransportConfig::default();
            transport_config.keep_alive_interval(Some(Duration::from_secs(1)));
            client_config.transport_config(Arc::new(transport_config));
            client_config
        };

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
    /// If no UDP addresses are added, and `derp_url` is `None`, it will error.
    /// If no UDP addresses are added, and the given `derp_url` cannot be dialed, it will error.
    pub fn add_node_addr(&self, node_addr: NodeAddr) -> Result<()> {
        self.msock.add_node_addr(node_addr);
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
        self.msock.close().await?;
        Ok(())
    }

    /// Call to notify the system of potential network changes.
    ///
    /// On many systems iroh is able to detect network changes by itself, however
    /// some systems like android do not expose this functionality to native code.
    /// Android does however provide this functionality to Java code.  This
    /// function allows for notifying iroh of any potential network changes like
    /// this.
    ///
    /// Even when the network did not change, or iroh was already able to detect
    /// the network change itself, there is no harm in calling this function.
    pub async fn network_change(&self) {
        self.msock.network_change().await;
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
    let peer_id = get_remote_node_id(&conn)?;
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
pub fn get_remote_node_id(connection: &quinn::Connection) -> Result<PublicKey> {
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

    use std::time::Instant;

    use rand_core::SeedableRng;
    use tracing::{error_span, info, info_span, Instrument};

    use crate::test_utils::run_derper;

    use super::*;

    const TEST_ALPN: &[u8] = b"n0/iroh/test";

    #[ignore]
    #[tokio::test]
    async fn magic_endpoint_connect_close() {
        let _guard = iroh_test::logging::setup();
        let (derp_map, derp_url, _guard) = run_derper().await.unwrap();
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
                let node_addr = NodeAddr::new(server_peer_id).with_derp_url(derp_url);
                let conn = ep.connect(node_addr, TEST_ALPN).await.unwrap();
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
        let root = testdir::testdir!();
        let path = root.join("peers");

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
        let node_addr = NodeAddr::new(peer_id).with_direct_addresses([direct_addr]);

        info!("setting up first endpoint");
        // first time, create a magic endpoint without peers but a peers file and add adressing
        // information for a peer
        let endpoint = new_endpoint(secret_key.clone(), path.clone()).await;
        assert!(endpoint.connection_infos().await.unwrap().is_empty());
        endpoint.add_node_addr(node_addr).unwrap();

        info!("closing endpoint");
        // close the endpoint and restart it
        endpoint.close(0u32.into(), b"done").await.unwrap();

        info!("restarting endpoint");
        // now restart it and check the addressing info of the peer
        let endpoint = new_endpoint(secret_key, path).await;
        let ConnectionInfo { mut addrs, .. } =
            endpoint.connection_info(peer_id).await.unwrap().unwrap();
        let conn_addr = addrs.pop().unwrap().addr;
        assert_eq!(conn_addr, direct_addr);
    }

    #[tokio::test]
    async fn magic_endpoint_derp_connect_loop() {
        let _guard = iroh_test::logging::setup();
        let n_iters = 5;
        let n_chunks_per_client = 2;
        let chunk_size = 10;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let (derp_map, derp_url, _guard) = run_derper().await.unwrap();
        let server_secret_key = SecretKey::generate_with_rng(&mut rng);
        let server_node_id = server_secret_key.public();
        let server = {
            let derp_map = derp_map.clone();
            tokio::spawn(
                async move {
                    let ep = MagicEndpoint::builder()
                        .secret_key(server_secret_key)
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .derp_mode(DerpMode::Custom(derp_map))
                        .bind(12345)
                        .await
                        .unwrap();
                    let eps = ep.local_addr().unwrap();
                    info!(me = %ep.node_id().fmt_short(), ipv4=%eps.0, ipv6=?eps.1, "server bound");
                    for i in 0..n_iters {
                        let now = Instant::now();
                        println!("[server] round {}", i + 1);
                        let conn = ep.accept().await.unwrap();
                        let (peer_id, _alpn, conn) = accept_conn(conn).await.unwrap();
                        info!(%i, peer = %peer_id.fmt_short(), "accepted connection");
                        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                        let mut buf = vec![0u8; chunk_size];
                        for _i in 0..n_chunks_per_client {
                            recv.read_exact(&mut buf).await.unwrap();
                            send.write_all(&buf).await.unwrap();
                        }
                        send.finish().await.unwrap();
                        recv.read_to_end(0).await.unwrap();
                        info!(%i, peer = %peer_id.fmt_short(), "finished");
                        println!("[server] round {} done in {:?}", i + 1, now.elapsed());
                    }
                }
                .instrument(error_span!("server")),
            )
        };

        let client_secret_key = SecretKey::generate_with_rng(&mut rng);
        let client = tokio::spawn(async move {
            for i in 0..n_iters {
                let now = Instant::now();
                println!("[client] round {}", i + 1);
                let derp_map = derp_map.clone();
                let client_secret_key = client_secret_key.clone();
                let derp_url = derp_url.clone();
                let fut = async move {
                    info!("client binding");
                    let start = Instant::now();
                    let ep = MagicEndpoint::builder()
                        .alpns(vec![TEST_ALPN.to_vec()])
                        .derp_mode(DerpMode::Custom(derp_map))
                        .secret_key(client_secret_key)
                        .bind(0)
                        .await
                        .unwrap();
                    let eps = ep.local_addr().unwrap();
                    info!(me = %ep.node_id().fmt_short(), ipv4=%eps.0, ipv6=?eps.1, t = ?start.elapsed(), "client bound");
                    let node_addr = NodeAddr::new(server_node_id).with_derp_url(derp_url);
                    info!(to = ?node_addr, "client connecting");
                    let t = Instant::now();
                    let conn = ep.connect(node_addr, TEST_ALPN).await.unwrap();
                    info!(t = ?t.elapsed(), "client connected");
                    let t = Instant::now();
                    let (mut send, mut recv) = conn.open_bi().await.unwrap();

                    for i in 0..n_chunks_per_client {
                        let mut buf = vec![i; chunk_size];
                        send.write_all(&buf).await.unwrap();
                        recv.read_exact(&mut buf).await.unwrap();
                        assert_eq!(buf, vec![i; chunk_size]);
                    }
                    send.finish().await.unwrap();
                    recv.read_to_end(0).await.unwrap();
                    info!(t = ?t.elapsed(), "client finished");
                    ep.close(0u32.into(), &[]).await.unwrap();
                    info!(total = ?start.elapsed(), "client closed");
                }
                .instrument(error_span!("client", %i));
                tokio::task::spawn(fut).await.unwrap();
                println!("[client] round {} done in {:?}", i + 1, now.elapsed());
            }
        });

        client.await.unwrap();
        server.abort();
        let _ = server.await;
    }

    // #[tokio::test]
    // async fn magic_endpoint_bidi_send_recv() {
    //     setup_logging();
    //     let (ep1, ep2, cleanup) = setup_pair().await.unwrap();

    //     let peer_id_1 = ep1.node_id();
    //     eprintln!("node id 1 {peer_id_1}");
    //     let peer_id_2 = ep2.node_id();
    //     eprintln!("node id 2 {peer_id_2}");

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
