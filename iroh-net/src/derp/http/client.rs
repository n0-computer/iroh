//! Based on tailscale/derp/derphttp/derphttp_client.go
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::StreamExt;
use hyper::upgrade::{Parts, Upgraded};
use hyper::{header::UPGRADE, Body, Request};
use iroh_metrics::inc;
use rand::Rng;
use rustls::client::Resumption;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, info_span, instrument, trace, warn, Instrument};
use url::Url;

use crate::derp::{
    client::Client as DerpClient, client::ClientBuilder as DerpClientBuilder, metrics::Metrics,
    server::PacketForwarderHandler, DerpNode, DerpRegion, MeshKey, PacketForwarder,
    ReceivedMessage, UseIpv4, UseIpv6,
};
use crate::dns::DNS_RESOLVER;
use crate::key::{PublicKey, SecretKey};

const DIAL_NODE_TIMEOUT: Duration = Duration::from_millis(1500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MESH_CLIENT_REDIAL_DELAY: Duration = Duration::from_secs(5);

/// Possible connection errors on the [`Client`]
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The client is closed
    #[error("client is closed")]
    Closed,
    /// There no underlying derp [`super::client::Client`] client exists for this http derp [`Client`]
    #[error("no derp client")]
    NoClient,
    /// There was an error sending a packet
    #[error("error sending a packet")]
    Send,
    /// There was an error receiving a packet
    #[error("error receiving a packet: {0:?}")]
    Receive(anyhow::Error),
    /// There was a connection timeout error
    #[error("connect timeout")]
    ConnectTimeout,
    /// No derp nodes are available for the given region
    #[error("DERP region is not available")]
    DerpRegionNotAvail,
    /// No derp nodes are availabe with that name
    #[error("no nodes available for {0}")]
    NoNodeForTarget(String),
    /// The derp node specified only allows STUN requests
    #[error("no derp nodes found for {0}, only are stun_only nodes")]
    StunOnlyNodesFound(String),
    /// There was an error dialing
    #[error("dial error")]
    DialIO(#[from] std::io::Error),
    /// There was an error from the task doing the dialing
    #[error("dial error")]
    DialTask(#[from] tokio::task::JoinError),
    /// Both IPv4 and IPv6 are disabled for this derp node
    #[error("both IPv4 and IPv6 are explicitly diabled for this node")]
    IPDisabled,
    /// No local addresses exist
    #[error("no local addr: {0}")]
    NoLocalAddr(String),
    /// There was http [`hyper::Error`]
    #[error("http connection error")]
    Hyper(#[from] hyper::Error),
    /// There was an unexpected status code
    #[error("unexpected status code: expected {0}, got {1}")]
    UnexpectedStatusCode(hyper::StatusCode, hyper::StatusCode),
    /// The connection failed to upgrade
    #[error("failed to upgrade connection: {0}")]
    Upgrade(String),
    /// The derp [`super::client::Client`] failed to build
    #[error("failed to build derp client: {0}")]
    Build(String),
    /// The ping request timed out
    #[error("ping timeout")]
    PingTimeout,
    /// The ping request was aborted
    #[error("ping aborted")]
    PingAborted,
    /// This [`Client`] cannot acknowledge pings
    #[error("cannot acknowledge pings")]
    CannotAckPings,
    /// The given [`Url`] is invalid
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// There was an error with DNS resolution
    #[error("dns: {0:?}")]
    Dns(Option<trust_dns_resolver::error::ResolveError>),
}

/// An HTTP DERP client.
///
/// Cheaply clonable.
#[derive(Clone)]
pub struct Client {
    inner: Arc<InnerClient>,
}

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for Client {}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Client {{}}")
    }
}

struct InnerClient {
    secret_key: SecretKey,
    get_region:
        Option<Box<dyn Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static>>,
    can_ack_pings: bool,
    is_preferred: Mutex<bool>,
    derp_client: Mutex<Option<DerpClient>>,
    is_closed: AtomicBool,
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    conn_gen: AtomicUsize,
    ping_tracker: Mutex<HashMap<[u8; 8], oneshot::Sender<()>>>,
    mesh_key: Option<MeshKey>,
    is_prober: bool,
    server_public_key: Option<PublicKey>,
    url: Option<Url>,
    tls_connector: tokio_rustls::TlsConnector,
}

/// Build a Client.
#[derive(Default)]
pub struct ClientBuilder {
    /// Default is false
    can_ack_pings: bool,
    /// Default is false
    is_preferred: bool,
    /// Default is None
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    /// Default is None
    mesh_key: Option<MeshKey>,
    /// Default is false
    is_prober: bool,
    /// Expected PublicKey of the server
    server_public_key: Option<PublicKey>,
    /// Server url.
    ///
    /// If the `url` field and `get_region` field are both `None`, the `ClientBuilder`
    /// will fail on `build`.
    url: Option<Url>,
    /// Add a call back function that returns the region you want this client
    /// to dial.
    ///
    /// If the `url` field and `get_region` field are both `None`, the `ClientBuilder`
    /// will fail on `build`.
    get_region:
        Option<Box<dyn Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static>>,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let address_family_selector_txt = match self.address_family_selector {
            Some(_) => "Some(Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>)",
            None => "None",
        };
        write!(f, "ClientBuilder {{ can_ack_pings: {}, is_preferred: {}, address_family_selector: {address_family_selector_txt} }}", self.can_ack_pings, self.is_preferred)
    }
}

impl ClientBuilder {
    /// Create a new [`ClientBuilder`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the server url
    pub fn server_url(mut self, url: impl Into<Url>) -> Self {
        self.url = Some(url.into());
        self
    }

    /// Add a call back function that returns the region you want this client
    /// to dial.
    pub fn get_region<F>(mut self, f: F) -> Self
    where
        F: Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static,
    {
        self.get_region = Some(Box::new(f));
        self
    }

    /// Returns if we should prefer ipv6
    /// it replaces the derphttp.AddressFamilySelector we pass
    /// It provides the hint as to whether in an IPv4-vs-IPv6 race that
    /// IPv4 should be held back a bit to give IPv6 a better-than-50/50
    /// chance of winning. We only return true when we believe IPv6 will
    /// work anyway, so we don't artificially delay the connection speed.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Box::new(selector));
        self
    }

    /// Enable this [`Client`] to acknowledge pings.
    pub fn can_ack_pings(mut self, can: bool) -> Self {
        self.can_ack_pings = can;
        self
    }

    /// Indicate this client is the preferred way to communicate
    /// to the peer with this client's [`PublicKey`]
    pub fn is_preferred(mut self, is: bool) -> Self {
        self.is_preferred = is;
        self
    }

    /// Indicates this client is a prober
    pub fn is_prober(mut self, is: bool) -> Self {
        self.is_prober = is;
        self
    }

    /// Build this [`Client`] with a [`MeshKey`], and allow it to mesh
    pub fn mesh_key(mut self, mesh_key: Option<MeshKey>) -> Self {
        self.mesh_key = mesh_key;
        self
    }

    /// Build the [`Client`]
    ///
    /// Will error if there is no region or no url set.
    pub fn build(self, key: SecretKey) -> anyhow::Result<Client> {
        anyhow::ensure!(self.get_region.is_some() || self.url.is_some(), "The `get_region` call back or `server_url` must be set so the Client knows how to dial the derp server.");

        // TODO: review TLS config
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let mut config = rustls::client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        #[cfg(test)]
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertVerifier));

        config.resumption = Resumption::default();

        let tls_connector: tokio_rustls::TlsConnector = Arc::new(config).into();

        Ok(Client {
            inner: Arc::new(InnerClient {
                secret_key: key,
                get_region: self.get_region,
                can_ack_pings: self.can_ack_pings,
                is_preferred: Mutex::new(self.is_preferred),
                derp_client: Mutex::new(None),
                is_closed: AtomicBool::new(false),
                address_family_selector: self.address_family_selector,
                conn_gen: AtomicUsize::new(0),
                ping_tracker: Mutex::new(HashMap::default()),
                mesh_key: self.mesh_key,
                is_prober: self.is_prober,
                server_public_key: self.server_public_key,
                url: self.url,
                tls_connector,
            }),
        })
    }

    /// The expected [`PublicKey`] of the [`super::server::Server`] we are connecting to.
    pub fn server_public_key(mut self, server_public_key: PublicKey) -> Self {
        self.server_public_key = Some(server_public_key);
        self
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum MeshClientEvent {
    Meshed,
    PeerPresent { peer: PublicKey },
    PeerGone { peer: PublicKey },
}

impl Client {
    /// The public key for this client
    pub fn public_key(&self) -> PublicKey {
        self.inner.secret_key.public()
    }

    /// Let the server know that this client is the preferred client
    pub async fn note_preferred(&self, is_preferred: bool) {
        {
            let mut old = self.inner.is_preferred.lock().await;
            if *old == is_preferred {
                return;
            }
            *old = is_preferred;
        }
        // only send the preference if we already have a connection
        let res = {
            let client = self.inner.derp_client.lock().await;
            if let Some(client) = &*client {
                client.note_preferred(is_preferred).await
            } else {
                return;
            }
        };
        // need to do this outside the above closure because they rely on the same lock
        // if there was an error sending, close the underlying derp connection
        if res.is_err() {
            self.close_for_reconnect().await;
        }
    }

    /// Get the local addr of the connection. If there is no current underlying derp connection
    /// or the [`Client`] is closed, returns `None`.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        if self.inner.is_closed.load(Ordering::SeqCst) {
            return None;
        }
        let client = self.inner.derp_client.lock().await;
        if let Some(client) = &*client {
            match client.local_addr().await {
                Ok(addr) => return Some(addr),
                _ => return None,
            }
        }
        None
    }

    /// Connect to a Derp Server and returns the underlying Derp Client.
    ///
    /// Returns [`ClientError::Closed`] if the [`Client`] is closed.
    ///
    /// If there is already an active derp connection, returns the already
    /// connected [`crate::derp::client::Client`].
    pub async fn connect(&self) -> Result<(DerpClient, usize), ClientError> {
        if self.inner.is_closed.load(Ordering::Relaxed) {
            return Err(ClientError::Closed);
        }
        let key = self.inner.secret_key.public();
        async move {
            // acquire lock on the derp client
            // we must hold onto the lock until we are sure we have a connection
            // or other calls to `connect` will attempt to start a connection
            // as well
            let mut derp_client_lock = self.inner.derp_client.lock().await;
            if let Some(derp_client) = &*derp_client_lock {
                trace!("already had connection");
                return Ok((derp_client.clone(), self.current_conn()));
            }

            trace!("no connection, trying to connect");
            let derp_client = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_0())
                .await
                .map_err(|_| ClientError::ConnectTimeout)??;

            let derp_client_clone = derp_client.clone();
            *derp_client_lock = Some(derp_client_clone);
            let conn_gen = self.next_conn();

            trace!("got connection, conn num {conn_gen}");
            Ok((derp_client, conn_gen))
        }
        .instrument(info_span!("client-connect", %key))
        .await
    }

    fn current_conn(&self) -> usize {
        self.inner.conn_gen.load(Ordering::SeqCst)
    }

    fn next_conn(&self) -> usize {
        self.inner.conn_gen.fetch_add(1, Ordering::SeqCst) + 1
    }

    async fn current_region(&self) -> Result<DerpRegion, ClientError> {
        if let Some(get_region) = &self.inner.get_region {
            let region = get_region()
                .await
                .ok_or_else(|| ClientError::DerpRegionNotAvail)?;

            return Ok(region);
        }
        Err(ClientError::DerpRegionNotAvail)
    }

    fn url(&self) -> Option<&Url> {
        self.inner.url.as_ref()
    }

    fn tls_servername(&self, node: Option<&DerpNode>) -> Option<rustls::ServerName> {
        if let Some(url) = self.url() {
            return url
                .host_str()
                .and_then(|s| rustls::ServerName::try_from(s).ok());
        }
        if let Some(node) = node {
            if let Some(host) = node.url.host_str() {
                return rustls::ServerName::try_from(host).ok();
            }
        }

        None
    }

    fn url_port(&self) -> Option<u16> {
        if let Some(port) = self.inner.url.as_ref().and_then(|url| url.port()) {
            return Some(port);
        }
        if let Some(ref url) = self.inner.url {
            match url.scheme() {
                "http" => return Some(80),
                "https" => return Some(443),
                _ => {}
            }
        }

        None
    }

    fn use_https(&self, node: Option<&DerpNode>) -> bool {
        // only disable https if we are explicitly dialing a http url
        if let Some(true) = self.inner.url.as_ref().map(|url| url.scheme() == "http") {
            return false;
        }
        if let Some(node) = node {
            if node.url.scheme() == "http" {
                return false;
            }
        }
        true
    }

    #[instrument(level = "debug", skip_all)]
    async fn connect_0(&self) -> Result<DerpClient, ClientError> {
        let url = self.url();
        let is_test_url = url
            .as_ref()
            .map(|url| url.as_str().ends_with(".invalid"))
            .unwrap_or_default();

        debug!("url: {:?}, is_test_url: {}", url, is_test_url);
        let (tcp_stream, derp_node) = if url.is_some() && !is_test_url {
            (self.dial_url().await?, None)
        } else {
            let region = self.current_region().await?;
            debug!("region: {:?}", region);
            let (tcp_stream, derp_node) = self.dial_region(region).await?;
            (tcp_stream, Some(derp_node))
        };

        let start = Instant::now();
        let local_addr = tcp_stream
            .local_addr()
            .map_err(|e| ClientError::NoLocalAddr(e.to_string()))?;

        let req = Request::builder()
            .uri("/derp")
            .header(UPGRADE, super::HTTP_UPGRADE_PROTOCOL)
            .body(Body::empty())
            .unwrap();

        let res = if self.use_https(derp_node.as_deref()) {
            debug!("Starting TLS handshake");

            let hostname = self
                .tls_servername(derp_node.as_deref())
                .ok_or_else(|| ClientError::InvalidUrl("no tls servername".into()))?;
            let tls_stream = self
                .inner
                .tls_connector
                .connect(hostname, tcp_stream)
                .await?;
            debug!("tls_connector connect success");
            let (mut request_sender, connection) = hyper::client::conn::Builder::new()
                .handshake(tls_stream)
                .await
                .map_err(ClientError::Hyper)?;
            tokio::spawn(
                async move {
                    // polling `connection` drives the HTTP exchange
                    // this will poll until we upgrade the connection, but not shutdown the underlying
                    // stream
                    debug!("waiting for connection");
                    if let Err(err) = connection.await {
                        warn!("client connection error: {:?}", err);
                    }
                    debug!("connection done");
                }
                .instrument(info_span!("http.conn")),
            );
            debug!("sending upgrade request");
            request_sender
                .send_request(req)
                .await
                .map_err(ClientError::Hyper)?
        } else {
            debug!("Starting handshake");
            let (mut request_sender, connection) = hyper::client::conn::Builder::new()
                .handshake(tcp_stream)
                .await
                .map_err(ClientError::Hyper)?;
            tokio::spawn(
                async move {
                    // polling `connection` drives the HTTP exchange
                    // this will poll until we upgrade the connection, but not shutdown the underlying
                    // stream
                    debug!("waiting for connection");
                    if let Err(err) = connection.await {
                        warn!("client connection error: {:?}", err);
                    }
                    debug!("connection done");
                }
                .instrument(info_span!("http.conn")),
            );
            debug!("sending upgrade request");
            request_sender
                .send_request(req)
                .await
                .map_err(ClientError::Hyper)?
        };

        if res.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            warn!("invalid status received: {:?}", res.status());
            return Err(ClientError::UnexpectedStatusCode(
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                res.status(),
            ));
        }

        trace!("tls handshake done: {:?}", start.elapsed());
        let start = Instant::now();

        debug!("starting upgrade");
        let upgraded = match hyper::upgrade::on(res).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                warn!("upgrade failed: {:?}", err);
                return Err(ClientError::Hyper(err));
            }
        };

        trace!("derp upgrade done: {:?}", start.elapsed());
        let start = Instant::now();

        debug!("connection upgraded");
        let (reader, writer) =
            downcast_upgrade(upgraded).map_err(|e| ClientError::Upgrade(e.to_string()))?;

        let derp_client =
            DerpClientBuilder::new(self.inner.secret_key.clone(), local_addr, reader, writer)
                .mesh_key(self.inner.mesh_key)
                .can_ack_pings(self.inner.can_ack_pings)
                .prober(self.inner.is_prober)
                .server_public_key(self.inner.server_public_key)
                .build()
                .await
                .map_err(|e| ClientError::Build(e.to_string()))?;

        trace!("derp handshake: {:?}", start.elapsed());
        let start = Instant::now();
        if *self.inner.is_preferred.lock().await && derp_client.note_preferred(true).await.is_err()
        {
            derp_client.close().await;
            return Err(ClientError::Send);
        }

        trace!("connect_0 done: {:?}", start.elapsed());
        Ok(derp_client)
    }

    /// String representation of the url or derp region we are trying to
    /// connect to.
    fn target_string(&self, reg: &DerpRegion) -> String {
        // TODO: if  self.Url, return the url string
        format!("region {} ({})", reg.region_id, reg.region_code)
    }

    async fn dial_url(&self) -> Result<TcpStream, ClientError> {
        let host = self.url().and_then(|url| url.host()).ok_or_else(|| {
            ClientError::InvalidUrl(format!("missing host from {:?}", self.url()))
        })?;

        debug!("dial url: {}", host);
        let dst_ip = match host {
            url::Host::Domain(hostname) => {
                // Need to do a DNS lookup
                let addr = DNS_RESOLVER
                    .lookup_ip(hostname)
                    .await
                    .map_err(|e| ClientError::Dns(Some(e)))?
                    .iter()
                    .next();
                addr.ok_or_else(|| ClientError::Dns(None))?
            }
            url::Host::Ipv4(ip) => IpAddr::V4(ip),
            url::Host::Ipv6(ip) => IpAddr::V6(ip),
        };

        let port = self
            .url_port()
            .ok_or_else(|| ClientError::InvalidUrl("missing url port".into()))?;
        let addr = SocketAddr::new(dst_ip, port);

        debug!("connecting to {}", addr);
        let tcp_stream = TcpStream::connect(addr).await?;
        Ok(tcp_stream)
    }

    /// Creates the uri string from a [`DerpNode`]
    ///
    /// Return a TCP stream to the provided region, trying each node in order
    /// (using [`Client::dial_node`]) until one connects
    async fn dial_region(
        &self,
        reg: DerpRegion,
    ) -> Result<(TcpStream, Arc<DerpNode>), ClientError> {
        debug!("dial region: {:?}", reg);
        let start = Instant::now();
        let target = self.target_string(&reg);
        if reg.nodes.is_empty() {
            return Err(ClientError::NoNodeForTarget(target));
        }
        // usually 1 IPv4, 1 IPv6 and 2x http
        const DIAL_PARALLELISM: usize = 4;

        let this = self.clone();
        let mut dials = futures::stream::iter(reg.nodes.clone().into_iter())
            .map(|node| {
                let this = this.clone();
                let target = target.clone();
                async move {
                    if node.stun_only {
                        return Err(ClientError::StunOnlyNodesFound(target));
                    }
                    let conn = this.dial_node(&node).await;
                    match conn {
                        Ok(conn) => Ok((conn, node)),
                        Err(e) => Err(e),
                    }
                }
            })
            .buffer_unordered(DIAL_PARALLELISM);

        let mut first_err = None;
        while let Some(res) = dials.next().await {
            match res {
                Ok((conn, node)) => {
                    // return on the first successfull one
                    trace!("dialed region in {:?}", start.elapsed());
                    return Ok((conn, node));
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap())
    }

    /// Returns a TCP connection to node n, racing IPv4 and IPv6
    /// (both as applicable) against each other.
    /// A node is only given `DIAL_NODE_TIMEOUT` to connect.
    ///
    // TODO(bradfitz): longer if no options remain perhaps? ...  Or longer
    // overall but have dialRegion start overlapping races?
    async fn dial_node(&self, node: &DerpNode) -> Result<TcpStream, ClientError> {
        // TODO: Add support for HTTP proxies.
        debug!("dial node: {:?}", node);

        match (node.ipv4.is_enabled(), node.ipv6.is_enabled()) {
            (true, true) => {
                let this = self.clone();
                let node1 = node.clone();
                let fut1 = Box::pin(
                    async move { this.start_dial(&node1, UseIp::Ipv4(node.ipv4)).await }
                        .instrument(info_span!("dial", proto = "ipv4")),
                );

                let this = self.clone();
                let node2 = node.clone();
                let fut2 = Box::pin(
                    async move { this.start_dial(&node2, UseIp::Ipv6(node.ipv6)).await }
                        .instrument(info_span!("dial", proto = "ipv6")),
                );

                match futures::future::select(fut1, fut2).await {
                    futures::future::Either::Left((ipv4, ipv6)) => match ipv4 {
                        Ok(conn) => Ok(conn),
                        Err(_) => ipv6.await,
                    },
                    futures::future::Either::Right((ipv6, ipv4)) => match ipv6 {
                        Ok(conn) => Ok(conn),
                        Err(_) => ipv4.await,
                    },
                }
            }
            (true, false) => self.start_dial(node, UseIp::Ipv4(node.ipv4)).await,
            (false, true) => self.start_dial(node, UseIp::Ipv6(node.ipv6)).await,
            (false, false) => Err(ClientError::IPDisabled),
        }
    }

    /// Reports whether IPv4 dials should be slightly
    /// delayed to give IPv6 a better chance of winning dial races.
    /// Implementations should only return true if IPv6 is expected
    /// to succeed. (otherwise delaying IPv4 will delay the connection
    /// overall)
    async fn prefer_ipv6(&self) -> bool {
        match self.inner.address_family_selector {
            Some(ref selector) => selector().await,
            None => false,
        }
    }

    async fn start_dial(
        &self,
        node: &DerpNode,
        dst_primary: UseIp,
    ) -> Result<TcpStream, ClientError> {
        trace!("dial start: {:?}", dst_primary);
        if matches!(dst_primary, UseIp::Ipv4(_)) && self.prefer_ipv6().await {
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Start v4 dial
        }
        let host: IpAddr = match dst_primary {
            UseIp::Ipv4(UseIpv4::Some(addr)) => addr.into(),
            UseIp::Ipv6(UseIpv6::Some(addr)) => addr.into(),
            _ => {
                let host = node
                    .url
                    .host()
                    .ok_or_else(|| ClientError::InvalidUrl("missing host".into()))?;
                match host {
                    url::Host::Domain(domain) => {
                        // Need to do a DNS lookup
                        let addr = DNS_RESOLVER
                            .lookup_ip(domain)
                            .await
                            .map_err(|e| ClientError::Dns(Some(e)))?
                            .iter()
                            .find(|addr| match dst_primary {
                                UseIp::Ipv4(_) => addr.is_ipv4(),
                                UseIp::Ipv6(_) => addr.is_ipv6(),
                            });
                        addr.ok_or_else(|| ClientError::Dns(None))?
                    }
                    url::Host::Ipv4(ip) => IpAddr::V4(ip),
                    url::Host::Ipv6(ip) => IpAddr::V6(ip),
                }
            }
        };
        let port = match node.url.port() {
            Some(port) => port,
            None => match node.url.scheme() {
                "http" => 80,
                "https" => 443,
                _ => return Err(ClientError::InvalidUrl(
                    "Invalid scheme in DERP hostname, only http: and https: schemes are supported."
                        .into(),
                )),
            },
        };
        let dst = format!("{host}:{port}");
        debug!("dialing {}", dst);
        let tcp_stream =
            tokio::time::timeout(
                DIAL_NODE_TIMEOUT,
                async move { TcpStream::connect(dst).await },
            )
            .await
            .map_err(|_| ClientError::ConnectTimeout)?
            .map_err(ClientError::DialIO)?;
        // TODO: ipv6 vs ipv4 specific connection

        trace!("dial done: {:?}", dst_primary);
        Ok(tcp_stream)
    }

    /// Send a ping to the server. Return once we get an expected pong.
    ///
    /// There must be a task polling `recv_detail` to process the `pong` response.
    pub async fn ping(&self) -> Result<Duration, ClientError> {
        let ping = rand::thread_rng().gen::<[u8; 8]>();
        debug!("ping: {}", hex::encode(ping));
        let (client, _) = self.connect().await?;

        let start = Instant::now();
        let (send, recv) = oneshot::channel();
        self.register_ping(ping, send).await;
        if client.send_ping(ping).await.is_err() {
            self.close_for_reconnect().await;
            let _ = self.unregister_ping(ping).await;
            return Err(ClientError::Send);
        }
        match tokio::time::timeout(PING_TIMEOUT, recv).await {
            Ok(Ok(())) => Ok(start.elapsed()),
            Err(_) => {
                self.unregister_ping(ping).await;
                Err(ClientError::PingTimeout)
            }
            Ok(Err(_)) => {
                self.unregister_ping(ping).await;
                Err(ClientError::PingAborted)
            }
        }
    }

    /// Send a pong back to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the pong message.
    ///
    /// If there is an error sending pong, it closes the underlying derp connection before
    /// returning.
    pub async fn send_pong(&self, data: [u8; 8]) -> Result<(), ClientError> {
        debug!("send_pong");
        if self.inner.can_ack_pings {
            let (client, _) = self.connect().await?;
            if client.send_pong(data).await.is_err() {
                self.close_for_reconnect().await;
                return Err(ClientError::Send);
            }
            Ok(())
        } else {
            Err(ClientError::CannotAckPings)
        }
    }

    /// Note that we have sent a ping, and store the [`oneshot::Sender`] we
    /// must notify when the pong returns
    async fn register_ping(&self, data: [u8; 8], chan: oneshot::Sender<()>) {
        let mut ping_tracker = self.inner.ping_tracker.lock().await;
        ping_tracker.insert(data, chan);
    }

    /// Remove the associated [`oneshot::Sender`] for `data` & return it.
    ///
    /// If there is no [`oneshot::Sender`] in the tracker, return `None`.
    async fn unregister_ping(&self, data: [u8; 8]) -> Option<oneshot::Sender<()>> {
        let mut ping_tracker = self.inner.ping_tracker.lock().await;
        ping_tracker.remove(&data)
    }

    /// Reads a message from the server. Returns the message and the `conn_get`, or the number of
    /// re-connections this Client has ever made
    #[instrument(skip(self))]
    pub async fn recv_detail(&self) -> Result<(ReceivedMessage, usize), ClientError> {
        loop {
            debug!("recv_detail tick");
            let (client, conn_gen) = self.connect().await?;
            match client.recv().await {
                Ok(msg) => {
                    if let Ok(region) = self.current_region().await {
                        trace!("[DERP] <- {} ({:?})", self.target_string(&region), msg);
                    } else if let Some(url) = self.url() {
                        trace!("[DERP] <- {url} ({:?})", msg);
                    }

                    if let ReceivedMessage::Pong(ping) = msg {
                        trace!("got pong: {}", hex::encode(ping));
                        if let Some(chan) = self.unregister_ping(ping).await {
                            if chan.send(()).is_err() {
                                warn!("pong recieved for ping {ping:?}, but the receiving channel was closed");
                            }
                            continue;
                        }
                    }
                    return Ok((msg, conn_gen));
                }
                Err(e) => {
                    self.close_for_reconnect().await;
                    if self.inner.is_closed.load(Ordering::SeqCst) {
                        return Err(ClientError::Closed);
                    }
                    // TODO(ramfox): more specific error?
                    return Err(ClientError::Receive(e));
                }
            }
        }
    }

    /// Send a packet to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the message.
    ///
    /// If there is an error sending the packet, it closes the underlying derp connection before
    /// returning.
    pub async fn send(&self, dst_key: PublicKey, b: Bytes) -> Result<(), ClientError> {
        debug!("send");
        let (client, _) = self.connect().await?;
        if client.send(dst_key, b).await.is_err() {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Close the underlying derp connection. The next time the client takes some action that
    /// requires a connection, it will call `connect`.
    pub async fn close_for_reconnect(&self) {
        debug!("close for reconnect");
        let mut client = self.inner.derp_client.lock().await;
        if let Some(client) = client.take() {
            client.close().await
        }
    }

    /// Close the http derp connection
    pub async fn close(self) {
        self.inner.is_closed.store(true, Ordering::Relaxed);
        self.close_for_reconnect().await;
    }

    /// Returns `true` if the underyling derp connection is established.
    pub async fn is_connected(&self) -> bool {
        if self.inner.is_closed.load(Ordering::Relaxed) {
            return false;
        }
        self.inner.derp_client.lock().await.is_some()
    }

    /// Send a request to subscribe as a "watcher" on the server.
    ///
    /// This returns the public key of the remote derp server that we have meshed to,
    /// as well as the `conn_gen` of the latest connection.  The `conn_gen` is the
    /// number of times we have successfully re-established a connection to that derp
    /// server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the "watch connection changes" message.
    ///
    /// If there is an error sending the message, it closes the underlying derp connection before
    /// returning.
    pub async fn watch_connection_changes(&self) -> Result<(PublicKey, usize), ClientError> {
        debug!("watch_connection_changes");
        let (client, conn_gen) = self.connect().await?;
        if client.watch_connection_changes().await.is_err() {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok((client.server_public_key(), conn_gen))
    }

    /// Send a "close peer" request to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the request.
    ///
    /// If there is an error sending, it closes the underlying derp connection before
    /// returning.
    pub async fn close_peer(&self, target: PublicKey) -> Result<(), ClientError> {
        debug!("close_peer");
        let (client, _) = self.connect().await?;
        if client.close_peer(target).await.is_err() {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Run this client as a mesh client.
    ///
    /// This method will error if you do not have a `mesh_key`.
    ///
    /// It will establish a connection to the derp server & subscribe to the
    /// network changes of that derp server. As peers connect to and disconnect
    /// from that server, we will get `PeerPresent` and `PeerGone` messages. We
    /// then and and remove that derp server as a `PacketForwarder` respectfully.
    ///
    /// If you pass in a `mesh_events` sender, it will send events about the mesh
    /// activities.
    /// [`MeshClientEvent::Meshed`] is sent the when we return successfully from `watch_connection_changes`,
    /// indicating that the given server is aware that this client exists and wants to
    /// track network changes.
    /// When peers connect and disconnect, [`MeshClientEvent::PeerPresent`] and  [`MeshClientEvent::PeerGone`]
    /// are sent respectively.
    ///
    /// This sender is typically used for aligning the mesh network during tests.
    pub(crate) async fn run_mesh_client(
        self,
        packet_forwarder_handler: PacketForwarderHandler<Client>,
        mesh_events: Option<tokio::sync::mpsc::Sender<MeshClientEvent>>,
    ) -> anyhow::Result<()> {
        // connect to the remote server & request to watching the remote's state changes
        let own_key = self.public_key();
        loop {
            let (server_public_key, last_conn_gen) = match self.watch_connection_changes().await {
                Ok(key) => {
                    if let Some(ref sender) = mesh_events {
                        if let Err(e) = sender.send(MeshClientEvent::Meshed).await {
                            bail!("unable to notify sender that we have successfully meshed with the remote server: {e:?}");
                        }
                    }
                    key
                }
                Err(e) => {
                    warn!("error connecting to derp server {e}");
                    tokio::time::sleep(MESH_CLIENT_REDIAL_DELAY).await;
                    continue;
                }
            };

            if server_public_key == own_key {
                bail!("detected self-connect; closing this client");
            }

            let peers_present = PeersPresent::new(server_public_key);
            info!("Connected to mesh derp server {server_public_key:?}");

            // receive detail loop
            loop {
                let (msg, conn_gen) = match self.recv_detail().await {
                    Ok(res) => res,
                    Err(e) => {
                        warn!("recv error: {e:?}");
                        tokio::time::sleep(MESH_CLIENT_REDIAL_DELAY).await;
                        break;
                    }
                };
                if conn_gen != last_conn_gen {
                    // TODO: In the current set up, once we know that this current
                    // connection is a new connection, we must re-establish to the
                    // server that we want to watch connection changes.
                    // In the future, depending on how we handle multiple connections
                    // for the same peer key in the derp server in the future, we may
                    // be okay to just listen for future peer present
                    // messages without re establishing this connection as a "watcher"
                    trace!("new connection: {} != {}", conn_gen, last_conn_gen);
                    break;
                }
                match msg {
                    ReceivedMessage::PeerPresent(key) => {
                        // ignore notifications about ourself
                        if key == own_key {
                            continue;
                        }
                        peers_present.insert(key).await?;
                        packet_forwarder_handler.add_packet_forwarder(key, self.clone())?;
                        if let Some(ref chan) = mesh_events {
                            chan.send(MeshClientEvent::PeerPresent { peer: key })
                                .await?;
                        }
                    }
                    ReceivedMessage::PeerGone(key) => {
                        // ignore notifications about ourself
                        if key == own_key {
                            continue;
                        }
                        peers_present.remove(key).await?;
                        packet_forwarder_handler.remove_packet_forwarder(key)?;
                        if let Some(ref chan) = mesh_events {
                            chan.send(MeshClientEvent::PeerGone { peer: key }).await?;
                        }
                    }
                    other => {
                        warn!("mesh: received unexpected message: {:?}", other);
                    }
                }
            }
        }
    }
}

const PEERS_PRESENT_LOGGING_DELAY: Duration = Duration::from_secs(5);
const PEERS_PRESENT_LOGGING_INTERVAL: Duration = Duration::from_secs(10);
const PEERS_PRESENT_QUEUE: usize = 100;

use tokio::sync::mpsc::{channel, Sender};

/// A struct to track and log the peers available on the remote server
#[derive(Debug)]
struct PeersPresent {
    /// Periodic logging task
    actor_task: JoinHandle<()>,
    /// Message channel
    actor_channel: Sender<PeersPresentMsg>,
}

/// Message for the PeerPresent actor loop
#[derive(Debug)]
enum PeersPresentMsg {
    /// Add a peer
    PeerPresent(PublicKey),
    /// Remove a peer
    PeerGone(PublicKey),
}

impl PeersPresent {
    fn new(remote_server_key: PublicKey) -> Self {
        let (send, mut recv) = channel(PEERS_PRESENT_QUEUE);
        let actor_task = tokio::spawn(
            async move {
                let mut map = HashSet::new();
                let start = Instant::now() + PEERS_PRESENT_LOGGING_DELAY;
                let mut status_logging_interval =
                    tokio::time::interval_at(start, PEERS_PRESENT_LOGGING_INTERVAL);
                loop {
                    tokio::select! {
                        biased;
                        msg = recv.recv() => {
                           match msg {
                                Some(m) => match m {
                                    PeersPresentMsg::PeerPresent(key) => {
                                        map.insert(key);
                                    }
                                    PeersPresentMsg::PeerGone(key) => {
                                        map.remove(&key);
                                    }
                                },
                                None => {
                                    warn!("sender dropped, closing `PeersPresent` actor loop");
                                    break;
                                },
                           }
                        },
                        _ = status_logging_interval.tick() => {
                            debug!(
                                "Peers present on Derp Server {:?}:\n{map:?}",
                                remote_server_key
                            );
                        }
                    }
                }
            }
            .instrument(info_span!("peers-present.actor")),
        );
        Self {
            actor_task,
            actor_channel: send,
        }
    }

    async fn insert(&self, key: PublicKey) -> anyhow::Result<()> {
        self.actor_channel
            .send(PeersPresentMsg::PeerPresent(key))
            .await?;
        Ok(())
    }

    async fn remove(&self, key: PublicKey) -> anyhow::Result<()> {
        self.actor_channel
            .send(PeersPresentMsg::PeerGone(key))
            .await?;
        Ok(())
    }
}

impl Drop for PeersPresent {
    fn drop(&mut self) {
        self.actor_task.abort();
    }
}

impl PacketForwarder for Client {
    fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, packet: bytes::Bytes) {
        let packet_forwarder = self.clone();
        tokio::spawn(async move {
            // attempt to send the packet 3 times
            for _ in 0..3 {
                let packet = packet.clone();
                debug!("forward packet");
                if let Ok((client, _)) = packet_forwarder.connect().await {
                    if client.forward_packet(srckey, dstkey, packet).await.is_ok() {
                        inc!(Metrics, packets_forwarded_out);
                        return;
                    }
                }
            }
            warn!("attempted three times to forward packet from {srckey:?} to {dstkey:?}, failed. Dropping packet.");
        }.instrument(info_span!("packet-forwarder")));
    }
}

// TODO: move to net or some reusable place
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum UseIp {
    Ipv4(UseIpv4),
    Ipv6(UseIpv6),
}

fn downcast_upgrade(
    upgraded: Upgraded,
) -> anyhow::Result<(
    Box<dyn AsyncRead + Unpin + Send + Sync + 'static>,
    Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>,
)> {
    match upgraded.downcast::<tokio::net::TcpStream>() {
        Ok(Parts { read_buf, io, .. }) => {
            let (reader, writer) = tokio::io::split(io);
            // Prepend data to the reader to avoid data loss
            let reader = std::io::Cursor::new(read_buf).chain(reader);

            Ok((Box::new(reader), Box::new(writer)))
        }
        Err(upgraded) => {
            if let Ok(Parts { read_buf, io, .. }) =
                upgraded.downcast::<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>()
            {
                let (reader, writer) = tokio::io::split(io);
                // Prepend data to the reader to avoid data loss
                let reader = std::io::Cursor::new(read_buf).chain(reader);

                return Ok((Box::new(reader), Box::new(writer)));
            }

            bail!(
                "could not downcast the upgraded connection to a TcpStream or client::TlsStream<TcpStream>"
            )
        }
    }
}

/// Used to allow self signed certificates in tests
#[cfg(test)]
struct NoCertVerifier;

#[cfg(test)]
impl rustls::client::ServerCertVerifier for NoCertVerifier {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derp::{http::ServerBuilder, types::ServerMessage};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use anyhow::Result;

    #[tokio::test]
    async fn test_recv_detail_connect_error() -> Result<()> {
        let key = SecretKey::generate();
        let bad_region = DerpRegion {
            region_id: 1,
            avoid: false,
            nodes: vec![DerpNode {
                name: "test_node".to_string(),
                region_id: 1,
                url: "https://bad.url".parse().unwrap(),
                stun_only: false,
                stun_port: 0,
                ipv4: UseIpv4::Some("35.175.99.112".parse().unwrap()),
                ipv6: UseIpv6::Disabled,
            }
            .into()],
            region_code: "test_region".to_string(),
        };

        let client = ClientBuilder::new()
            .get_region(move || {
                let region = bad_region.clone();
                Box::pin(async move { Some(region) })
            })
            .build(key.clone())?;

        // ensure that the client will bubble up any connection error & not
        // just loop ad infinitum attempting to connect
        if (client.recv_detail().await).is_ok() {
            bail!("expected client with bad derp region detail to return with an error");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_run_mesh_client() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        // set up http server w/ mesh key
        let server_key = SecretKey::generate();
        let mesh_key: MeshKey = [0; 32];
        let http_server = ServerBuilder::new("127.0.0.1:0".parse().unwrap())
            .secret_key(Some(server_key))
            .mesh_key(Some(mesh_key))
            .spawn()
            .await?;

        let addr = http_server.addr();

        // build mesh client
        let url = addr.to_string();
        let url: Url = format!("http://{url}/derp").parse().unwrap();

        let mesh_client_secret_key = SecretKey::generate();
        let mesh_client = ClientBuilder::new()
            .mesh_key(Some(mesh_key))
            .server_url(url.clone())
            .build(mesh_client_secret_key.clone())?;

        // build a packet_forwarder_handler, we can inspect the receive channel to ensure
        // the correct actions are happening
        let (server_channel_s, mut server_channel_r) = tokio::sync::mpsc::channel(10);
        let packet_forwarder_handler = PacketForwarderHandler::new(server_channel_s);

        let mesh_client_key = mesh_client.public_key();
        info!("mesh client public key: {mesh_client_key:?}");

        let (send, mut recv) = tokio::sync::mpsc::channel(32);
        // spawn a task to run the mesh client
        let mesh_task = tokio::spawn(
            async move {
                mesh_client
                    .run_mesh_client(packet_forwarder_handler, Some(send))
                    .await
            }
            .instrument(info_span!("mesh-client")),
        );

        let msg = tokio::time::timeout(Duration::from_secs(5), recv.recv()).await?;
        assert!(matches!(msg, Some(MeshClientEvent::Meshed)));

        // create another client that will become a normal peer for the derp server
        let normal_client = ClientBuilder::new()
            .server_url(url)
            .build(SecretKey::generate())?;
        let normal_client_key = normal_client.public_key();
        info!("normal client public key: {normal_client:?}");
        let _ = normal_client.connect().await?;

        // wait for "add packet forwarder" message
        match server_channel_r.recv().await {
            Some(msg) => match msg {
                ServerMessage::AddPacketForwarder { key, .. } => {
                    debug!("received `ServerMessage::AddPacketForwarder` for {key:?}");
                    assert!(key == mesh_client_key || key == normal_client_key);
                }
                _ => bail!("expected `ServerMessage::AddPacketForwarder`, got {msg:?}"),
            },
            None => bail!("no messages received off of the server_channel"),
        }

        // close normal client
        drop(normal_client);

        // wait for "remove packet forwarder" message
        // potentially may get another `PeerPresent` message about ourselves, this is
        // non deterministic
        loop {
            match server_channel_r.recv().await {
                Some(msg) => match msg {
                    ServerMessage::RemovePacketForwarder(key) => {
                        debug!("received `ServerMessage::RemovePacketForwarder` for {key:?}");
                        break;
                    }
                    ServerMessage::AddPacketForwarder { key, .. } => {
                        debug!("received `ServerMessage::RemovePacketForwarder` for {key:?}");
                        assert!(key == mesh_client_key || key == normal_client_key);
                    }
                    _ => bail!("expected `ServerMessage::RemovePacketForwarder`, got {msg:?}"),
                },
                None => bail!("no messages received off of the server_channel"),
            }
        }

        // clean up `run_mesh_client`
        mesh_task.abort();
        http_server.shutdown().await;
        Ok(())
    }
}
