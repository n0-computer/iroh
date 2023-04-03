//! Based on tailscale/derp/derphttp/derphttp_client.go
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use hyper::{header::UPGRADE, Body, Request};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::hp::derp::{
    client::ClientBuilder as DerpClientBuilder, DerpNode, MeshKey, PacketForwarder, UseIpv4,
    UseIpv6,
};
use crate::hp::key;

use crate::hp::derp::{client::Client as DerpClient, DerpRegion, ReceivedMessage};

const DIAL_NODE_TIMEOUT: Duration = Duration::from_millis(1500);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("client is closed")]
    Closed,
    #[error("no derp client")]
    NoClient,
    #[error("error sending a packet")]
    Send,
    #[error("connect timeout")]
    ConnectTimeout,
    #[error("DERP region is not available")]
    DerpRegionNotAvail,
    #[error("no nodes available for {0}")]
    NoNodeForTarget(String),
    #[error("no derp nodes found for {0}, only are stun_only nodes")]
    StunOnlyNodesFound(String),
    #[error("dial error")]
    DialIO(#[from] std::io::Error),
    #[error("dial error")]
    DialTask(#[from] tokio::task::JoinError),
    #[error("both IPv4 and IPv6 are explicitly diabled for this node")]
    IPDisabled,
    #[error("no local addr: {0}")]
    NoLocalAddr(String),
    #[error("http connection error")]
    Hyper(#[from] hyper::Error),
    #[error("unexpected status code: expected {0}, got {1}")]
    UnexpectedStatusCode(hyper::StatusCode, hyper::StatusCode),
    #[error("failed to upgrade connection")]
    Upgrade,
    #[error("failed to build derp client: {0}")]
    Build(String),
    #[error("ping timeout")]
    PingTimeout,
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
    secret_key: key::node::SecretKey,
    get_region:
        Option<Box<dyn Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static>>,
    can_ack_pings: bool,
    is_preferred: Mutex<bool>,
    derp_client: Mutex<Option<DerpClient<tokio::net::tcp::OwnedReadHalf>>>,
    is_closed: AtomicBool,
    address_family_selector:
        Option<Box<dyn Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static>>,
    conn_gen: AtomicUsize,
    ping_tracker: Mutex<HashMap<[u8; 8], oneshot::Sender<()>>>,
    mesh_key: Option<MeshKey>,
    is_prober: bool,
}

/// Build a Client
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
    pub fn new() -> Self {
        Self {
            can_ack_pings: false,
            is_preferred: false,
            address_family_selector: None,
            mesh_key: None,
            is_prober: false,
        }
    }

    // S returns if we should prefer ipv6
    // it replaces the derphttp.AddressFamilySelector we pass
    // It provides the hint as to whether in an IPv4-vs-IPv6 race that
    // IPv4 should be held back a bit to give IPv6 a better-than-50/50
    // chance of winning. We only return true when we believe IPv6 will
    // work anyway, so we don't artificially delay the connection speed.
    pub fn address_family_selector<S>(mut self, selector: S) -> Self
    where
        S: Fn() -> BoxFuture<'static, bool> + Send + Sync + 'static,
    {
        self.address_family_selector = Some(Box::new(selector));
        self
    }

    pub fn can_ack_pings(mut self, can: bool) -> Self {
        self.can_ack_pings = can;
        self
    }

    pub fn is_preferred(mut self, is: bool) -> Self {
        self.is_preferred = is;
        self
    }

    pub fn is_prober(mut self, is: bool) -> Self {
        self.is_prober = is;
        self
    }

    pub fn mesh_key(mut self, mesh_key: Option<MeshKey>) -> Self {
        self.mesh_key = mesh_key;
        self
    }

    pub fn new_region<F>(self, key: key::node::SecretKey, f: F) -> Client
    where
        F: Fn() -> BoxFuture<'static, Option<DerpRegion>> + Send + Sync + 'static,
    {
        Client {
            inner: Arc::new(InnerClient {
                secret_key: key,
                get_region: Some(Box::new(f)),
                can_ack_pings: self.can_ack_pings,
                is_preferred: Mutex::new(self.is_preferred),
                derp_client: Mutex::new(None),
                is_closed: AtomicBool::new(false),
                address_family_selector: self.address_family_selector,
                conn_gen: AtomicUsize::new(0),
                ping_tracker: Mutex::new(HashMap::default()),
                mesh_key: self.mesh_key,
                is_prober: self.is_prober,
            }),
        }
    }
}

impl Client {
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
        if let Err(_) = res {
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
    /// connected [`crate::hp::derp::client::Client`].
    async fn connect(
        &self,
    ) -> Result<(DerpClient<tokio::net::tcp::OwnedReadHalf>, usize), ClientError> {
        let key = self.inner.secret_key.public_key();
        debug!("client {key:?} - connect");
        if self.inner.is_closed.load(Ordering::Relaxed) {
            return Err(ClientError::Closed);
        }

        {
            // acquire lock on the derp client
            // we must hold onto the lock until we are sure we have a connection
            // or other calls to `connect` will attempt to start a connection
            // as well
            let mut derp_client_lock = self.inner.derp_client.lock().await;
            if let Some(derp_client) = &*derp_client_lock {
                debug!("client {key:?} - already had connection");
                return Ok((
                    derp_client.clone(),
                    self.inner.conn_gen.load(Ordering::SeqCst),
                ));
            }

            debug!("client {key:?} - no connection, trying to connect");
            let derp_client = tokio::time::timeout(CONNECT_TIMEOUT, self.connect_0())
                .await
                .map_err(|_| ClientError::ConnectTimeout)??;

            let derp_client_clone = derp_client.clone();
            *derp_client_lock = Some(derp_client_clone);
            let conn_gen = self.inner.conn_gen.fetch_add(1, Ordering::SeqCst);
            debug!("client {key:?} - got connection, conn num {conn_gen}");
            Ok((derp_client, conn_gen))
        }
    }

    async fn connect_0(&self) -> Result<DerpClient<tokio::net::tcp::OwnedReadHalf>, ClientError> {
        let region = {
            if let Some(get_region) = &self.inner.get_region {
                get_region()
                    .await
                    .expect("Cannot connection client: DERP region is unknown")
            } else {
                return Err(ClientError::DerpRegionNotAvail);
            }
        };

        let (tcp_stream, _node) = self.dial_region(region).await?;

        let local_addr = tcp_stream
            .local_addr()
            .map_err(|e| ClientError::NoLocalAddr(e.to_string()))?;

        let (mut request_sender, connection) = hyper::client::conn::handshake(tcp_stream)
            .await
            .map_err(|e| ClientError::Hyper(e))?;

        tokio::spawn(async move {
            // polling `connection` drives the HTTP exchange
            // this will poll until we upgrade the connection, but not shutdown the underlying
            // stream
            debug!("connect: waiting for connection");
            if let Err(err) = connection.await {
                warn!("client connection error: {:?}", err);
            }
            debug!("connect: connection done");
        });

        let req = Request::builder()
            .header(UPGRADE, super::HTTP_UPGRADE_PROTOCOL)
            .body(Body::empty())
            .unwrap();

        debug!("connect: sending upgrade request");
        let res = request_sender
            .send_request(req)
            .await
            .map_err(|e| ClientError::Hyper(e))?;

        if res.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            warn!("connect: invalid status received: {:?}", res.status());
            return Err(ClientError::UnexpectedStatusCode(
                hyper::StatusCode::SWITCHING_PROTOCOLS,
                res.status(),
            ));
        }

        debug!("connect: starting upgrade");
        let upgraded = match hyper::upgrade::on(res).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                warn!("connect: upgrade failed: {:?}", err);
                return Err(ClientError::Hyper(err));
            }
        };

        debug!("connect: connection upgraded");
        let parts = upgraded
            .downcast::<TcpStream>()
            .map_err(|_| ClientError::Upgrade)?;

        let (reader, writer) = parts.io.into_split();
        debug!("connect: buf: {:?}", parts.read_buf);

        debug!("connect: building..");
        let derp_client =
            DerpClientBuilder::new(self.inner.secret_key.clone(), local_addr, reader, writer)
                .mesh_key(self.inner.mesh_key.clone())
                .can_ack_pings(self.inner.can_ack_pings)
                .is_prober(self.inner.is_prober)
                .build(Some(parts.read_buf))
                .await
                .map_err(|e| ClientError::Build(e.to_string()))?;

        if *self.inner.is_preferred.lock().await {
            if let Err(_) = derp_client.note_preferred(true).await {
                derp_client.close().await;
                return Err(ClientError::Send);
            }
        }
        debug!("connect: built");
        Ok(derp_client)
    }

    /// String representation of the url or derp region we are trying to
    /// connect to.
    fn target_string(&self, reg: &DerpRegion) -> String {
        // TODO: if  self.Url, return the url string
        format!("region {} ({})", reg.region_id, reg.region_code)
    }

    /// Creates the uri string from a [`DerpNode`]
    ///

    /// Return a TCP stream to the provided region, trying each node in order
    /// (using [`Client::dial_node`]) until one connects
    async fn dial_region(&self, reg: DerpRegion) -> Result<(TcpStream, DerpNode), ClientError> {
        let target = self.target_string(&reg);
        if reg.nodes.is_empty() {
            return Err(ClientError::NoNodeForTarget(target));
        }
        let mut first_err: Option<ClientError> = None;
        for node in reg.nodes {
            if node.stun_only {
                if first_err.is_none() {
                    first_err = Some(ClientError::StunOnlyNodesFound(target.clone()));
                }
                continue;
            }
            let conn = self.dial_node(&node).await;
            match conn {
                Ok(conn) => return Ok((conn, node)),
                Err(e) => first_err = Some(e),
            }
        }
        let err = first_err.unwrap();
        Err(err)
    }

    /// Returns a TCP connection to node n, racing IPv4 and IPv6
    /// (both as applicable) against each other.
    /// A node is only given `DIAL_NODE_TIMEOUT` to connect.
    ///
    // TODO(bradfitz): longer if no options remain perhaps? ...  Or longer
    // overall but have dialRegion start overlapping races?
    async fn dial_node(&self, node: &DerpNode) -> Result<TcpStream, ClientError> {
        // TODO: Add support for HTTP proxies.

        let mut dials = JoinSet::new();

        if node.ipv4.is_enabled() {
            let this = self.clone();
            let node = node.clone();
            dials.spawn(async move { this.start_dial(&node, UseIp::Ipv4(node.ipv4)).await });
        }
        if node.ipv6.is_enabled() {
            let this = self.clone();
            let node = node.clone();
            dials.spawn(async move { this.start_dial(&node, UseIp::Ipv6(node.ipv6)).await });
        }

        // Return the first successfull dial, otherwise the first error we saw.
        let mut first_err = None;
        while let Some(res) = dials.join_next().await {
            match res.map_err(|e| ClientError::DialTask(e))? {
                Ok(conn) => {
                    // Cancel rest
                    dials.abort_all();
                    return Ok(conn);
                }
                Err(err) => {
                    if first_err.is_none() {
                        first_err = Some(err);
                    }
                    if dials.is_empty() {
                        return Err(ClientError::DialIO(first_err.unwrap()));
                    }
                }
            }
        }
        Err(ClientError::IPDisabled)
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
    ) -> Result<TcpStream, std::io::Error> {
        if matches!(dst_primary, UseIp::Ipv4(_)) && self.prefer_ipv6().await {
            tokio::time::sleep(Duration::from_millis(200)).await;
            // Start v4 dial
        }
        let host = match dst_primary {
            UseIp::Ipv4(UseIpv4::Some(addr)) => addr.to_string(),
            UseIp::Ipv6(UseIpv6::Some(addr)) => addr.to_string(),
            _ => node.host_name.clone(),
        };
        let port = if node.derp_port != 0 {
            node.derp_port
        } else {
            443
        };
        let dst = format!("{host}:{port}");
        let tcp_stream =
            tokio::time::timeout(
                DIAL_NODE_TIMEOUT,
                async move { TcpStream::connect(dst).await },
            )
            .await??;
        // TODO: ipv6 vs ipv4 specific connection

        Ok(tcp_stream)
    }

    /// Send a ping to the server. Return once we get an expected pong.
    ///
    /// There must be a task polling `recv_detail` to process the `pong` response.
    pub async fn ping(&self) -> Result<(), ClientError> {
        debug!("ping");
        let (client, _) = self.connect().await?;
        let ping = rand::thread_rng().gen::<[u8; 8]>();
        let (send, recv) = oneshot::channel();
        self.register_ping(ping, send).await;
        if let Err(_) = client.send_ping(ping).await {
            self.close_for_reconnect().await;
            let _ = self.unregister_ping(ping).await;
            return Err(ClientError::Send);
        }
        if tokio::time::timeout(PING_TIMEOUT, recv).await.is_err() {
            self.unregister_ping(ping).await;
            return Err(ClientError::PingTimeout);
        }
        Ok(())
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
        let (client, _) = self.connect().await?;
        if let Err(_) = client.send_pong(data).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
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
    pub async fn recv_detail(&self) -> Result<(ReceivedMessage, usize), ClientError> {
        loop {
            debug!("recv_detail");
            let (client, conn_gen) = self.connect().await?;
            match client.recv().await {
                Ok(msg) => {
                    if let ReceivedMessage::Pong(ping) = msg {
                        if let Some(chan) = self.unregister_ping(ping).await {
                            if let Err(_) = chan.send(()) {
                                tracing::warn!("pong recieved for ping {ping:?}, but the receiving channel was closed");
                            }
                            continue;
                        }
                    }
                    return Ok((msg, conn_gen));
                }
                Err(_) => {
                    self.close_for_reconnect().await;
                    if self.inner.is_closed.load(Ordering::SeqCst) {
                        return Err(ClientError::Closed);
                    }
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
    pub async fn send(&self, dst_key: key::node::PublicKey, b: Vec<u8>) -> Result<(), ClientError> {
        debug!("send");
        let (client, _) = self.connect().await?;
        if let Err(_) = client.send(dst_key, b).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Close the underlying derp connection. The next time the client takes some action that
    /// requires a connection, it will call `connect`.
    async fn close_for_reconnect(&self) {
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

    /// Send a request to subscribe as a "watcher" on the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the "watch connection changes" message.
    ///
    /// If there is an error sending the message, it closes the underlying derp connection before
    /// returning.
    pub async fn watch_connection_changes(&self) -> Result<(), ClientError> {
        debug!("watch_connection_changes");
        let (client, _) = self.connect().await?;
        if let Err(_) = client.watch_connection_changes().await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }

    /// Send a "close peer" request to the server.
    ///
    /// If there is no underlying active derp connection, it creates one before attempting to
    /// send the request.
    ///
    /// If there is an error sending, it closes the underlying derp connection before
    /// returning.
    pub async fn close_peer(&self, target: key::node::PublicKey) -> Result<(), ClientError> {
        debug!("close_peer");
        let (client, _) = self.connect().await?;
        if let Err(_) = client.close_peer(target).await {
            self.close_for_reconnect().await;
            return Err(ClientError::Send);
        }
        Ok(())
    }
}

impl PacketForwarder for Client {
    fn forward_packet(
        &mut self,
        srckey: key::node::PublicKey,
        dstkey: key::node::PublicKey,
        packet: bytes::Bytes,
    ) {
        let packet_forwarder = self.clone();
        tokio::spawn(async move {
            // attempt to send the packet 3 times
            for _ in 0..3 {
                let srckey = srckey.clone();
                let dstkey = dstkey.clone();
                let packet = packet.clone();
                if let Ok((client, _)) = packet_forwarder.connect().await {
                    if let Ok(_) = client.forward_packet(srckey, dstkey, packet).await {
                        return;
                    }
                }
            }
            tracing::warn!("attempted three times to forward packet from {srckey:?} to {dstkey:?}, failed. Dropping packet.");
        });
    }
}

// TODO: move to net or some reusable place
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum UseIp {
    Ipv4(UseIpv4),
    Ipv6(UseIpv6),
}
