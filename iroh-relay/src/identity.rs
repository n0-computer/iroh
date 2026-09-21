//! Experimental, explicitly enabled relay protocol for typed identities.
//!
//! Registration proves possession of a credential over a fresh challenge bound
//! to the relay URL. Forwarded datagrams carry the authenticated sender's ID.
//! Application authentication still occurs end to end in QUIC TLS.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use iroh_base::RelayUrl;
use iroh_identity::{Error, LocalIdentity, PeerId};
use n0_future::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_websockets::{Message, WebSocketStream};

/// HTTP path for the versioned protocol. Legacy `/relay` is unchanged.
pub const PATH: &str = "/relay/identity-v1";
/// Required WebSocket subprotocol, with no legacy fallback.
pub const PROTOCOL: &str = "iroh-identity-relay/1";
const MAX_FRAME: usize = 66000;
const TIMEOUT: Duration = Duration::from_secs(10);
/// Both ends ping an idle session so a silently dead TCP connection is
/// detected and released instead of holding its registration.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(45);

fn error(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Io(io::Error::other(error))
}

fn proof(url: &RelayUrl, nonce: &[u8], id: PeerId) -> Vec<u8> {
    let mut out = b"iroh identity relay registration v1\0".to_vec();
    let audience = url.as_str().as_bytes();
    out.extend_from_slice(&(audience.len() as u32).to_be_bytes());
    out.extend_from_slice(audience);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&id.to_bytes());
    out
}

async fn read<S: AsyncRead + AsyncWrite + Unpin>(
    ws: &mut WebSocketStream<S>,
) -> Result<Bytes, Error> {
    loop {
        let message = ws.next().await.ok_or(Error::Closed)?.map_err(error)?;
        if message.is_binary() {
            return Ok(message.into_payload().into());
        }
        if message.is_close() || message.is_text() {
            return Err(Error::Protocol("expected binary relay frame"));
        }
    }
}

fn datagram(peer: PeerId, contents: &[u8]) -> Result<Bytes, Error> {
    if contents.is_empty() || contents.len() > 65535 {
        return Err(Error::Protocol("invalid datagram size"));
    }
    let id = peer.to_bytes();
    let mut out = Vec::with_capacity(2 + id.len() + contents.len());
    out.push(3);
    out.push(id.len() as u8);
    out.extend_from_slice(&id);
    out.extend_from_slice(contents);
    Ok(out.into())
}

fn parse_datagram(bytes: Bytes) -> Result<(PeerId, Bytes), Error> {
    if bytes.len() < 3 || bytes[0] != 3 {
        return Err(Error::Protocol("invalid datagram frame"));
    }
    let end = 2 + bytes[1] as usize;
    if end >= bytes.len() || bytes.len() - end > 65535 {
        return Err(Error::Protocol("invalid datagram length"));
    }
    let peer = PeerId::from_bytes(&bytes[2..end])?;
    Ok((peer, bytes.slice(end..)))
}

/// Tracks the keepalive deadline of one session. Any received frame,
/// including the peer's automatic pong replies, proves liveness.
struct Keepalive {
    ping: tokio::time::Interval,
    last_received: tokio::time::Instant,
}

impl Keepalive {
    fn new() -> Self {
        let now = tokio::time::Instant::now();
        let mut ping = tokio::time::interval_at(now + KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            ping,
            last_received: now,
        }
    }

    fn received(&mut self) {
        self.last_received = tokio::time::Instant::now();
    }

    /// Waits for the next ping slot and fails once the peer has been silent
    /// for the full keepalive timeout.
    async fn tick(&mut self) -> Result<(), Error> {
        self.ping.tick().await;
        if self.last_received.elapsed() >= KEEPALIVE_TIMEOUT {
            return Err(Error::Protocol("relay keepalive timeout"));
        }
        Ok(())
    }
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// An authenticated connection to a versioned relay.
pub struct Client {
    ws: WebSocketStream<Box<dyn Io>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRelayClient")
            .finish_non_exhaustive()
    }
}

/// Resolved dial targets and the TLS server name used for HTTPS relays.
///
/// IP literal hosts, including bracketed IPv6, dial directly and verify the
/// certificate against the address; domains resolve to every address.
struct Target {
    addrs: Vec<SocketAddr>,
    name: rustls::pki_types::ServerName<'static>,
}

async fn resolve(url: &RelayUrl) -> Result<Target, Error> {
    let port = url
        .port_or_known_default()
        .ok_or(Error::Protocol("missing relay port"))?;
    match url.host() {
        None => Err(Error::Protocol("missing relay host")),
        Some(url::Host::Ipv4(ip)) => Ok(Target {
            addrs: vec![SocketAddr::new(ip.into(), port)],
            name: rustls::pki_types::ServerName::IpAddress(ip.into()),
        }),
        Some(url::Host::Ipv6(ip)) => Ok(Target {
            addrs: vec![SocketAddr::new(ip.into(), port)],
            name: rustls::pki_types::ServerName::IpAddress(ip.into()),
        }),
        Some(url::Host::Domain(domain)) => {
            let addrs: Vec<_> = tokio::net::lookup_host((domain, port)).await?.collect();
            let name = rustls::pki_types::ServerName::try_from(domain.to_owned()).map_err(error)?;
            Ok(Target { addrs, name })
        }
    }
}

/// Dial each resolved address in order, like the standard library does.
async fn dial(target: &Target) -> Result<tokio::net::TcpStream, Error> {
    let mut last = Error::Io(io::Error::other("relay host did not resolve"));
    for addr in &target.addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => return Ok(tcp),
            Err(error) => last = Error::Io(error),
        }
    }
    Err(last)
}

impl Client {
    /// Connect and register. The TLS client configuration carries the
    /// endpoint's CA trust and crypto provider for HTTPS relays.
    pub async fn connect(
        url: &RelayUrl,
        identity: &LocalIdentity,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        tokio::time::timeout(TIMEOUT, Self::connect_inner(url, identity, tls))
            .await
            .map_err(error)?
    }

    async fn connect_inner(
        url: &RelayUrl,
        identity: &LocalIdentity,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        let target = resolve(url).await?;
        let tcp = dial(&target).await?;
        tcp.set_nodelay(true)?;
        let stream: Box<dyn Io> = match url.scheme() {
            "http" => Box::new(tcp),
            "https" => {
                let connector = tokio_rustls::TlsConnector::from(tls);
                Box::new(connector.connect(target.name, tcp).await?)
            }
            _ => return Err(Error::Protocol("unsupported relay URL scheme")),
        };
        let mut dial = url::Url::parse(url.as_str()).map_err(error)?;
        dial.set_path(PATH);
        dial.set_query(None);
        let (mut ws, response) = tokio_websockets::ClientBuilder::new()
            .uri(dial.as_str())
            .map_err(error)?
            .add_header(
                http::header::SEC_WEBSOCKET_PROTOCOL,
                http::HeaderValue::from_static(PROTOCOL),
            )
            .map_err(error)?
            .limits(tokio_websockets::Limits::default().max_payload_len(Some(MAX_FRAME)))
            .connect_on(stream)
            .await
            .map_err(error)?;
        if response
            .headers()
            .get(http::header::SEC_WEBSOCKET_PROTOCOL)
            .is_none_or(|v| v != PROTOCOL)
        {
            return Err(Error::Protocol("relay protocol mismatch"));
        }
        let challenge = read(&mut ws).await?;
        if challenge.len() != 33 || challenge[0] != 0 {
            return Err(Error::Protocol("invalid relay challenge"));
        }
        let public = identity.public_key();
        let signature = identity.sign(&proof(url, &challenge[1..], identity.id()))?;
        let mut auth = vec![1];
        auth.extend_from_slice(&(public.as_ref().len() as u32).to_be_bytes());
        auth.extend_from_slice(public.as_ref());
        auth.extend_from_slice(&signature);
        ws.send(Message::binary(auth)).await.map_err(error)?;
        if read(&mut ws).await?.as_ref() != [2] {
            return Err(Error::Protocol("relay registration rejected"));
        }
        Ok(Self { ws })
    }

    /// Drive bounded outbound and inbound datagram queues until disconnected.
    ///
    /// Returns when the relay closes the session, replaces this registration,
    /// or stops answering keepalive pings.
    pub async fn run(
        self,
        mut outgoing: tokio::sync::mpsc::Receiver<(PeerId, Bytes)>,
        incoming: tokio::sync::mpsc::Sender<(PeerId, Bytes)>,
    ) -> Result<(), Error> {
        let (mut sink, mut stream) = n0_future::split::split(self.ws);
        let mut keepalive = Keepalive::new();
        loop {
            tokio::select! {
                value = outgoing.recv() => {
                    let (peer, contents) = value.ok_or(Error::Closed)?;
                    tokio::time::timeout(TIMEOUT, sink.send(Message::binary(datagram(peer, &contents)?))).await.map_err(error)?.map_err(error)?;
                }
                value = stream.next() => {
                    let message = value.ok_or(Error::Closed)?.map_err(error)?;
                    keepalive.received();
                    if message.is_close() { return Err(Error::Closed); }
                    if message.is_binary() {
                        let value = parse_datagram(message.into_payload().into())?;
                        // Congestion has UDP semantics; no unbounded buffering.
                        let _ = incoming.try_send(value);
                    } else if message.is_text() { return Err(Error::Protocol("unexpected text frame")); }
                }
                result = keepalive.tick() => {
                    result?;
                    tokio::time::timeout(TIMEOUT, sink.send(Message::ping(Bytes::new()))).await.map_err(error)?.map_err(error)?;
                }
            }
        }
    }
}

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
pub use server::Service;
