use std::{num::NonZeroU32, time::Instant};

use anyhow::{bail, ensure, Result};
use bytes::Bytes;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

use super::client_conn::ClientConnBuilder;
use super::PROTOCOL_VERSION;
use crate::hp::key::node::PublicKey;

pub(crate) struct RateLimiter {
    inner: governor::RateLimiter<
        governor::state::direct::NotKeyed,
        governor::state::InMemoryState,
        governor::clock::DefaultClock,
        governor::middleware::NoOpMiddleware,
    >,
}

impl RateLimiter {
    pub(crate) fn new(bytes_per_second: usize, bytes_burst: usize) -> Result<Option<Self>> {
        if (bytes_per_second == 0 || bytes_burst == 0) {
            return Ok(None);
        }
        let bytes_per_second = NonZeroU32::new(u32::try_from(bytes_per_second)?).unwrap();
        let bytes_burst = NonZeroU32::new(u32::try_from(bytes_burst)?).unwrap();
        Ok(Some(Self {
            inner: governor::RateLimiter::direct(
                governor::Quota::per_second(bytes_per_second).allow_burst(bytes_burst),
            ),
        }))
    }

    pub(crate) fn check_n(&self, n: usize) -> Result<()> {
        ensure!(n != 0);
        let n = NonZeroU32::new(u32::try_from(n)?).unwrap();
        match self.inner.check_n(n) {
            Ok(_) => Ok(()),
            Err(_) => bail!("batch cannot go through"),
        }
    }
}

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(crate) struct Packet {
    /// The sender of the packet
    pub(crate) src: PublicKey,
    /// When a packet was put onto a queue before it was sent,
    /// and is used for reporting metrics on the duration of packets
    /// in the queue.
    pub(crate) enqueued_at: Instant,

    /// The data packet bytes.
    pub(crate) bytes: Bytes,
}

/// PeerConnState represents whether or not a peer is connected to the server.
#[derive(Debug, Clone)]
pub(crate) struct PeerConnState {
    pub(crate) peer: PublicKey,
    pub(crate) present: bool,
}

#[derive(Debug, Serialize, Deserialize, MaxSize, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    /// The DERP protocol version that the client was built with.
    /// See [`PROTOCOL_VERSION`].
    pub(crate) version: usize,
    /// Optionally specifies a pre-shared key used by trusted clients.
    /// It's required to subscribe to the connection list and forward
    /// packets. It's empty for regular users.
    /// TODO: this is a string in the go-impl, using an Option<array> here
    /// to satisfy postcard's `MaxSize` trait
    pub(crate) mesh_key: Option<[u8; 32]>,
    /// Whether the client declares it's able to ack pings
    pub(crate) can_ack_pings: bool,
    /// Whether this client is a prober.
    pub(crate) is_prober: bool,
}

/// The information we send to the [`super::client::Client`] about the [`super::server::Server`]'s
/// protocol version & rate limiting
///
/// If either `token_bucket_bytes_per_second` or `token_bucket_bytes_burst` is 0, there is no rate
/// limit.
#[derive(Debug, Clone, Serialize, Deserialize, MaxSize)]
pub(crate) struct ServerInfo {
    pub(crate) version: usize,
    pub(crate) token_bucket_bytes_per_second: usize,
    pub(crate) token_bucket_bytes_burst: usize,
}

impl ServerInfo {
    /// Specifies the server requires no rate limit
    pub fn no_rate_limit() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            token_bucket_bytes_burst: 0,
            token_bucket_bytes_per_second: 0,
        }
    }
}

pub trait PacketForwarder: Send + Sync + 'static {
    fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, packet: Bytes);
}

pub(crate) enum ServerMessage<R, W, P>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    AddWatcher(PublicKey),
    ClosePeer(PublicKey),
    SendPacket((PublicKey, Packet)),
    SendDiscoPacket((PublicKey, Packet)),
    CreateClient(ClientConnBuilder<R, W, P>),
    RemoveClient(PublicKey),
    AddPacketForwarder((PublicKey, P)),
    RemovePacketForwarder(PublicKey),
    Shutdown,
}

impl<R, W, P> std::fmt::Debug for ServerMessage<R, W, P>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerMessage::AddWatcher(key) => write!(f, "ServerMessage::AddWatcher({key:?})"),
            ServerMessage::ClosePeer(key) => write!(f, "ServerMessage::ClosePeer({key:?})"),
            ServerMessage::SendPacket((key, packet)) => {
                write!(f, "ServerMessage::SendPacket(({key:?}, {packet:?}))")
            }
            ServerMessage::SendDiscoPacket((key, packet)) => {
                write!(f, "ServerMessage::SendDiscoPacket(({key:?}, {packet:?}))")
            }
            ServerMessage::CreateClient(client_builder) => {
                write!(
                    f,
                    "ServerMessage::CreateClient({:?}, {})",
                    client_builder.key, client_builder.conn_num
                )
            }
            ServerMessage::RemoveClient(key) => write!(f, "ServerMessage::RemoveClient({key:?})"),
            ServerMessage::AddPacketForwarder((key, p)) => write!(
                f,
                "ServerMessage::AddPacketForwarder(({key:?}, PacketForwarder)))"
            ),
            ServerMessage::RemovePacketForwarder(key) => {
                write!(f, "ServerMessage::RemovePacketForwarder({key:?})")
            }
            ServerMessage::Shutdown => {
                write!(f, "ServerMessage::Shutdown")
            }
        }
    }
}
