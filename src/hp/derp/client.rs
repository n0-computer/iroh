//! based on tailscale/derp/derp_client.go
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use governor::RateLimiter;
use postcard::experimental::max_size::MaxSize;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use super::{
    read_frame, server::ServerInfo, write_frame, write_frame_header, FrameType, FRAME_CLIENT_INFO,
    FRAME_FORWARD_PACKET, FRAME_PING, FRAME_PONG, FRAME_SEND_PACKET, MAGIC, MAX_PACKET_SIZE,
    PROTOCOL_VERSION,
};
use crate::hp::{
    derp::{FRAME_SERVER_KEY, MAX_INFO_LEN, NONCE_LEN},
    key::{self, node::PublicKey},
    magicsock::Conn,
};

const SERVER_KEY_FRAME_MAX_SIZE: u32 = 1024;

/// A DERP Client.
struct Client<W, R, S, C, MW = governor::middleware::NoOpMiddleware>
where
    /// TODO: static????
    W: AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + Unpin,
    S: governor::state::DirectStateStore<Key = governor::state::direct::NotKeyed>,
    C: governor::clock::Clock,
    MW: governor::middleware::RateLimitingMiddleware<C::Instant>,
{
    /// Server key of the DERP server, not a machine or node key
    server_key: key::node::PublicKey,
    /// TODO: maybe change to "secret_key" to match `key::node::SecretKey` naming
    private_key: key::node::SecretKey,
    /// public key associated with `private_key`
    public_key: key::node::PublicKey,
    conn: Conn,
    reader: R,
    /// TODO: This is a string in the go impl, using bytes here to make it easier for postcard
    /// to serialize. 32 is a random number I chose. Need to figure out what the `mesh_key`
    /// is in practice.
    mesh_key: [u8; 32],
    can_ack_pings: bool,
    is_prober: bool,

    // mutex lock to protect the writer
    writer: Arc<Mutex<W>>,
    // TODO: maybe write a trait to make working with the rate limiter less gross cause it's currently disgusting
    rate_limiter: Option<Arc<RateLimiter<governor::state::direct::NotKeyed, S, C, MW>>>,
    /// bytes to discard on next Recv
    peeked: usize,
    /// sticky (set by Recv)
    /// TODO: temporarily a string until I figure out what this is in practice
    read_err: String,
}

/// TODO: ClientBuilder

impl<W, R, S, C, MW> Client<W, R, S, C, MW>
where
    W: AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + Unpin,
    S: governor::state::DirectStateStore<Key = governor::state::direct::NotKeyed>,
    C: governor::clock::Clock,
    MW: governor::middleware::RateLimitingMiddleware<C::Instant>,
{
    // TODO: for something relatively straight forward, this is pretty hard to follow
    // TODO: also, should Client.server_key be an option?
    async fn recv_server_key(&mut self) -> Result<()> {
        // expecting MAGIC followed by 32 bytes that contain the server key
        let magic_len = MAGIC.len();
        let mut buf = BytesMut::with_capacity(magic_len + 32);
        let (frame_type, frame_len) =
            read_frame(&mut self.reader, SERVER_KEY_FRAME_MAX_SIZE, &mut buf).await?;
        let buffer_len = u32::try_from(buf.len())?;
        if frame_len < buffer_len
            || frame_type != FRAME_SERVER_KEY
            || buf[..magic_len] != MAGIC.bytes().collect::<Vec<_>>()[..]
        {
            bail!("invalid server greeting");
        }
        let key: [u8; 32] = buf[magic_len..magic_len + 32].try_into()?;
        self.server_key = key::node::PublicKey::from(key);
        Ok(())
    }

    async fn parse_server_info(&self, buf: &mut [u8]) -> Result<ServerInfo> {
        // TODO: should NONCE_LEN just be usize?
        let max_len = NONCE_LEN as usize + MAX_INFO_LEN;
        let frame_len = buf.len();
        if frame_len < NONCE_LEN as usize {
            bail!("short ServerInfo frame");
        }
        if frame_len > max_len {
            bail!("long ServerInfo frame");
        }

        let msg = self
            .private_key
            .open_from(&self.public_key, buf)
            .context(format!(
                "failed to open crypto_box from server key {:?}",
                self.server_key.as_bytes()
            ))?;
        let info: ServerInfo = postcard::from_bytes(&msg)?;
        Ok(info)
    }

    async fn send_client_key(&mut self) -> Result<()> {
        let mut buf = BytesMut::zeroed(ClientInfo::POSTCARD_MAX_SIZE);
        let msg = postcard::to_slice(
            &ClientInfo {
                version: PROTOCOL_VERSION,
                mesh_key: self.mesh_key,
                can_ack_pings: self.can_ack_pings,
                is_prober: self.is_prober,
            },
            &mut buf,
        )?;
        let mut msg = self.private_key.seal_to(&self.public_key, msg);
        // TODO: doing bufs all over the place...
        let mut buf: Vec<u8> = self.public_key.as_bytes().to_vec();
        buf.append(&mut msg);
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, FRAME_CLIENT_INFO, &buf).await
    }

    /// Returns a reference to the server's public key.
    pub fn server_public_key(&self) -> PublicKey {
        self.server_key.clone()
    }

    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`MAX_PACKET_SIZE`]
    pub async fn send(&mut self, dstkey: PublicKey, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_PACKET_SIZE {
            bail!("packet too big: {}", packet.len());
        }
        let frame_len = u32::try_from(key::node::KEY_SIZE + packet.len())?;
        let rate_limiter = match &self.rate_limiter {
            None => None,
            Some(rl) => Some(Arc::clone(&rl)),
        };
        {
            let mut writer = self.writer.lock().await;
            if let Some(rate_limiter) = rate_limiter {
                match rate_limiter.check_n(std::num::NonZeroU32::new(frame_len).unwrap()) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::warn!("droping send: rate limit reached");
                        return Ok(());
                    }
                }
            }
            write_frame_header(&mut *writer, FRAME_SEND_PACKET, frame_len).await?;
            writer.write_all(dstkey.as_bytes()).await?;
            writer.write_all(packet).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    pub async fn forward_packet(
        &self,
        srckey: PublicKey,
        dstkey: PublicKey,
        packet: &[u8],
    ) -> Result<()> {
        if packet.len() > MAX_PACKET_SIZE {
            bail!("packet too big: {}", packet.len());
        }

        let frame_len = u32::try_from(key::node::KEY_SIZE + packet.len())?;
        let writer = Arc::clone(&self.writer);
        let write_task = tokio::spawn(async move {
            let mut writer = writer.lock().await;
            write_frame_header(&mut *writer, FRAME_FORWARD_PACKET, frame_len).await?;
            writer.write_all(srckey.as_bytes()).await?;
            writer.write_all(dstkey.as_bytes()).await?;
            writer.flush().await?;
            Ok::<(), anyhow::Error>(())
        });

        match tokio::time::timeout(Duration::from_secs(5), write_task).await {
            Ok(res) => res?,
            Err(_) => self.write_timeout_fired().await,
        }
    }

    async fn write_timeout_fired(&self) -> Result<()> {
        self.conn.close().await
    }

    pub async fn send_ping(&self, data: [u8; 8]) -> Result<()> {
        self.send_ping_or_pong(FRAME_PING, data).await
    }

    pub async fn send_pong(&self, data: [u8; 8]) -> Result<()> {
        self.send_ping_or_pong(FRAME_PONG, data).await
    }

    async fn send_ping_or_pong(&self, frame_type: FrameType, data: [u8; 8]) -> Result<()> {
        let mut writer = self.writer.lock().await;
        write_frame_header(&mut *writer, frame_type, 8).await?;
        writer.write_all(&data).await?;
        writer.flush().await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, MaxSize)]
pub(crate) struct ClientInfo {
    /// The DERP protocol version that the client was built with.
    /// See [`PROTOCOL_VERSION`].
    version: usize,
    /// Optionally specifies a pre-shared key used by trusted clients.
    /// It's required to subscribe to the connection list and forward
    /// packets. It's empty for regular users.
    /// TODO: this is a string in the go-impl, using an array here
    /// to satisfy postcard's `MaxSize` trait
    mesh_key: [u8; 32],
    /// Whether the client declares it's able to ack pings
    can_ack_pings: bool,
    /// Whether this client is a prober.
    is_prober: bool,
}

#[derive(Debug, Clone)]
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        source: key::node::PublicKey,
        /// The received packet bytes. It aliases the memory passed to Client.Recv.
        data: Vec<u8>, // TODO: ref
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the server.
    PeerGone(key::node::PublicKey),
    /// Indicates that the client is connected to the server. (Only used by trusted mesh clients)
    PeerPresent(key::node::PublicKey),
    /// Sent by the server upon first connect.
    ServerInfo {
        /// How many bytes per second the server says it will accept, including all framing bytes.
        ///
        /// Zero means unspecified. There might be a limit, but the client need not try to respect it.
        token_bucket_bytes_per_second: usize,
        /// TokenBucketBytesBurst is how many bytes the server will
        /// allow to burst, temporarily violating
        /// TokenBucketBytesPerSecond.
        ///
        /// Zero means unspecified. There might be a limit, but the client need not try to respect it.
        token_bucket_bytes_burst: usize,
    },
    /// Request from a client or server to reply to the
    /// other side with a PongMessage with the given payload.
    Ping([u8; 8]),
    /// Reply to a Ping from a client or server
    /// with the payload sent previously in a Ping.
    Pong([u8; 8]),
    /// A one-way empty message from server to client, just to
    /// keep the connection alive. It's like a Ping, but doesn't solicit
    /// a reply from the client.
    KeepAlive,
    /// A one-way message from server to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the server doesn't broadcast a HealthMessage
        /// until a problem exists.
        problem: Option<String>,
    },
    /// A one-way message from server to client, advertising that the server is restarting.
    ServerRestarting {
        /// An advisory duration that the client should wait before attempting to reconnect.
        /// It might be zero. It exists for the server to smear out the reconnects.
        reconnect_in: Duration,
        /// An advisory duration for how long the client should attempt to reconnect
        /// before giving up and proceeding with its normal connection failure logic. The interval
        /// between retries is undefined for now. A server should not send a TryFor duration more
        /// than a few seconds.
        try_for: Duration,
    },
}
