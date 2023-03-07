//! based on tailscale/derp/derp_client.go
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use governor::RateLimiter;
use postcard::experimental::max_size::MaxSize;
use quinn::AsyncUdpSocket;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use super::{
    read_frame, read_frame_header, server::ServerInfo, write_frame, write_frame_header, FrameType,
    FRAME_CLIENT_INFO, FRAME_CLOSE_PEER, FRAME_FORWARD_PACKET, FRAME_HEALTH, FRAME_NOTE_PREFERRED,
    FRAME_PEER_GONE, FRAME_PING, FRAME_PONG, FRAME_RESTARTING, FRAME_SEND_PACKET,
    FRAME_SERVER_INFO, FRAME_WATCH_CONNS, MAGIC, MAX_PACKET_SIZE, PROTOCOL_VERSION,
};
use crate::hp::{
    derp::{
        FRAME_KEEP_ALIVE, FRAME_PEER_PRESENT, FRAME_RECV_PACKET, FRAME_SERVER_KEY, MAX_FRAME_SIZE,
        MAX_INFO_LEN, NONCE_LEN,
    },
    key::{self, node::PublicKey},
    magicsock::Conn,
};

const SERVER_KEY_FRAME_MAX_SIZE: usize = 1024;

/// A DERP Client.
struct Client<W, R, S, C, MW = governor::middleware::NoOpMiddleware>
where
    W: AsyncWrite + Send + Unpin + 'static, // TODO: static?
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
    /// sticky (set by Recv)
    /// TODO: temporarily a string until I figure out what to do about cloning errors
    recv_err: Arc<Mutex<Option<String>>>,
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
        if frame_len < buf.len()
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
        let max_len = NONCE_LEN + MAX_INFO_LEN;
        let frame_len = buf.len();
        if frame_len < NONCE_LEN {
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
        let frame_len = key::node::KEY_SIZE + packet.len();
        let rate_limiter = match &self.rate_limiter {
            None => None,
            Some(rl) => Some(Arc::clone(&rl)),
        };
        {
            let mut writer = self.writer.lock().await;
            if let Some(rate_limiter) = rate_limiter {
                let frame_len = u32::try_from(frame_len)?;
                match rate_limiter.check_n(std::num::NonZeroU32::new(frame_len).unwrap()) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::warn!("dropping send: rate limit reached");
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

        let frame_len = key::node::KEY_SIZE + packet.len();
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

    /// Sends a packet that tells the server whether this
    /// client is the user's preferred server. This is only
    /// used in the server for stats.
    pub async fn note_preferred(&self, preferred: bool) -> Result<()> {
        let byte = {
            if preferred {
                [0x00]
            } else {
                [0x01]
            }
        };
        let mut writer = self.writer.lock().await;
        write_frame_header(&mut *writer, FRAME_NOTE_PREFERRED, 1).await?;
        writer.write(&byte).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Sends a request to subscribe to the peer's connection list.
    /// It's a fatal error if the client wasn't created using [`MeshKey`].
    pub async fn watch_connection_changes(&self) -> Result<()> {
        let mut writer = self.writer.lock().await;
        write_frame_header(&mut *writer, FRAME_WATCH_CONNS, 0).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Asks the server to close the target's TCP connection.
    /// It's a fatal error if the client wasn't created using [`MeshKey`]
    pub async fn close_peer(&self, target: PublicKey) -> Result<()> {
        let mut writer = self.writer.lock().await;
        write_frame(&mut *writer, FRAME_CLOSE_PEER, target.as_bytes()).await?;
        Ok(())
    }

    async fn set_send_rate_limiter(&mut self, sm: ReceivedMessage) {
        if let ReceivedMessage::ServerInfo {
            token_bucket_bytes_per_second,
            ..
        } = sm
        {
            if token_bucket_bytes_per_second == 0 {
                self.rate_limiter = None;
            } else {
                // make a new rate_limiter & add it to the client
                todo!("the rate limiter stuff is a mess, figure it out");
            }
        }
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        {
            let recv_err = self.recv_err.lock().await;
            if let Some(e) = &*recv_err {
                bail!(e.clone());
            }
        }
        Ok(self.conn.local_addr()?)
    }

    /// Reads a messages from a DERP server.
    ///
    /// The returned message may alias memory owned by the [`Client`]; if
    /// should only be accessed until the next call to [`Client`].
    ///
    /// Once [`recv`] returns an error, the [`Client`] is dead forever.
    pub async fn recv(&self) -> Result<ReceivedMessage> {
        self.recv_check_error(Duration::from_secs(120)).await
    }

    async fn recv_check_error(&self, timeout: Duration) -> Result<ReceivedMessage> {
        {
            let recv_err = self.recv_err.lock().await;
            if let Some(err) = &*recv_err {
                bail!(err.clone());
            }
        }
        match self.recv_timeout(timeout).await {
            Ok(m) => Ok(m),
            Err(e) => {
                let mut recv_err = self.recv_err.lock().await;
                // if it's errored on a simultaneous call to `recv` alread, just
                // return the other error
                if let Some(err) = &*recv_err {
                    bail!(err.clone());
                } else {
                    *recv_err = Some(e.to_string());
                    bail!(e);
                }
            }
        }
    }

    async fn recv_timeout(&self, timeout: Duration) -> Result<ReceivedMessage> {
        todo!();
    }

    async fn recv_0(&mut self) -> Result<ReceivedMessage> {
        let mut frame_payload = BytesMut::with_capacity(4 * 1024);
        loop {
            let (frame_type, frame_len) = read_frame_header(&mut self.reader).await?;
            if frame_len > MAX_FRAME_SIZE {
                bail!("unexpectedly large frame of {} bytes returned", frame_len);
            }
            let mut read_total = 0;
            loop {
                let read = self.reader.read(&mut frame_payload).await?;
                if read == 0 {
                    break;
                }
                read_total += read;
            }
            if read_total != frame_len {
                bail!(
                    "unexpected number of bytes sent in frame, said {}, received {}",
                    frame_len,
                    read_total
                );
            }

            match frame_type {
                FRAME_SERVER_INFO => {
                    // Server sends this at start-up. Currently unused.
                    // Just has a JSON messages saying "version: 2",
                    // but the protocol seems extensible enough as-is without
                    // needing to wait an RTT to discover the version at startup
                    // We'd prefer to give the connection to the client (magicsock)
                    // to start writing as soon as possible.
                    let server_info = self.parse_server_info(&mut frame_payload).await?;
                    let received = ReceivedMessage::ServerInfo {
                        token_bucket_bytes_per_second: server_info.token_bucket_bytes_per_second,
                        token_bucket_bytes_burst: server_info.token_bucket_bytes_burst,
                    };
                    self.set_send_rate_limiter(received.clone()).await;
                    return Ok(received);
                }
                FRAME_KEEP_ALIVE => {
                    // A one-way keep-alive message that doesn't require an ack.
                    // This predated FRAME_PING/FRAME_PONG.
                    return Ok(ReceivedMessage::KeepAlive);
                }
                FRAME_PEER_GONE => {
                    if (frame_len) < crypto_box::KEY_SIZE {
                        tracing::warn!(
                            "unexpected: dropping short PEER_GONE frame from DERP server"
                        );
                        continue;
                    }
                    let key = get_key_from_slice(&frame_payload[..])?;
                    return Ok(ReceivedMessage::PeerGone(PublicKey::from(key)));
                }
                FRAME_PEER_PRESENT => {
                    if (frame_len) < crypto_box::KEY_SIZE {
                        tracing::warn!(
                            "unexpected: dropping short PEER_PRESENT frame from DERP server"
                        );
                        continue;
                    }
                    let key = get_key_from_slice(&frame_payload[..])?;
                    return Ok(ReceivedMessage::PeerPresent(PublicKey::from(key)));
                }
                FRAME_RECV_PACKET => {
                    if (frame_len) < crypto_box::KEY_SIZE {
                        tracing::warn!("unexpected: dropping short packet from DERP server");
                        continue;
                    }
                    let key = get_key_from_slice(&frame_payload[..])?;
                    let packet = ReceivedMessage::ReceivedPacket {
                        source: key,
                        data: frame_payload[crypto_box::KEY_SIZE..].to_vec(),
                    };
                    return Ok(packet);
                }
                FRAME_PING => {
                    if frame_len < 8 {
                        tracing::warn!("unexpected: dropping short PING frame");
                        continue;
                    }
                    let ping = <[u8; 8]>::try_from(&frame_payload[..8])?;
                    return Ok(ReceivedMessage::Ping(ping));
                }
                FRAME_PONG => {
                    if frame_len < 8 {
                        tracing::warn!("unexpected: dropping short PONG frame");
                        continue;
                    }
                    let pong = <[u8; 8]>::try_from(&frame_payload[..8])?;
                    return Ok(ReceivedMessage::Pong(pong));
                }
                FRAME_HEALTH => {
                    let problem = Some(String::from_utf8_lossy(&frame_payload).into());
                    return Ok(ReceivedMessage::Health { problem });
                }
                FRAME_RESTARTING => {
                    if frame_len < 8 {
                        tracing::warn!("unexpected: dropping short server restarting frame");
                        continue;
                    }
                    let reconnect_in = <[u8; 4]>::try_from(&frame_payload[..4])?;
                    let try_for = <[u8; 4]>::try_from(&frame_payload[4..8])?;
                    let reconnect_in =
                        Duration::from_millis(u32::from_be_bytes(reconnect_in) as u64);
                    let try_for = Duration::from_millis(u32::from_be_bytes(try_for) as u64);
                    return Ok(ReceivedMessage::ServerRestarting {
                        reconnect_in,
                        try_for,
                    });
                }
                _ => {
                    frame_payload.clear();
                }
            }
        }
    }
}

// errors if `frame_len` is less than the expected key size
fn get_key_from_slice(payload: &[u8]) -> Result<PublicKey> {
    Ok(<[u8; crypto_box::KEY_SIZE]>::try_from(payload)?.into())
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
