//! based on tailscale/derp/derp_client.go
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bytes::BytesMut;
use postcard::experimental::max_size::MaxSize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::{
    read_frame,
    types::{ClientInfo, Conn, RateLimiter, ServerInfo},
    write_frame, FrameType, FRAME_CLIENT_INFO, FRAME_CLOSE_PEER, FRAME_FORWARD_PACKET,
    FRAME_HEALTH, FRAME_KEEP_ALIVE, FRAME_NOTE_PREFERRED, FRAME_PEER_GONE, FRAME_PEER_PRESENT,
    FRAME_PING, FRAME_PONG, FRAME_RECV_PACKET, FRAME_RESTARTING, FRAME_SEND_PACKET,
    FRAME_SERVER_INFO, FRAME_SERVER_KEY, FRAME_WATCH_CONNS, MAGIC, MAX_FRAME_SIZE, MAX_INFO_LEN,
    MAX_PACKET_SIZE, NONCE_LEN, NOT_PREFERRED, PREFERRED, PROTOCOL_VERSION,
};

use crate::hp::key::node::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH};

/// A DERP Client.
pub struct Client<W, R, C>
where
    W: AsyncWrite + Send + Unpin + 'static, // TODO: static?
    R: AsyncRead + Unpin,
    C: Conn,
{
    /// Server key of the DERP server, not a machine or node key
    server_key: PublicKey,
    /// The public/private keypair
    secret_key: SecretKey,
    conn: C,
    reader: R,
    /// TODO: This is a string in the go impl, using bytes here to make it easier for postcard
    /// to serialize. 32 is a random number I chose. Need to figure out what the `mesh_key`
    /// is in practice.
    mesh_key: Option<[u8; 32]>,
    can_ack_pings: bool,
    is_prober: bool,

    // protected by a mutex in the go impl
    writer: W,
    // TODO: maybe write a trait to make working with the rate limiter less gross cause it's currently disgusting
    rate_limiter: Option<RateLimiter>,
    /// Once the Client has received an error while receiving (`recv`), it's considered dead & should
    /// respond to all future attempts to `recv` with an error
    /// TODO: name?
    is_dead: AtomicBool,
}

impl<W, R, C> Client<W, R, C>
where
    W: AsyncWrite + Unpin + Send,
    R: AsyncRead + Unpin,
    C: Conn,
{
    async fn recv_server_key(&mut self) -> Result<PublicKey> {
        recv_server_key(&mut self.reader).await
    }

    async fn parse_server_info(&self, buf: &mut [u8]) -> Result<ServerInfo> {
        let max_len = NONCE_LEN + MAX_INFO_LEN;
        let frame_len = buf.len();
        ensure!(frame_len > NONCE_LEN, "short ServerInfo frame");
        ensure!(frame_len < max_len, "long ServerInfo frame");

        let msg = self
            .secret_key
            .open_from(&self.server_key, buf)
            .context(format!(
                "failed to open crypto_box from server key {:?}",
                self.server_key.as_bytes()
            ))?;
        let info: ServerInfo = postcard::from_bytes(&msg)?;
        Ok(info)
    }

    async fn send_client_key(&mut self) -> Result<()> {
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
            mesh_key: self.mesh_key,
            can_ack_pings: self.can_ack_pings,
            is_prober: self.is_prober,
        };
        super::send_client_key(
            &mut self.writer,
            &self.secret_key,
            &self.server_key,
            &client_info,
        )
        .await
    }

    /// Returns a reference to the server's public key.
    pub fn server_public_key(&self) -> PublicKey {
        self.server_key.clone()
    }

    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`MAX_PACKET_SIZE`]
    // TODO: the rate limiter is only on this method, is it because it's the only method that
    // theoretically sends a bunch of data, or is it an oversight? For example, the `forward_packet` method does not have a rate limiter, but _does_ have a timeout.
    pub async fn send(&mut self, dstkey: PublicKey, packet: &[u8]) -> Result<()> {
        send_packet(&mut self.writer, &self.rate_limiter, dstkey, packet).await
    }

    /// Used by mesh peers to forward packets.
    ///
    // TODO: this is the only method with a timeout, why? Why does it have a timeout and no rate
    // limiter?
    pub async fn forward_packet(
        &mut self,
        srckey: PublicKey,
        dstkey: PublicKey,
        packet: &[u8],
    ) -> Result<()> {
        tokio::select! {
            biased;
            res = forward_packet(&mut self.writer, srckey, dstkey, packet) => {
                res
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                self.write_timeout_fired().await
            }
        }
    }

    async fn write_timeout_fired(&self) -> Result<()> {
        self.conn.close()
    }

    pub async fn send_ping(&mut self, data: &[u8; 8]) -> Result<()> {
        send_ping(&mut self.writer, data).await
    }

    pub async fn send_pong(&mut self, data: &[u8; 8]) -> Result<()> {
        send_pong(&mut self.writer, data).await
    }

    /// Sends a packet that tells the server whether this
    /// client is the user's preferred server. This is only
    /// used in the server for stats.
    pub async fn note_preferred(&mut self, preferred: bool) -> Result<()> {
        send_note_preferred(&mut self.writer, preferred).await
    }

    /// Sends a request to subscribe to the peer's connection list.
    /// It's a fatal error if the client wasn't created using [`MeshKey`].
    pub async fn watch_connection_changes(&mut self) -> Result<()> {
        watch_connection_changes(&mut self.writer).await
    }

    /// Asks the server to close the target's TCP connection.
    /// It's a fatal error if the client wasn't created using [`MeshKey`]
    pub async fn close_peer(&mut self, target: PublicKey) -> Result<()> {
        close_peer(&mut self.writer, target).await
    }

    async fn set_send_rate_limiter(&mut self, sm: ReceivedMessage) {
        if let ReceivedMessage::ServerInfo {
            token_bucket_bytes_per_second,
            token_bucket_bytes_burst,
        } = sm
        {
            if token_bucket_bytes_per_second == 0 || token_bucket_bytes_burst == 0 {
                self.rate_limiter = None;
            } else {
                self.rate_limiter = Some(
                    RateLimiter::new(token_bucket_bytes_per_second, token_bucket_bytes_burst)
                        .unwrap(),
                );
            }
        }
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        {
            if self.is_dead.load(Ordering::Relaxed) {
                bail!("Client is dead");
            }
        }
        Ok(self.conn.local_addr())
    }

    /// Reads a messages from a DERP server.
    ///
    /// The returned message may alias memory owned by the [`Client`]; if
    /// should only be accessed until the next call to [`Client`].
    ///
    /// Once [`recv`] returns an error, the [`Client`] is dead forever.
    pub async fn recv(&mut self) -> Result<ReceivedMessage> {
        self.recv_check_error(Duration::from_secs(120)).await
    }

    async fn recv_check_error(&mut self, timeout_duration: Duration) -> Result<ReceivedMessage> {
        if self.is_dead.load(Ordering::Relaxed) {
            bail!("Client is dead");
        }
        match self.recv_timeout(timeout_duration).await {
            Ok(m) => Ok(m),
            Err(e) => {
                self.is_dead.swap(true, Ordering::Relaxed);
                bail!(e);
            }
        }
    }

    async fn recv_timeout(&mut self, timeout_duration: Duration) -> Result<ReceivedMessage> {
        tokio::select! {
            biased;
            res = self.recv_0() => {
                res
            } _ = tokio::time::sleep(timeout_duration) => {
                bail!("recv call exceeded timeout");
            }
        }
    }

    async fn recv_0(&mut self) -> Result<ReceivedMessage> {
        // in practice, quic packets (and thus DERP frames) are under 1.5 KiB
        let mut frame_payload = BytesMut::with_capacity(1024 + 512);
        loop {
            let (frame_type, frame_len) =
                read_frame(&mut self.reader, MAX_FRAME_SIZE, &mut frame_payload).await?;

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
                    if (frame_len) < PUBLIC_KEY_LENGTH {
                        tracing::warn!(
                            "unexpected: dropping short PEER_GONE frame from DERP server"
                        );
                        continue;
                    }
                    return Ok(ReceivedMessage::PeerGone(PublicKey::try_from(
                        &frame_payload[..PUBLIC_KEY_LENGTH],
                    )?));
                }
                FRAME_PEER_PRESENT => {
                    if (frame_len) < PUBLIC_KEY_LENGTH {
                        tracing::warn!(
                            "unexpected: dropping short PEER_PRESENT frame from DERP server"
                        );
                        continue;
                    }
                    return Ok(ReceivedMessage::PeerPresent(PublicKey::try_from(
                        &frame_payload[..PUBLIC_KEY_LENGTH],
                    )?));
                }
                FRAME_RECV_PACKET => {
                    if (frame_len) < PUBLIC_KEY_LENGTH {
                        tracing::warn!("unexpected: dropping short packet from DERP server");
                        continue;
                    }
                    let (source, data) = parse_recv_frame(&frame_payload)?;
                    let packet = ReceivedMessage::ReceivedPacket {
                        source,
                        data: data.to_vec(),
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

pub struct ClientBuilder<W, R, C>
where
    W: AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + Unpin,
    C: Conn,
{
    secret_key: SecretKey,
    conn: C,
    reader: R,
    writer: W,
    mesh_key: Option<[u8; 32]>,
    is_prober: bool,
    server_public_key: Option<PublicKey>,
    can_ack_pings: bool,
}

impl<W, R, C> ClientBuilder<W, R, C>
where
    W: AsyncWrite + Send + Unpin + 'static,
    R: AsyncRead + Unpin,
    C: Conn,
{
    pub fn new(secret_key: SecretKey, conn: C, reader: R, writer: W) -> Self {
        Self {
            secret_key,
            conn,
            reader,
            writer,
            mesh_key: None,
            is_prober: false,
            server_public_key: None,
            can_ack_pings: false,
        }
    }

    pub fn mesh_key(mut self, mesh_key: [u8; 32]) -> Self {
        self.mesh_key = Some(mesh_key);
        self
    }

    pub fn is_prober(mut self) -> Self {
        self.is_prober = true;
        self
    }

    // TODO: after implementing the [`Server`], I'm 95% sure this was only used for test on the go
    // impl, or at least, we have no use of it in our current set up.
    pub fn server_public_key(mut self, key: PublicKey) -> Self {
        self.server_public_key = Some(key);
        self
    }

    pub fn can_ack_pings(mut self) -> Self {
        self.can_ack_pings = true;
        self
    }

    pub async fn build(mut self) -> Result<Client<W, R, C>>
    where
        W: AsyncWrite + Send + Unpin + 'static,
        R: AsyncRead + Unpin,
        C: Conn,
    {
        // TODO: see `Client::server_public_key` todo, but assigning a server_public_key should
        // probably be removed
        let server_key = if let Some(key) = self.server_public_key {
            key
        } else {
            recv_server_key(&mut self.reader)
                .await
                .context("failed to receive server key")?
        };
        let mut client = Client {
            server_key,
            secret_key: self.secret_key,
            conn: self.conn,
            reader: self.reader,
            mesh_key: self.mesh_key,
            can_ack_pings: self.can_ack_pings,
            is_prober: self.is_prober,
            writer: self.writer,
            rate_limiter: None,
            is_dead: AtomicBool::new(false),
        };

        client.send_client_key().await?;
        Ok(client)
    }
}

pub(crate) async fn recv_server_key<R: AsyncRead + Unpin>(mut reader: R) -> Result<PublicKey> {
    // expecting MAGIC followed by 32 bytes that contain the server key
    let magic_len = MAGIC.len();
    let expected_frame_len = magic_len + 32;
    let mut buf = BytesMut::with_capacity(expected_frame_len);

    let (frame_type, frame_len) = read_frame(&mut reader, MAX_FRAME_SIZE, &mut buf).await?;

    if expected_frame_len != frame_len
        || frame_type != FRAME_SERVER_KEY
        || buf[..magic_len] != *MAGIC.as_bytes()
    {
        bail!("invalid server greeting");
    }

    Ok(get_key_from_slice(&buf[magic_len..expected_frame_len])?)
}

// errors if `frame_len` is less than the expected key size
fn get_key_from_slice(payload: &[u8]) -> Result<PublicKey> {
    Ok(<[u8; PUBLIC_KEY_LENGTH]>::try_from(payload)?.into())
}

#[derive(Debug, Clone)]
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        source: PublicKey,
        /// The received packet bytes. It aliases the memory passed to Client.Recv.
        data: Vec<u8>, // TODO: ref
    },
    /// Indicates that the client identified by the underlying public key had previously sent you a
    /// packet but has now disconnected from the server.
    PeerGone(PublicKey),
    /// Indicates that the client is connected to the server. (Only used by trusted mesh clients)
    PeerPresent(PublicKey),
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

pub(crate) async fn send_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    rate_limiter: &Option<RateLimiter>,
    dstkey: PublicKey,
    packet: &[u8],
) -> Result<()> {
    ensure!(
        packet.len() <= MAX_PACKET_SIZE,
        "packet too big: {}",
        packet.len()
    );
    let frame_len = PUBLIC_KEY_LENGTH + packet.len();
    if let Some(rate_limiter) = rate_limiter {
        if rate_limiter.check_n(frame_len).is_err() {
            tracing::warn!("dropping send: rate limit reached");
            return Ok(());
        }
    }
    write_frame(&mut writer, FRAME_SEND_PACKET, &[dstkey.as_bytes(), packet]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn forward_packet<W: AsyncWrite + Unpin>(
    mut writer: W,
    srckey: PublicKey,
    dstkey: PublicKey,
    packet: &[u8],
) -> Result<()> {
    ensure!(
        packet.len() <= MAX_PACKET_SIZE,
        "packet too big: {}",
        packet.len()
    );

    write_frame(
        &mut writer,
        FRAME_FORWARD_PACKET,
        &[srckey.as_bytes(), dstkey.as_bytes(), packet],
    )
    .await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn send_ping<W: AsyncWrite + Unpin>(mut writer: W, data: &[u8; 8]) -> Result<()> {
    send_ping_or_pong(&mut writer, FRAME_PING, data).await
}

async fn send_pong<W: AsyncWrite + Unpin>(mut writer: W, data: &[u8; 8]) -> Result<()> {
    send_ping_or_pong(&mut writer, FRAME_PONG, data).await
}

async fn send_ping_or_pong<W: AsyncWrite + Unpin>(
    mut writer: W,
    frame_type: FrameType,
    data: &[u8; 8],
) -> Result<()> {
    write_frame(&mut writer, frame_type, &[data]).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn send_note_preferred<W: AsyncWrite + Unpin>(
    mut writer: W,
    preferred: bool,
) -> Result<()> {
    let byte = {
        if preferred {
            [PREFERRED]
        } else {
            [NOT_PREFERRED]
        }
    };
    write_frame(&mut writer, FRAME_NOTE_PREFERRED, &[&byte]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn watch_connection_changes<W: AsyncWrite + Unpin>(mut writer: W) -> Result<()> {
    write_frame(&mut writer, FRAME_WATCH_CONNS, &[]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn close_peer<W: AsyncWrite + Unpin>(
    mut writer: W,
    target: PublicKey,
) -> Result<()> {
    write_frame(&mut writer, FRAME_CLOSE_PEER, &[target.as_bytes()]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) fn parse_recv_frame(frame: &[u8]) -> Result<(PublicKey, &[u8])> {
    ensure!(
        frame.len() >= PUBLIC_KEY_LENGTH,
        "frame is shorter than expected"
    );
    Ok((
        PublicKey::try_from(&frame[..PUBLIC_KEY_LENGTH])?,
        &frame[PUBLIC_KEY_LENGTH..],
    ))
}
