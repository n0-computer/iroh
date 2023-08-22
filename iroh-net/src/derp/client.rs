//! based on tailscale/derp/derp_client.go
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info_span, Instrument};

use super::client_conn::Io;
use super::PER_CLIENT_SEND_QUEUE_DEPTH;
use super::{
    read_frame,
    types::{ClientInfo, MeshKey, RateLimiter, ServerInfo},
    write_frame, FrameType, MAGIC, MAX_FRAME_SIZE, MAX_PACKET_SIZE, NOT_PREFERRED, PREFERRED,
    PROTOCOL_VERSION,
};

use crate::derp::codec::WriteFrame;
use crate::derp::write_frame2;
use crate::key::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH};

const CLIENT_RECV_TIMEOUT: Duration = Duration::from_secs(120);

impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for Client {}

/// A DERP Client.
/// Cheaply clonable.
/// Call `close` to shutdown the write loop and read functionality.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<InnerClient>,
}

#[derive(Debug)]
pub struct InnerClient {
    // our local addrs
    local_addr: SocketAddr,

    /// Channel on which to communicate to the server. The associated [`mpsc::Receiver`] will close
    /// if there is ever an error writing to the server.
    writer_channel: mpsc::Sender<ClientWriterMessage>,
    /// JoinHandle for the [`ClientWriter`] task
    writer_task: Mutex<Option<JoinHandle<Result<()>>>>,
    /// The reader connected to the server
    reader: Mutex<tokio::io::ReadHalf<Box<dyn Io + Send + Sync + 'static>>>,
    /// [`PublicKey`] of the server we are connected to
    server_public_key: PublicKey,
}

impl Client {
    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`super::MAX_PACKET_SIZE`]
    pub async fn send(&self, dstkey: PublicKey, packet: Bytes) -> Result<()> {
        debug!(%dstkey, len = packet.len(), "[DERP] send");

        self.inner
            .writer_channel
            .send(ClientWriterMessage::Packet((dstkey, packet)))
            .await?;
        Ok(())
    }

    /// Used by mesh peers to forward packets.
    ///
    // TODO: this is the only method with a timeout, why? Why does it have a timeout and no rate
    // limiter?
    pub async fn forward_packet(
        &self,
        srckey: PublicKey,
        dstkey: PublicKey,
        packet: Bytes,
    ) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::FwdPacket((srckey, dstkey, packet)))
            .await?;
        Ok(())
    }

    /// Send a ping with 8 bytes of random data.
    pub async fn send_ping(&self, data: [u8; 8]) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::Ping(data))
            .await?;
        Ok(())
    }

    /// Respond to a ping request. The `data` field should be filled
    /// by the 8 bytes of random data send by the ping.
    pub async fn send_pong(&self, data: [u8; 8]) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::Pong(data))
            .await?;
        Ok(())
    }

    /// Sends a packet that tells the server whether this
    /// client is the user's preferred server. This is only
    /// used in the server for stats.
    pub async fn note_preferred(&self, preferred: bool) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::NotePreferred(preferred))
            .await?;
        Ok(())
    }

    /// Sends a request to subscribe to the peer's connection list.
    /// It's a fatal error if the client wasn't created using [`MeshKey`].
    pub async fn watch_connection_changes(&self) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::WatchConnectionChanges)
            .await?;
        Ok(())
    }

    /// Asks the server to close the target's TCP connection.
    ///
    /// It's a fatal error if the client wasn't created using [`MeshKey`]
    pub async fn close_peer(&self, target: PublicKey) -> Result<()> {
        self.inner
            .writer_channel
            .send(ClientWriterMessage::ClosePeer(target))
            .await?;
        Ok(())
    }

    /// The local address that the [`Client`] is listening on.
    pub async fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr)
    }

    /// Whether or not this [`Client`] is closed.
    ///
    /// The [`Client`] is considered closed if the write side of the client is no longer running.
    pub async fn is_closed(&self) -> bool {
        self.inner.writer_task.lock().await.is_none()
    }

    /// Reads a messages from a DERP server.
    ///
    /// The returned message may alias memory owned by the [`Client`]; it
    /// should only be accessed until the next call to [`Client`].
    ///
    /// Once it returns an error, the [`Client`] is dead forever.
    pub async fn recv(&self) -> Result<ReceivedMessage> {
        if self.is_closed().await {
            bail!("client is closed");
        }
        match tokio::time::timeout(CLIENT_RECV_TIMEOUT, self.recv_0()).await {
            Err(e) => {
                self.close().await;
                Err(e.into())
            }
            Ok(Err(e)) => {
                self.close().await;
                Err(e)
            }
            Ok(Ok(msg)) => Ok(msg),
        }
    }

    async fn recv_0(&self) -> Result<ReceivedMessage> {
        // in practice, quic packets (and thus DERP frames) are under 1.5 KiB
        let mut frame_payload = BytesMut::with_capacity(1024 + 512);
        loop {
            let mut reader = self.inner.reader.lock().await;
            let (frame_type, frame_len) =
                match read_frame(&mut *reader, MAX_FRAME_SIZE, &mut frame_payload).await {
                    Ok((t, l)) => (t, l),
                    Err(e) => {
                        self.close().await;
                        bail!(e);
                    }
                };

            match frame_type {
                FrameType::KeepAlive => {
                    // A one-way keep-alive message that doesn't require an ack.
                    // This predated FrameType::Ping/FrameType::Pong.
                    return Ok(ReceivedMessage::KeepAlive);
                }
                FrameType::PeerGone => {
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
                FrameType::PeerPresent => {
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
                FrameType::RecvPacket => {
                    if (frame_len) < PUBLIC_KEY_LENGTH {
                        tracing::warn!("unexpected: dropping short packet from DERP server");
                        continue;
                    }
                    let (source, data) = parse_recv_frame(frame_payload)?;
                    let packet = ReceivedMessage::ReceivedPacket { source, data };
                    return Ok(packet);
                }
                FrameType::Ping => {
                    if frame_len < 8 {
                        tracing::warn!("unexpected: dropping short PING frame");
                        continue;
                    }
                    let ping = <[u8; 8]>::try_from(&frame_payload[..8])?;
                    return Ok(ReceivedMessage::Ping(ping));
                }
                FrameType::Pong => {
                    if frame_len < 8 {
                        tracing::warn!("unexpected: dropping short PONG frame");
                        continue;
                    }
                    let pong = <[u8; 8]>::try_from(&frame_payload[..8])?;
                    return Ok(ReceivedMessage::Pong(pong));
                }
                FrameType::Health => {
                    let problem = Some(String::from_utf8_lossy(&frame_payload).into());
                    return Ok(ReceivedMessage::Health { problem });
                }
                FrameType::Restarting => {
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

    /// Close the client
    ///
    /// Shuts down the write loop directly and marks the client as closed. The [`Client`] will
    /// check if the client is closed before attempting to read from it.
    pub async fn close(&self) {
        let mut writer_task = self.inner.writer_task.lock().await;
        let task = writer_task.take();
        match task {
            None => {}
            Some(task) => {
                // only error would be that the writer_channel receiver is closed
                let _ = self
                    .inner
                    .writer_channel
                    .send(ClientWriterMessage::Shutdown)
                    .await;
                match task.await {
                    Ok(Err(e)) => {
                        tracing::warn!("error closing down the client: {e:?}");
                    }
                    Err(e) => {
                        tracing::warn!("error closing down the client: {e:?}");
                    }
                    _ => {}
                }
            }
        }
    }

    /// The [`PublicKey`] of the [`super::server::Server`] this [`Client`] is connected with.
    pub fn server_public_key(self) -> PublicKey {
        self.inner.server_public_key
    }
}

/// The kinds of messages we can send to the [`super::server::Server`]
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ClientWriterMessage {
    /// Send a packet (addressed to the [`PublicKey`]) to the server
    Packet((PublicKey, Bytes)),
    /// Forward a packet from the src [`PublicKey`] to the dst [`PublicKey`] to the server
    /// Should only be used for mesh clients.
    FwdPacket((PublicKey, PublicKey, Bytes)),
    /// Send a pong to the server
    Pong([u8; 8]),
    /// Send a ping to the server
    Ping([u8; 8]),
    /// Tell the server whether or not this client is the user's preferred client
    NotePreferred(bool),
    /// Subscribe to the server's connection list.
    /// Should only be used for mesh clients.
    WatchConnectionChanges,
    /// Asks the server to close the target's connection.
    /// Should only be used for mesh clients.
    ClosePeer(PublicKey),
    /// Shutdown the writer
    Shutdown,
}

/// Call [`ClientWriter::run`] to listen for messages to send to the client.
/// Should be used by the [`Client`]
///
/// Shutsdown when you send a [`ClientWriterMessage::Shutdown`], or if there is an error writing to
/// the server.
struct ClientWriter<W: AsyncWrite + Unpin + Send + 'static> {
    recv_msgs: mpsc::Receiver<ClientWriterMessage>,
    writer: W,
    rate_limiter: Option<RateLimiter>,
}

impl<W: AsyncWrite + Unpin + Send + 'static> ClientWriter<W> {
    async fn run(mut self) -> Result<()> {
        loop {
            match self.recv_msgs.recv().await {
                None => {
                    bail!("channel unexpectedly closed");
                }
                Some(ClientWriterMessage::Packet((key, bytes))) => {
                    // TODO: the rate limiter is only used on this method, is it because it's the only method that
                    // theoretically sends a bunch of data, or is it an oversight? For example,
                    // the `forward_packet` method does not have a rate limiter, but _does_ have a timeout.
                    send_packet(&mut self.writer, &self.rate_limiter, key, &bytes).await?;
                }
                Some(ClientWriterMessage::FwdPacket((srckey, dstkey, bytes))) => {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        forward_packet(&mut self.writer, srckey, dstkey, &bytes),
                    )
                    .await??;
                }
                Some(ClientWriterMessage::Pong(msg)) => {
                    send_pong(&mut self.writer, &msg).await?;
                }
                Some(ClientWriterMessage::Ping(msg)) => {
                    send_ping(&mut self.writer, &msg).await?;
                }
                Some(ClientWriterMessage::NotePreferred(preferred)) => {
                    send_note_preferred(&mut self.writer, preferred).await?;
                }
                Some(ClientWriterMessage::WatchConnectionChanges) => {
                    watch_connection_changes(&mut self.writer).await?;
                }
                Some(ClientWriterMessage::ClosePeer(target)) => {
                    close_peer(&mut self.writer, target).await?;
                }
                Some(ClientWriterMessage::Shutdown) => {
                    return Ok(());
                }
            }
        }
    }
}

/// The Builder returns a [`Client`] starts a [`ClientWriter`] run task.
pub struct ClientBuilder<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    secret_key: SecretKey,
    reader: tokio::io::ReadHalf<Box<dyn Io + Send + Sync + 'static>>,
    writer: W,
    local_addr: SocketAddr,
    mesh_key: Option<MeshKey>,
    is_prober: bool,
    server_public_key: Option<PublicKey>,
    can_ack_pings: bool,
}

impl<W> ClientBuilder<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    pub fn new(
        secret_key: SecretKey,
        local_addr: SocketAddr,
        reader: tokio::io::ReadHalf<Box<dyn Io + Send + Sync + 'static>>,
        writer: W,
    ) -> Self {
        Self {
            secret_key,
            reader,
            writer,
            local_addr,
            mesh_key: None,
            is_prober: false,
            server_public_key: None,
            can_ack_pings: false,
        }
    }

    pub fn mesh_key(mut self, mesh_key: Option<MeshKey>) -> Self {
        self.mesh_key = mesh_key;
        self
    }

    pub fn prober(mut self, is_prober: bool) -> Self {
        self.is_prober = is_prober;
        self
    }

    // Set the expected server_public_key. If this is not what is sent by the
    // [`super::server::Server`], it is an error.
    pub fn server_public_key(mut self, key: Option<PublicKey>) -> Self {
        self.server_public_key = key;
        self
    }

    pub fn can_ack_pings(mut self, can_ack_pings: bool) -> Self {
        self.can_ack_pings = can_ack_pings;
        self
    }

    async fn server_handshake(
        &mut self,
        buf: Option<Bytes>,
    ) -> Result<(PublicKey, Option<RateLimiter>)> {
        debug!("server_handshake: started");
        let server_key = if let Some(buf) = buf {
            recv_server_key(buf.chain(&mut self.reader))
                .await
                .context("failed to receive server key")?
        } else {
            recv_server_key(&mut self.reader)
                .await
                .context("failed to receive server key")?
        };
        debug!("server_handshake: received server_key: {:?}", server_key);

        if let Some(expected_key) = &self.server_public_key {
            if *expected_key != server_key {
                bail!("unexpected server key, expected {expected_key:?} got {server_key:?}");
            }
        }
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
            mesh_key: self.mesh_key,
            can_ack_pings: self.can_ack_pings,
            is_prober: self.is_prober,
        };
        debug!("server_handshake: sending client_key: {:?}", &client_info);
        let shared_secret = self.secret_key.shared(&server_key);
        crate::derp::send_client_key(
            &mut self.writer,
            &shared_secret,
            &self.secret_key.public(),
            &client_info,
        )
        .await?;
        let mut buf = BytesMut::new();
        let (frame_type, _) =
            crate::derp::read_frame(&mut self.reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(FrameType::ServerInfo, frame_type);
        shared_secret.open(&mut buf)?;
        let info: ServerInfo = postcard::from_bytes(&buf)?;
        if info.version != PROTOCOL_VERSION {
            bail!(
                "incompatiable protocol version, expected {PROTOCOL_VERSION}, got {}",
                info.version
            );
        }
        let rate_limiter = RateLimiter::new(
            info.token_bucket_bytes_per_second,
            info.token_bucket_bytes_burst,
        )?;

        debug!("server_handshake: done");
        Ok((server_key, rate_limiter))
    }

    pub async fn build(mut self, buf: Option<Bytes>) -> Result<Client> {
        // exchange information with the server
        let (server_public_key, rate_limiter) = self.server_handshake(buf).await?;

        // create task to handle writing to the server
        let (writer_sender, writer_recv) = mpsc::channel(PER_CLIENT_SEND_QUEUE_DEPTH);
        let writer_task = tokio::spawn(
            async move {
                let client_writer = ClientWriter {
                    rate_limiter,
                    writer: self.writer,
                    recv_msgs: writer_recv,
                };
                client_writer.run().await?;
                Ok(())
            }
            .instrument(info_span!("client.writer")),
        );

        let client = Client {
            inner: Arc::new(InnerClient {
                local_addr: self.local_addr,
                writer_channel: writer_sender,
                writer_task: Mutex::new(Some(writer_task)),
                reader: Mutex::new(self.reader),
                server_public_key,
            }),
        };

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
        || frame_type != FrameType::ServerKey
        || buf[..magic_len] != *MAGIC.as_bytes()
    {
        bail!("invalid server greeting");
    }

    get_key_from_slice(&buf[magic_len..expected_frame_len])
}

// errors if `frame_len` is less than the expected [`PUBLIC_KEY_LENGTH`]
fn get_key_from_slice(payload: &[u8]) -> Result<PublicKey> {
    let key = PublicKey::try_from(&payload[..PUBLIC_KEY_LENGTH])?;
    Ok(key)
}

#[derive(derive_more::Debug, Clone)]
/// The type of message received by the [`Client`] from the [`super::server::Server`].
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        /// The [`PublicKey`] of the packet sender.
        source: PublicKey,
        /// The received packet bytes. It aliases the memory passed to [`Client::recv`].
        #[debug(skip)]
        data: Bytes, // TODO: ref
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
        /// How many bytes the server will allow in one burst, temporarily violating
        /// `token_bucket_bytes_per_second`.
        ///
        /// Zero means unspecified. There might be a limit, but the [`Client`] need not try to respect it.
        token_bucket_bytes_burst: usize,
    },
    /// Request from a client or server to reply to the
    /// other side with a [`ReceivedMessage::Pong`] with the given payload.
    Ping([u8; 8]),
    /// Reply to a [`ReceivedMessage::Ping`] from a client or server
    /// with the payload sent previously in the ping.
    Pong([u8; 8]),
    /// A one-way empty message from server to client, just to
    /// keep the connection alive. It's like a [ReceivedMessage::Ping], but doesn't solicit
    /// a reply from the client.
    KeepAlive,
    /// A one-way message from server to client, declaring the connection health state.
    Health {
        /// If set, is a description of why the connection is unhealthy.
        ///
        /// If `None` means the connection is healthy again.
        ///
        /// The default condition is healthy, so the server doesn't broadcast a [`ReceivedMessage::Health`]
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
    write_frame2(
        &mut writer,
        WriteFrame::SendPacket {
            dst_key: dstkey,
            packet: packet.to_vec().into(),
        }
    )
    .await?;
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
        FrameType::ForwardPacket,
        &[srckey.as_bytes(), dstkey.as_bytes(), packet],
    )
    .await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn send_ping<W: AsyncWrite + Unpin>(mut writer: W, data: &[u8; 8]) -> Result<()> {
    send_ping_or_pong(&mut writer, FrameType::Ping, data).await
}

async fn send_pong<W: AsyncWrite + Unpin>(mut writer: W, data: &[u8; 8]) -> Result<()> {
    send_ping_or_pong(&mut writer, FrameType::Pong, data).await
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
    write_frame(&mut writer, FrameType::NotePreferred, &[&byte]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn watch_connection_changes<W: AsyncWrite + Unpin>(mut writer: W) -> Result<()> {
    write_frame(&mut writer, FrameType::WatchConns, &[]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn close_peer<W: AsyncWrite + Unpin>(
    mut writer: W,
    target: PublicKey,
) -> Result<()> {
    write_frame(&mut writer, FrameType::ClosePeer, &[target.as_bytes()]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) fn parse_recv_frame(frame: BytesMut) -> Result<(PublicKey, Bytes)> {
    ensure!(
        frame.len() >= PUBLIC_KEY_LENGTH,
        "frame is shorter than expected"
    );
    Ok((
        PublicKey::try_from(&frame[..PUBLIC_KEY_LENGTH])?,
        frame.freeze().slice(PUBLIC_KEY_LENGTH..),
    ))
}
