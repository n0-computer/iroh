//! based on tailscale/derp/derp_client.go
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bytes::Bytes;
use futures::stream::Stream;
use futures::{Sink, SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info_span, trace, Instrument};

use super::codec::PER_CLIENT_READ_QUEUE_DEPTH;
use super::{
    codec::{
        recv_frame, write_frame, DerpCodec, Frame, FrameType, MAX_PACKET_SIZE,
        PER_CLIENT_SEND_QUEUE_DEPTH, PROTOCOL_VERSION,
    },
    types::{ClientInfo, MeshKey, RateLimiter, ServerInfo},
};

use crate::key::{PublicKey, SecretKey};
use crate::util::AbortingJoinHandle;

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
pub struct ClientReceiver {
    /// The reader channel, receiving incoming messages.
    reader_channel: mpsc::Receiver<Result<ReceivedMessage>>,
}

impl ClientReceiver {
    /// Reads a messages from a DERP server.
    ///
    /// Once it returns an error, the [`Client`] is dead forever.
    pub async fn recv(&mut self) -> Result<ReceivedMessage> {
        let msg = self
            .reader_channel
            .recv()
            .await
            .ok_or(anyhow!("shut down"))??;
        Ok(msg)
    }
}

type DerpReader = FramedRead<Box<dyn AsyncRead + Unpin + Send + Sync + 'static>, DerpCodec>;

#[derive(derive_more::Debug)]
pub struct InnerClient {
    // our local addrs
    local_addr: SocketAddr,
    /// Channel on which to communicate to the server. The associated [`mpsc::Receiver`] will close
    /// if there is ever an error writing to the server.
    writer_channel: mpsc::Sender<ClientWriterMessage>,
    /// JoinHandle for the [`ClientWriter`] task
    writer_task: AbortingJoinHandle<Result<()>>,
    reader_task: AbortingJoinHandle<()>,
    /// [`PublicKey`] of the server we are connected to
    server_public_key: PublicKey,
}

impl Client {
    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`super::MAX_PACKET_SIZE`]
    pub async fn send(&self, dstkey: PublicKey, packet: Bytes) -> Result<()> {
        trace!(%dstkey, len = packet.len(), "[DERP] send");

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
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.inner.local_addr)
    }

    /// Whether or not this [`Client`] is closed.
    ///
    /// The [`Client`] is considered closed if the write side of the client is no longer running.
    pub fn is_closed(&self) -> bool {
        self.inner.writer_task.is_finished()
    }

    /// Close the client
    ///
    /// Shuts down the write loop directly and marks the client as closed. The [`Client`] will
    /// check if the client is closed before attempting to read from it.
    pub async fn close(&self) {
        if self.inner.writer_task.is_finished() && self.inner.reader_task.is_finished() {
            return;
        }

        self.inner
            .writer_channel
            .send(ClientWriterMessage::Shutdown)
            .await
            .ok();
        self.inner.reader_task.abort();
    }

    /// The [`PublicKey`] of the [`super::server::Server`] this [`Client`] is connected with.
    pub fn server_public_key(self) -> PublicKey {
        self.inner.server_public_key
    }
}

fn process_incoming_frame(frame: Frame) -> Result<ReceivedMessage> {
    match frame {
        Frame::KeepAlive => {
            // A one-way keep-alive message that doesn't require an ack.
            // This predated FrameType::Ping/FrameType::Pong.
            Ok(ReceivedMessage::KeepAlive)
        }
        Frame::PeerGone { peer } => Ok(ReceivedMessage::PeerGone(peer)),
        Frame::PeerPresent { peer } => Ok(ReceivedMessage::PeerPresent(peer)),
        Frame::RecvPacket { src_key, content } => {
            let packet = ReceivedMessage::ReceivedPacket {
                source: src_key,
                data: content,
            };
            Ok(packet)
        }
        Frame::Ping { data } => Ok(ReceivedMessage::Ping(data)),
        Frame::Pong { data } => Ok(ReceivedMessage::Pong(data)),
        Frame::Health { problem } => {
            let problem = std::str::from_utf8(&problem)?.to_owned();
            let problem = Some(problem);
            Ok(ReceivedMessage::Health { problem })
        }
        Frame::Restarting {
            reconnect_in,
            try_for,
        } => {
            let reconnect_in = Duration::from_millis(reconnect_in as u64);
            let try_for = Duration::from_millis(try_for as u64);
            Ok(ReceivedMessage::ServerRestarting {
                reconnect_in,
                try_for,
            })
        }
        _ => bail!("unexpected packet: {:?}", frame.typ()),
    }
}

/// The kinds of messages we can send to the [`super::server::Server`]
#[derive(Debug)]
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
    writer: FramedWrite<W, DerpCodec>,
    rate_limiter: Option<RateLimiter>,
}

impl<W: AsyncWrite + Unpin + Send + 'static> ClientWriter<W> {
    async fn run(mut self) -> Result<()> {
        while let Some(msg) = self.recv_msgs.recv().await {
            match msg {
                ClientWriterMessage::Packet((key, bytes)) => {
                    // TODO: the rate limiter is only used on this method, is it because it's the only method that
                    // theoretically sends a bunch of data, or is it an oversight? For example,
                    // the `forward_packet` method does not have a rate limiter, but _does_ have a timeout.
                    send_packet(&mut self.writer, &self.rate_limiter, key, bytes).await?;
                }
                ClientWriterMessage::FwdPacket((srckey, dstkey, bytes)) => {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        forward_packet(&mut self.writer, srckey, dstkey, bytes),
                    )
                    .await??;
                }
                ClientWriterMessage::Pong(data) => {
                    write_frame(&mut self.writer, Frame::Pong { data }, None).await?;
                    self.writer.flush().await?;
                }
                ClientWriterMessage::Ping(data) => {
                    write_frame(&mut self.writer, Frame::Ping { data }, None).await?;
                    self.writer.flush().await?;
                }
                ClientWriterMessage::NotePreferred(preferred) => {
                    write_frame(&mut self.writer, Frame::NotePreferred { preferred }, None).await?;
                    self.writer.flush().await?;
                }
                ClientWriterMessage::WatchConnectionChanges => {
                    write_frame(&mut self.writer, Frame::WatchConns, None).await?;
                    self.writer.flush().await?;
                }
                ClientWriterMessage::ClosePeer(peer) => {
                    write_frame(&mut self.writer, Frame::ClosePeer { peer }, None).await?;
                    self.writer.flush().await?;
                }
                ClientWriterMessage::Shutdown => {
                    return Ok(());
                }
            }
        }

        bail!("channel unexpectedly closed");
    }
}

/// The Builder returns a [`Client`] starts a [`ClientWriter`] run task.
pub struct ClientBuilder {
    secret_key: SecretKey,
    reader: DerpReader,
    writer: FramedWrite<Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>, DerpCodec>,
    local_addr: SocketAddr,
    mesh_key: Option<MeshKey>,
    is_prober: bool,
    server_public_key: Option<PublicKey>,
    can_ack_pings: bool,
}

impl ClientBuilder {
    pub fn new(
        secret_key: SecretKey,
        local_addr: SocketAddr,
        reader: Box<dyn AsyncRead + Unpin + Send + Sync + 'static>,
        writer: Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>,
    ) -> Self {
        Self {
            secret_key,
            reader: FramedRead::new(reader, DerpCodec),
            writer: FramedWrite::new(writer, DerpCodec),
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

    async fn server_handshake(&mut self) -> Result<(PublicKey, Option<RateLimiter>)> {
        debug!("server_handshake: started");
        let server_key = recv_server_key(&mut self.reader)
            .await
            .context("failed to receive server key")?;

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
        crate::derp::codec::send_client_key(
            &mut self.writer,
            &shared_secret,
            &self.secret_key.public(),
            &client_info,
        )
        .await?;

        let Frame::ServerInfo { encrypted_message } =
            recv_frame(FrameType::ServerInfo, &mut self.reader).await?
        else {
            bail!("expected server info");
        };
        let mut buf = encrypted_message.to_vec();
        shared_secret.open(&mut buf)?;
        let info: ServerInfo = postcard::from_bytes(&buf)?;
        if info.version != PROTOCOL_VERSION {
            bail!(
                "incompatible protocol version, expected {PROTOCOL_VERSION}, got {}",
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

    pub async fn build(mut self) -> Result<(Client, ClientReceiver)> {
        // exchange information with the server
        let (server_public_key, rate_limiter) = self.server_handshake().await?;

        // create task to handle writing to the server
        let (writer_sender, writer_recv) = mpsc::channel(PER_CLIENT_SEND_QUEUE_DEPTH);
        let writer_task = tokio::task::spawn(
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

        let (reader_sender, reader_recv) = mpsc::channel(PER_CLIENT_READ_QUEUE_DEPTH);
        let writer_sender2 = writer_sender.clone();
        let reader_task = tokio::task::spawn(async move {
            loop {
                let frame = tokio::time::timeout(CLIENT_RECV_TIMEOUT, self.reader.next()).await;
                let res = match frame {
                    Ok(Some(Ok(frame))) => process_incoming_frame(frame),
                    Ok(Some(Err(err))) => {
                        // Error processing incoming messages
                        Err(err)
                    }
                    Ok(None) => {
                        // EOF
                        Err(anyhow::anyhow!("EOF: reader stream ended"))
                    }
                    Err(err) => {
                        // Timeout
                        Err(err.into())
                    }
                };
                if res.is_err() {
                    // shutdown
                    writer_sender2
                        .send(ClientWriterMessage::Shutdown)
                        .await
                        .ok();
                    break;
                }
                if reader_sender.send(res).await.is_err() {
                    // shutdown, as the reader is gone
                    writer_sender2
                        .send(ClientWriterMessage::Shutdown)
                        .await
                        .ok();
                    break;
                }
            }
        });

        let client = Client {
            inner: Arc::new(InnerClient {
                local_addr: self.local_addr,
                writer_channel: writer_sender,
                writer_task: writer_task.into(),
                reader_task: reader_task.into(),
                server_public_key,
            }),
        };

        let client_receiver = ClientReceiver {
            reader_channel: reader_recv,
        };

        Ok((client, client_receiver))
    }
}

pub(crate) async fn recv_server_key<S: Stream<Item = anyhow::Result<Frame>> + Unpin>(
    stream: S,
) -> Result<PublicKey> {
    if let Frame::ServerKey { key } = recv_frame(FrameType::ServerKey, stream).await? {
        Ok(key)
    } else {
        bail!("expected server key");
    }
}

#[derive(derive_more::Debug, Clone)]
/// The type of message received by the [`Client`] from the [`super::server::Server`].
pub enum ReceivedMessage {
    /// Represents an incoming packet.
    ReceivedPacket {
        /// The [`PublicKey`] of the packet sender.
        source: PublicKey,
        /// The received packet bytes.
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

pub(crate) async fn send_packet<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    rate_limiter: &Option<RateLimiter>,
    dst_key: PublicKey,
    packet: Bytes,
) -> Result<()> {
    ensure!(
        packet.len() <= MAX_PACKET_SIZE,
        "packet too big: {}",
        packet.len()
    );

    let frame = Frame::SendPacket { dst_key, packet };
    if let Some(rate_limiter) = rate_limiter {
        if rate_limiter.check_n(frame.len()).is_err() {
            tracing::warn!("dropping send: rate limit reached");
            return Ok(());
        }
    }
    writer.send(frame).await?;
    writer.flush().await?;

    Ok(())
}

pub(crate) async fn forward_packet<S: Sink<Frame, Error = std::io::Error> + Unpin>(
    mut writer: S,
    src_key: PublicKey,
    dst_key: PublicKey,
    packet: Bytes,
) -> Result<()> {
    ensure!(
        packet.len() <= MAX_PACKET_SIZE,
        "packet too big: {}",
        packet.len()
    );

    write_frame(
        &mut writer,
        Frame::ForwardPacket {
            src_key,
            dst_key,
            packet,
        },
        None,
    )
    .await?;
    writer.flush().await?;
    Ok(())
}
