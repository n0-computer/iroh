//! based on tailscale/derp/derp_client.go
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Result};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use futures_sink::Sink;
use futures_util::sink::SinkExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, info_span, trace, Instrument};

use super::codec::PER_CLIENT_READ_QUEUE_DEPTH;
use super::{
    codec::{
        write_frame, DerpCodec, Frame, MAX_PACKET_SIZE, PER_CLIENT_SEND_QUEUE_DEPTH,
        PROTOCOL_VERSION,
    },
    types::{ClientInfo, RateLimiter},
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

/// A relay Client.
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
    /// Reads a messages from a relay server.
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

type RelayReader = FramedRead<Box<dyn AsyncRead + Unpin + Send + Sync + 'static>, DerpCodec>;

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
}

impl Client {
    /// Sends a packet to the node identified by `dstkey`
    ///
    /// Errors if the packet is larger than [`super::MAX_PACKET_SIZE`]
    pub async fn send(&self, dstkey: PublicKey, packet: Bytes) -> Result<()> {
        trace!(%dstkey, len = packet.len(), "[RELAY] send");

        self.inner
            .writer_channel
            .send(ClientWriterMessage::Packet((dstkey, packet)))
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
}

fn process_incoming_frame(frame: Frame) -> Result<ReceivedMessage> {
    match frame {
        Frame::KeepAlive => {
            // A one-way keep-alive message that doesn't require an ack.
            // This predated FrameType::Ping/FrameType::Pong.
            Ok(ReceivedMessage::KeepAlive)
        }
        Frame::PeerGone { peer } => Ok(ReceivedMessage::PeerGone(peer)),
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
    /// Send a pong to the server
    Pong([u8; 8]),
    /// Send a ping to the server
    Ping([u8; 8]),
    /// Tell the server whether or not this client is the user's preferred client
    NotePreferred(bool),
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
                    send_packet(&mut self.writer, &self.rate_limiter, key, bytes).await?;
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
    reader: RelayReader,
    writer: FramedWrite<Box<dyn AsyncWrite + Unpin + Send + Sync + 'static>, DerpCodec>,
    local_addr: SocketAddr,
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
        }
    }

    async fn server_handshake(&mut self) -> Result<Option<RateLimiter>> {
        debug!("server_handshake: started");
        let client_info = ClientInfo {
            version: PROTOCOL_VERSION,
        };
        debug!("server_handshake: sending client_key: {:?}", &client_info);
        crate::relay::codec::send_client_key(&mut self.writer, &self.secret_key, &client_info)
            .await?;

        // TODO: add some actual configuration
        let rate_limiter = RateLimiter::new(0, 0)?;

        debug!("server_handshake: done");
        Ok(rate_limiter)
    }

    pub async fn build(mut self) -> Result<(Client, ClientReceiver)> {
        // exchange information with the server
        let rate_limiter = self.server_handshake().await?;

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
            }),
        };

        let client_receiver = ClientReceiver {
            reader_channel: reader_recv,
        };

        Ok((client, client_receiver))
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
