//! The server-side representation of an ongoing client relaying connection.

use std::{future::Future, num::NonZeroU32, pin::Pin, sync::Arc, task::Poll, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_sink::Sink;
use futures_util::{SinkExt, Stream, StreamExt};
use iroh_base::key::NodeId;
use iroh_metrics::{inc, inc_by};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{error, info, instrument, trace, warn, Instrument};

use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, KEEP_ALIVE},
    },
    server::{
        actor::{self, Packet},
        metrics::Metrics,
        streams::RelayedStream,
        ClientConnRateLimit,
    },
};

/// Configuration for a [`ClientConn`].
#[derive(Debug)]
pub(super) struct ClientConnConfig {
    pub(super) node_id: NodeId,
    pub(super) stream: RelayedStream,
    pub(super) write_timeout: Duration,
    pub(super) channel_capacity: usize,
    pub(super) rate_limit: ClientConnRateLimit,
    pub(super) server_channel: mpsc::Sender<actor::Message>,
}

/// The [`Server`] side representation of a [`Client`]'s connection.
///
/// [`Server`]: crate::server::Server
/// [`Client`]: crate::client::Client
#[derive(Debug)]
pub(super) struct ClientConn {
    /// Unique counter, incremented each time we accept a new connection.
    pub(super) conn_num: usize,
    /// Identity of the connected peer.
    pub(super) key: NodeId,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: AbortOnDropHandle<()>,
    /// Queue of packets intended for the client.
    pub(super) send_queue: mpsc::Sender<Packet>,
    /// Queue of disco packets intended for the client.
    pub(super) disco_send_queue: mpsc::Sender<Packet>,
    /// Channel to notify the client that a previous sender has disconnected.
    pub(super) peer_gone: mpsc::Sender<NodeId>,
}

impl ClientConn {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    /// Call [`ClientConn::shutdown`] to close the read and write loops before dropping the [`ClientConn`]
    pub fn new(config: ClientConnConfig, conn_num: usize) -> ClientConn {
        let ClientConnConfig {
            node_id: key,
            stream: io,
            write_timeout,
            channel_capacity,
            rate_limit: rate_limit_config,
            server_channel,
        } = config;

        let quota = governor::Quota::per_second(rate_limit_config.bytes_per_second)
            .allow_burst(rate_limit_config.max_burst_bytes);
        // TODO: Allow creating this with mocked time for tests?
        let rate_limiter = governor::RateLimiter::direct(quota);
        let stream = RateLimitedRelayedStream::new(io, rate_limiter);

        let done = CancellationToken::new();
        let client_id = (key, conn_num);
        let (send_queue_s, send_queue_r) = mpsc::channel(channel_capacity);

        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(channel_capacity);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(channel_capacity);

        let actor = Actor {
            stream,
            timeout: write_timeout,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,
            key,
            preferred: false,
            server_channel: server_channel.clone(),
        };

        // start io loop
        let io_done = done.clone();
        let io_client_id = client_id;
        let handle = tokio::task::spawn(
            async move {
                let (key, conn_num) = io_client_id;
                let res = actor.run(io_done).await;

                // remove the client when the actor terminates, no matter how it exits
                let _ = server_channel
                    .send(actor::Message::RemoveClient {
                        node_id: key,
                        conn_num,
                    })
                    .await;
                match res {
                    Err(e) => {
                        warn!(
                            "connection manager for {key:?} {conn_num}: writer closed in error {e}"
                        );
                    }
                    Ok(()) => {
                        info!("connection manager for {key:?} {conn_num}: writer closed");
                    }
                }
            }
            .instrument(tracing::info_span!("client_conn_actor")),
        );

        ClientConn {
            conn_num,
            key,
            handle: AbortOnDropHandle::new(handle),
            done,
            send_queue: send_queue_s,
            disco_send_queue: disco_send_queue_s,
            peer_gone: peer_gone_s,
        }
    }

    /// Shutdown the reader and writer loops and closes the connection.
    ///
    /// Any shutdown errors will be logged as warnings.
    pub async fn shutdown(self) {
        self.done.cancel();
        if let Err(e) = self.handle.await {
            warn!(
                "error closing actor loop for client connection {:?} {}: {e:?}",
                self.key, self.conn_num
            );
        };
    }
}

/// Manages all the reads and writes to this client. It periodically sends a `KEEP_ALIVE`
/// message to the client to keep the connection alive.
///
/// Call `run` to manage the input and output to and from the connection and the server.
/// Once it hits its first write error or error receiving off a channel,
/// it errors on return.
/// If writes do not complete in the given `timeout`, it will also error.
///
/// On the "write" side, the [`Actor`] can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame to inform the client that a peer they have previously sent messages to
///    is gone from the network
///  - packets from other peers
///
/// On the "read" side, it can:
///     - receive a ping and write a pong back
///     - note whether the client is `preferred`, aka this client is the preferred way
///     to speak to the node ID associated with that client.
#[derive(Debug)]
struct Actor {
    /// IO Stream to talk to the client
    stream: RateLimitedRelayedStream,
    /// Maximum time we wait to complete a write to the client
    timeout: Duration,
    /// Packets queued to send to the client
    send_queue: mpsc::Receiver<Packet>,
    /// Important packets queued to send to the client
    disco_send_queue: mpsc::Receiver<Packet>,
    /// Notify the client that a previous sender has disconnected
    node_gone: mpsc::Receiver<NodeId>,
    /// [`NodeId`] of this client
    key: NodeId,
    /// Channel used to communicate with the server about actions
    /// it needs to take on behalf of the client
    server_channel: mpsc::Sender<actor::Message>,
    /// Notes that the client considers this the preferred connection (important in cases
    /// where the client moves to a different network, but has the same NodeId)
    preferred: bool,
}

impl Actor {
    async fn run(mut self, done: CancellationToken) -> Result<()> {
        let jitter = Duration::from_secs(5);
        let mut keep_alive = tokio::time::interval(KEEP_ALIVE + jitter);
        // ticks immediately
        keep_alive.tick().await;

        loop {
            tokio::select! {
                biased;

                _ = done.cancelled() => {
                    trace!("actor loop cancelled, exiting");
                    // final flush
                    self.stream.flush().await.context("flush")?;
                    break;
                }
                read_res = self.stream.next() => {
                    trace!("handle frame");
                    match read_res {
                        Some(Ok(frame)) => {
                            self.handle_frame(frame).await.context("handle_read")?;
                        }
                        Some(Err(err)) => {
                            return Err(err);
                        }
                        None => {
                            // Unexpected EOF
                            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read stream ended").into());
                        }
                    }
                }
                node_id = self.node_gone.recv() => {
                    let node_id = node_id.context("Server.node_gone dropped")?;
                    trace!("node_id gone: {:?}", node_id);
                    self.write_frame(Frame::NodeGone { node_id }).await?;
                }
                packet = self.send_queue.recv() => {
                    let packet = packet.context("Server.send_queue dropped")?;
                    trace!("send packet");
                    self.send_packet(packet).await.context("send packet")?;
                }
                packet = self.disco_send_queue.recv() => {
                    let packet = packet.context("Server.disco_send_queue dropped")?;
                    trace!("send disco packet");
                    self.send_packet(packet).await.context("send packet")?;
                }
                _ = keep_alive.tick() => {
                    trace!("keep alive");
                    self.write_frame(Frame::KeepAlive).await?;
                }
            }
            self.stream.flush().await.context("tick flush")?;
        }
        Ok(())
    }

    /// Writes the given frame to the connection.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn write_frame(&mut self, frame: Frame) -> Result<()> {
        write_frame(&mut self.stream, frame, Some(self.timeout)).await
    }

    /// Writes contents to the client in a `RECV_PACKET` frame.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    /// Does not flush.
    async fn send_packet(&mut self, packet: Packet) -> Result<()> {
        let src_key = packet.src;
        let content = packet.data;

        if let Ok(len) = content.len().try_into() {
            inc_by!(Metrics, bytes_sent, len);
        }
        self.write_frame(Frame::RecvPacket { src_key, content })
            .await
    }

    /// Handles frame read results.
    async fn handle_frame(&mut self, frame: Frame) -> Result<()> {
        // TODO: "note client activity", meaning we update the server that the client with this
        // public key was the last one to receive data
        // it will be relevant when we add the ability to hold onto multiple clients
        // for the same public key
        match frame {
            Frame::NotePreferred { preferred } => {
                self.preferred = preferred;
                inc!(Metrics, other_packets_recv);
            }
            Frame::SendPacket { dst_key, packet } => {
                let packet_len = packet.len();
                self.handle_frame_send_packet(dst_key, packet).await?;
                inc_by!(Metrics, bytes_recv, packet_len as u64);
            }
            Frame::Ping { data } => {
                inc!(Metrics, got_ping);
                // TODO: add rate limiter
                self.write_frame(Frame::Pong { data }).await?;
                inc!(Metrics, sent_pong);
            }
            Frame::Health { .. } => {
                inc!(Metrics, other_packets_recv);
            }
            _ => {
                inc!(Metrics, unknown_frames);
            }
        }
        Ok(())
    }

    async fn handle_frame_send_packet(&self, dst_key: NodeId, data: Bytes) -> Result<()> {
        let message = if disco::looks_like_disco_wrapper(&data) {
            inc!(Metrics, disco_packets_recv);
            actor::Message::SendDiscoPacket {
                dst: dst_key,
                src: self.key,
                data,
            }
        } else {
            inc!(Metrics, send_packets_recv);
            actor::Message::SendPacket {
                dst: dst_key,
                src: self.key,
                data,
            }
        };

        self.server_channel
            .send(message)
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;
        Ok(())
    }
}

/// Rate limiter for reading from a [`RelayedStream`].
///
/// The writes to the sink are not rate limited.
///
/// This potentially buffers one frame if the rate limiter does not allows this frame.
/// While the frame is buffered the undernlying stream is no longer polled.
#[derive(derive_more::Debug)]
struct RateLimitedRelayedStream {
    inner: RelayedStream,
    limiter: Arc<governor::DefaultDirectRateLimiter>,
    #[debug("Option<Pin<Box<dyn Future<Output = ()>>>>")]
    delay: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
    buf: Option<anyhow::Result<Frame>>,
}

impl RateLimitedRelayedStream {
    fn new(inner: RelayedStream, limiter: governor::DefaultDirectRateLimiter) -> Self {
        Self {
            inner,
            limiter: Arc::new(limiter),
            delay: None,
            buf: None,
        }
    }
}

impl Stream for RateLimitedRelayedStream {
    type Item = anyhow::Result<Frame>;

    #[instrument(name = "rate_limited_relayed_stream", skip_all)]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            // If we have a delay installed, we need to await it.
            if let Some(ref mut wait_fut) = self.delay {
                tokio::pin!(wait_fut);
                match wait_fut.poll(cx) {
                    Poll::Ready(_) => {
                        self.delay.take();
                        continue;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            // If we have an item buffered, check if we can yield it.
            if let Some(ref item) = self.buf {
                match item {
                    Err(_) => {
                        // Yielding errors is not rate-limited.
                        match self.buf.take() {
                            Some(item) => return Poll::Ready(Some(item)),
                            None => continue, // unreachable
                        }
                    }
                    Ok(frame) => {
                        // First we need to know how many bytes this frame consumes.
                        let Ok(frame_len) = TryInto::<u32>::try_into(frame.len_with_header())
                            .and_then(TryInto::<NonZeroU32>::try_into)
                        else {
                            error!("frame len not NonZeroU32, is MAX_FRAME_SIZE too large?");
                            // Let this frame through anyway so to not completely break.
                            match self.buf.take() {
                                Some(item) => return Poll::Ready(Some(item)),
                                None => continue, // unreachable
                            }
                        };

                        // Now check the rate limiter.
                        match self.limiter.check_n(frame_len) {
                            Ok(Ok(_)) => {
                                // Item not rate-limited, yield it.
                                match self.buf.take() {
                                    Some(frame) => return Poll::Ready(Some(frame)),
                                    None => continue, // unreachable
                                }
                            }
                            Ok(Err(_until)) => {
                                // Item is rate-limited, install a delay future.
                                let limiter = self.limiter.clone();
                                let fut = async move {
                                    limiter.until_n_ready(frame_len).await.ok();
                                };
                                self.delay = Some(Box::pin(fut));
                                continue;
                            }
                            Err(_insufficient_capacity) => {
                                error!("frame larger than bucket capacity, accepting frame");
                                // Let this frame through since this is misconfigured.
                                match self.buf.take() {
                                    Some(item) => return Poll::Ready(Some(item)),
                                    None => continue, // unreachable
                                }
                            }
                        }
                    }
                }
            }
            // If we have neither a delay future or a buffered item, poll for a new item.
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    self.buf = Some(item);
                    continue;
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Frame> for RateLimitedRelayedStream {
    type Error = std::io::Error;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_ready(cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Frame) -> std::result::Result<(), Self::Error> {
        Pin::new(&mut self.inner).start_send(item)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use bytes::Bytes;
    use iroh_base::key::SecretKey;
    use testresult::TestResult;
    use tokio_util::codec::Framed;

    use super::*;
    use crate::{
        client::conn,
        protos::relay::{recv_frame, DerpCodec, FrameType},
        server::streams::MaybeTlsStream,
    };

    #[tokio::test]
    async fn test_client_actor_basic() -> Result<()> {
        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let key = SecretKey::generate().public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, DerpCodec);
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);
        let quota = governor::Quota::per_second(NonZeroU32::MAX);
        let limiter = governor::RateLimiter::direct(quota);
        let stream = RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec));

        let actor = Actor {
            stream: RateLimitedRelayedStream::new(stream, limiter),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,

            key,
            server_channel: server_channel_s,
            preferred: true,
        };

        let done = CancellationToken::new();
        let io_done = done.clone();
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });

        // Write tests
        println!("-- write");
        let data = b"hello world!";

        // send packet
        println!("  send packet");
        let packet = Packet {
            src: key,
            data: Bytes::from(&data[..]),
        };
        send_queue_s.send(packet.clone()).await?;
        let frame = recv_frame(FrameType::RecvPacket, &mut io_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: key,
                content: data.to_vec().into()
            }
        );

        // send disco packet
        println!("  send disco packet");
        disco_send_queue_s.send(packet.clone()).await?;
        let frame = recv_frame(FrameType::RecvPacket, &mut io_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: key,
                content: data.to_vec().into()
            }
        );

        // send peer_gone
        println!("send peer gone");
        peer_gone_s.send(key).await?;
        let frame = recv_frame(FrameType::PeerGone, &mut io_rw).await?;
        assert_eq!(frame, Frame::NodeGone { node_id: key });

        // Read tests
        println!("--read");

        // send ping, expect pong
        let data = b"pingpong";
        write_frame(&mut io_rw, Frame::Ping { data: *data }, None).await?;

        // recv pong
        println!(" recv pong");
        let frame = recv_frame(FrameType::Pong, &mut io_rw).await?;
        assert_eq!(frame, Frame::Pong { data: *data });

        // change preferred to false
        println!("  preferred: false");
        write_frame(&mut io_rw, Frame::NotePreferred { preferred: false }, None).await?;
        // tokio::time::sleep(Duration::from_millis(100)).await;
        // assert!(!preferred.load(Ordering::Relaxed));

        // change preferred to true
        println!("  preferred: true");
        write_frame(&mut io_rw, Frame::NotePreferred { preferred: true }, None).await?;
        // tokio::time::sleep(Duration::from_millis(100)).await;
        // assert!(preferred.fetch_and(true, Ordering::Relaxed));

        let target = SecretKey::generate().public();

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        conn::send_packet(&mut io_rw, &None, target, Bytes::from_static(data)).await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            actor::Message::SendPacket {
                dst: got_target,
                data: got_data,
                src: got_src,
            } => {
                assert_eq!(target, got_target);
                assert_eq!(key, got_src);
                assert_eq!(&data[..], &got_data);
            }
            m => {
                bail!("expected ServerMessage::SendPacket, got {m:?}");
            }
        }

        // send disco packet
        println!("  send disco packet");
        // starts with `MAGIC` & key, then data
        let mut disco_data = disco::MAGIC.as_bytes().to_vec();
        disco_data.extend_from_slice(target.as_bytes());
        disco_data.extend_from_slice(data);
        conn::send_packet(&mut io_rw, &None, target, disco_data.clone().into()).await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            actor::Message::SendDiscoPacket {
                dst: got_target,
                src: got_src,
                data: got_data,
            } => {
                assert_eq!(target, got_target);
                assert_eq!(key, got_src);
                assert_eq!(&disco_data[..], &got_data);
            }
            m => {
                bail!("expected ServerMessage::SendDiscoPacket, got {m:?}");
            }
        }

        done.cancel();
        handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_client_conn_read_err() -> Result<()> {
        let (_send_queue_s, send_queue_r) = mpsc::channel(10);
        let (_disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (_peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let key = SecretKey::generate().public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, DerpCodec);
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);
        let quota = governor::Quota::per_second(NonZeroU32::MAX);
        let limiter = governor::RateLimiter::direct(quota);
        let stream = RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec));

        println!("-- create client conn");
        let actor = Actor {
            stream: RateLimitedRelayedStream::new(stream, limiter),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,

            key,
            server_channel: server_channel_s,
            preferred: true,
        };

        let done = CancellationToken::new();
        let io_done = done.clone();

        println!("-- run client conn");
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });

        // send packet
        println!("   send packet");
        let data = b"hello world!";
        let target = SecretKey::generate().public();

        conn::send_packet(&mut io_rw, &None, target, Bytes::from_static(data)).await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            actor::Message::SendPacket {
                dst: got_target,
                src: got_src,
                data: got_data,
            } => {
                assert_eq!(target, got_target);
                assert_eq!(key, got_src);
                assert_eq!(&data[..], &got_data);
                println!("    send packet success");
            }
            m => {
                bail!("expected ServerMessage::SendPacket, got {m:?}");
            }
        }

        println!("-- drop io");
        drop(io_rw);

        // expect task to complete after encountering an error
        if let Err(err) = tokio::time::timeout(Duration::from_secs(1), handle).await?? {
            if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                if io_err.kind() == std::io::ErrorKind::UnexpectedEof {
                    println!("   task closed successfully with `UnexpectedEof` error");
                } else {
                    bail!("expected `UnexpectedEof` error, got unknown error: {io_err:?}");
                }
            } else {
                bail!("expected `std::io::Error`, got `None`");
            }
        } else {
            bail!("expected task to finish in `UnexpectedEof` error, got `Ok(())`");
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limit() -> TestResult {
        let _logging = iroh_test::logging::setup();
        let (_send_queue_s, send_queue_r) = mpsc::channel(10);
        let (_disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (_peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let key = SecretKey::generate().public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, DerpCodec);
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);

        // We are only allowed to send 32 bytes per minute
        const LIMIT: u32 = 50;
        let quota = governor::Quota::per_minute(NonZeroU32::try_from(LIMIT)?);
        let limiter = governor::RateLimiter::direct(quota);
        let stream = RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec));

        println!("-- create client conn");
        let actor = Actor {
            stream: RateLimitedRelayedStream::new(stream, limiter),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,
            key,
            server_channel: server_channel_s,
            preferred: true,
        };

        let done = CancellationToken::new();
        let io_done = done.clone();

        info!("-- run client conn");
        let handle = tokio::task::spawn(async move { actor.run(io_done).await });
        let _handle = AbortOnDropHandle::new(handle);

        // Prepare a packet to send.
        let data = Bytes::from_static(b"hello world!");
        let target = SecretKey::generate().public();

        // Assert the frame * 2 is over our limit.
        let frame = Frame::SendPacket {
            dst_key: target,
            packet: data.clone(),
        };
        let frame_len = frame.len_with_header();
        assert!(frame_len * 2 > LIMIT as usize);
        info!("-- send packet with {frame_len} bytes");

        // Send a packet, it should arrive.
        conn::send_packet(&mut io_rw, &None, target, data.clone()).await?;
        let msg = server_channel_r.recv().await.context("actor died?")?;
        assert!(matches!(msg, actor::Message::SendPacket { .. }));

        // Send another packet, it should not arrive
        conn::send_packet(&mut io_rw, &None, target, data).await?;
        let ret = tokio::time::timeout(Duration::from_secs(1), server_channel_r.recv()).await;
        assert!(ret.is_err());

        Ok(())
    }
}
