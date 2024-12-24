//! The server-side representation of an ongoing client relaying connection.

use std::{future::Future, num::NonZeroU32, pin::Pin, sync::Arc, task::Poll, time::Duration};

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_lite::FutureExt;
use futures_sink::Sink;
use futures_util::{SinkExt, Stream, StreamExt};
use iroh_base::NodeId;
use iroh_metrics::{inc, inc_by};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{error, info, instrument, trace, warn, Instrument};

use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, KEEP_ALIVE},
    },
    server::{clients::Clients, metrics::Metrics, streams::RelayedStream, ClientRateLimit},
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
struct Packet {
    /// The sender of the packet
    src: NodeId,
    /// The data packet bytes.
    data: Bytes,
}

/// Number of times we try to send to a client connection before dropping the data;
const RETRIES: usize = 3;

/// Configuration for a [`Client`].
#[derive(Debug)]
pub(super) struct Config {
    pub(super) node_id: NodeId,
    pub(super) stream: RelayedStream,
    pub(super) write_timeout: Duration,
    pub(super) channel_capacity: usize,
    pub(super) rate_limit: Option<ClientRateLimit>,
}

/// The [`Server`] side representation of a [`Client`]'s connection.
///
/// [`Server`]: crate::server::Server
/// [`Client`]: crate::client::Client
#[derive(Debug)]
pub(super) struct Client {
    /// Identity of the connected peer.
    node_id: NodeId,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: AbortOnDropHandle<()>,
    /// Queue of packets intended for the client.
    send_queue: mpsc::Sender<Packet>,
    /// Queue of disco packets intended for the client.
    disco_send_queue: mpsc::Sender<Packet>,
    /// Channel to notify the client that a previous sender has disconnected.
    peer_gone: mpsc::Sender<NodeId>,
}

impl Client {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    /// Call [`Client::shutdown`] to close the read and write loops before dropping the [`Client`]
    pub(super) fn new(config: Config, clients: &Clients) -> Client {
        let Config {
            node_id,
            stream: io,
            write_timeout,
            channel_capacity,
            rate_limit,
        } = config;

        let stream = match rate_limit {
            Some(cfg) => {
                let mut quota = governor::Quota::per_second(cfg.bytes_per_second);
                if let Some(max_burst) = cfg.max_burst_bytes {
                    quota = quota.allow_burst(max_burst);
                }
                let limiter = governor::RateLimiter::direct(quota);
                RateLimitedRelayedStream::new(io, limiter)
            }
            None => RateLimitedRelayedStream::unlimited(io),
        };

        let done = CancellationToken::new();
        let (send_queue_s, send_queue_r) = mpsc::channel(channel_capacity);

        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(channel_capacity);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(channel_capacity);

        let actor = Actor {
            stream,
            timeout: write_timeout,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,
            node_id,
            clients: clients.clone(),
        };

        // start io loop
        let io_done = done.clone();
        let io_client_id = node_id;
        let handle = tokio::task::spawn(
            async move {
                let key = io_client_id;
                match actor.run(io_done).await {
                    Err(e) => {
                        warn!("connection manager for {key:?}: writer closed in error {e:?}");
                    }
                    Ok(()) => {
                        info!("connection manager for {key:?}: writer closed");
                    }
                }
            }
            .instrument(tracing::info_span!("client_conn_actor")),
        );

        Client {
            node_id,
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
    pub(super) async fn shutdown(self) {
        self.done.cancel();
        if let Err(e) = self.handle.await {
            warn!(
                "error closing actor loop for client connection {:?}: {e:?}",
                self.node_id,
            );
        };
    }

    pub(super) fn send_packet(&self, src: NodeId, data: Bytes) -> Result<(), SendError> {
        try_send(&self.send_queue, Packet { src, data })
    }

    pub(super) fn send_disco_packet(&self, src: NodeId, data: Bytes) -> Result<(), SendError> {
        try_send(&self.disco_send_queue, Packet { src, data })
    }

    pub(super) fn send_peer_gone(&self, key: NodeId) -> Result<(), SendError> {
        try_send(&self.peer_gone, key)
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SendError {
    #[error("packet dropped")]
    PacketDropped,
    #[error("sender closed")]
    SenderClosed,
}

/// Tries up to `3` times to send a message into the given channel, retrying iff it is full.
fn try_send<T>(sender: &mpsc::Sender<T>, msg: T) -> Result<(), SendError> {
    let mut msg = msg;
    for _ in 0..RETRIES {
        match sender.try_send(msg) {
            Ok(_) => {
                return Ok(());
            }
            // if the queue is full, try again (max 3 times)
            Err(mpsc::error::TrySendError::Full(m)) => msg = m,
            // only other option is `TrySendError::Closed`, report the
            // closed error
            Err(_) => return Err(SendError::SenderClosed),
        }
    }
    Err(SendError::PacketDropped)
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
    node_id: NodeId,
    /// Reference to the other connected clients.
    clients: Clients,
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
                maybe_frame = self.stream.next() => {
                    self.handle_frame(maybe_frame).await.context("handle read")?;
                }
                // First priority, disco packets
                packet = self.disco_send_queue.recv() => {
                    let packet = packet.context("Server.disco_send_queue dropped")?;
                    self.send_disco_packet(packet).await.context("send packet")?;
                }
                // Second priority, sending regular packets
                packet = self.send_queue.recv() => {
                    let packet = packet.context("Server.send_queue dropped")?;
                    self.send_packet(packet).await.context("send packet")?;
                }
                // Last priority, sending left nodes
                node_id = self.node_gone.recv() => {
                    let node_id = node_id.context("Server.node_gone dropped")?;
                    trace!("node_id gone: {:?}", node_id);
                    self.write_frame(Frame::NodeGone { node_id }).await?;
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
    async fn send_raw(&mut self, packet: Packet) -> Result<()> {
        let src_key = packet.src;
        let content = packet.data;

        if let Ok(len) = content.len().try_into() {
            inc_by!(Metrics, bytes_sent, len);
        }
        self.write_frame(Frame::RecvPacket { src_key, content })
            .await
    }

    async fn send_packet(&mut self, packet: Packet) -> Result<()> {
        trace!("send packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                inc!(Metrics, send_packets_sent);
                Ok(())
            }
            Err(err) => {
                inc!(Metrics, send_packets_dropped);
                Err(err)
            }
        }
    }

    async fn send_disco_packet(&mut self, packet: Packet) -> Result<()> {
        trace!("send disco packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                inc!(Metrics, disco_packets_sent);
                Ok(())
            }
            Err(err) => {
                inc!(Metrics, disco_packets_dropped);
                Err(err)
            }
        }
    }

    /// Handles frame read results.
    async fn handle_frame(&mut self, maybe_frame: Option<Result<Frame>>) -> Result<()> {
        trace!(?maybe_frame, "handle incoming frame");
        let frame = match maybe_frame {
            Some(frame) => frame?,
            None => anyhow::bail!("stream terminated"),
        };
        match frame {
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

    async fn handle_frame_send_packet(&self, dst: NodeId, data: Bytes) -> Result<()> {
        if disco::looks_like_disco_wrapper(&data) {
            inc!(Metrics, disco_packets_recv);
            self.clients
                .send_disco_packet(dst, data, self.node_id)
                .await?;
        } else {
            inc!(Metrics, send_packets_recv);
            self.clients.send_packet(dst, data, self.node_id).await?;
        }
        Ok(())
    }
}

/// Rate limiter for reading from a [`RelayedStream`].
///
/// The writes to the sink are not rate limited.
///
/// This potentially buffers one frame if the rate limiter does not allows this frame.
/// While the frame is buffered the undernlying stream is no longer polled.
#[derive(Debug)]
struct RateLimitedRelayedStream {
    inner: RelayedStream,
    limiter: Option<Arc<governor::DefaultDirectRateLimiter>>,
    state: State,
    /// Keeps track if this stream was ever rate-limited.
    limited_once: bool,
}

#[derive(derive_more::Debug)]
enum State {
    #[debug("Blocked")]
    Blocked {
        /// Future which will complete when the item can be yielded.
        delay: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
        /// Item to yield when the `delay` future completes.
        item: anyhow::Result<Frame>,
    },
    Ready,
}

impl RateLimitedRelayedStream {
    fn new(inner: RelayedStream, limiter: governor::DefaultDirectRateLimiter) -> Self {
        Self {
            inner,
            limiter: Some(Arc::new(limiter)),
            state: State::Ready,
            limited_once: false,
        }
    }

    fn unlimited(inner: RelayedStream) -> Self {
        Self {
            inner,
            limiter: None,
            state: State::Ready,
            limited_once: false,
        }
    }
}

impl RateLimitedRelayedStream {
    /// Records metrics about being rate-limited.
    fn record_rate_limited(&mut self) {
        // TODO: add a label for the frame type.
        inc!(Metrics, frames_rx_ratelimited_total);
        if !self.limited_once {
            inc!(Metrics, conns_rx_ratelimited_total);
            self.limited_once = true;
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
        let Some(ref limiter) = self.limiter else {
            // If there is no rate-limiter directly poll the inner.
            return Pin::new(&mut self.inner).poll_next(cx);
        };
        let limiter = limiter.clone();
        loop {
            match &mut self.state {
                State::Ready => {
                    // Poll inner for a new item.
                    match Pin::new(&mut self.inner).poll_next(cx) {
                        Poll::Ready(Some(item)) => {
                            match &item {
                                Ok(frame) => {
                                    // How many bytes does this frame consume?
                                    let Ok(frame_len) =
                                        TryInto::<u32>::try_into(frame.len_with_header())
                                            .and_then(TryInto::<NonZeroU32>::try_into)
                                    else {
                                        error!("frame len not NonZeroU32, is MAX_FRAME_SIZE too large?");
                                        // Let this frame through so to not completely break.
                                        return Poll::Ready(Some(item));
                                    };

                                    match limiter.check_n(frame_len) {
                                        Ok(Ok(_)) => return Poll::Ready(Some(item)),
                                        Ok(Err(_)) => {
                                            // Item is rate-limited.
                                            self.record_rate_limited();
                                            let delay = Box::pin({
                                                let limiter = limiter.clone();
                                                async move {
                                                    limiter.until_n_ready(frame_len).await.ok();
                                                }
                                            });
                                            self.state = State::Blocked { delay, item };
                                            continue;
                                        }
                                        Err(_insufficient_capacity) => {
                                            error!(
                                                "frame larger than bucket capacity: \
                                                 configuration error: \
                                                 max_burst_bytes < MAX_FRAME_SIZE?"
                                            );
                                            // Let this frame through so to not completely break.
                                            return Poll::Ready(Some(item));
                                        }
                                    }
                                }
                                Err(_) => {
                                    // Yielding errors is not rate-limited.
                                    return Poll::Ready(Some(item));
                                }
                            }
                        }
                        Poll::Ready(None) => return Poll::Ready(None),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                State::Blocked { delay, .. } => {
                    match delay.poll(cx) {
                        Poll::Ready(_) => {
                            match std::mem::replace(&mut self.state, State::Ready) {
                                State::Ready => unreachable!(),
                                State::Blocked { item, .. } => {
                                    // Yield the item directly, rate-limit has already been
                                    // accounted for by awaiting the future.
                                    return Poll::Ready(Some(item));
                                }
                            }
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
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
    use bytes::Bytes;
    use iroh_base::SecretKey;
    use testresult::TestResult;
    use tokio_util::codec::Framed;

    use super::*;
    use crate::{
        protos::relay::{recv_frame, FrameType, RelayCodec},
        server::streams::MaybeTlsStream,
    };

    #[tokio::test]
    async fn test_client_actor_basic() -> Result<()> {
        let _logging = iroh_test::logging::setup();

        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let node_id = SecretKey::generate(rand::thread_rng()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, RelayCodec::test());
        let stream =
            RelayedStream::Relay(Framed::new(MaybeTlsStream::Test(io), RelayCodec::test()));

        let clients = Clients::default();
        let actor = Actor {
            stream: RateLimitedRelayedStream::unlimited(stream),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,
            node_id,
            clients: clients.clone(),
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
            src: node_id,
            data: Bytes::from(&data[..]),
        };
        send_queue_s.send(packet.clone()).await?;
        let frame = recv_frame(FrameType::RecvPacket, &mut io_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: node_id,
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
                src_key: node_id,
                content: data.to_vec().into()
            }
        );

        // send peer_gone
        println!("send peer gone");
        peer_gone_s.send(node_id).await?;
        let frame = recv_frame(FrameType::PeerGone, &mut io_rw).await?;
        assert_eq!(frame, Frame::NodeGone { node_id });

        // Read tests
        println!("--read");

        // send ping, expect pong
        let data = b"pingpong";
        write_frame(&mut io_rw, Frame::Ping { data: *data }, None).await?;

        // recv pong
        println!(" recv pong");
        let frame = recv_frame(FrameType::Pong, &mut io_rw).await?;
        assert_eq!(frame, Frame::Pong { data: *data });

        let target = SecretKey::generate(rand::thread_rng()).public();

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        conn::send_packet(&mut io_rw, target, Bytes::from_static(data)).await?;
        // send disco packet
        println!("  send disco packet");
        // starts with `MAGIC` & key, then data
        let mut disco_data = disco::MAGIC.as_bytes().to_vec();
        disco_data.extend_from_slice(target.as_bytes());
        disco_data.extend_from_slice(data);
        conn::send_packet(&mut io_rw, target, disco_data.clone().into()).await?;

        done.cancel();
        handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_client_conn_read_err() -> Result<()> {
        let (_send_queue_s, send_queue_r) = mpsc::channel(10);
        let (_disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (_peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let key = SecretKey::generate(rand::thread_rng()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, RelayCodec::test());
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);
        let stream =
            RelayedStream::Relay(Framed::new(MaybeTlsStream::Test(io), RelayCodec::test()));

        println!("-- create client conn");
        let actor = Actor {
            stream: RateLimitedRelayedStream::unlimited(stream),
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
        let target = SecretKey::generate(rand::thread_rng()).public();

        io_rw
            .send(Frame::SendPacket {
                dst_key: target,
                packet: Bytes::from_static(data),
            })
            .await?;
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

        const LIMIT: u32 = 50;
        const MAX_FRAMES: u32 = 100;

        // Rate limiter allowing LIMIT bytes/s
        let quota = governor::Quota::per_second(NonZeroU32::try_from(LIMIT)?);
        let limiter = governor::RateLimiter::direct(quota);

        // Build the rate limited stream.
        let (io_read, io_write) = tokio::io::duplex((LIMIT * MAX_FRAMES) as _);
        let mut frame_writer = Framed::new(io_write, RelayCodec::test());
        let stream = RelayedStream::Relay(Framed::new(
            MaybeTlsStream::Test(io_read),
            RelayCodec::test(),
        ));
        let mut stream = RateLimitedRelayedStream::new(stream, limiter);

        // Prepare a frame to send, assert its size.
        let data = Bytes::from_static(b"hello world!!");
        let target = SecretKey::generate(rand::thread_rng()).public();
        let frame = Frame::SendPacket {
            dst_key: target,
            packet: data.clone(),
        };
        let frame_len = frame.len_with_header();
        assert_eq!(frame_len, LIMIT as usize);

        // Send a frame, it should arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await?;
        frame_writer.flush().await?;
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        // Next frame does not arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await?;
        frame_writer.flush().await?;
        let res = tokio::time::timeout(Duration::from_millis(100), stream.next()).await;
        assert!(res.is_err(), "expecting a timeout");
        info!("-- timeout happened");

        // Wait long enough.
        info!("-- sleep");
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Frame arrives.
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        Ok(())
    }
}
