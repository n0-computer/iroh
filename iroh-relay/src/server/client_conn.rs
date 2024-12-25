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

use super::clients::Clients;
use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, KEEP_ALIVE},
    },
    server::{metrics::Metrics, streams::RelayedStream, ClientConnRateLimit},
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    pub(super) src: NodeId,
    /// The data packet bytes.
    pub(super) data: Bytes,
}

/// Configuration for a [`ClientConn`].
#[derive(Debug)]
pub(super) struct ClientConnConfig {
    pub(super) node_id: NodeId,
    pub(super) stream: RelayedStream,
    pub(super) write_timeout: Duration,
    pub(super) channel_capacity: usize,
    pub(super) rate_limit: Option<ClientConnRateLimit>,
    pub(super) clients: Clients,
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
            rate_limit,
            clients,
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
            clients: clients.clone(),
        };

        // start io loop
        let io_done = done.clone();
        let io_client_id = client_id;
        let handle = tokio::task::spawn(
            async move {
                let (key, conn_num) = io_client_id;
                match actor.run(io_done).await {
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
    /// Reference to the other connected clients.
    clients: Clients,
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
                    trace!(frame = ?read_res, "handle frame");
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

    async fn handle_frame_send_packet(&self, dst: NodeId, data: Bytes) -> Result<()> {
        if disco::looks_like_disco_wrapper(&data) {
            inc!(Metrics, disco_packets_recv);
            self.clients.send_disco_packet(dst, data, self.key).await?;
        } else {
            inc!(Metrics, send_packets_recv);
            self.clients.send_packet(dst, data, self.key).await?;
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
        client::conn,
        protos::relay::{recv_frame, FrameType, RelayCodec},
        server::streams::MaybeTlsStream,
    };

    #[tokio::test]
    async fn test_client_actor_basic() -> Result<()> {
        let _logging = iroh_test::logging::setup();

        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let key = SecretKey::generate(rand::thread_rng()).public();
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
            key,
            clients: clients.clone(),
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

        // change preferred to true
        println!("  preferred: true");
        write_frame(&mut io_rw, Frame::NotePreferred { preferred: true }, None).await?;

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
