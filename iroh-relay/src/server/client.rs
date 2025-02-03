//! The server-side representation of an ongoing client relaying connection.

use std::{future::Future, num::NonZeroU32, pin::Pin, sync::Arc, task::Poll, time::Duration};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use iroh_base::NodeId;
use iroh_metrics::{inc, inc_by};
use n0_future::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use rand::Rng;
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, error, instrument, trace, warn, Instrument};

use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, PING_INTERVAL},
    },
    server::{clients::Clients, metrics::Metrics, streams::RelayedStream, ClientRateLimit},
    PingTracker,
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    src: NodeId,
    /// The data packet bytes.
    data: Bytes,
}

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
    /// Connection identifier.
    connection_id: u64,
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
    pub(super) fn new(config: Config, connection_id: u64, clients: &Clients) -> Client {
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
            connection_id,
            clients: clients.clone(),
            ping_tracker: PingTracker::default(),
        };

        // start io loop
        let io_done = done.clone();
        let handle = tokio::task::spawn(actor.run(io_done).instrument(tracing::info_span!(
            "client connection actor",
            remote_node = %node_id.fmt_short(),
            connection_id = connection_id
        )));

        Client {
            node_id,
            connection_id,
            handle: AbortOnDropHandle::new(handle),
            done,
            send_queue: send_queue_s,
            disco_send_queue: disco_send_queue_s,
            peer_gone: peer_gone_s,
        }
    }

    pub(super) fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// Shutdown the reader and writer loops and closes the connection.
    ///
    /// Any shutdown errors will be logged as warnings.
    pub(super) async fn shutdown(self) {
        self.start_shutdown();
        if let Err(e) = self.handle.await {
            warn!(
                remote_node = %self.node_id.fmt_short(),
                "error closing actor loop: {e:#?}",
            );
        };
    }

    /// Starts the process of shutdown.
    pub(super) fn start_shutdown(&self) {
        self.done.cancel();
    }

    pub(super) fn try_send_packet(
        &self,
        src: NodeId,
        data: Bytes,
    ) -> Result<(), TrySendError<Packet>> {
        self.send_queue.try_send(Packet { src, data })
    }

    pub(super) fn try_send_disco_packet(
        &self,
        src: NodeId,
        data: Bytes,
    ) -> Result<(), TrySendError<Packet>> {
        self.disco_send_queue.try_send(Packet { src, data })
    }

    pub(super) fn try_send_peer_gone(&self, key: NodeId) -> Result<(), TrySendError<NodeId>> {
        self.peer_gone.try_send(key)
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
    /// Connection identifier.
    connection_id: u64,
    /// Reference to the other connected clients.
    clients: Clients,
    ping_tracker: PingTracker,
}

impl Actor {
    async fn run(mut self, done: CancellationToken) {
        match self.run_inner(done).await {
            Err(e) => {
                warn!("actor errored {e:#?}, exiting");
            }
            Ok(()) => {
                debug!("actor finished, exiting");
            }
        }

        self.clients.unregister(self.connection_id, self.node_id);
    }

    async fn run_inner(&mut self, done: CancellationToken) -> Result<()> {
        // Add some jitter to ping pong interactions, to avoid all pings being sent at the same time
        let next_interval = || {
            let random_secs = rand::rngs::OsRng.gen_range(1..=5);
            Duration::from_secs(random_secs) + PING_INTERVAL
        };

        let mut ping_interval = tokio::time::interval(next_interval());
        // ticks immediately
        ping_interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ping_interval.tick().await;

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
                    // reset the ping interval, we just received a message
                    ping_interval.reset();
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
                _ = self.ping_tracker.timeout() => {
                    trace!("pong timed out");
                    break;
                }
                _ = ping_interval.tick() => {
                    trace!("keep alive ping");
                    // new interval
                    ping_interval.reset_after(next_interval());
                    let data = self.ping_tracker.new_ping();
                    self.write_frame(Frame::Ping { data }).await?;
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
                self.handle_frame_send_packet(dst_key, packet)?;
                inc_by!(Metrics, bytes_recv, packet_len as u64);
            }
            Frame::Ping { data } => {
                inc!(Metrics, got_ping);
                // TODO: add rate limiter
                self.write_frame(Frame::Pong { data }).await?;
                inc!(Metrics, sent_pong);
            }
            Frame::Pong { data } => {
                self.ping_tracker.pong_received(data);
            }
            Frame::Health { problem } => {
                bail!("server issue: {:?}", problem);
            }
            _ => {
                inc!(Metrics, unknown_frames);
            }
        }
        Ok(())
    }

    fn handle_frame_send_packet(&self, dst: NodeId, data: Bytes) -> Result<()> {
        if disco::looks_like_disco_wrapper(&data) {
            inc!(Metrics, disco_packets_recv);
            self.clients.send_disco_packet(dst, data, self.node_id)?;
        } else {
            inc!(Metrics, send_packets_recv);
            self.clients.send_packet(dst, data, self.node_id)?;
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
    use tracing::info;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        protos::relay::{recv_frame, FrameType, RelayCodec},
        server::streams::MaybeTlsStream,
    };

    #[tokio::test]
    #[traced_test]
    async fn test_client_actor_basic() -> Result<()> {
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
            connection_id: 0,
            node_id,
            clients: clients.clone(),
            ping_tracker: PingTracker::default(),
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
        io_rw
            .send(Frame::SendPacket {
                dst_key: target,
                packet: Bytes::from_static(data),
            })
            .await?;

        // send disco packet
        println!("  send disco packet");
        // starts with `MAGIC` & key, then data
        let mut disco_data = disco::MAGIC.as_bytes().to_vec();
        disco_data.extend_from_slice(target.as_bytes());
        disco_data.extend_from_slice(data);
        io_rw
            .send(Frame::SendPacket {
                dst_key: target,
                packet: disco_data.clone().into(),
            })
            .await?;

        done.cancel();
        handle.await?;
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_rate_limit() -> TestResult {
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
