//! The server-side representation of an ongoing client relaying connection.

use std::{collections::HashSet, sync::Arc, time::Duration};

use bytes::Bytes;
use iroh_base::NodeId;
use n0_future::{SinkExt, StreamExt};
use nested_enum_utils::common_fields;
use rand::Rng;
use snafu::{Backtrace, GenerateImplicitData, Snafu};
use time::{Date, OffsetDateTime};
use tokio::{
    sync::mpsc::{self, error::TrySendError},
    time::MissedTickBehavior,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, trace, warn, Instrument};

use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, SendError as SendRelayError, PING_INTERVAL},
    },
    server::{
        clients::Clients,
        metrics::Metrics,
        streams::{RelayedStream, StreamError},
    },
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
    pub(super) fn new(
        config: Config,
        connection_id: u64,
        clients: &Clients,
        metrics: Arc<Metrics>,
    ) -> Client {
        let Config {
            node_id,
            stream,
            write_timeout,
            channel_capacity,
        } = config;

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
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            metrics,
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

/// Handle frame error
#[common_fields({
    backtrace: Option<Backtrace>,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HandleFrameError {
    #[snafu(transparent)]
    ForwardPacket { source: ForwardPacketError },
    #[snafu(transparent)]
    Streams { source: StreamError },
    #[snafu(display("Stream terminated"))]
    StreamTerminated {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(transparent)]
    Relay { source: SendRelayError },
    #[snafu(display("Server issue: {problem:?}"))]
    Health {
        problem: Bytes,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
}

/// Run error
#[common_fields({
    backtrace: Option<Backtrace>,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RunError {
    #[snafu(transparent)]
    ForwardPacket { source: ForwardPacketError },
    #[snafu(display("Flush"))]
    Flush {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(transparent)]
    HandleFrame { source: HandleFrameError },
    #[snafu(display("Server.disco_send_queue dropped"))]
    DiscoSendQueuePacketDrop {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Failed to send disco packet"))]
    DiscoPacketSend {
        source: SendRelayError,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Server.send_queue dropped"))]
    SendQueuePacketDrop {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Failed to send packet"))]
    PacketSend {
        source: SendRelayError,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Server.node_gone dropped"))]
    NodeGoneDrop {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("NodeGone write frame failed"))]
    NodeGoneWriteFrame {
        source: SendRelayError,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Keep alive write frame failed"))]
    KeepAliveWriteFrame {
        source: SendRelayError,
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
    #[snafu(display("Tick flush"))]
    TickFlush {
        #[snafu(implicit)]
        span_trace: n0_snafu::SpanTrace,
    },
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
    stream: RelayedStream,
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
    /// Statistics about the connected clients
    client_counter: ClientCounter,
    ping_tracker: PingTracker,
    metrics: Arc<Metrics>,
}

impl Actor {
    async fn run(mut self, done: CancellationToken) {
        // Note the accept and disconnects metrics must be in a pair.  Technically the
        // connection is accepted long before this in the HTTP server, but it is clearer to
        // handle the metric here.
        self.metrics.accepts.inc();
        if self.client_counter.update(self.node_id) {
            self.metrics.unique_client_keys.inc();
        }
        match self.run_inner(done).await {
            Err(e) => {
                warn!("actor errored {e:#?}, exiting");
            }
            Ok(()) => {
                debug!("actor finished, exiting");
            }
        }

        self.clients.unregister(self.connection_id, self.node_id);
        self.metrics.disconnects.inc();
    }

    async fn run_inner(&mut self, done: CancellationToken) -> Result<(), RunError> {
        use snafu::ResultExt;

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
                    self.stream.flush().await.map_err(|_| FlushSnafu.build())?;
                    break;
                }
                maybe_frame = self.stream.next() => {
                    self.handle_frame(maybe_frame).await?;
                    // reset the ping interval, we just received a message
                    ping_interval.reset();
                }
                // First priority, disco packets
                packet = self.disco_send_queue.recv() => {
                    let packet = packet.ok_or(DiscoSendQueuePacketDropSnafu.build())?;
                    self.send_disco_packet(packet).await.context(DiscoPacketSendSnafu)?;
                }
                // Second priority, sending regular packets
                packet = self.send_queue.recv() => {
                    let packet = packet.ok_or(SendQueuePacketDropSnafu.build())?;
                    self.send_packet(packet).await.context(PacketSendSnafu)?;
                }
                // Last priority, sending left nodes
                node_id = self.node_gone.recv() => {
                    let node_id = node_id.ok_or(NodeGoneDropSnafu.build())?;
                    trace!("node_id gone: {:?}", node_id);
                    self.write_frame(Frame::NodeGone { node_id }).await.context(NodeGoneWriteFrameSnafu)?;
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
                    self.write_frame(Frame::Ping { data }).await.context(KeepAliveWriteFrameSnafu)?;
                }
            }

            self.stream
                .flush()
                .await
                .map_err(|_| TickFlushSnafu.build())?;
        }
        Ok(())
    }

    /// Writes the given frame to the connection.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn write_frame(&mut self, frame: Frame) -> Result<(), SendRelayError> {
        write_frame(&mut self.stream, frame, Some(self.timeout)).await
    }

    /// Writes contents to the client in a `RECV_PACKET` frame.
    ///
    /// Errors if the send does not happen within the `timeout` duration
    /// Does not flush.
    async fn send_raw(&mut self, packet: Packet) -> Result<(), SendRelayError> {
        let src_key = packet.src;
        let content = packet.data;

        if let Ok(len) = content.len().try_into() {
            self.metrics.bytes_sent.inc_by(len);
        }
        self.write_frame(Frame::RecvPacket { src_key, content })
            .await
    }

    async fn send_packet(&mut self, packet: Packet) -> Result<(), SendRelayError> {
        trace!("send packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                self.metrics.send_packets_sent.inc();
                Ok(())
            }
            Err(err) => {
                self.metrics.send_packets_dropped.inc();
                Err(err)
            }
        }
    }

    async fn send_disco_packet(&mut self, packet: Packet) -> Result<(), SendRelayError> {
        trace!("send disco packet");
        match self.send_raw(packet).await {
            Ok(()) => {
                self.metrics.disco_packets_sent.inc();
                Ok(())
            }
            Err(err) => {
                self.metrics.disco_packets_dropped.inc();
                Err(err)
            }
        }
    }

    /// Handles frame read results.
    async fn handle_frame(
        &mut self,
        maybe_frame: Option<Result<Frame, StreamError>>,
    ) -> Result<(), HandleFrameError> {
        trace!(?maybe_frame, "handle incoming frame");
        let frame = match maybe_frame {
            Some(frame) => frame?,
            None => return Err(StreamTerminatedSnafu.build()),
        };

        match frame {
            Frame::SendPacket { dst_key, packet } => {
                let packet_len = packet.len();
                if let Err(err @ ForwardPacketError { .. }) =
                    self.handle_frame_send_packet(dst_key, packet)
                {
                    warn!("failed to handle send packet frame: {err:#}");
                }
                self.metrics.bytes_recv.inc_by(packet_len as u64);
            }
            Frame::Ping { data } => {
                self.metrics.got_ping.inc();
                // TODO: add rate limiter
                self.write_frame(Frame::Pong { data }).await?;
                self.metrics.sent_pong.inc();
            }
            Frame::Pong { data } => {
                self.ping_tracker.pong_received(data);
            }
            Frame::Health { problem } => return Err(HealthSnafu { problem }.build()),
            _ => {
                self.metrics.unknown_frames.inc();
            }
        }
        Ok(())
    }

    fn handle_frame_send_packet(&self, dst: NodeId, data: Bytes) -> Result<(), ForwardPacketError> {
        if disco::looks_like_disco_wrapper(&data) {
            self.metrics.disco_packets_recv.inc();
            self.clients
                .send_disco_packet(dst, data, self.node_id, &self.metrics)?;
        } else {
            self.metrics.send_packets_recv.inc();
            self.clients
                .send_packet(dst, data, self.node_id, &self.metrics)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum PacketScope {
    Disco,
    Data,
}

#[derive(Debug)]
pub(crate) enum SendError {
    Full,
    Closed,
}

#[derive(Debug, Snafu)]
#[snafu(display("failed to forward {scope:?} packet: {reason:?}"))]
pub(crate) struct ForwardPacketError {
    scope: PacketScope,
    reason: SendError,
    backtrace: Option<snafu::Backtrace>,
}

impl ForwardPacketError {
    pub(crate) fn new(scope: PacketScope, reason: SendError) -> Self {
        Self {
            scope,
            reason,
            backtrace: GenerateImplicitData::generate(),
        }
    }
}

/// Tracks how many unique nodes have been seen during the last day.
#[derive(Debug)]
struct ClientCounter {
    clients: HashSet<NodeId>,
    last_clear_date: Date,
}

impl Default for ClientCounter {
    fn default() -> Self {
        Self {
            clients: HashSet::new(),
            last_clear_date: OffsetDateTime::now_utc().date(),
        }
    }
}

impl ClientCounter {
    fn check_and_clear(&mut self) {
        let today = OffsetDateTime::now_utc().date();
        if today != self.last_clear_date {
            self.clients.clear();
            self.last_clear_date = today;
        }
    }

    /// Marks this node as seen, returns whether it is new today or not.
    fn update(&mut self, client: NodeId) -> bool {
        self.check_and_clear();
        self.clients.insert(client)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bytes::Bytes;
    use iroh_base::SecretKey;
    use n0_snafu::{Result, ResultExt};
    use tracing::info;
    use tracing_test::traced_test;

    use super::*;
    use crate::protos::relay::{recv_frame, FrameType};

    #[tokio::test]
    #[traced_test]
    async fn test_client_actor_basic() -> Result {
        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);

        let node_id = SecretKey::generate(rand::thread_rng()).public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = RelayedStream::test_client(io_rw);
        let stream = RelayedStream::test_server(io);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        let actor = Actor {
            stream,
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            node_gone: peer_gone_r,
            connection_id: 0,
            node_id,
            clients: clients.clone(),
            client_counter: ClientCounter::default(),
            ping_tracker: PingTracker::default(),
            metrics,
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
        send_queue_s.send(packet.clone()).await.context("send")?;
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
        disco_send_queue_s
            .send(packet.clone())
            .await
            .context("send")?;
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
        peer_gone_s.send(node_id).await.context("send")?;
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
            .await
            .context("send")?;

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
            .await
            .context("send")?;

        done.cancel();
        handle.await.context("join")?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    #[traced_test]
    async fn test_rate_limit() -> Result {
        const LIMIT: u32 = 50;
        const MAX_FRAMES: u32 = 100;

        // Build the rate limited stream.
        let (io_read, io_write) = tokio::io::duplex((LIMIT * MAX_FRAMES) as _);
        let mut frame_writer = RelayedStream::test_client(io_write);
        // Rate limiter allowing LIMIT bytes/s
        let mut stream = RelayedStream::test_server_limited(io_read, LIMIT / 10, LIMIT);

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
        frame_writer.send(frame.clone()).await.context("send")?;
        frame_writer.flush().await.context("flush")?;
        let recv_frame = tokio::time::timeout(Duration::from_millis(500), stream.next())
            .await
            .expect("timeout")
            .expect("option")
            .expect("ok");
        assert_eq!(recv_frame, frame);

        // Next frame does not arrive.
        info!("-- send packet");
        frame_writer.send(frame.clone()).await.context("send")?;
        frame_writer.flush().await.context("flush")?;
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
