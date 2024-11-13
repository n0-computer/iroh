//! The server-side representation of an ongoing client relaying connection.

use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_lite::StreamExt;
use futures_util::SinkExt;
use iroh_base::key::PublicKey;
use iroh_metrics::{inc, inc_by};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{info, trace, warn, Instrument};

use crate::{
    protos::{
        disco,
        relay::{write_frame, Frame, KEEP_ALIVE},
    },
    server::{
        actor::{self, Packet},
        metrics::Metrics,
        streams::RelayedStream,
    },
};

/// Configuration for a [`ClientConn`].
#[derive(Debug)]
pub(super) struct ClientConnConfig {
    pub(super) key: PublicKey,
    pub(super) stream: RelayedStream,
    pub(super) write_timeout: Duration,
    pub(super) channel_capacity: usize,
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
    pub(super) key: PublicKey,
    /// Used to close the connection loop.
    done: CancellationToken,
    /// Actor handle.
    handle: AbortOnDropHandle<()>,
    /// Queue of packets intended for the client.
    pub(super) send_queue: mpsc::Sender<Packet>,
    /// Queue of disco packets intended for the client.
    pub(super) disco_send_queue: mpsc::Sender<Packet>,
    /// Channel to notify the client that a previous sender has disconnected.
    pub(super) peer_gone: mpsc::Sender<PublicKey>,
}

impl ClientConn {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    /// Call [`ClientConn::shutdown`] to close the read and write loops before dropping the [`ClientConn`]
    pub fn new(config: ClientConnConfig, conn_num: usize) -> ClientConn {
        let ClientConnConfig {
            key,
            stream: io,
            write_timeout,
            channel_capacity,
            server_channel,
        } = config;

        let done = CancellationToken::new();
        let client_id = (key, conn_num);
        let (send_queue_s, send_queue_r) = mpsc::channel(channel_capacity);

        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(channel_capacity);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(channel_capacity);

        let actor = Actor {
            stream: io,
            timeout: write_timeout,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,
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
                    .send(actor::Message::RemoveClient { key, conn_num })
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
            .instrument(tracing::debug_span!("client_conn actor")),
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
    /// IO Steram to talk to the client
    stream: RelayedStream,
    /// Maximum time we wait to complete a write to the client
    timeout: Duration,
    /// Packets queued to send to the client
    send_queue: mpsc::Receiver<Packet>,
    /// Important packets queued to send to the client
    disco_send_queue: mpsc::Receiver<Packet>,
    /// Notify the client that a previous sender has disconnected
    peer_gone: mpsc::Receiver<PublicKey>,
    /// [`PublicKey`] of this client
    key: PublicKey,
    /// Channel used to communicate with the server about actions
    /// it needs to take on behalf of the client
    server_channel: mpsc::Sender<actor::Message>,
    /// Notes that the client considers this the preferred connection (important in cases
    /// where the client moves to a different network, but has the same PublicKey)
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
                peer = self.peer_gone.recv() => {
                    let peer = peer.context("Server.peer_gone dropped")?;
                    trace!("peer gone: {:?}", peer);
                    self.write_frame(Frame::PeerGone { peer }).await?;
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

    /// Writes the given frame to the conneciton.
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

    async fn handle_frame_send_packet(&self, dst_key: PublicKey, data: Bytes) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use anyhow::bail;
    use iroh_base::key::SecretKey;
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

        let actor = Actor {
            stream: RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec)),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,

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
        assert_eq!(frame, Frame::PeerGone { peer: key });

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

        println!("-- create client conn");
        let actor = Actor {
            stream: RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec)),
            timeout: Duration::from_secs(1),
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,

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
}
