use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{trace, Instrument};

use crate::util::AbortingJoinHandle;
use crate::{disco::looks_like_disco_wrapper, key::PublicKey};

use iroh_metrics::{inc, inc_by};

use super::codec::{DerpCodec, Frame};
use super::server::MaybeTlsStream;
use super::{
    codec::{write_frame, KEEP_ALIVE},
    metrics::Metrics,
    types::{Packet, PacketForwarder, PeerConnState, ServerMessage},
};

/// The [`super::server::Server`] side representation of a [`super::client::Client`]'s connection
#[derive(Debug)]
pub(crate) struct ClientConnManager {
    /// Static after construction, process-wide unique counter, incremented each time we accept  
    pub(crate) conn_num: usize,

    // TODO: in the go impl, we have a ptr to the server & use that ptr to update stats
    // in rust, we should probably have a stats struct separate from the server that we
    // can update in different threads, this may become a series of channels on which to
    // send updates
    // stats: Stats,
    pub(crate) key: PublicKey,
    /// Sent when connection closes
    // TODO: maybe should be a receiver
    done: CancellationToken,

    /// Controls how quickly two connections with the same client key can kick
    /// each other off the server by taking ownership of a key
    // TODO: replace with rate limiter, also, this should probably be on the ClientSets, not on
    // the client itself
    // replace_limiter: RateLimiter,
    io_handle: AbortingJoinHandle<Result<()>>,

    /// Channels that allow the [`ClientConnManager`] (and the Server) to send
    /// the client messages. These `Senders` correspond to `Receivers` on the
    /// [`ClientConnIo`].
    pub(crate) client_channels: ClientChannels,
}

/// Channels that the [`ClientConnManager`] uses to communicate with the
/// [`ClientConnIo`] to forward the client:
///  - information about a peer leaving the network (This should only happen for peers that this
///  client was previously communciating with)
///  - forwarded packets (if they are mesh client)
///  - packets sent to this client from another client in the network
#[derive(Debug)]
pub(crate) struct ClientChannels {
    /// Queue of packets intended for the client
    pub(crate) send_queue: mpsc::Sender<Packet>,
    /// Queue of important packets intended for the client
    pub(crate) disco_send_queue: mpsc::Sender<Packet>,
    /// Notify the client that a previous sender has disconnected (Not used by mesh peers)
    pub(crate) peer_gone: mpsc::Sender<PublicKey>,
    /// Send a client (if it is a mesh peer) records that will
    /// allow the client to update their map of who's connected
    /// to this node
    pub(crate) mesh_update: mpsc::Sender<Vec<PeerConnState>>,
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + std::fmt::Debug> Io for T {}

/// A builds a [`ClientConnManager`] from a [`PublicKey`] and an io connection.
#[derive(Debug)]
pub struct ClientConnBuilder<P>
where
    P: PacketForwarder,
{
    pub(crate) key: PublicKey,
    pub(crate) conn_num: usize,
    pub(crate) io: Framed<MaybeTlsStream, DerpCodec>,
    pub(crate) can_mesh: bool,
    pub(crate) write_timeout: Option<Duration>,
    pub(crate) channel_capacity: usize,
    pub(crate) server_channel: mpsc::Sender<ServerMessage<P>>,
}

impl<P> ClientConnBuilder<P>
where
    P: PacketForwarder,
{
    /// Creates a client from a connection, which starts a read and write loop to handle
    /// io to the client
    pub(crate) fn build(self) -> ClientConnManager {
        ClientConnManager::new(
            self.key,
            self.conn_num,
            self.io,
            self.can_mesh,
            self.write_timeout,
            self.channel_capacity,
            self.server_channel,
        )
    }
}

impl ClientConnManager {
    /// Creates a client from a connection & starts a read and write loop to handle io to and from
    /// the client
    /// Call [`ClientConnManager::shutdown`] to close the read and write loops before dropping the [`ClientConnManager`]
    #[allow(clippy::too_many_arguments)]
    pub fn new<P>(
        key: PublicKey,
        conn_num: usize,
        io: Framed<MaybeTlsStream, DerpCodec>,
        can_mesh: bool,
        write_timeout: Option<Duration>,
        channel_capacity: usize,
        server_channel: mpsc::Sender<ServerMessage<P>>,
    ) -> ClientConnManager
    where
        P: PacketForwarder,
    {
        let done = CancellationToken::new();
        let client_id = (key, conn_num);
        let (send_queue_s, send_queue_r) = mpsc::channel(channel_capacity);

        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(channel_capacity);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(channel_capacity);
        let (mesh_update_s, mesh_update_r) = mpsc::channel(channel_capacity);

        let preferred = Arc::from(AtomicBool::from(false));

        let conn_io = ClientConnIo {
            can_mesh,
            io,
            timeout: write_timeout,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,
            mesh_update_r,
            mesh_update_s: mesh_update_s.clone(),

            key,
            preferred: Arc::clone(&preferred),
            server_channel: server_channel.clone(),
        };

        // start io loop
        let io_done = done.clone();
        let io_client_id = client_id;
        let io_handle = tokio::task::spawn(
            async move {
                let key = io_client_id.0;
                let conn_num = io_client_id.1;
                let res = conn_io.run(io_done).await;
                let _ = server_channel
                    .send(ServerMessage::RemoveClient((key, conn_num)))
                    .await;
                match res {
                    Err(e) => {
                        tracing::warn!(
                            "connection manager for {key:?} {conn_num}: writer closed in error {e}"
                        );
                        Err(e)
                    }
                    Ok(_) => {
                        tracing::warn!("connection manager for {key:?} {conn_num}: writer closed");
                        Ok(())
                    }
                }
            }
            .instrument(tracing::debug_span!("conn_io")),
        );

        ClientConnManager {
            conn_num,
            key,
            io_handle: io_handle.into(),
            done,
            client_channels: ClientChannels {
                send_queue: send_queue_s,
                disco_send_queue: disco_send_queue_s,
                peer_gone: peer_gone_s,
                mesh_update: mesh_update_s,
            },
        }
    }

    /// Shutdown the [`ClientConnManager`] reader and writer loops and closes the "actual" connection.
    ///
    /// Logs any shutdown errors as warnings.
    pub async fn shutdown(self) {
        self.done.cancel();
        if let Err(e) = self.io_handle.await {
            tracing::warn!(
                "error closing IO loop for client connection {:?} {}: {e:?}",
                self.key,
                self.conn_num
            );
        }
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
/// On the "write" side, the [`ClientConnIo`] can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame to inform the client that a peer they have previously sent messages to
///  is gone from the network
///  - packets from other peers
///
/// If the client is a mesh client, it can also send updates about peers in the mesh.
///
/// On the "read" side, it can:
///     - receive a ping and write a pong back
///     - notify the server to send a packet to another peer on behalf of the client
///     - note whether the client is `preferred`, aka this client is the preferred way
///     to speak to the node ID associated with that client.
///
/// If the `ClientConnIo` `can_mesh` that means that the associated [`super::client::Client`] is connected to
/// a derp [`super::server::Server`] that is apart of the same mesh network as this [`super::server::Server`]. It can:
///     - tell the server to add the current client as a watcher. This cause the server
///     to inform that client when peers join and leave the network:
///         - PEER_GONE frames inform the client a peer is gone from the network
///         - PEER_PRESENT frames inform the client a peer has joined the network
///     - tell the server to close a given peer
///     - tell the server to forward a packet from another peer.
#[derive(Debug)]
pub(crate) struct ClientConnIo<P: PacketForwarder> {
    /// Indicates whether this client can mesh
    can_mesh: bool,
    /// Io to talk to the client
    io: Framed<MaybeTlsStream, DerpCodec>,
    /// Max time we wait to complete a write to the client
    timeout: Option<Duration>,
    /// Packets queued to send to the client
    send_queue: mpsc::Receiver<Packet>,
    /// Important packets queued to send to the client
    disco_send_queue: mpsc::Receiver<Packet>,
    /// Notify the client that a previous sender has disconnected (not used by mesh peers)
    peer_gone: mpsc::Receiver<PublicKey>,
    /// Used by mesh peers (a set of regional DERP servers) and contains records
    /// that need to be sent to the client for them to update their map of who's
    /// connected to this node
    /// Notify the client of a peer state change ([`PeerConnState`])
    mesh_update_r: mpsc::Receiver<Vec<PeerConnState>>,
    /// Used by `reschedule_mesh_update` to reschedule additional mesh_updates
    mesh_update_s: mpsc::Sender<Vec<PeerConnState>>,

    /// [`PublicKey`] of this client
    key: PublicKey,

    /// Channels used to communicate with the server about actions
    /// it needs to take on behalf of the client
    server_channel: mpsc::Sender<ServerMessage<P>>,

    /// Notes that the client considers this the preferred connection (important in cases
    /// where the client moves to a different network, but has the same PublicKey)
    // TODO: I'm taking a chance & using an atomic here rather
    // than passing this through the server to update manually on the connection... although we
    // might find that the alternative is better, once I have a better idea of how this is supposed
    // to be read.
    preferred: Arc<AtomicBool>,
}

impl<P> ClientConnIo<P>
where
    P: PacketForwarder,
{
    async fn run(mut self, done: CancellationToken) -> Result<()> {
        let jitter = Duration::from_secs(5);
        let mut keep_alive = tokio::time::interval(KEEP_ALIVE + jitter);
        // ticks immediately
        keep_alive.tick().await;

        loop {
            trace!("tick");
            tokio::select! {
                biased;

                _ = done.cancelled() => {
                    trace!("cancelled");
                    // final flush
                    self.io.flush().await.context("flush")?;
                    return Ok(());
                }
                read_res = self.io.next() => {
                    trace!("handle read");
                    match read_res {
                        Some(Ok(frame)) => {
                            self.handle_read(frame).await.context("handle_read")?;
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
                    self.send_peer_gone(peer).await?;
                }
                updates = self.mesh_update_r.recv() => {
                    let updates = updates.context("Server.mesh_update dropped")?;
                    trace!("mesh updates");
                    self.send_mesh_updates(updates).await?;
                }
                packet = self.send_queue.recv() => {
                    let packet = packet.context("Server.send_queue dropped")?;
                    trace!("send packet");
                    self.send_packet(packet).await.context("send packet")?;
                    // TODO: stats
                    // record `packet.enqueuedAt`
                }
                packet = self.disco_send_queue.recv() => {
                    let packet = packet.context("Server.disco_send_queue dropped")?;
                    trace!("send disco packet");
                    self.send_packet(packet).await.context("send packet")?;
                    // TODO: stats
                    // record `packet.enqueuedAt`
                }
                _ = keep_alive.tick() => {
                    trace!("keep alive");
                    self.send_keep_alive().await.context("send keep alive")?;
                }
            }
            // TODO: golang batches as many writes as are in all the channels
            // & then flushes when there is no more work to be done at the moment.
            // refactor to get something similar
            self.io.flush().await.context("final flush")?;
        }
    }

    /// Sends a `keep alive` frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_keep_alive(&mut self) -> Result<()> {
        write_frame(&mut self.io, Frame::KeepAlive, self.timeout).await
    }

    /// Send a `pong` frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_pong(&mut self, data: [u8; 8]) -> Result<()> {
        // TODO: stats
        // record `send_pong`
        write_frame(&mut self.io, Frame::Pong { data }, self.timeout).await
    }

    /// Sends a peer gone frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_peer_gone(&mut self, peer: PublicKey) -> Result<()> {
        // TODO: stats
        // c.s.peerGoneFrames.Add(1)
        write_frame(&mut self.io, Frame::PeerGone { peer }, self.timeout).await
    }

    /// Sends a peer present frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_peer_present(&mut self, peer: PublicKey) -> Result<()> {
        write_frame(&mut self.io, Frame::PeerPresent { peer }, self.timeout).await
    }

    // TODO: golang comment:
    // "Drains as many mesh `PEER_STATE_CHANGE`s entries as possible
    // into the write buffer WITHOUT flushing or otherwise blocking (as it holds the mutex while
    // working).
    // If it can't drain them all, it schedules itself to be called again in the future."
    /// Send mesh updates for the first 16 (arbitrary #, based on the size that
    /// the goimpl seems to "want" the `PeerConnState` vector to be) `PeerConnState`
    /// in the vector. If there are more than 16 entries, it schedules itself for a
    /// future update.
    async fn send_mesh_updates(&mut self, mut updates: Vec<PeerConnState>) -> Result<()> {
        ensure!(
            self.can_mesh,
            "unexpected request to update mesh peers on a connection that is not able to mesh"
        );
        let scheduled_updates: Vec<_> = if updates.len() < 16 {
            std::mem::take(&mut updates)
        } else {
            updates.drain(..16).collect()
        };
        for peer_conn_state in scheduled_updates {
            if peer_conn_state.present {
                self.send_peer_present(peer_conn_state.peer).await?;
            } else {
                self.send_peer_gone(peer_conn_state.peer).await?;
            }
        }
        if !updates.is_empty() {
            self.request_mesh_update(updates).await?;
        }
        Ok(())
    }

    async fn request_mesh_update(&self, updates: Vec<PeerConnState>) -> Result<()> {
        ensure!(
            self.can_mesh,
            "unexpected request to update mesh peers on a connection that is not able to mesh"
        );
        self.mesh_update_s.send(updates).await?;
        Ok(())
    }

    /// Writes contents to the client in a `RECV_PACKET` frame. If `srcKey.is_zero`, it uses the
    /// old DERPv1 framing format, otherwise uses the DERPv2 framing format. The bytes of contents
    /// are only valid until this function returns, do not retain the slices.
    /// Does not flush.
    async fn send_packet(&mut self, packet: Packet) -> Result<()> {
        let src_key = packet.src;
        let content = packet.bytes;

        if let Ok(len) = content.len().try_into() {
            inc_by!(Metrics, bytes_sent, len);
        }
        write_frame(
            &mut self.io,
            Frame::RecvPacket { src_key, content },
            self.timeout,
        )
        .await
    }

    /// Handles read results.
    async fn handle_read(&mut self, frame: Frame) -> Result<()> {
        // TODO: "note client activity", meaning we update the server that the client with this
        // public key was the last one to receive data
        // it will be relevant when we add the ability to hold onto multiple clients
        // for the same public key
        match frame {
            Frame::NotePreferred { preferred } => {
                self.handle_frame_note_preferred(preferred)?;
                inc!(Metrics, other_packets_recv);
            }
            Frame::SendPacket { dst_key, packet } => {
                let packet_len = packet.len();
                self.handle_frame_send_packet(dst_key, packet).await?;
                inc_by!(Metrics, bytes_recv, packet_len as u64);
            }
            Frame::ForwardPacket {
                src_key,
                dst_key,
                packet,
            } => {
                self.handle_frame_forward_packet(src_key, dst_key, packet)
                    .await?;
                inc!(Metrics, packets_forwarded_in);
            }
            Frame::WatchConns => {
                self.handle_frame_watch_conns().await?;
                inc!(Metrics, other_packets_recv);
            }
            Frame::ClosePeer { peer } => {
                self.handle_frame_close_peer(peer).await?;
                inc!(Metrics, other_packets_recv);
            }
            Frame::Ping { data } => {
                self.handle_frame_ping(data).await?;
                inc!(Metrics, got_ping);
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

    /// Preferred indicates if this is the preferred connection to the client with
    /// this public key.
    fn set_preferred(&mut self, v: bool) -> Result<()> {
        // swap `preferred` for the value `v`
        // if `preferred` was already the same as `v`, return
        // otherwise, report the swap in stats
        if self.preferred.swap(v, Ordering::Relaxed) == v {
            return Ok(());
        }
        // TODO: stats:
        // 	if v {
        // c.s.curHomeClients.Add(1)
        // homeMove = &c.s.homeMovesIn
        // } else {
        // c.s.curHomeClients.Add(-1)
        // homeMove = &c.s.homeMovesOut
        // }
        // 	// Keep track of varz for home serve moves in/out.  But ignore
        // // the initial packet set when a client connects, which we
        // // assume happens within 5 seconds. In any case, just for
        // // graphs, so not important to miss a move. But it shouldn't:
        // // the netcheck/re-STUNs in magicsock only happen about every
        // // 30 seconds.
        // if time.Since(c.connectedAt) > 5*time.Second {
        // 	homeMove.Add(1)
        // }
        Ok(())
    }

    fn handle_frame_note_preferred(&mut self, preferred: bool) -> Result<()> {
        self.set_preferred(preferred)
    }

    async fn handle_frame_watch_conns(&mut self) -> Result<()> {
        ensure!(self.can_mesh, "insufficient permissions");
        self.send_server(ServerMessage::AddWatcher(self.key))
            .await?;

        Ok(())
    }

    async fn send_server(&self, msg: ServerMessage<P>) -> Result<()> {
        self.server_channel
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;
        Ok(())
    }

    // assumes ping is 8 bytes
    async fn handle_frame_ping(&mut self, data: [u8; 8]) -> Result<()> {
        // TODO:stats
        // c.s.gotPing.Add(1)

        // TODO: add rate limiter
        self.send_pong(data).await?;
        inc!(Metrics, sent_pong);
        Ok(())
    }

    async fn handle_frame_close_peer(&self, key: PublicKey) -> Result<()> {
        ensure!(self.can_mesh, "insufficient permissions");
        self.send_server(ServerMessage::ClosePeer(key)).await?;
        Ok(())
    }

    /// Parse the FORWARD_PACKET frame, getting the destination, source, and
    /// packet content. Then sends the packet to the server, who directs it
    /// to the destination.
    ///
    /// Errors if this client is not a trusted mesh peer, or if the keys cannot
    /// be parsed correctly, or if the packet is larger than MAX_PACKET_SIZE
    async fn handle_frame_forward_packet(
        &self,
        srckey: PublicKey,
        dstkey: PublicKey,
        data: Bytes,
    ) -> Result<()> {
        ensure!(self.can_mesh, "insufficient permissions");

        // TODO: stats:
        // s.packetsRecv.Add(1)
        // s.bytesRecv.Add(int64(len(contents)))
        // s.packetsForwardedIn.Add(1)

        let packet = Packet {
            src: srckey,
            bytes: data,
        };
        self.transfer_packet(dstkey, packet).await
    }

    /// Parse the SEND_PACKET frame, getting the destination and packet content
    /// Then sends the packet to the server, who directs it to the destination.
    ///
    /// Errors if the key cannot be parsed correctly, or if the packet is
    /// larger than MAX_PACKET_SIZE
    async fn handle_frame_send_packet(&self, dst_key: PublicKey, data: Bytes) -> Result<()> {
        let packet = Packet {
            src: self.key,
            bytes: data,
        };
        self.transfer_packet(dst_key, packet).await
    }

    /// Send the given packet to the server. The server will attempt to
    /// send the packet to the destination, dropping the packet if the
    /// destination is not connected, or if the destination client can
    /// not fit any more messages in its queue.
    async fn transfer_packet(&self, dstkey: PublicKey, packet: Packet) -> Result<()> {
        if looks_like_disco_wrapper(&packet.bytes) {
            inc!(Metrics, disco_packets_recv);
            self.send_server(ServerMessage::SendDiscoPacket((dstkey, packet)))
                .await?;
        } else {
            inc!(Metrics, send_packets_recv);
            self.send_server(ServerMessage::SendPacket((dstkey, packet)))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::derp::codec::{recv_frame, FrameType};
    use crate::key::SecretKey;

    use super::*;

    use anyhow::bail;

    struct MockPacketForwarder {}
    impl PacketForwarder for MockPacketForwarder {
        fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, _packet: Bytes) {
            tracing::info!("forwarding packet from {srckey:?} to {dstkey:?}");
        }
    }

    #[tokio::test]
    async fn test_client_conn_io_basic() -> Result<()> {
        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);
        let (mesh_update_s, mesh_update_r) = mpsc::channel(10);

        let preferred = Arc::from(AtomicBool::from(true));
        let key = SecretKey::generate().public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, DerpCodec);
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);

        let conn_io = ClientConnIo::<MockPacketForwarder> {
            can_mesh: true,
            io: Framed::new(MaybeTlsStream::Test(io), DerpCodec),
            timeout: None,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,
            mesh_update_r,
            mesh_update_s: mesh_update_s.clone(),

            key,
            server_channel: server_channel_s,
            preferred: Arc::clone(&preferred),
        };

        let done = CancellationToken::new();
        let io_done = done.clone();
        let io_handle = tokio::task::spawn(async move { conn_io.run(io_done).await });

        // Write tests
        println!("-- write");
        let data = b"hello world!";

        // send packet
        println!("  send packet");
        let packet = Packet {
            src: key,
            bytes: Bytes::from(&data[..]),
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

        // send mesh_update
        let updates = vec![
            PeerConnState {
                peer: key,
                present: true,
            },
            PeerConnState {
                peer: key,
                present: false,
            },
        ];

        mesh_update_s.send(updates.clone()).await?;
        let frame = recv_frame(FrameType::PeerPresent, &mut io_rw).await?;
        assert_eq!(frame, Frame::PeerPresent { peer: key });

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
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!preferred.load(Ordering::Relaxed));

        // change preferred to true
        println!("  preferred: true");
        write_frame(&mut io_rw, Frame::NotePreferred { preferred: true }, None).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(preferred.fetch_and(true, Ordering::Relaxed));

        // add this client as a watcher
        write_frame(&mut io_rw, Frame::WatchConns, None).await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::AddWatcher(got_key) => assert_eq!(key, got_key),
            m => {
                bail!("expected ServerMessage::AddWatcher, got {m:?}");
            }
        }

        // send message to close a peer
        println!("  close peer");
        let target = SecretKey::generate().public();
        write_frame(&mut io_rw, Frame::ClosePeer { peer: target }, None).await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::ClosePeer(got_target) => assert_eq!(target, got_target),
            m => {
                bail!("expected ServerMessage::ClosePeer, got {m:?}");
            }
        }

        // send packet
        println!("  send packet");
        let data = b"hello world!";
        crate::derp::client::send_packet(&mut io_rw, &None, target, Bytes::from_static(data))
            .await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::SendPacket((got_target, packet)) => {
                assert_eq!(target, got_target);
                assert_eq!(key, packet.src);
                assert_eq!(&data[..], &packet.bytes);
            }
            m => {
                bail!("expected ServerMessage::SendPacket, got {m:?}");
            }
        }

        // send disco packet
        println!("  send disco packet");
        // starts with `MAGIC` & key, then data
        let mut disco_data = crate::disco::MAGIC.as_bytes().to_vec();
        disco_data.extend_from_slice(target.as_bytes());
        disco_data.extend_from_slice(data);
        crate::derp::client::send_packet(&mut io_rw, &None, target, disco_data.clone().into())
            .await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::SendDiscoPacket((got_target, packet)) => {
                assert_eq!(target, got_target);
                assert_eq!(key, packet.src);
                assert_eq!(&disco_data[..], &packet.bytes);
            }
            m => {
                bail!("expected ServerMessage::SendDiscoPacket, got {m:?}");
            }
        }

        // forward packet
        println!("  forward packet");
        let fwd_key = SecretKey::generate().public();
        crate::derp::client::forward_packet(&mut io_rw, fwd_key, target, Bytes::from_static(data))
            .await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::SendPacket((got_target, packet)) => {
                assert_eq!(target, got_target);
                assert_eq!(fwd_key, packet.src);
                assert_eq!(&data[..], &packet.bytes);
            }
            m => {
                bail!("expected ServerMessage::SendPacket, got {m:?}");
            }
        }

        // forward disco packet
        println!("  forward disco packet");
        crate::derp::client::forward_packet(&mut io_rw, fwd_key, target, disco_data.clone().into())
            .await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::SendDiscoPacket((got_target, packet)) => {
                assert_eq!(target, got_target);
                assert_eq!(fwd_key, packet.src);
                assert_eq!(&disco_data[..], &packet.bytes);
            }
            m => {
                bail!("expected ServerMessage::SendDiscoPacket, got {m:?}");
            }
        }

        done.cancel();
        io_handle.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_client_conn_read_err() -> Result<()> {
        let (_send_queue_s, send_queue_r) = mpsc::channel(10);
        let (_disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (_peer_gone_s, peer_gone_r) = mpsc::channel(10);
        let (mesh_update_s, mesh_update_r) = mpsc::channel(10);

        let preferred = Arc::from(AtomicBool::from(true));
        let key = SecretKey::generate().public();
        let (io, io_rw) = tokio::io::duplex(1024);
        let mut io_rw = Framed::new(io_rw, DerpCodec);
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);

        println!("-- create client conn");
        let conn_io = ClientConnIo::<MockPacketForwarder> {
            can_mesh: true,
            io: Framed::new(MaybeTlsStream::Test(io), DerpCodec),
            timeout: None,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            peer_gone: peer_gone_r,
            mesh_update_r,
            mesh_update_s: mesh_update_s.clone(),

            key,
            server_channel: server_channel_s,
            preferred: Arc::clone(&preferred),
        };

        let done = CancellationToken::new();
        let io_done = done.clone();

        println!("-- run client conn");
        let io_handle = tokio::task::spawn(async move { conn_io.run(io_done).await });

        // send packet
        println!("   send packet");
        let data = b"hello world!";
        let target = SecretKey::generate().public();

        crate::derp::client::send_packet(&mut io_rw, &None, target, Bytes::from_static(data))
            .await?;
        let msg = server_channel_r.recv().await.unwrap();
        match msg {
            ServerMessage::SendPacket((got_target, packet)) => {
                assert_eq!(target, got_target);
                assert_eq!(key, packet.src);
                assert_eq!(&data[..], &packet.bytes);
                println!("    send packet success");
            }
            m => {
                bail!("expected ServerMessage::SendPacket, got {m:?}");
            }
        }

        println!("-- drop io");
        drop(io_rw);

        // expect task to complete after encountering an error
        if let Err(err) = tokio::time::timeout(Duration::from_secs(1), io_handle).await?? {
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
