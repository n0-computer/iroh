use std::sync::atomic::AtomicBool;
use std::time::Duration;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::hp::{
    disco::looks_like_disco_wrapper,
    key::node::{PublicKey, PUBLIC_KEY_LENGTH},
};

use super::client::ClientInfo;
use super::conn::Conn;
use super::{
    read_frame, write_frame_timeout, FRAME_CLOSE_PEER, FRAME_FORWARD_PACKET, FRAME_KEEP_ALIVE,
    FRAME_NOTE_PREFERRED, FRAME_PEER_GONE, FRAME_PEER_PRESENT, FRAME_PING, FRAME_PONG,
    FRAME_RECV_PACKET, FRAME_SEND_PACKET, FRAME_WATCH_CONNS, KEEP_ALIVE, MAX_FRAME_SIZE,
    MAX_PACKET_SIZE,
};

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
struct Packet {
    /// The sender of the packet
    src: PublicKey,
    /// When a packet was put onto a queue before it was sent,
    /// and is used for reporting metrics on the duration of packets
    /// in the queue.
    enqueued_at: Instant,

    /// The data packet bytes.
    bytes: Bytes,
}

/// PeerConnState represents whether or not a peer is connected to the server.
#[derive(Debug, Clone)]
struct PeerConnState {
    peer: PublicKey,
    present: bool,
}

#[derive(Debug)]
/// A client's connection to the server
/// A handle?
/// should have senders here, & be clonable, i think?
/// should be able to be held by server
struct ClientConnManager<C>
where
    C: Conn,
{
    /// Static after construction, process-wide unique counter, incremented each Accept
    conn_num: i64,

    // TODO: in the go impl, we have a ptr to the server & use that ptr to update stats
    // in rust, we should probably have a stats struct separate from the server that we
    // can update in different threads, this may become a series of channels on which to
    // send updates
    // stats: Stats,
    conn: C,
    key: PublicKey,
    info: ClientInfo,
    /// Sent when connection closes
    // TODO: maybe should be a receiver
    done: CancellationToken,
    /// Usually ip:port from `SocketAddr`
    remote_addr: String,
    /// zero if remote_addr is not `ip:port`
    remote_ip_port: u16,
    /// When true, the [`ClientInfo`] had the correct mesh token for inter-region routing
    can_mesh: bool,
    /// Whether more than 1 `ClientConnManager` for one key is connected
    is_dup: AtomicBool,
    /// Whether sends to this peer are disabled due to active/active dups
    is_disabled: AtomicBool,

    /// Controls how quickly two connections with the same client key can kick
    /// each other off the server by taking ownership of a key
    // TODO: replace with rate limiter, also, this should probably be on the ClientSets, not on
    // the client itself
    // replace_limiter: RateLimiter,

    /// Instant at which we created the `ClientConnManager`
    connected_at: Instant,

    reader_handle: JoinHandle<Result<()>>,
    writer_handle: JoinHandle<Result<()>>,

    /// Channels that allow the ClientConnManager (and the Server) to send
    /// the client messages. These `Senders` correspond to `Receivers` on the
    /// [`ClientConnWriter`].
    client_channels: ClientChannels,
}

/// Channels that the [`ClientConnReader`] needs in order to notify the server
/// about actions it needs to take on behalf of the client.
#[derive(Debug)]
struct ServerChannels {
    /// Send a notification to the Server to add this client as a watcher
    add_watcher: mpsc::Sender<PublicKey>,
    /// Send a notification to the Server to close connections to the given peer
    close_peer: mpsc::Sender<PublicKey>,
    /// Send a notification to the server to send this packet to the destination
    send_queue: mpsc::Sender<(PublicKey, Packet)>,
    /// Send a notification to the server to forward this pacekt to the destination
    disco_send_queue: mpsc::Sender<(PublicKey, Packet)>,
}

/// Channels that the [`ClientConnManager`] uses to communicate with the
/// [`ClientConnWriter`] to forward the client:
///  - information about a peer leaving the network (This should only happen for peers that this
///  client was previously communciating with)
///  - forwarded packets (if they are mesh client)
///  - packets sent to this client from another client in the network
#[derive(Debug)]
struct ClientChannels {
    /// Queue of packets intended for the client
    send_queue: mpsc::Sender<Packet>,
    /// Queue of important packets intended for the client
    disco_send_queue: mpsc::Sender<Packet>,
    /// Notify the client that a previous sender has disconnected (Not used by mesh peers)
    peer_gone: mpsc::Sender<PublicKey>,
    /// Send a client (if it is a mesh peer) records that will
    /// allow the client to update their map of who's connected
    /// to this node
    mesh_update: mpsc::Sender<Vec<PeerConnState>>,
}

impl<C> ClientConnManager<C>
where
    C: Conn,
{
    async fn new<R, W>(
        key: PublicKey,
        conn_num: i64,
        conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
        remote_ip_port: u16,
        can_mesh: bool,
        client_info: ClientInfo,
        write_timeout: Duration,
        channel_capacity: usize,
        server_channels: ServerChannels,
        shutdown_client: mpsc::Sender<(PublicKey, i64)>,
    ) -> Result<ClientConnManager<C>>
    where
        R: AsyncRead + Unpin + Send + Sync + 'static,
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let done = CancellationToken::new();
        let client_id = (key.clone(), conn_num);
        let (send_queue_s, send_queue_r) = mpsc::channel(channel_capacity);

        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(channel_capacity);
        let (send_pong_s, send_pong_r) = mpsc::channel(channel_capacity);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(channel_capacity);
        let (mesh_update_s, mesh_update_r) = mpsc::channel(channel_capacity);
        let conn_writer = ClientConnWriter {
            can_mesh,
            writer,
            timeout: write_timeout,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            send_pong: send_pong_r,
            peer_gone: peer_gone_r,
            mesh_update_r,
            mesh_update_s: mesh_update_s.clone(),
        };

        let conn_reader = ClientConnReader {
            can_mesh,
            reader,
            key: key.clone(),
            send_pong: send_pong_s,
            server_channels,
            preferred: false,
        };

        // start writer loop
        let writer_done = done.clone();
        let writer_shutdown_client = shutdown_client.clone();
        let writer_client_id = client_id.clone();
        let writer_handle = tokio::spawn(async move {
            let res = conn_writer.run(writer_done).await;
            if let Err(e) = writer_shutdown_client.try_send(writer_client_id.clone()) {
                tracing::warn!(
                    "unable to let server know to shut down client {writer_client_id:?}: {e:?}"
                );
            }
            res
        });

        // start reader loop
        let reader_done = done.clone();
        let reader_handle = tokio::spawn(async move {
            let res = conn_reader.run(reader_done).await;
            if let Err(e) = shutdown_client.try_send(client_id.clone()) {
                tracing::warn!(
                    "unable to let server know to shut down client {client_id:?}: {e:?}"
                );
            }
            res
        });

        // return client conn to server
        Ok(ClientConnManager {
            conn_num,
            conn,
            key,
            remote_addr,
            remote_ip_port,
            can_mesh,
            is_dup: AtomicBool::from(false),
            is_disabled: AtomicBool::from(false),
            connected_at: Instant::now(),
            writer_handle,
            reader_handle,
            info: client_info,
            done,
            client_channels: ClientChannels {
                send_queue: send_queue_s,
                disco_send_queue: disco_send_queue_s,
                peer_gone: peer_gone_s,
                mesh_update: mesh_update_s,
            },
        })
    }

    /// Shutdown the `ClientConnManager` reader and writer loops and closes the "actual" connection.
    ///
    /// Logs any shutdown errors as warnings.
    async fn shutdown(self) {
        self.done.cancel();
        if let Err(e) = self.writer_handle.await {
            tracing::warn!(
                "error closing writer loop for client connection {:?} {}: {e:?}",
                self.key,
                self.conn_num
            );
        }
        if let Err(e) = self.reader_handle.await {
            tracing::warn!(
                "error closing reader loop for client connection {:?} {}: {e:?}",
                self.key,
                self.conn_num
            );
        }
        if let Err(e) = self.conn.close() {
            tracing::warn!(
                "error closing connection to client {:?} {}: {e:?}",
                self.key,
                self.conn_num
            );
        }
    }
}

/// Manages all the writes to this client. It periodically sends a `KEEP_ALIVE`
/// message to the client to keep the connection alive.
///
/// Call `run` to start listening for instructions from the
/// server or from the associated `ClientConnReader`. Once it hits its
/// first write error or error receiving off a channel, it error an return.
/// If writes do not complete in the given `timeout`, it will also error.
///
/// The `ClientConnWriter` can send the client:
///  - a KEEP_ALIVE frame
///  - a PEER_GONE frame, informing the client a peer is gone from the network // TODO: is this
///  a mesh only thing?
///  - packets from other peers
///
/// If the client is a mesh client, it can also send updates about peers in the mesh.
#[derive(Debug)]
pub(crate) struct ClientConnWriter<W: AsyncWrite + Unpin + Send + Sync> {
    /// Indicates whether this client can mesh
    can_mesh: bool,
    /// Writer we use to write to the client
    writer: W,
    /// Max time we wait to complete a write to the client
    timeout: Duration,
    /// Packets queued to send to the client
    send_queue: mpsc::Receiver<Packet>,
    /// Important packets queued to send to the client
    disco_send_queue: mpsc::Receiver<Packet>,
    /// Pong replies to send to the client
    send_pong: mpsc::Receiver<[u8; 8]>,
    /// Notify the client that a previous sender has disconnected (not used by mesh peers)
    peer_gone: mpsc::Receiver<PublicKey>,
    /// Used by mesh peers (a set of regional DERP servers) and contains records
    /// that need to be sent to the client for them to update their map of who's
    /// connected to this node
    /// Notify the client of a peer state change ([`PeerConnState`])
    mesh_update_r: mpsc::Receiver<Vec<PeerConnState>>,
    /// Used by `reschedule_mesh_update` to reschedule additional mesh_updates
    mesh_update_s: mpsc::Sender<Vec<PeerConnState>>,
}

impl<W> ClientConnWriter<W>
where
    W: AsyncWrite + Unpin + Send + Sync,
{
    async fn run(mut self, done: CancellationToken) -> Result<()> {
        let jitter = Duration::from_secs(5);
        let mut keep_alive = tokio::time::interval(KEEP_ALIVE + jitter);
        // ticks immediately
        keep_alive.tick().await;
        loop {
            tokio::select! {
                _ = done.cancelled() => {
                    return Ok(());
                }
                peer = self.peer_gone.recv() => {
                    let peer = peer.context("Server.peer_gone dropped")?;
                    self.send_peer_gone(peer).await?;
                }
                updates = self.mesh_update_r.recv() => {
                    let updates = updates.context("Server.mesh_update dropped")?;
                    self.send_mesh_updates(updates).await?;
                }
                packet = self.send_queue.recv() => {
                    let packet = packet.context("Server.send_queue dropped")?;
                    self.send_packet(packet).await?;
                    // TODO: stats
                    // record `packet.enqueuedAt`
                }
                packet = self.disco_send_queue.recv() => {
                    let packet = packet.context("Server.disco_send_queue dropped")?;
                    self.send_packet(packet).await?;
                    // TODO: stats
                    // record `packet.enqueuedAt`
                }
                data = self.send_pong.recv() => {
                    let data = data.context("ClientConnReader.send_pong dropped")?;
                    self.send_pong(data).await?;
                    // TODO: stats
                    // record `send_pong`
                }
                _ = keep_alive.tick() => {
                    self.send_keep_alive().await?;
                }
            }
            // TODO: golang batches as many writes as are in all the channels
            // & then flushes when there is no more work to be done at the moment.
            // refactor to get something similar
            self.writer.flush().await?;
        }
    }

    /// Send  `FRAME_KEEP_ALIVE`, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_keep_alive(&mut self) -> Result<()> {
        write_frame_timeout(&mut self.writer, FRAME_KEEP_ALIVE, vec![], self.timeout).await
    }

    /// Send a `pong` frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_pong(&mut self, data: [u8; 8]) -> Result<()> {
        // TODO: stats
        // c.s.peerGoneFrames.Add(1)
        write_frame_timeout(&mut self.writer, FRAME_PONG, vec![&data], self.timeout).await
    }

    /// Sends a peer gone frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_peer_gone(&mut self, peer: PublicKey) -> Result<()> {
        // TODO: stats
        // c.s.peerGoneFrames.Add(1)
        write_frame_timeout(
            &mut self.writer,
            FRAME_PEER_GONE,
            vec![peer.as_bytes()],
            self.timeout,
        )
        .await
    }

    /// Sends a peer present frame, does not flush
    ///
    /// Errors if the send does not happen within the `timeout` duration
    async fn send_peer_present(&mut self, peer: PublicKey) -> Result<()> {
        write_frame_timeout(
            &mut self.writer,
            FRAME_PEER_PRESENT,
            vec![peer.as_bytes()],
            self.timeout,
        )
        .await
    }

    // TODO: golang comment:
    // "Drains as many mesh `PEER_STATE_CHANGE`s entries as possible
    // into the write buffer WITHOUT flushing or otherwise blocking (as it holds the mutex while
    // working).
    // If it can't drain them all, it schedules itself to be called again in the future."
    /// Send mesh updates for the first 16 (arbitrary #, based on the size that
    /// the goimpl seems to "want" the `PeerConnState` vector to be) `PeerConnState`
    /// in the vector. If there are more than 16 entires, it schedules itself for a
    /// future update.
    async fn send_mesh_updates(&mut self, mut updates: Vec<PeerConnState>) -> Result<()> {
        if !self.can_mesh {
            bail!(
                "unexpected request to update mesh peers on a connection that is not able to mesh"
            );
        }
        let scheduled_updates: Vec<_> = if updates.len() < 16 {
            updates.drain(..).collect()
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
        if updates.len() != 0 {
            self.request_mesh_update(updates).await?;
        }
        Ok(())
    }

    // runs in a go routing in the go impl
    async fn request_mesh_update(&self, updates: Vec<PeerConnState>) -> Result<()> {
        if !self.can_mesh {
            bail!(
                "unexpected request to update mesh peers on a connection that is not able to mesh"
            );
        }
        self.mesh_update_s.send(updates).await?;
        Ok(())
    }

    /// Writes contents to the client in a `RECV_PACKET` frame. If `srcKey.is_zero`, it uses the
    /// old DERPv1 framing format, otherwise uses the DERPv2 framing format. The bytes of contents
    /// are only valid until this function returns, do not retain the slices.
    /// Does not flush.
    async fn send_packet(&mut self, packet: Packet) -> Result<()> {
        // TODO: stats:
        // 	defer func() {
        // // Stats update.
        // if err != nil {
        // 	c.s.recordDrop(contents, packet.src, c.key, dropReasonWriteError)
        // } else {
        // 	c.s.packetsSent.Add(1)
        // 	c.s.bytesSent.Add(int64(len(packet.contents)))
        // }
        // }()
        let srckey = packet.src;
        let contents = packet.bytes;
        if srckey.is_zero() {
            // TODO: ensure we handle this correctly on the client side
            write_frame_timeout(
                &mut self.writer,
                FRAME_RECV_PACKET,
                vec![&contents],
                self.timeout,
            )
            .await
        } else {
            write_frame_timeout(
                &mut self.writer,
                FRAME_RECV_PACKET,
                vec![srckey.as_bytes(), &contents],
                self.timeout,
            )
            .await
        }
    }
}

/// Responsible for reading frames from the client, parsing the frames, and sending
/// the content to the correct location.
///
/// The `ClientConnReader` can:
///     - receive a ping and notify the `ClientConnWriter` to write a pong back
///     to the client
///     - notify the server to send a packet to another peer on behalf of the client
///     - note whether the client is `preferred`  TODO: what is this?
///
/// If the `ClientConnReader` `can_mesh` (is a trusted mesh peer), it can also:
///     - tell the server to add the current client as a watcher TODO: what is a watcher?
///     - tell the server to close a given peer
///     - tell the server to forward a packet from another peer.
struct ClientConnReader<R>
where
    R: AsyncRead + Unpin + Send + Sync,
{
    /// Indicates whether this client can mesh
    can_mesh: bool,
    /// Reader we use to read from the client
    reader: R,
    /// PublicKey of this client
    key: PublicKey,
    /// Pong replies to sent to the client, processed by the [`ClientConnWriter`]
    send_pong: mpsc::Sender<[u8; 8]>,

    /// Channels used to communicate with the server about actions
    /// it needs to take on behalf of the client
    server_channels: ServerChannels,

    /// TODO: what is this?
    preferred: bool,
}

impl<R> ClientConnReader<R>
where
    R: AsyncRead + Unpin + Send + Sync,
{
    async fn run(mut self, done: CancellationToken) -> Result<()> {
        tokio::select! {
            biased;
            res = self.read() => {
                res
            }
            _ = done.cancelled() => {
                Ok(())
            }
        }
    }

    /// Read off the `reader`, erroring and returning at the first error
    async fn read(&mut self) -> Result<()> {
        let mut buf = BytesMut::new();
        loop {
            // TODO: return Ok(()) if EOF error
            let (frame_type, _frame_len) =
                read_frame(&mut self.reader, MAX_FRAME_SIZE, &mut buf).await?;
            // TODO: "note client activity", meaning we update the server that the client with this
            // public key was the last one to receive data
            match frame_type {
                FRAME_NOTE_PREFERRED => {
                    self.handle_frame_note_preferred(&buf)?;
                }
                FRAME_SEND_PACKET => {
                    self.handle_frame_send_packet(&buf).await?;
                }
                FRAME_FORWARD_PACKET => {
                    self.handle_frame_forward_packet(&buf).await?;
                }
                FRAME_WATCH_CONNS => {
                    self.handle_frame_watch_conns(&buf).await?;
                }
                FRAME_CLOSE_PEER => {
                    self.handle_frame_close_peer(&buf).await?;
                }
                FRAME_PING => {
                    self.handle_frame_ping(&buf).await?;
                }
                _ => {
                    buf.clear();
                }
            }
        }
    }

    // TODO: what does preferred mean?
    fn set_preferred(&mut self, v: bool) -> Result<()> {
        if self.preferred == v {
            return Ok(());
        }
        self.preferred = v;
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

    fn handle_frame_note_preferred(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != 1 {
            bail!("FRAME_NOTE_PREFERRED content is an unexpected size");
        }
        self.set_preferred(data[0] != 0)
    }

    async fn handle_frame_watch_conns(&mut self, data: &[u8]) -> Result<()> {
        if !data.is_empty() {
            bail!("FRAME_WATCH_CONNS content is an unexpected size");
        }
        if !self.can_mesh {
            bail!("insufficient permissions");
        }
        self.server_channels
            .add_watcher
            .send(self.key.clone())
            .await?;
        Ok(())
    }

    // assumes ping is 8 bytes
    async fn handle_frame_ping(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != 8 {
            bail!("FRAME_PING unexpected length {}", data.len());
        }
        // TODO:stats
        // c.s.gotPing.Add(1)

        // TODO: add rate limiter

        let data = <[u8; 8]>::try_from(data)?;
        self.send_pong.send(data).await?;
        Ok(())
    }

    async fn handle_frame_close_peer(&self, data: &[u8]) -> Result<()> {
        if !self.can_mesh {
            bail!("insufficient permissions");
        }
        let key = PublicKey::try_from(data)?;
        self.server_channels.close_peer.send(key).await?;
        Ok(())
    }

    /// Parse the FORWARD_PACKET frame, getting the destination, source, and
    /// packet content. Then sends the packet to the server, who directs it
    /// to the destination.
    ///
    /// Errors if this client is not a trusted mesh peer, or if the keys cannot
    /// be parsed correctly, or if the packet is larger than MAX_PACKET_SIZE
    async fn handle_frame_forward_packet(&self, data: &[u8]) -> Result<()> {
        if !self.can_mesh {
            bail!("insufficient permissions");
        }
        let (srckey, dstkey, data) = parse_forward_packet(data)?;

        // TODO: stats:
        // s.packetsRecv.Add(1)
        // s.bytesRecv.Add(int64(len(contents)))
        // s.packetsForwaredIn.Add(1)

        let packet = Packet {
            src: srckey,
            bytes: Bytes::from(data.to_owned()),
            enqueued_at: Instant::now(),
        };
        self.transfer_packet(dstkey, packet).await
    }

    /// Parse the SEND_PACKET frame, getting the destination and packet content
    /// Then sends the packet to the server, who directs it to the destination.
    ///
    /// Errors if the key cannot be parsed correctly, or if the packet is
    /// larger than MAX_PACKET_SIZE
    async fn handle_frame_send_packet(&self, data: &[u8]) -> Result<()> {
        let (dstkey, data) = parse_send_packet(data)?;
        // TODO: stats:
        // s.packetsRecv.Add(1)
        // s.bytesRecv.Add(int64(len(contents)))
        let packet = Packet {
            src: self.key.clone(),
            bytes: Bytes::from(data.to_owned()),
            enqueued_at: Instant::now(),
        };
        self.transfer_packet(dstkey, packet).await
    }

    /// Send the given packet to the server. The server will attempt to
    /// send the packet to the destination, dropping the packet if the
    /// destination is not connected, or if the destination client can
    /// not fit any more messages in its queue.
    async fn transfer_packet(&self, dstkey: PublicKey, packet: Packet) -> Result<()> {
        if looks_like_disco_wrapper(&packet.bytes) {
            self.server_channels
                .send_queue
                .send((dstkey, packet))
                .await
                .expect("server send_queue dropped");
        } else {
            self.server_channels
                .disco_send_queue
                .send((dstkey, packet))
                .await
                .expect("server disco_send_queue dropped");
        }
        Ok(())
    }
}

fn parse_forward_packet(data: &[u8]) -> Result<(PublicKey, PublicKey, &[u8])> {
    if data.len() < PUBLIC_KEY_LENGTH * 2 {
        bail!("short FORWARD_PACKET frame");
    }

    let packet_len = data.len() - (PUBLIC_KEY_LENGTH * 2);
    if packet_len > MAX_PACKET_SIZE {
        bail!("data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}");
    }
    let srckey = PublicKey::try_from(&data[..PUBLIC_KEY_LENGTH])?;
    let dstkey = PublicKey::try_from(&data[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH * 2])?;
    let data = &data[PUBLIC_KEY_LENGTH * 2..];

    Ok((srckey, dstkey, data))
}

fn parse_send_packet(data: &[u8]) -> Result<(PublicKey, &[u8])> {
    if data.len() < PUBLIC_KEY_LENGTH {
        bail!("short SEND_PACKET frame");
    }
    let packet_len = data.len() - PUBLIC_KEY_LENGTH;
    if packet_len > MAX_PACKET_SIZE {
        bail!("data packet longer ({packet_len}) than max of {MAX_PACKET_SIZE}");
    }
    let dstkey = PublicKey::try_from(&data[..PUBLIC_KEY_LENGTH])?;
    let data = &data[PUBLIC_KEY_LENGTH..];
    Ok((dstkey, data))
}

#[cfg(test)]
mod tests {
    use crate::hp::derp::server::WRITE_TIMEOUT;

    use super::*;

    #[tokio::test]
    async fn test_client_conn_reader_basic() -> Result<()> {
        let (mut reader, mut writer) = tokio::io::duplex(1024);

        // set up read manager with reader
        // set up channels to send off read manager
        // send each kind of packet from the client
        // test that correct messages got to channels
        todo!();
    }

    #[tokio::test]
    async fn test_client_conn_writer_basic() -> Result<()> {
        let (mut reader, mut writer) = tokio::io::duplex(1024);
        let mut buf = BytesMut::new();
        let (send_queue_s, send_queue_r) = mpsc::channel(10);
        let (disco_send_queue_s, disco_send_queue_r) = mpsc::channel(10);
        let (send_pong_s, send_pong_r) = mpsc::channel(10);
        let (peer_gone_s, peer_gone_r) = mpsc::channel(10);
        let (mesh_update_s, mesh_update_r) = mpsc::channel(10);
        let conn_writer = ClientConnWriter {
            can_mesh: true,
            writer,
            timeout: WRITE_TIMEOUT,
            send_queue: send_queue_r,
            disco_send_queue: disco_send_queue_r,
            send_pong: send_pong_r,
            peer_gone: peer_gone_r,
            mesh_update_r,
            mesh_update_s: mesh_update_s.clone(),
        };

        let done = CancellationToken::new();
        let writer_done = done.clone();
        let writer_handle = tokio::spawn(async move { conn_writer.run(writer_done).await });
        let key = PublicKey::from([1u8; PUBLIC_KEY_LENGTH]);
        let data = b"hello world!";

        // send packet
        let packet = Packet {
            src: key.clone(),
            enqueued_at: Instant::now(),
            bytes: Bytes::from(&data[..]),
        };
        send_queue_s.send(packet.clone()).await?;
        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_RECV_PACKET, frame_type);
        assert_eq!(data.len() + PUBLIC_KEY_LENGTH, frame_len);
        let (got_key, got_data) = crate::hp::derp::client::parse_recv_frame(&buf)?;
        assert_eq!(key, got_key);
        assert_eq!(&data[..], got_data);

        // send disco packet
        disco_send_queue_s.send(packet.clone()).await?;
        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_RECV_PACKET, frame_type);
        assert_eq!(data.len() + PUBLIC_KEY_LENGTH, frame_len);
        let (got_key, got_data) = crate::hp::derp::client::parse_recv_frame(&buf)?;
        assert_eq!(key, got_key);
        assert_eq!(&data[..], got_data);

        // send pong
        let msg = b"pingpong";
        send_pong_s.send(*msg).await?;
        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_PONG, frame_type);
        assert_eq!(8, frame_len);
        assert_eq!(msg, &buf[..]);

        // send peer_gone
        peer_gone_s.send(key.clone()).await?;
        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_PEER_GONE, frame_type);
        assert_eq!(PUBLIC_KEY_LENGTH, frame_len);
        assert_eq!(key, PublicKey::try_from(&buf[..])?);

        // send mesh_upate
        let updates = vec![
            PeerConnState {
                peer: key.clone(),
                present: true,
            },
            PeerConnState {
                peer: key.clone(),
                present: false,
            },
        ];

        mesh_update_s.send(updates.clone()).await?;
        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_PEER_PRESENT, frame_type);
        assert_eq!(PUBLIC_KEY_LENGTH, frame_len);
        assert_eq!(key, PublicKey::try_from(&buf[..])?);

        let (frame_type, frame_len) = read_frame(&mut reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(FRAME_PEER_GONE, frame_type);
        assert_eq!(PUBLIC_KEY_LENGTH, frame_len);
        assert_eq!(key, PublicKey::try_from(&buf[..])?);

        done.cancel();
        writer_handle.await??;
        Ok(())
    }
}
