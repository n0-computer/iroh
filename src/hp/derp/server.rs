//! based on tailscale/derp/derp_server.go
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::hp::key::node::{PublicKey, SecretKey};

use super::{
    clients::Clients,
    types::{ClientInfo, Conn, PacketForwarder, PeerConnState, ServerMessage},
};
// TODO: skiping `verboseDropKeys` for now

/// The number of packets buffered for sending per client
const PER_CLIENT_SEND_QUEUE_DEPTH: usize = 32;

pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

// TODO: handle duplicate connections, we currently just replace the most recent connection with
// any previous connection
// /// A temporary (2021-08-30) mechanism to change the policy
// /// of how duplicate connections for the same key are handled.
// #[derive(Debug)]
// enum DupPolicy {
//     /// A DupPolicy where the last connection to send traffic for a peer
//     /// if the active one.
//     LastWriterIsActive,
//     /// A DupPolicy that detects if peers are trying to send traffic interleaved
//     /// with each other and then disables all of them
//     DisabledFighters,
// }

#[derive(Debug)]
/// A DERP server.
pub struct Server<'a> {
    /// Optionally specifies how long to wait before failing when writing
    /// to a cliet
    write_timeout: Option<Duration>,
    secret_key: SecretKey,
    // TODO: this is a string in the go impl, I made it a standard length array
    // of bytes in this impl for ease of serializing. (Postcard cannot estimate
    // the size of the serialized struct if this field is a `String`). This should
    // be discussed and worked out.
    mesh_key: [u8; 32],
    /// the encoded x509 cert to send after `LetsEncrypt` cert+intermediate
    meta_cert: &'a [u8],

    /// Counters:
    // TODO: this is the go impl, need to add this in
    // 	packetsSent, bytesSent       expvar.Int
    // packetsRecv, bytesRecv       expvar.Int
    // packetsRecvByKind            metrics.LabelMap
    // packetsRecvDisco             *expvar.Int
    // packetsRecvOther             *expvar.Int
    // _                            align64
    // packetsDropped               expvar.Int
    // packetsDroppedReason         metrics.LabelMap
    // packetsDroppedReasonCounters []*expvar.Int // indexed by dropReason
    // packetsDroppedType           metrics.LabelMap
    // packetsDroppedTypeDisco      *expvar.Int
    // packetsDroppedTypeOther      *expvar.Int
    // _                            align64
    // packetsForwardedOut          expvar.Int
    // packetsForwardedIn           expvar.Int
    // peerGoneFrames               expvar.Int // number of peer gone frames sent
    // gotPing                      expvar.Int // number of ping frames from client
    // sentPong                     expvar.Int // number of pong frames enqueued to client
    // accepts                      expvar.Int
    // curClients                   expvar.Int
    // curHomeClients               expvar.Int // ones with preferred
    // dupClientKeys                expvar.Int // current number of public keys we have 2+ connections for
    // dupClientConns               expvar.Int // current number of connections sharing a public key
    // dupClientConnTotal           expvar.Int // total number of accepted connections when a dup key existed
    // unknownFrames                expvar.Int
    // homeMovesIn                  expvar.Int // established clients announce home server moves in
    // homeMovesOut                 expvar.Int // established clients announce home server moves out
    // multiForwarderCreated        expvar.Int
    // multiForwarderDeleted        expvar.Int
    // removePktForwardOther        expvar.Int
    // avgQueueDuration             *uint64          // In milliseconds; accessed atomically
    // tcpRtt                       metrics.LabelMap // histogram

    /// When true, only accept client connections to the DERP server if the `client_key` is a
    /// known  peer in the network, as specified by a running "tailscaled's client's
    /// LocalAPI"
    verify_clients: bool,

    closed: AtomicBool,
    // TODO: how is this used, should it be a `Sender`?
    // net_conns: HashMap<C, Receiver<()>>,
    // clients: HashMap<PublicKey, ClientSet>,
    /// Maps from netip.AddrPort to a client's public key
    key_of_addr: HashMap<SocketAddr, PublicKey>,
    // watchers: HashMap<ClientConn, bool>,
}

impl<'a> Server<'a> {
    /// replace with builder
    pub fn new(key: SecretKey) -> Self {
        // TODO:
        todo!();
    }

    /// Reports whether the server is configured with a mesh key.
    pub fn has_mesh_key(&self) -> bool {
        !self.mesh_key.is_empty()
    }

    /// Returns the configured mesh key, may be empty.
    pub fn mesh_key(&self) -> [u8; 32] {
        self.mesh_key
    }

    /// Returns the server's private key.
    pub fn private_key(&self) -> SecretKey {
        self.secret_key.clone()
    }

    /// Returns the server's public key.
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.verifying_key()
    }

    /// Closes the server and waits for the connections to disconnect.
    pub async fn close(self) {
        // let closed = self.closed.load(Ordering::Relaxed);
        // if closed {
        //     return;
        // }
        // self.closed.swap(true, Ordering::Relaxed);
        // let mut closed_channels = Vec::new();

        // for (net_conn, closed) in self.net_conns.into_iter() {
        //     match net_conn.close() {
        //         Ok(_) => closed_channels.push(closed),
        //         Err(e) => {
        //             tracing::warn!("error closing connection {e:#?}")
        //         }
        //     }
        // }

        // for c in closed_channels.into_iter() {
        //     if let Err(e) = c.await {
        //         tracing::warn!("error while closing connection {e:#?}");
        //     }
        // }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Reports whether the client with the specified key is connected.
    /// This is used in tests to verify that nodes are connected
    // TODO: we may not need this
    fn is_client_connected_for_test(&self, key: PublicKey) -> bool {
        todo!();
    }

    /// Adds a new connection to the server and serves it.
    ///
    /// The provided [`AsyncReader`] and [`AsyncWriter`] must be already connected to the [`Conn`].
    /// Accept blocks until the Server is closed or the connection closes on its own.
    ///
    /// Accept closes `conn`.
    pub fn accept<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        // conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
    ) -> Result<()> {
        todo!();
    }

    /// Initializes `Server::meta_cert` with a self-signed x509 cert
    /// encoding this server's public key and protocol version. "cmd/derp_server
    /// then sends this after the Let's Encrypt leaf + intermediate certs after
    /// the ServerHello (encrypted in TLS 1.3, not that is matters much).
    ///
    /// Then the client can save a round trime getting that and can start speaking
    /// DERP right away. (we don't use ALPN because that's sent in the clear and
    /// we're being paranoid to not look too weird to any middleboxes, given that
    /// DERP is an ultimate fallback path). But since the post-ServerHello certs
    /// are encrypted we can have the client also use them as a signal to be able
    /// to start speaking DERP right away, starting with its identity proof,
    /// encrypted to the server's public key.
    ///
    /// This RTT optimization fails where there's a corp-mandated TLS proxy with
    /// corp-mandated root certs on employee machines and TLS proxy cleans up
    /// unnecessary certs. In that case we jsut fall back to the extra RTT.
    fn init_meta_cert(&self) {
        todo!();
    }

    // Returns the server metadata cert that can be sent by the TLS server to
    // let the client skip a round trip during start-up.
    pub fn meta_cert(&self) -> &[u8] {
        self.meta_cert.clone()
    }

    /// Notes that client c is no authenticated and ready for packets.
    ///
    /// If `SCLient::key` is connected more than once, the earlier connection(s)
    /// are placed in a non-active state where we read from them (primarily to
    /// observe EOFs/timeouts) but won't send them frames on the assumption
    /// that they're dead.
    // fn register_client(&mut self, client: ClientConn) {
    //     todo!();
    // }

    fn accept_0<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &mut self,
        // conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
        conn_num: i64,
    ) -> Result<()> {
        todo!();
    }

    fn record_drop(
        &self,
        packet_bytes: &[u8],
        srckey: PublicKey,
        dstkey: PublicKey,
        reason: DropReason,
    ) {
        todo!();
    }

    fn verify_client(&self, client_key: PublicKey, info: ClientInfo) -> Result<()> {
        todo!();
    }

    fn send_server_key<W: AsyncWrite + Unpin>(&self, writer: W) -> Result<()> {
        todo!();
    }

    fn send_server_info<W: AsyncWrite + Unpin>(
        &self,
        writer: W,
        client_key: PublicKey,
    ) -> Result<()> {
        todo!();
    }

    /// Reads the `FRAME_CLIENT_INFO` frame from the client (its proof of identity)
    /// upon it's initial connection. It should be considered especially untrusted
    /// at this point.
    fn recv_client_key<R: AsyncRead + Unpin>(&self, reader: R) -> Result<(PublicKey, ClientInfo)> {
        todo!();
    }

    pub fn add_packet_forwarder(&self, dst: PublicKey, fwd: impl PacketForwarder) {
        todo!();
    }

    pub fn remove_packet_forwarder(&self, dst: PublicKey, fwd: impl PacketForwarder) {
        todo!();
    }

    pub fn consistency_check() -> Result<()> {
        todo!();
    }

    // fn serve_debug_traffic() {
    //     todo!();
    // }
}

#[derive(Debug)]
enum DropReason {
    /// Unknown destination PublicKey
    UnknownDest,
    /// Unkonwn destination PublicKey on a derp-forwarded packet
    UnknownDestOnFwd,
    /// Destination disconnected before we could send
    Gone,
    /// Destination queue is full, dropped packet at queue head
    QueueHead,
    /// Destination queue is full, dropped packet at queue tail
    QueueTail,
    /// OS write failed
    WriteError,
    /// The PublicKey is connected 2+ times (active/active, fighting)
    DupClient,
}

pub(crate) struct ServerActor<C, R, W, P>
where
    C: Conn,
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    key: PublicKey,
    receiver: mpsc::Receiver<ServerMessage<C, R, W, P>>,
    /// All clients connected to this server
    clients: Clients<C>,
    /// Representation of the mesh network. Keys that are associated with `None` are strictly local
    /// clients.
    client_mesh: HashMap<PublicKey, Option<P>>,
    /// Mesh clients that need to be appraised on the state of the network
    watchers: HashSet<PublicKey>,
}

impl<C, R, W, P> ServerActor<C, R, W, P>
where
    C: Conn,
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    pub(crate) fn new(key: PublicKey, receiver: mpsc::Receiver<ServerMessage<C, R, W, P>>) -> Self {
        Self {
            key,
            receiver,
            clients: Clients::new(),
            client_mesh: HashMap::default(),
            watchers: HashSet::default(),
        }
    }

    pub(crate) async fn run(mut self, done: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = done.cancelled() => {
                    tracing::warn!("server actor loop cancelled, closing loop");
                    // TODO: stats: drain channel & count dropped packets etc
                    // close all client connections and client read/write loops
                    self.clients.shutdown().await;
                    return Ok(());
                }
                msg = self.receiver.recv() => {
                    let msg = match msg {
                        Some(m) => m,
                        None => {
                            tracing::warn!("server channel sender closed unexpectedly, shutting down server loop");
                            self.clients.shutdown().await;
                            anyhow::bail!("server channel sender closed unexpectedly, closed client connections, and shutting down server loop");
                        }
                    };
                   match msg {
                       ServerMessage::AddWatcher(key) => {
                           // connecting to ourselves, ignore
                           if key == self.key {
                               continue;
                           }
                           // list of all connected clients
                           let updates = self.clients.all_clients().map(|k| PeerConnState{ peer: k.clone(), present: true }).collect();
                           // add to the list of watchers
                           self.watchers.insert(key.clone());
                           // send list of connected clients to the client
                           self.clients.send_mesh_updates(&key, updates);
                       },
                       ServerMessage::ClosePeer(key) => {
                           // close the actual underlying connection to the client, but don't remove it from
                           // the list of clients
                           self.clients.close_conn(&key);
                       },
                        ServerMessage::SendPacket((key, packet)) => {
                            let src = packet.src.clone();
                            if self.clients.contains_key(&key) {
                                // if this client is in our local network, just try to send the
                                // packet
                                if self.clients.send_packet(&key, packet).is_ok() {
                                    self.clients.record_send(&src, key);
                                }
                            } else if let Some(Some(fwd)) = self.client_mesh.get_mut(&key) {
                                // if this client is in our mesh network & has a packet
                                // forwarder
                                fwd.forward_packet(packet.src, key, packet.bytes);
                            } else {
                                tracing::warn!("no way to reach client {key:?}, dropped packet");
                            }
                        }
                       ServerMessage::SendDiscoPacket((key, packet)) => {
                            let src = packet.src.clone();
                            if self.clients.contains_key(&key) {
                                // if this client is in our local network, just try to send the
                                // packet
                                if self.clients.send_disco_packet(&key, packet).is_ok() {
                                    self.clients.record_send(&src, key);
                                }
                            } else if let Some(Some(fwd)) = self.client_mesh.get_mut(&key) {
                                // if this client is in our mesh network & has a packet
                                // forwarder
                                fwd.forward_packet(packet.src, key, packet.bytes);
                            } else {
                                tracing::warn!("no way to reach client {key:?}, dropped packet");
                            }
                       }
                       ServerMessage::CreateClient(client_builder) => {
                           let key = client_builder.key.clone();
                           // add client to mesh
                            if !self.client_mesh.contains_key(&key) {
                                // `None` means its a local client (so it doesn't need a packet
                                // forwarder)
                                self.client_mesh.insert(key.clone(), None);
                            }
                            // build and register client, starting up read & write loops for the
                            // client connection
                            self.clients.register(client_builder);
                            // broadcast to watchers that a new peer has joined the network
                            self.broadcast_peer_state_change(key, true);

                        }
                       ServerMessage::RemoveClient(key) => {
                           // remove the client from the map of clients, & notify any peers that it
                           // has sent messages that it has left the network
                           self.clients.unregister(&key);
                           // remove from mesh
                           self.client_mesh.remove(&key);
                           // broadcast to watchers that this peer has left the network
                           self.broadcast_peer_state_change(key, false);
                       }
                       ServerMessage::AddPacketForwarder((key, packet_forwarder)) => {
                           // Only one packet forward allowed at a time right now
                           self.client_mesh.insert(key, Some(packet_forwarder));
                       },

                       ServerMessage::RemovePacketForwarder(key) => {
                           // check if we have a local connection to the client at `key`
                           if self.clients.contains_key(&key) {
                               // remove any current packet forwarder associated with key
                               // and not that we have a local connection to the client at the
                               // given key
                               self.client_mesh.insert(key, None);
                           } else {
                               self.client_mesh.remove(&key);
                           }
                       },
                   }
                }
            }
        }
    }

    pub(crate) fn broadcast_peer_state_change(&mut self, peer: PublicKey, present: bool) {
        let keys = self.watchers.iter();
        self.clients
            .broadcast_peer_state_change(keys, vec![PeerConnState { peer, present }]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hp::derp::client_conn::ClientBuilder;
    use crate::hp::key::node::PUBLIC_KEY_LENGTH;

    use anyhow::Result;
    use tokio::io::DuplexStream;

    struct MockConn {}
    impl Conn for MockConn {
        fn close(&self) -> Result<()> {
            Ok(())
        }
        fn local_addr(&self) -> std::net::SocketAddr {
            "127.0.0.1:3333".parse().unwrap()
        }
    }

    struct MockPacketForwarder {}
    impl PacketForwarder for MockPacketForwarder {
        fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, _packet: bytes::Bytes) {
            tracing::info!("forwarding packet from {srckey:?} to {dstkey:?}");
        }
    }

    fn test_client_builder(
        key: PublicKey,
        conn_num: usize,
        server_channel: mpsc::Sender<
            ServerMessage<MockConn, DuplexStream, DuplexStream, MockPacketForwarder>,
        >,
    ) -> (
        ClientBuilder<MockConn, DuplexStream, DuplexStream, MockPacketForwarder>,
        DuplexStream,
        DuplexStream,
    ) {
        let (test_reader, writer) = tokio::io::duplex(1024);
        let (reader, test_writer) = tokio::io::duplex(1024);
        (
            ClientBuilder {
                key,
                conn_num,
                conn: MockConn {},
                reader,
                writer,
                can_mesh: true,
                write_timeout: None,
                channel_capacity: 10,
                server_channel,
            },
            test_reader,
            test_writer,
        )
    }

    #[tokio::test]
    async fn test_server_actor() -> Result<()> {
        let server_key = PublicKey::from([1u8; PUBLIC_KEY_LENGTH]);
        // make server actor
        let (server_channel, server_channel_r) = mpsc::channel(20);
        let server_actor: ServerActor<MockConn, DuplexStream, DuplexStream, MockPacketForwarder> =
            ServerActor::new(server_key, server_channel_r);
        let done = CancellationToken::new();
        let server_done = done.clone();
        // run server actor
        let server_task = tokio::spawn(async move { server_actor.run(server_done).await });

        let key_a = PublicKey::from([3u8; PUBLIC_KEY_LENGTH]);
        let (client_a, a_reader, a_writer) =
            test_client_builder(key_a.clone(), 1, server_channel.clone());
        // create client a
        server_channel
            .send(ServerMessage::CreateClient(client_a))
            .await?;
        // add a to watcher list
        server_channel
            .send(ServerMessage::AddWatcher(key_a.clone()))
            .await?;

        // TODO: expect empty message on client a

        let key_b = PublicKey::from([10u8; PUBLIC_KEY_LENGTH]);

        // server message: create client b
        let (client_b, b_reader, b_writer) =
            test_client_builder(key_b.clone(), 2, server_channel.clone());
        server_channel
            .send(ServerMessage::CreateClient(client_b))
            .await?;
        // expect mesh update message on client a
        // server message: create client c
        // server message: add client c as watcher
        // expect mesh update message on client c about a & b
        // add packet forwarder for client c
        // write message from b to a
        // get message on a reader
        // write disco message from b to c
        // get message on c reader
        // remove b
        // get peer gone message on a
        // get mesh update on a & c
        // cancel loop
        // cannot write to client
        // fail on write to server channel?
        done.cancel();
        server_task.await??;
        Ok(())
    }
}
