//! based on tailscale/derp/derp_server.go
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Result};
use bytes::BytesMut;
use postcard::experimental::max_size::MaxSize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::hp::key::node::{PublicKey, SecretKey, PUBLIC_KEY_LENGTH};

use super::{
    clients::Clients,
    types::{ClientInfo, Conn, PacketForwarder, PeerConnState, ServerMessage},
};
use super::{read_frame, FRAME_SERVER_INFO};
use super::{
    types::ServerInfo, write_frame, FRAME_CLIENT_INFO, FRAME_SERVER_KEY, MAGIC, PROTOCOL_VERSION,
    SERVER_CHANNEL_SIZE,
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
///
/// TODO: how small does this have to be before this is considered cheap to clone?
/// It would make alot of the APIs easier if we could just clone this.
pub struct Server<'a, C, R, W, P>
where
    C: Conn,
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    /// Optionally specifies how long to wait before failing when writing
    /// to a client
    write_timeout: Option<Duration>,
    /// secret_key of the client
    secret_key: SecretKey,
    // TODO: this is a string in the go impl, I made it a standard length array
    // of bytes in this impl for ease of serializing. (Postcard cannot estimate
    // the size of the serialized struct if this field is a `String`). This should
    // be discussed and worked out.
    // from go impl: log.Fatalf("key in %s must contain 64+ hex digits", *meshPSKFile)
    mesh_key: Option<[u8; 32]>,
    /// the encoded x509 cert to send after `LetsEncrypt` cert+intermediate
    meta_cert: &'a [u8],
    /// Channel on which to communicate to the `ServerActor`
    server_channel: mpsc::Sender<ServerMessage<C, R, W, P>>,
    /// When true, only accept client connections to the DERP server if the `client_key` is a
    /// known  peer in the network, as specified by a running "tailscaled's client's
    /// LocalAPI"
    verify_clients: bool,
    /// When true, the server has been shutdown.
    closed: Arc<AtomicBool>,
    /// (number of bytes allowed per second, number of bytes allowed at once)
    /// If "bytes per second" is 0, it is as if there is no rate limit
    rate_limit: Option<(usize, usize)>,
    /// Server loop handler
    loop_handler: JoinHandle<Result<()>>,
    /// Done token:
    cancel: CancellationToken,
    // TODO: stats collection
    // Counters:
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
}

impl<'a, C, R, W, P> Server<'a, C, R, W, P>
where
    C: Conn,
    R: AsyncRead + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    P: PacketForwarder,
{
    /// replace with builder
    pub fn new(key: SecretKey, mesh_key: Option<[u8; 32]>, verify_clients: bool) -> Self {
        let (server_channel_s, server_channel_r) = mpsc::channel(SERVER_CHANNEL_SIZE);
        let server_actor = ServerActor::new(key.verifying_key(), server_channel_r);
        let cancel_token = CancellationToken::new();
        let done = cancel_token.clone();
        let server_task = tokio::spawn(async move { server_actor.run(done).await });
        let meta_cert = init_meta_cert();
        Self {
            // TODO: add some default
            write_timeout: None,
            secret_key: key,
            mesh_key,
            meta_cert,
            server_channel: server_channel_s,
            verify_clients,
            closed: Arc::new(AtomicBool::new(false)),
            rate_limit: None,
            loop_handler: server_task,
            cancel: cancel_token,
        }
    }

    /// Reports whether the server is configured with a mesh key.
    pub fn has_mesh_key(&self) -> bool {
        self.mesh_key.is_some()
    }

    /// Returns the configured mesh key, may be empty.
    pub fn mesh_key(&self) -> Option<[u8; 32]> {
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
        let is_closed = self.is_closed();
        if !is_closed {
            self.cancel.cancel();
            match self.loop_handler.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("error shutting down server: {e:?}"),
                Err(e) => tracing::warn!("error waiting for the server process to close: {e:?}"),
            }
            self.closed.swap(true, Ordering::Relaxed);
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Adds a new connection to the server and serves it.
    ///
    /// The provided [`AsyncReader`] and [`AsyncWriter`] must be already connected to the [`Conn`].
    /// Accept blocks until the Server is closed or the connection closes on its own.
    ///
    /// Accept closes `conn`.
    pub fn accept(
        &self,
        // conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
    ) -> Result<()> {
        todo!();
    }

    // Returns the server metadata cert that can be sent by the TLS server to
    // let the client skip a round trip during start-up.
    pub fn meta_cert(&self) -> &[u8] {
        self.meta_cert.clone()
    }

    fn accept_0(
        &mut self,
        // conn: C,
        reader: R,
        writer: W,
        remote_addr: String,
        conn_num: i64,
    ) -> Result<()> {
        todo!();
    }

    fn verify_client(&self, client_key: PublicKey, info: ClientInfo) -> Result<()> {
        if !self.verify_clients {
            return Ok(());
        }
        // status, err = tailscale.Status(context.TODO())
        // 	if err != nil {
        // return fmt.Errorf("failed to query local tailscaled status: %w", err)
        // }
        // if clientKey == status.Self.PublicKey {
        // return nil
        // }
        // if _, exists := status.Peer[clientKey]; !exists {
        // return fmt.Errorf("client %v not in set of peers", clientKey)
        // }
        // // TODO(bradfitz): add policy for configurable bandwidth rate per client?
        // return nil
        Ok(())
    }

    async fn send_server_key(&self, mut writer: W) -> Result<()> {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC.as_bytes());
        buf.extend_from_slice(self.public_key().as_bytes());
        let content = &[buf.as_slice()];
        write_frame(&mut writer, FRAME_SERVER_KEY, content).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn send_server_info(&self, mut writer: W, client_key: PublicKey) -> Result<()> {
        let server_info = if let Some((bytes_per_second, bytes_burst)) = self.rate_limit {
            ServerInfo {
                version: PROTOCOL_VERSION,
                token_bucket_bytes_per_second: bytes_per_second,
                token_bucket_bytes_burst: bytes_burst,
            }
        } else {
            ServerInfo {
                version: PROTOCOL_VERSION,
                token_bucket_bytes_per_second: 0,
                token_bucket_bytes_burst: 0,
            }
        };
        let mut buf = BytesMut::zeroed(ServerInfo::POSTCARD_MAX_SIZE);
        let msg = postcard::to_slice(&server_info, &mut buf)?;
        let msg = self.secret_key.seal_to(&client_key, msg);
        let msg = &[msg.as_slice()];
        write_frame(&mut writer, FRAME_SERVER_INFO, msg).await?;
        writer.flush().await?;
        Ok(())
    }

    /// Reads the `FRAME_CLIENT_INFO` frame from the client (its proof of identity)
    /// upon it's initial connection. It should be considered especially untrusted
    /// at this point.
    async fn recv_client_key(&self, mut reader: R) -> Result<(PublicKey, ClientInfo)> {
        let mut buf = BytesMut::new();
        // the client is untrusted at this point, limit the input size even smaller than our usual
        // maximum frame size
        let (frame_type, _) = read_frame(&mut reader, 256 * 1024, &mut buf).await?;
        ensure!(
            frame_type == FRAME_CLIENT_INFO,
            "expected FRAME_CLIENT_INFO frame got {frame_type}"
        );
        let key = PublicKey::try_from(&buf[..PUBLIC_KEY_LENGTH])?;
        let msg = self.secret_key.open_from(&key, &buf[PUBLIC_KEY_LENGTH..])?;
        let info: ClientInfo = postcard::from_bytes(&msg)?;
        Ok((key, info))
    }

    pub fn add_packet_forwarder_fn(&self) -> impl Fn(PublicKey, P) -> Result<()> {
        let server_channel = self.server_channel.clone();
        move |key, fwd| {
            server_channel.try_send(ServerMessage::AddPacketForwarder((key, fwd)))?;
            Ok(())
        }
    }

    pub fn remove_packet_forwarder_fn(&self) -> impl Fn(PublicKey) -> Result<()> {
        let server_channel = self.server_channel.clone();
        move |key| {
            server_channel.try_send(ServerMessage::RemovePacketForwarder(key))?;
            Ok(())
        }
    }
}

// TODO: may not need this yet
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
                           // send list of connected clients to the client
                           self.clients.send_mesh_updates(&key, updates);

                           // add to the list of watchers
                           self.watchers.insert(key.clone());
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

/// Initializes `the Server` with a self-signed x509 cert
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
fn init_meta_cert<'a>() -> &'a [u8] {
    // TODO: implement certificate creation
    //
    // pub, priv, err := ed25519.GenerateKey(crand.Reader)
    // if err != nil {
    // 	log.Fatal(err)
    // }
    // tmpl := &x509.Certificate{
    // 	SerialNumber: big.NewInt(ProtocolVersion),
    // 	Subject: pkix.Name{
    // 		CommonName: fmt.Sprintf("derpkey%s", s.publicKey.UntypedHexString()),
    // 	},
    // 	// Windows requires NotAfter and NotBefore set:
    // 	NotAfter:  time.Now().Add(30 * 24 * time.Hour),
    // 	NotBefore: time.Now().Add(-30 * 24 * time.Hour),
    // 	// Per https://github.com/golang/go/issues/51759#issuecomment-1071147836,
    // 	// macOS requires BasicConstraints when subject == issuer:
    // 	BasicConstraintsValid: true,
    // }
    // cert, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, pub, priv)
    // if err != nil {
    // 	log.Fatalf("CreateCertificate: %v", err)
    // }
    // s.metaCert = cert
    //
    b"todo: implement init_meta_cert"
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hp::{
        derp::{
            client_conn::ClientBuilder, FRAME_PEER_GONE, FRAME_PEER_PRESENT, FRAME_RECV_PACKET,
            MAX_FRAME_SIZE,
        },
        key::node::PUBLIC_KEY_LENGTH,
    };

    use anyhow::Result;
    use bytes::BytesMut;
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

    struct MockPacketForwarder {
        packets: mpsc::Sender<(PublicKey, PublicKey, bytes::Bytes)>,
    }

    impl PacketForwarder for MockPacketForwarder {
        fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, packet: bytes::Bytes) {
            let _ = self.packets.try_send((srckey, dstkey, packet));
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
        let (client_a, mut a_reader, _a_writer) =
            test_client_builder(key_a.clone(), 1, server_channel.clone());
        // create client a
        server_channel
            .send(ServerMessage::CreateClient(client_a))
            .await?;
        // add a to watcher list
        server_channel
            .send(ServerMessage::AddWatcher(key_a.clone()))
            .await?;

        // a expects mesh peer update about itself, aka the only peer in the network currently
        let mut buf = BytesMut::new();
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        assert_eq!(key_a.as_bytes()[..], buf[..]);

        let key_b = PublicKey::from([9u8; PUBLIC_KEY_LENGTH]);

        // server message: create client b
        let (client_b, _b_reader, mut b_writer) =
            test_client_builder(key_b.clone(), 2, server_channel.clone());
        server_channel
            .send(ServerMessage::CreateClient(client_b))
            .await?;

        // expect mesh update message on client a
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        assert_eq!(key_b.as_bytes()[..], buf[..]);

        // server message: create client c
        let key_c = PublicKey::from([10u8; PUBLIC_KEY_LENGTH]);
        let (client_c, mut c_reader, _c_writer) =
            test_client_builder(key_c.clone(), 3, server_channel.clone());
        server_channel
            .send(ServerMessage::CreateClient(client_c))
            .await?;

        // expect mesh update message on client_a
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        assert_eq!(key_c.as_bytes()[..], buf[..]);

        // server message: add client c as watcher
        server_channel
            .send(ServerMessage::AddWatcher(key_c.clone()))
            .await?;

        // expect mesh update message on client c about all peers in the network (a, b, & c)
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut c_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        let mut peers = vec![buf[..PUBLIC_KEY_LENGTH].to_vec()];
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut c_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        peers.push(buf[..PUBLIC_KEY_LENGTH].to_vec());
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut c_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);
        peers.push(buf[..PUBLIC_KEY_LENGTH].to_vec());
        assert!(peers.contains(&key_a.as_bytes().to_vec()));
        assert!(peers.contains(&key_b.as_bytes().to_vec()));
        assert!(peers.contains(&key_c.as_bytes().to_vec()));

        // add packet forwarder for client d
        let key_d = PublicKey::from([11u8; PUBLIC_KEY_LENGTH]);
        let (packet_s, mut packet_r) = mpsc::channel(10);
        let fwd_d = MockPacketForwarder { packets: packet_s };
        server_channel
            .send(ServerMessage::AddPacketForwarder((key_d.clone(), fwd_d)))
            .await?;

        // write message from b to a
        let msg = b"hello world!";
        crate::hp::derp::client::send_packet(&mut b_writer, &None, key_a.clone(), msg).await?;
        // get message on a reader
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        let (key, frame) = crate::hp::derp::client::parse_recv_frame(&buf)?;
        assert_eq!(FRAME_RECV_PACKET, frame_type);
        assert_eq!(key_b, key);
        assert_eq!(msg, frame);

        // write disco message from b to d
        let mut disco_msg = crate::hp::disco::MAGIC.as_bytes().to_vec();
        disco_msg.extend_from_slice(key_b.as_bytes());
        disco_msg.extend_from_slice(msg);
        crate::hp::derp::client::send_packet(&mut b_writer, &None, key_d.clone(), &disco_msg)
            .await?;
        // get message on d reader
        let (got_src, got_dst, got_packet) = packet_r.recv().await.unwrap();
        assert_eq!(got_src, key_b);
        assert_eq!(got_dst, key_d);
        assert_eq!(disco_msg, got_packet.to_vec());
        // remove b
        server_channel
            .send(ServerMessage::RemoveClient(key_b.clone()))
            .await?;

        // get peer gone message on a
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);
        assert_eq!(&key_b.as_bytes()[..], &buf[..]);

        // get mesh update on a & c
        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut a_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);
        assert_eq!(&key_b.as_bytes()[..], &buf[..]);

        let (frame_type, _) =
            crate::hp::derp::read_frame(&mut c_reader, MAX_FRAME_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);
        assert_eq!(&key_b.as_bytes()[..], &buf[..]);

        done.cancel();
        server_task.await??;
        Ok(())
    }
}
