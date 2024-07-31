//! The main event loop for the relay server.
//!
//! based on tailscale/derp/derp_server.go

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context as _, Result};
use hyper::HeaderMap;
use iroh_metrics::core::UsageStatsReport;
use iroh_metrics::{inc, inc_by, report_usage_stats};
use time::{Date, OffsetDateTime};
use tokio::sync::mpsc;
use tokio_tungstenite::WebSocketStream;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{info_span, trace, Instrument};
use tungstenite::protocol::Role;

use crate::key::{PublicKey, SecretKey};
use crate::relay::http::Protocol;
use crate::relay::server::streams::{MaybeTlsStream, RelayIo};
use crate::relay::server::types::ServerMessage;
use crate::relay::{
    codec::{
        recv_client_key, DerpCodec, PER_CLIENT_SEND_QUEUE_DEPTH, PROTOCOL_VERSION,
        SERVER_CHANNEL_SIZE,
    },
    server::client_conn::ClientConnBuilder,
    server::clients::Clients,
    server::metrics::Metrics,
};
use crate::util::AbortingJoinHandle;

// TODO: skipping `verboseDropKeys` for now

static CONN_NUM: AtomicUsize = AtomicUsize::new(1);
fn new_conn_num() -> usize {
    CONN_NUM.fetch_add(1, Ordering::Relaxed)
}

pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The task for a running server actor.
///
/// Will forcefully abort the server actor loop when dropped.
/// For stopping gracefully, use [`ServerActorTask::close`].
///
/// Responsible for managing connections to relay [`Conn`](crate::relay::RelayConn)s, sending packets from one client to another.
#[derive(Debug)]
pub struct ServerActorTask {
    /// Optionally specifies how long to wait before failing when writing
    /// to a client
    write_timeout: Option<Duration>,
    /// secret_key of the client
    secret_key: SecretKey,
    /// The DER encoded x509 cert to send after `LetsEncrypt` cert+intermediate.
    meta_cert: Vec<u8>,
    /// Channel on which to communicate to the [`ServerActor`]
    server_channel: mpsc::Sender<ServerMessage>,
    /// When true, the server has been shutdown.
    closed: bool,
    /// Server loop handler
    loop_handler: AbortingJoinHandle<Result<()>>,
    /// Done token, forces a hard shutdown. To gracefully shutdown, use [`ServerActorTask::close`]
    cancel: CancellationToken,
    // TODO: stats collection
}

impl ServerActorTask {
    /// TODO: replace with builder
    pub fn new(key: SecretKey) -> Self {
        let (server_channel_s, server_channel_r) = mpsc::channel(SERVER_CHANNEL_SIZE);
        let server_actor = ServerActor::new(key.public(), server_channel_r);
        let cancel_token = CancellationToken::new();
        let done = cancel_token.clone();
        let server_task = tokio::spawn(
            async move { server_actor.run(done).await }
                .instrument(info_span!("relay.server", me = %key.public().fmt_short())),
        )
        .into();
        let meta_cert = init_meta_cert(&key.public());
        Self {
            write_timeout: Some(WRITE_TIMEOUT),
            secret_key: key,
            meta_cert,
            server_channel: server_channel_s,
            closed: false,
            loop_handler: server_task,
            cancel: cancel_token,
        }
    }

    /// Returns the server's secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Returns the server's public key.
    pub fn public_key(&self) -> PublicKey {
        self.secret_key.public()
    }

    /// Closes the server and waits for the connections to disconnect.
    pub async fn close(mut self) {
        if !self.closed {
            if let Err(err) = self.server_channel.send(ServerMessage::Shutdown).await {
                tracing::warn!(
                    "could not shutdown the server gracefully, doing a forced shutdown: {:?}",
                    err
                );
                self.cancel.cancel();
            }
            match self.loop_handler.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("error shutting down server: {e:?}"),
                Err(e) => tracing::warn!("error waiting for the server process to close: {e:?}"),
            }
            self.closed = true;
        }
    }

    /// Aborts the server.
    ///
    /// You should prefer to use [`ServerActorTask::close`] for a graceful shutdown.
    pub fn abort(&self) {
        self.cancel.cancel();
    }

    /// Whether or not the relay [`ServerActorTask`] is closed.
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Create a [`ClientConnHandler`], which can verify connections and add them to the
    /// [`ServerActorTask`].
    pub fn client_conn_handler(&self, default_headers: HeaderMap) -> ClientConnHandler {
        ClientConnHandler {
            server_channel: self.server_channel.clone(),
            secret_key: self.secret_key.clone(),
            write_timeout: self.write_timeout,
            default_headers: Arc::new(default_headers),
        }
    }

    /// Returns the server metadata cert that can be sent by the TLS server to
    /// let the client skip a round trip during start-up.
    pub fn meta_cert(&self) -> &[u8] {
        &self.meta_cert
    }
}

/// Handle incoming connections to the Server.
///
/// Created by the [`ServerActorTask`] by calling [`ServerActorTask::client_conn_handler`].
///
/// Can be cheaply cloned.
#[derive(Debug)]
pub struct ClientConnHandler {
    server_channel: mpsc::Sender<ServerMessage>,
    secret_key: SecretKey,
    write_timeout: Option<Duration>,
    pub(crate) default_headers: Arc<HeaderMap>,
}

impl Clone for ClientConnHandler {
    fn clone(&self) -> Self {
        Self {
            server_channel: self.server_channel.clone(),
            secret_key: self.secret_key.clone(),
            write_timeout: self.write_timeout,
            default_headers: Arc::clone(&self.default_headers),
        }
    }
}

impl ClientConnHandler {
    /// Adds a new connection to the server and serves it.
    ///
    /// Will error if it takes too long (10 sec) to write or read to the connection, if there is
    /// some read or write error to the connection,  if the server is meant to verify clients,
    /// and is unable to verify this one, or if there is some issue communicating with the server.
    ///
    /// The provided [`AsyncRead`] and [`AsyncWrite`] must be already connected to the connection.
    ///
    /// [`AsyncRead`]: tokio::io::AsyncRead
    /// [`AsyncWrite`]: tokio::io::AsyncWrite
    pub async fn accept(&self, protocol: Protocol, io: MaybeTlsStream) -> Result<()> {
        trace!(?protocol, "accept: start");
        let mut io = match protocol {
            Protocol::Relay => {
                inc!(Metrics, derp_accepts);
                RelayIo::Derp(Framed::new(io, DerpCodec))
            }
            Protocol::Websocket => {
                inc!(Metrics, websocket_accepts);
                RelayIo::Ws(WebSocketStream::from_raw_socket(io, Role::Server, None).await)
            }
        };
        trace!("accept: recv client key");
        let (client_key, info) = recv_client_key(&mut io)
            .await
            .context("unable to receive client information")?;

        if info.version != PROTOCOL_VERSION {
            bail!(
                "unexpected client version {}, expected {}",
                info.version,
                PROTOCOL_VERSION
            );
        }

        trace!("accept: build client conn");
        let client_conn_builder = ClientConnBuilder {
            key: client_key,
            conn_num: new_conn_num(),
            io,
            write_timeout: self.write_timeout,
            channel_capacity: PER_CLIENT_SEND_QUEUE_DEPTH,
            server_channel: self.server_channel.clone(),
        };
        trace!("accept: create client");
        self.server_channel
            .send(ServerMessage::CreateClient(client_conn_builder))
            .await
            .map_err(|_| {
                anyhow::anyhow!("server channel closed, the server is probably shutdown")
            })?;
        Ok(())
    }
}

struct ServerActor {
    key: PublicKey,
    receiver: mpsc::Receiver<ServerMessage>,
    /// All clients connected to this server
    clients: Clients,
    client_counter: ClientCounter,
}

impl ServerActor {
    fn new(key: PublicKey, receiver: mpsc::Receiver<ServerMessage>) -> Self {
        Self {
            key,
            receiver,
            clients: Clients::new(),
            client_counter: ClientCounter::default(),
        }
    }

    async fn run(mut self, done: CancellationToken) -> Result<()> {
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
                        ServerMessage::SendPacket((key, packet)) => {
                            tracing::trace!("send packet from: {:?} to: {:?} ({}b)", packet.src, key, packet.bytes.len());
                            let src = packet.src;
                            if self.clients.contains_key(&key) {
                                // if this client is in our local network, just try to send the
                                // packet
                                if self.clients.send_packet(&key, packet).is_ok() {
                                    self.clients.record_send(&src, key);
                                }
                            } else {
                                tracing::warn!("send packet: no way to reach client {key:?}, dropped packet");
                                inc!(Metrics, send_packets_dropped);
                            }
                        }
                        ServerMessage::SendDiscoPacket((key, packet)) => {
                            tracing::trace!("send disco packet from: {:?} to: {:?} ({}b)", packet.src, key, packet.bytes.len());
                            let src = packet.src;
                            if self.clients.contains_key(&key) {
                                // if this client is in our local network, just try to send the
                                // packet
                                if self.clients.send_disco_packet(&key, packet).is_ok() {
                                    self.clients.record_send(&src, key);
                                }
                            } else {
                                tracing::warn!("send disco packet: no way to reach client {key:?}, dropped packet");
                                inc!(Metrics, disco_packets_dropped);
                            }
                        }
                        ServerMessage::CreateClient(client_builder) => {
                            inc!(Metrics, accepts);

                            tracing::trace!("create client: {:?}", client_builder.key);
                            let key = client_builder.key;

                            report_usage_stats(&UsageStatsReport::new(
                                "relay_accepts".to_string(),
                                self.key.to_string(),
                                1,
                                None, // TODO(arqu): attribute to user id; possibly with the re-introduction of request tokens or other auth
                                Some(key.to_string()),
                            )).await;
                            let nc = self.client_counter.update(key);
                            inc_by!(Metrics, unique_client_keys, nc);

                            // build and register client, starting up read & write loops for the
                            // client connection
                            self.clients.register(client_builder);

                        }
                        ServerMessage::RemoveClient((key, conn_num)) => {
                            inc!(Metrics, disconnects);
                            tracing::trace!("remove client: {:?}", key);
                            // ensure we still have the client in question
                            if self.clients.has_client(&key, conn_num) {
                                // remove the client from the map of clients, & notify any peers that it
                                // has sent messages that it has left the network
                                self.clients.unregister(&key);
                            }
                        }
                        ServerMessage::Shutdown => {
                            tracing::info!("server gracefully shutting down...");
                            // close all client connections and client read/write loops
                            self.clients.shutdown().await;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Initializes the [`ServerActor`] with a self-signed x509 cert
/// encoding this server's public key and protocol version. "cmd/relay_server
/// then sends this after the Let's Encrypt leaf + intermediate certs after
/// the ServerHello (encrypted in TLS 1.3, not that is matters much).
///
/// Then the client can save a round trime getting that and can start speaking
/// relay right away. (we don't use ALPN because that's sent in the clear and
/// we're being paranoid to not look too weird to any middleboxes, given that
/// relay is an ultimate fallback path). But since the post-ServerHello certs
/// are encrypted we can have the client also use them as a signal to be able
/// to start speaking relay right away, starting with its identity proof,
/// encrypted to the server's public key.
///
/// This RTT optimization fails where there's a corp-mandated TLS proxy with
/// corp-mandated root certs on employee machines and TLS proxy cleans up
/// unnecessary certs. In that case we just fall back to the extra RTT.
fn init_meta_cert(server_key: &PublicKey) -> Vec<u8> {
    let mut params =
        rcgen::CertificateParams::new([format!("derpkey{}", hex::encode(server_key.as_bytes()))]);
    params.serial_number = Some((PROTOCOL_VERSION as u64).into());
    // Windows requires not_after and not_before set:
    params.not_after = time::OffsetDateTime::now_utc().saturating_add(30 * time::Duration::DAY);
    params.not_before = time::OffsetDateTime::now_utc().saturating_sub(30 * time::Duration::DAY);

    rcgen::Certificate::from_params(params)
        .expect("fixed inputs")
        .serialize_der()
        .expect("fixed allocations")
}

struct ClientCounter {
    clients: HashMap<PublicKey, usize>,
    last_clear_date: Date,
}

impl Default for ClientCounter {
    fn default() -> Self {
        Self {
            clients: HashMap::new(),
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

    /// Updates the client counter.
    pub fn update(&mut self, client: PublicKey) -> u64 {
        self.check_and_clear();
        let new_conn = !self.clients.contains_key(&client);
        let counter = self.clients.entry(client).or_insert(0);
        *counter += 1;
        new_conn as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::relay::{
        client::conn::{ConnBuilder, ConnReader, ConnWriter, ReceivedMessage},
        client::streams::{MaybeTlsStreamReader, MaybeTlsStreamWriter},
        codec::{recv_frame, ClientInfo, Frame, FrameType},
    };
    use tokio_util::codec::{FramedRead, FramedWrite};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use bytes::Bytes;
    use tokio::io::DuplexStream;

    fn test_client_builder(
        key: PublicKey,
        conn_num: usize,
        server_channel: mpsc::Sender<ServerMessage>,
    ) -> (ClientConnBuilder, Framed<DuplexStream, DerpCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        (
            ClientConnBuilder {
                key,
                conn_num,
                io: RelayIo::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec)),
                write_timeout: None,
                channel_capacity: 10,
                server_channel,
            },
            Framed::new(test_io, DerpCodec),
        )
    }

    #[tokio::test]
    async fn test_server_actor() -> Result<()> {
        let server_key = SecretKey::generate().public();

        // make server actor
        let (server_channel, server_channel_r) = mpsc::channel(20);
        let server_actor: ServerActor = ServerActor::new(server_key, server_channel_r);
        let done = CancellationToken::new();
        let server_done = done.clone();

        // run server actor
        let server_task = tokio::spawn(
            async move { server_actor.run(server_done).await }
                .instrument(info_span!("relay.server")),
        );

        let key_a = SecretKey::generate().public();
        let (client_a, mut a_io) = test_client_builder(key_a, 1, server_channel.clone());

        // create client a
        server_channel
            .send(ServerMessage::CreateClient(client_a))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // server message: create client b
        let key_b = SecretKey::generate().public();
        let (client_b, mut b_io) = test_client_builder(key_b, 2, server_channel.clone());
        server_channel
            .send(ServerMessage::CreateClient(client_b))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // write message from b to a
        let msg = b"hello world!";
        crate::relay::client::conn::send_packet(&mut b_io, &None, key_a, Bytes::from_static(msg))
            .await?;

        // get message on a's reader
        let frame = recv_frame(FrameType::RecvPacket, &mut a_io).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: key_b,
                content: msg.to_vec().into()
            }
        );

        // remove b
        server_channel
            .send(ServerMessage::RemoveClient((key_b, 2)))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // get peer gone message on a about b leaving the network
        // (we get this message because b has sent us a packet before)
        let frame = recv_frame(FrameType::PeerGone, &mut a_io).await?;
        assert_eq!(Frame::PeerGone { peer: key_b }, frame);

        // close gracefully
        server_channel
            .send(ServerMessage::Shutdown)
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;
        server_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn test_client_conn_handler() -> Result<()> {
        // create client connection handler
        let (server_channel_s, mut server_channel_r) = mpsc::channel(10);
        let client_key = SecretKey::generate();
        let handler = ClientConnHandler {
            secret_key: client_key.clone(),
            write_timeout: None,
            server_channel: server_channel_s,
            default_headers: Default::default(),
        };

        // create the parts needed for a client
        let (client, server_io) = tokio::io::duplex(10);
        let (client_reader, client_writer) = tokio::io::split(client);
        let _client_reader = FramedRead::new(client_reader, DerpCodec);
        let mut client_writer = FramedWrite::new(client_writer, DerpCodec);

        // start a task as if a client is doing the "accept" handshake
        let pub_client_key = client_key.public();
        let client_task: AbortingJoinHandle<Result<()>> = tokio::spawn(async move {
            // send the client info
            let client_info = ClientInfo {
                version: PROTOCOL_VERSION,
            };
            crate::relay::codec::send_client_key(&mut client_writer, &client_key, &client_info)
                .await?;

            Ok(())
        })
        .into();

        // attempt to add the connection to the server
        handler
            .accept(Protocol::Relay, MaybeTlsStream::Test(server_io))
            .await?;
        client_task.await??;

        // ensure we inform the server to create the client from the connection!
        match server_channel_r.recv().await.unwrap() {
            ServerMessage::CreateClient(builder) => {
                assert_eq!(pub_client_key, builder.key);
            }
            _ => anyhow::bail!("unexpected server message"),
        }
        Ok(())
    }

    fn make_test_client(secret_key: SecretKey) -> (tokio::io::DuplexStream, ConnBuilder) {
        let (client, server) = tokio::io::duplex(10);
        let (client_reader, client_writer) = tokio::io::split(client);

        let client_reader = MaybeTlsStreamReader::Mem(client_reader);
        let client_writer = MaybeTlsStreamWriter::Mem(client_writer);

        let client_reader = ConnReader::Derp(FramedRead::new(client_reader, DerpCodec));
        let client_writer = ConnWriter::Derp(FramedWrite::new(client_writer, DerpCodec));

        (
            server,
            ConnBuilder::new(secret_key, None, client_reader, client_writer),
        )
    }

    #[tokio::test]
    async fn test_server_basic() -> Result<()> {
        let _guard = iroh_test::logging::setup();

        // create the server!
        let server_key = SecretKey::generate();
        let server: ServerActorTask = ServerActorTask::new(server_key);

        // create client a and connect it to the server
        let key_a = SecretKey::generate();
        let public_key_a = key_a.public();
        let (rw_a, client_a_builder) = make_test_client(key_a);
        let handler = server.client_conn_handler(Default::default());
        let handler_task = tokio::spawn(async move {
            handler
                .accept(Protocol::Relay, MaybeTlsStream::Test(rw_a))
                .await
        });
        let (client_a, mut client_receiver_a) = client_a_builder.build().await?;
        handler_task.await??;

        // create client b and connect it to the server
        let key_b = SecretKey::generate();
        let public_key_b = key_b.public();
        let (rw_b, client_b_builder) = make_test_client(key_b);
        let handler = server.client_conn_handler(Default::default());
        let handler_task = tokio::spawn(async move {
            handler
                .accept(Protocol::Relay, MaybeTlsStream::Test(rw_b))
                .await
        });
        let (client_b, mut client_receiver_b) = client_b_builder.build().await?;
        handler_task.await??;

        // send message from a to b!
        let msg = Bytes::from_static(b"hello client b!!");
        client_a.send(public_key_b, msg.clone()).await?;
        match client_receiver_b.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_a, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // send message from b to a!
        let msg = Bytes::from_static(b"nice to meet you client a!!");
        client_b.send(public_key_a, msg.clone()).await?;
        match client_receiver_a.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_b, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // close the server and clients
        server.close().await;

        // client connections have been shutdown
        let res = client_a
            .send(public_key_b, Bytes::from_static(b"try to send"))
            .await;
        assert!(res.is_err());
        assert!(client_receiver_b.recv().await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn test_server_replace_client() -> Result<()> {
        tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(EnvFilter::from_default_env())
            .try_init()
            .ok();

        // create the server!
        let server_key = SecretKey::generate();
        let server: ServerActorTask = ServerActorTask::new(server_key);

        // create client a and connect it to the server
        let key_a = SecretKey::generate();
        let public_key_a = key_a.public();
        let (rw_a, client_a_builder) = make_test_client(key_a);
        let handler = server.client_conn_handler(Default::default());
        let handler_task = tokio::spawn(async move {
            handler
                .accept(Protocol::Relay, MaybeTlsStream::Test(rw_a))
                .await
        });
        let (client_a, mut client_receiver_a) = client_a_builder.build().await?;
        handler_task.await??;

        // create client b and connect it to the server
        let key_b = SecretKey::generate();
        let public_key_b = key_b.public();
        let (rw_b, client_b_builder) = make_test_client(key_b.clone());
        let handler = server.client_conn_handler(Default::default());
        let handler_task = tokio::spawn(async move {
            handler
                .accept(Protocol::Relay, MaybeTlsStream::Test(rw_b))
                .await
        });
        let (client_b, mut client_receiver_b) = client_b_builder.build().await?;
        handler_task.await??;

        // send message from a to b!
        let msg = Bytes::from_static(b"hello client b!!");
        client_a.send(public_key_b, msg.clone()).await?;
        match client_receiver_b.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_a, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // send message from b to a!
        let msg = Bytes::from_static(b"nice to meet you client a!!");
        client_b.send(public_key_a, msg.clone()).await?;
        match client_receiver_a.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_b, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // create client b and connect it to the server
        let (new_rw_b, new_client_b_builder) = make_test_client(key_b);
        let handler = server.client_conn_handler(Default::default());
        let handler_task = tokio::spawn(async move {
            handler
                .accept(Protocol::Relay, MaybeTlsStream::Test(new_rw_b))
                .await
        });
        let (new_client_b, mut new_client_receiver_b) = new_client_b_builder.build().await?;
        handler_task.await??;

        // assert!(client_b.recv().await.is_err());

        // send message from a to b!
        let msg = Bytes::from_static(b"are you still there, b?!");
        client_a.send(public_key_b, msg.clone()).await?;
        match new_client_receiver_b.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_a, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // send message from b to a!
        let msg = Bytes::from_static(b"just had a spot of trouble but I'm back now,a!!");
        new_client_b.send(public_key_a, msg.clone()).await?;
        match client_receiver_a.recv().await? {
            ReceivedMessage::ReceivedPacket { source, data } => {
                assert_eq!(public_key_b, source);
                assert_eq!(&msg[..], data);
            }
            msg => {
                anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
            }
        }

        // close the server and clients
        server.close().await;

        // client connections have been shutdown
        let res = client_a
            .send(public_key_b, Bytes::from_static(b"try to send"))
            .await;
        assert!(res.is_err());
        assert!(new_client_receiver_b.recv().await.is_err());
        Ok(())
    }
}
