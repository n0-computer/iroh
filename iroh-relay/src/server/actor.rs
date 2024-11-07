//! The main event loop for the relay server.
//!
//! based on tailscale/derp/derp_server.go

use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use anyhow::{bail, Result};
use bytes::Bytes;
use iroh_base::key::PublicKey;
use iroh_metrics::{core::UsageStatsReport, inc, inc_by, report_usage_stats};
use time::{Date, OffsetDateTime};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{info_span, trace, warn, Instrument};

use crate::{
    defaults::timeouts::SERVER_WRITE_TIMEOUT as WRITE_TIMEOUT,
    protos::relay::SERVER_CHANNEL_SIZE,
    server::{client_conn::ClientConnConfig, clients::Clients, metrics::Metrics},
};

// TODO: skipping `verboseDropKeys` for now

static CONN_NUM: AtomicUsize = AtomicUsize::new(1);
pub(crate) fn new_conn_num() -> usize {
    CONN_NUM.fetch_add(1, Ordering::Relaxed)
}

#[derive(derive_more::Debug)]
pub(super) enum Message {
    SendPacket {
        dst: PublicKey,
        data: Bytes,
        src: PublicKey,
    },
    SendDiscoPacket {
        dst: PublicKey,
        data: Bytes,
        src: PublicKey,
    },
    #[debug("CreateClient")]
    CreateClient(ClientConnConfig),
    RemoveClient((PublicKey, usize)),
}

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    pub(super) src: PublicKey,
    /// The data packet bytes.
    pub(super) data: Bytes,
}

/// The task for a running server actor.
///
/// Will forcefully abort the server actor loop when dropped.
/// For stopping gracefully, use [`ServerActorTask::close`].
///
/// Responsible for managing connections to relay [`Conn`](crate::RelayConn)s, sending packets from one client to another.
#[derive(Debug)]
pub(super) struct ServerActorTask {
    /// Optionally specifies how long to wait before failing when writing
    /// to a client
    pub(super) write_timeout: Option<Duration>,
    /// Channel on which to communicate to the [`ServerActor`]
    pub(super) server_channel: mpsc::Sender<Message>,
    /// Server loop handler
    loop_handler: AbortOnDropHandle<Result<()>>,
    /// Done token, forces a hard shutdown. To gracefully shutdown, use [`ServerActorTask::close`]
    cancel: CancellationToken,
    // TODO: stats collection
}

impl ServerActorTask {
    /// Creates a new `ServerActorTask` and start the actor.
    pub(super) fn spawn() -> Self {
        let (server_channel_s, server_channel_r) = mpsc::channel(SERVER_CHANNEL_SIZE);
        let server_actor = Actor::new(server_channel_r);
        let cancel_token = CancellationToken::new();
        let done = cancel_token.clone();
        let server_task = AbortOnDropHandle::new(tokio::spawn(
            async move { server_actor.run(done).await }.instrument(info_span!("relay.server")),
        ));

        Self {
            write_timeout: Some(WRITE_TIMEOUT),
            server_channel: server_channel_s,
            loop_handler: server_task,
            cancel: cancel_token,
        }
    }

    /// Closes the server and waits for the connections to disconnect.
    pub(super) async fn close(self) {
        self.cancel.cancel();
        match self.loop_handler.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("error shutting down server: {e:?}"),
            Err(e) => warn!("error waiting for the server process to close: {e:?}"),
        }
    }
}

struct Actor {
    /// Channel to receive control messages
    receiver: mpsc::Receiver<Message>,
    /// All clients connected to this server
    clients: Clients,
    /// Statistics about the connected clients
    client_counter: ClientCounter,
}

impl Actor {
    fn new(receiver: mpsc::Receiver<Message>) -> Self {
        Self {
            receiver,
            clients: Clients::default(),
            client_counter: ClientCounter::default(),
        }
    }

    async fn run(mut self, done: CancellationToken) -> Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = done.cancelled() => {
                    warn!("server actor loop cancelled, closing loop");
                    // TODO: stats: drain channel & count dropped packets etc
                    // close all client connections and client read/write loops
                    self.clients.shutdown().await;
                    return Ok(());
                }
                Some(msg) = self.receiver.recv() => {
                    self.handle_message(msg);
                }
                else => {
                    warn!("unexpected server error, shutting down server loop");
                    self.clients.shutdown().await;
                    bail!("unexpected server error, closed client connections, and shutting down server loop");
                }
            }
        }
    }

    fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::SendPacket { dst, data, src } => {
                trace!(
                    "send packet from: {:?} to: {:?} ({}b)",
                    src,
                    dst,
                    data.len()
                );
                if self.clients.contains_key(&dst) {
                    // if this client is in our local network, just try to send the packet
                    if self.clients.send_packet(&dst, Packet { data, src }).is_ok() {
                        self.clients.record_send(&src, dst);
                    }
                } else {
                    warn!("send packet: no way to reach client {dst:?}, dropped packet");
                    inc!(Metrics, send_packets_dropped);
                }
            }
            Message::SendDiscoPacket { dst, data, src } => {
                trace!(
                    "send disco packet from: {:?} to: {:?} ({}b)",
                    src,
                    dst,
                    data.len()
                );
                if self.clients.contains_key(&dst) {
                    // if this client is in our local network, just try to send the packet
                    if self
                        .clients
                        .send_disco_packet(&dst, Packet { data, src })
                        .is_ok()
                    {
                        self.clients.record_send(&src, dst);
                    }
                } else {
                    warn!("send disco packet: no way to reach client {dst:?}, dropped packet");
                    inc!(Metrics, disco_packets_dropped);
                }
            }
            Message::CreateClient(client_builder) => {
                inc!(Metrics, accepts);

                trace!("create client: {:?}", client_builder.key);
                let key = client_builder.key;

                // build and register client, starting up read & write loops for the client connection
                self.clients.register(client_builder);
                tokio::task::spawn(async move {
                    report_usage_stats(&UsageStatsReport::new(
                        "relay_accepts".to_string(),
                        "relay_server".to_string(), // TODO: other id?
                        1,
                        None, // TODO(arqu): attribute to user id; possibly with the re-introduction of request tokens or other auth
                        Some(key.to_string()),
                    ))
                    .await;
                });
                let nc = self.client_counter.update(key);
                inc_by!(Metrics, unique_client_keys, nc);
            }
            Message::RemoveClient((key, conn_num)) => {
                inc!(Metrics, disconnects);
                trace!("remove client: {:?}", key);
                // ensure we still have the client in question
                if self.clients.has_client(&key, conn_num) {
                    // remove the client from the map of clients, & notify any peers that it
                    // has sent messages that it has left the network
                    self.clients.unregister(&key);
                }
            }
        }
    }
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
    fn update(&mut self, client: PublicKey) -> u64 {
        self.check_and_clear();
        let new_conn = !self.clients.contains_key(&client);
        let counter = self.clients.entry(client).or_insert(0);
        *counter += 1;
        new_conn as u64
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh_base::key::SecretKey;
    use tokio::io::DuplexStream;
    use tokio_util::codec::{Framed, FramedRead, FramedWrite};
    use tracing_subscriber::{prelude::*, EnvFilter};

    use super::*;
    use crate::{
        client::{
            conn::{ConnBuilder, ConnReader, ConnWriter, ReceivedMessage},
            streams::{MaybeTlsStreamReader, MaybeTlsStreamWriter},
        },
        protos::relay::{recv_frame, ClientInfo, DerpCodec, Frame, FrameType},
        server::{
            client_conn::ClientConnConfig,
            streams::{MaybeTlsStream, RelayedStream},
            MaybeTlsStreamServer,
        },
    };

    fn test_client_builder(
        key: PublicKey,
        server_channel: mpsc::Sender<Message>,
    ) -> (ClientConnConfig, Framed<DuplexStream, DerpCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        (
            ClientConnConfig {
                key,
                io: RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec)),
                write_timeout: None,
                channel_capacity: 10,
                server_channel,
            },
            Framed::new(test_io, DerpCodec),
        )
    }

    #[tokio::test]
    async fn test_server_actor() -> Result<()> {
        // make server actor
        let (server_channel, server_channel_r) = mpsc::channel(20);
        let server_actor: Actor = Actor::new(server_channel_r);
        let done = CancellationToken::new();
        let server_done = done.clone();

        // run server actor
        let server_task = tokio::spawn(
            async move { server_actor.run(server_done).await }
                .instrument(info_span!("relay.server")),
        );

        let key_a = SecretKey::generate().public();
        let (client_a, mut a_io) = test_client_builder(key_a, server_channel.clone());

        // create client a
        server_channel
            .send(Message::CreateClient(client_a))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // server message: create client b
        let key_b = SecretKey::generate().public();
        let (client_b, mut b_io) = test_client_builder(key_b, server_channel.clone());
        server_channel
            .send(Message::CreateClient(client_b))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // write message from b to a
        let msg = b"hello world!";
        crate::client::conn::send_packet(&mut b_io, &None, key_a, Bytes::from_static(msg)).await?;

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
            .send(Message::RemoveClient((key_b, 2)))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // get peer gone message on a about b leaving the network
        // (we get this message because b has sent us a packet before)
        let frame = recv_frame(FrameType::PeerGone, &mut a_io).await?;
        assert_eq!(Frame::PeerGone { peer: key_b }, frame);

        // close gracefully
        done.cancel();
        server_task.await??;
        Ok(())
    }

    // #[tokio::test]
    // async fn test_client_conn_handler() -> Result<()> {
    //     // create client connection handler
    //     let (server_channel_s, mut server_channel_r) = mpsc::channel(10);
    //     let client_key = SecretKey::generate();
    //     let handler = ClientConnHandler {
    //         write_timeout: None,
    //         server_channel: server_channel_s,
    //         default_headers: Default::default(),
    //     };

    //     // create the parts needed for a client
    //     let (client, server_io) = tokio::io::duplex(10);
    //     let (client_reader, client_writer) = tokio::io::split(client);
    //     let _client_reader = FramedRead::new(client_reader, DerpCodec);
    //     let mut client_writer = FramedWrite::new(client_writer, DerpCodec);
    //     // start a task as if a client is doing the "accept" handshake
    //     let pub_client_key = client_key.public();
    //     let client_task = AbortOnDropHandle::<Result<()>>::new(tokio::spawn(async move {
    //         // send the client info
    //         let client_info = ClientInfo {
    //             version: PROTOCOL_VERSION,
    //         };
    //         crate::protos::relay::send_client_key(&mut client_writer, &client_key, &client_info)
    //             .await?;

    //         Ok(())
    //     }));

    //     // attempt to add the connection to the server
    //     handler
    //         .accept(Protocol::Relay, MaybeTlsStream::Test(server_io))
    //         .await?;
    //     client_task.await??;

    //     // ensure we inform the server to create the client from the connection!
    //     match server_channel_r.recv().await.unwrap() {
    //         ServerMessage::CreateClient(builder) => {
    //             assert_eq!(pub_client_key, builder.key);
    //         }
    //         _ => anyhow::bail!("unexpected server message"),
    //     }
    //     Ok(())
    // }

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

    // #[tokio::test]
    // async fn test_server_basic() -> Result<()> {
    //     let _guard = iroh_test::logging::setup();

    //     // create the server!
    //     let server: ServerActorTask = ServerActorTask::new();

    //     // create client a and connect it to the server
    //     let key_a = SecretKey::generate();
    //     let public_key_a = key_a.public();
    //     let (rw_a, client_a_builder) = make_test_client(key_a);
    //     let handler = server.client_conn_handler(Default::default());
    //     let handler_task = tokio::spawn(async move {
    //         handler
    //             .accept(Protocol::Relay, MaybeTlsStream::Test(rw_a))
    //             .await
    //     });
    //     let (client_a, mut client_receiver_a) = client_a_builder.build().await?;
    //     handler_task.await??;

    //     // create client b and connect it to the server
    //     let key_b = SecretKey::generate();
    //     let public_key_b = key_b.public();
    //     let (rw_b, client_b_builder) = make_test_client(key_b);
    //     let handler = server.client_conn_handler(Default::default());
    //     let handler_task = tokio::spawn(async move {
    //         handler
    //             .accept(Protocol::Relay, MaybeTlsStream::Test(rw_b))
    //             .await
    //     });
    //     let (client_b, mut client_receiver_b) = client_b_builder.build().await?;
    //     handler_task.await??;

    //     // send message from a to b!
    //     let msg = Bytes::from_static(b"hello client b!!");
    //     client_a.send(public_key_b, msg.clone()).await?;
    //     match client_receiver_b.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_a, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // send message from b to a!
    //     let msg = Bytes::from_static(b"nice to meet you client a!!");
    //     client_b.send(public_key_a, msg.clone()).await?;
    //     match client_receiver_a.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_b, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // close the server and clients
    //     server.close().await;

    //     // client connections have been shutdown
    //     let res = client_a
    //         .send(public_key_b, Bytes::from_static(b"try to send"))
    //         .await;
    //     assert!(res.is_err());
    //     assert!(client_receiver_b.recv().await.is_err());
    //     Ok(())
    // }

    // #[tokio::test]
    // async fn test_server_replace_client() -> Result<()> {
    //     tracing_subscriber::registry()
    //         .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
    //         .with(EnvFilter::from_default_env())
    //         .try_init()
    //         .ok();

    //     // create the server!
    //     let server: ServerActorTask = ServerActorTask::new();

    //     // create client a and connect it to the server
    //     let key_a = SecretKey::generate();
    //     let public_key_a = key_a.public();
    //     let (rw_a, client_a_builder) = make_test_client(key_a);
    //     let handler = server.client_conn_handler(Default::default());
    //     let handler_task = tokio::spawn(async move {
    //         handler
    //             .accept(Protocol::Relay, MaybeTlsStream::Test(rw_a))
    //             .await
    //     });
    //     let (client_a, mut client_receiver_a) = client_a_builder.build().await?;
    //     handler_task.await??;

    //     // create client b and connect it to the server
    //     let key_b = SecretKey::generate();
    //     let public_key_b = key_b.public();
    //     let (rw_b, client_b_builder) = make_test_client(key_b.clone());
    //     let handler = server.client_conn_handler(Default::default());
    //     let handler_task = tokio::spawn(async move {
    //         handler
    //             .accept(Protocol::Relay, MaybeTlsStream::Test(rw_b))
    //             .await
    //     });
    //     let (client_b, mut client_receiver_b) = client_b_builder.build().await?;
    //     handler_task.await??;

    //     // send message from a to b!
    //     let msg = Bytes::from_static(b"hello client b!!");
    //     client_a.send(public_key_b, msg.clone()).await?;
    //     match client_receiver_b.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_a, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // send message from b to a!
    //     let msg = Bytes::from_static(b"nice to meet you client a!!");
    //     client_b.send(public_key_a, msg.clone()).await?;
    //     match client_receiver_a.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_b, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // create client b and connect it to the server
    //     let (new_rw_b, new_client_b_builder) = make_test_client(key_b);
    //     let handler = server.client_conn_handler(Default::default());
    //     let handler_task = tokio::spawn(async move {
    //         handler
    //             .accept(Protocol::Relay, MaybeTlsStream::Test(new_rw_b))
    //             .await
    //     });
    //     let (new_client_b, mut new_client_receiver_b) = new_client_b_builder.build().await?;
    //     handler_task.await??;

    //     // assert!(client_b.recv().await.is_err());

    //     // send message from a to b!
    //     let msg = Bytes::from_static(b"are you still there, b?!");
    //     client_a.send(public_key_b, msg.clone()).await?;
    //     match new_client_receiver_b.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_a, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // send message from b to a!
    //     let msg = Bytes::from_static(b"just had a spot of trouble but I'm back now,a!!");
    //     new_client_b.send(public_key_a, msg.clone()).await?;
    //     match client_receiver_a.recv().await? {
    //         ReceivedMessage::ReceivedPacket { source, data } => {
    //             assert_eq!(public_key_b, source);
    //             assert_eq!(&msg[..], data);
    //         }
    //         msg => {
    //             anyhow::bail!("expected ReceivedPacket msg, got {msg:?}");
    //         }
    //     }

    //     // close the server and clients
    //     server.close().await;

    //     // client connections have been shutdown
    //     let res = client_a
    //         .send(public_key_b, Bytes::from_static(b"try to send"))
    //         .await;
    //     assert!(res.is_err());
    //     assert!(new_client_receiver_b.recv().await.is_err());
    //     Ok(())
    // }
}
