//! The main event loop for the relay server.
//!
//! based on tailscale/derp/derp_server.go

use std::{collections::HashMap, time::Duration};

use anyhow::{bail, Result};
use bytes::Bytes;
use iroh_base::NodeId;
use iroh_metrics::{inc, inc_by};
use time::{Date, OffsetDateTime};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{info, info_span, trace, warn, Instrument};

use crate::{
    defaults::timeouts::SERVER_WRITE_TIMEOUT as WRITE_TIMEOUT,
    protos::relay::SERVER_CHANNEL_SIZE,
    server::{client_conn::ClientConnConfig, clients::Clients, metrics::Metrics},
};

#[derive(Debug)]
pub(super) enum Message {
    SendPacket {
        dst: NodeId,
        data: Bytes,
        src: NodeId,
    },
    SendDiscoPacket {
        dst: NodeId,
        data: Bytes,
        src: NodeId,
    },
    CreateClient(ClientConnConfig),
    RemoveClient {
        node_id: NodeId,
        conn_num: usize,
    },
}

/// A request to write a dataframe to a Client
#[derive(Debug, Clone)]
pub(super) struct Packet {
    /// The sender of the packet
    pub(super) src: NodeId,
    /// The data packet bytes.
    pub(super) data: Bytes,
}

/// The task for a running server actor.
///
/// Will forcefully abort the server actor loop when dropped.
/// For stopping gracefully, use [`ServerActorTask::close`].
///
/// Responsible for managing connections to a relay, sending packets from one client to another.
#[derive(Debug)]
pub(super) struct ServerActorTask {
    /// Specifies how long to wait before failing when writing to a client.
    pub(super) write_timeout: Duration,
    /// Channel on which to communicate to the [`Actor`]
    pub(super) server_channel: mpsc::Sender<Message>,
    /// Server loop handler
    loop_handler: AbortOnDropHandle<Result<()>>,
    /// Token to shutdown the actor loop.
    cancel: CancellationToken,
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
            write_timeout: WRITE_TIMEOUT,
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
            Ok(Err(e)) => warn!("error shutting down server: {e:#}"),
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
                    info!("server actor loop cancelled, closing loop");
                    // TODO: stats: drain channel & count dropped packets etc
                    // close all client connections and client read/write loops
                    self.clients.shutdown().await;
                    return Ok(());
                }
                msg = self.receiver.recv() => match msg {
                    Some(msg) => {
                        self.handle_message(msg).await;
                    }
                    None => {
                        warn!("unexpected actor error: receiver gone, shutting down actor loop");
                        self.clients.shutdown().await;
                        bail!("unexpected actor error, closed client connections, and shutting down actor loop");
                    }
                }
            }
        }
    }

    async fn handle_message(&mut self, msg: Message) {
        match msg {
            Message::SendPacket { dst, data, src } => {
                trace!(
                    src = src.fmt_short(),
                    dst = dst.fmt_short(),
                    len = data.len(),
                    "send packet"
                );
                if self.clients.contains_key(&dst) {
                    match self.clients.send_packet(&dst, Packet { data, src }).await {
                        Ok(()) => {
                            self.clients.record_send(&src, dst);
                            inc!(Metrics, send_packets_sent);
                        }
                        Err(err) => {
                            trace!(?dst, "failed to send packet: {err:#}");
                            inc!(Metrics, send_packets_dropped);
                        }
                    }
                } else {
                    warn!(?dst, "no way to reach client, dropped packet");
                    inc!(Metrics, send_packets_dropped);
                }
            }
            Message::SendDiscoPacket { dst, data, src } => {
                trace!(?src, ?dst, len = data.len(), "send disco packet");
                if self.clients.contains_key(&dst) {
                    match self
                        .clients
                        .send_disco_packet(&dst, Packet { data, src })
                        .await
                    {
                        Ok(()) => {
                            self.clients.record_send(&src, dst);
                            inc!(Metrics, disco_packets_sent);
                        }
                        Err(err) => {
                            trace!(?dst, "failed to send disco packet: {err:#}");
                            inc!(Metrics, disco_packets_dropped);
                        }
                    }
                } else {
                    warn!(?dst, "disco: no way to reach client, dropped packet");
                    inc!(Metrics, disco_packets_dropped);
                }
            }
            Message::CreateClient(client_builder) => {
                inc!(Metrics, accepts);
                let node_id = client_builder.node_id;
                trace!(node_id = node_id.fmt_short(), "create client");

                // build and register client, starting up read & write loops for the client
                // connection
                self.clients.register(client_builder).await;
                let nc = self.client_counter.update(node_id);
                inc_by!(Metrics, unique_client_keys, nc);
            }
            Message::RemoveClient { node_id, conn_num } => {
                inc!(Metrics, disconnects);
                trace!(node_id = %node_id.fmt_short(), "remove client");
                // ensure we still have the client in question
                if self.clients.has_client(&node_id, conn_num) {
                    // remove the client from the map of clients, & notify any nodes that it
                    // has sent messages that it has left the network
                    self.clients.unregister(&node_id).await;
                }
            }
        }
    }
}

/// Counts how many `NodeId`s seen, how many times.
/// Gets reset every day.
struct ClientCounter {
    clients: HashMap<NodeId, usize>,
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
    fn update(&mut self, client: NodeId) -> u64 {
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
    use iroh_base::SecretKey;
    use tokio::io::DuplexStream;
    use tokio_util::codec::Framed;

    use super::*;
    use crate::{
        protos::relay::{recv_frame, Frame, FrameType, RelayCodec},
        server::{
            client_conn::ClientConnConfig,
            streams::{MaybeTlsStream, RelayedStream},
        },
    };

    fn test_client_builder(
        node_id: NodeId,
        server_channel: mpsc::Sender<Message>,
    ) -> (ClientConnConfig, Framed<DuplexStream, RelayCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        (
            ClientConnConfig {
                node_id,
                stream: RelayedStream::Relay(Framed::new(
                    MaybeTlsStream::Test(io),
                    RelayCodec::test(),
                )),
                write_timeout: Duration::from_secs(1),
                channel_capacity: 10,
                rate_limit: None,
                server_channel,
            },
            Framed::new(test_io, RelayCodec::test()),
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

        let node_id_a = SecretKey::generate(rand::thread_rng()).public();
        let (client_a, mut a_io) = test_client_builder(node_id_a, server_channel.clone());

        // create client a
        server_channel
            .send(Message::CreateClient(client_a))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // server message: create client b
        let node_id_b = SecretKey::generate(rand::thread_rng()).public();
        let (client_b, mut b_io) = test_client_builder(node_id_b, server_channel.clone());
        server_channel
            .send(Message::CreateClient(client_b))
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // write message from b to a
        let msg = b"hello world!";
        crate::client::conn::send_packet(&mut b_io, node_id_a, Bytes::from_static(msg)).await?;

        // get message on a's reader
        let frame = recv_frame(FrameType::RecvPacket, &mut a_io).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: node_id_b,
                content: msg.to_vec().into()
            }
        );

        // remove b
        server_channel
            .send(Message::RemoveClient {
                node_id: node_id_b,
                conn_num: 1,
            })
            .await
            .map_err(|_| anyhow::anyhow!("server gone"))?;

        // get the nodes gone message on a about b leaving the network
        // (we get this message because b has sent us a packet before)
        let frame = recv_frame(FrameType::PeerGone, &mut a_io).await?;
        assert_eq!(Frame::NodeGone { node_id: node_id_b }, frame);

        // close gracefully
        done.cancel();
        server_task.await??;
        Ok(())
    }
}
