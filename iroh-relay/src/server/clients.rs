//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use iroh_base::NodeId;
use iroh_metrics::inc;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use super::{
    actor::Packet,
    client_conn::{ClientConn, ClientConnConfig},
    metrics::Metrics,
};

/// Number of times we try to send to a client connection before dropping the data;
const RETRIES: usize = 3;

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default)]
pub(super) struct Clients {
    /// The list of all currently connected clients.
    inner: HashMap<NodeId, Client>,
    /// The next connection number to use.
    conn_num: usize,
}

impl Clients {
    pub async fn shutdown(&mut self) {
        trace!("shutting down {} clients", self.inner.len());

        futures_buffered::join_all(
            self.inner
                .drain()
                .map(|(_, client)| async move { client.shutdown().await }),
        )
        .await;
    }

    /// Record that `src` sent or forwarded a packet to `dst`
    pub fn record_send(&mut self, src: &NodeId, dst: NodeId) {
        if let Some(client) = self.inner.get_mut(src) {
            client.record_send(dst);
        }
    }

    pub fn contains_key(&self, key: &NodeId) -> bool {
        self.inner.contains_key(key)
    }

    pub fn has_client(&self, key: &NodeId, conn_num: usize) -> bool {
        if let Some(client) = self.inner.get(key) {
            return client.conn.conn_num == conn_num;
        }
        false
    }

    fn next_conn_num(&mut self) -> usize {
        let conn_num = self.conn_num;
        self.conn_num = self.conn_num.wrapping_add(1);
        conn_num
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub async fn register(&mut self, client_config: ClientConnConfig) {
        let key = client_config.node_id;
        trace!("registering client: {:?}", key);
        let conn_num = self.next_conn_num();
        let client = ClientConn::new(client_config, conn_num);
        // TODO: in future, do not remove clients that share a NodeId, instead,
        // expand the `Client` struct to handle multiple connections & a policy for
        // how to handle who we write to when multiple connections exist.
        let client = Client::new(client);
        if let Some(old_client) = self.inner.insert(key, client) {
            warn!("multiple connections found for {key:?}, pruning old connection",);
            old_client.shutdown().await;
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    pub async fn unregister(&mut self, peer: &NodeId) {
        trace!("unregistering client: {:?}", peer);
        if let Some(client) = self.inner.remove(peer) {
            for key in client.sent_to.iter() {
                self.send_peer_gone(key, *peer);
            }
            warn!("pruning connection {peer:?}");
            client.shutdown().await;
        }
    }

    /// Attempt to send a packet to client with [`NodeId`] `key`
    pub async fn send_packet(&mut self, key: &NodeId, packet: Packet) -> Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_packet(packet);
            return self.process_result(key, res).await;
        }
        bail!("Could not find client for {key:?}, dropped packet");
    }

    pub async fn send_disco_packet(&mut self, key: &NodeId, packet: Packet) -> Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_disco_packet(packet);
            return self.process_result(key, res).await;
        }
        bail!("Could not find client for {key:?}, dropped packet");
    }

    fn send_peer_gone(&mut self, key: &NodeId, peer: NodeId) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_peer_gone(peer);
            let _ = self.process_result_no_fallback(key, res);
            return;
        }
        warn!("Could not find client for {key:?}, dropping peer gone packet");
    }

    async fn process_result(&mut self, key: &NodeId, res: Result<(), SendError>) -> Result<()> {
        match res {
            Ok(_) => return Ok(()),
            Err(SendError::PacketDropped) => {
                warn!("client {key:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                warn!("Can no longer write to client {key:?}, dropping message and pruning connection");
                self.unregister(key).await;
            }
        }
        bail!("unable to send msg");
    }

    fn process_result_no_fallback(
        &mut self,
        key: &NodeId,
        res: Result<(), SendError>,
    ) -> Result<()> {
        match res {
            Ok(_) => return Ok(()),
            Err(SendError::PacketDropped) => {
                warn!("client {key:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                warn!("Can no longer write to client {key:?}");
            }
        }
        bail!("unable to send msg");
    }
}

/// Represents a connection to a client.
// TODO: expand to allow for _multiple connections_ associated with a single NodeId. This
// introduces some questions around which connection should be prioritized when forwarding packets
#[derive(Debug)]
pub(super) struct Client {
    /// The client connection associated with the [`NodeId`]
    conn: ClientConn,
    /// list of peers we have sent messages to
    sent_to: HashSet<NodeId>,
}

impl Client {
    fn new(conn: ClientConn) -> Self {
        Self {
            conn,
            sent_to: HashSet::default(),
        }
    }

    /// Record that this client sent a packet to the `dst` client
    fn record_send(&mut self, dst: NodeId) {
        self.sent_to.insert(dst);
    }

    async fn shutdown(self) {
        self.conn.shutdown().await;
    }

    fn send_packet(&self, packet: Packet) -> Result<(), SendError> {
        try_send(&self.conn.send_queue, packet)
    }

    fn send_disco_packet(&self, packet: Packet) -> Result<(), SendError> {
        try_send(&self.conn.disco_send_queue, packet)
    }

    fn send_peer_gone(&self, key: NodeId) -> Result<(), SendError> {
        let res = try_send(&self.conn.peer_gone, key);
        match res {
            Ok(_) => {
                inc!(Metrics, other_packets_sent);
            }
            Err(_) => {
                inc!(Metrics, other_packets_dropped);
            }
        }
        res
    }
}

/// Tries up to `3` times to send a message into the given channel, retrying iff it is full.
fn try_send<T>(sender: &mpsc::Sender<T>, msg: T) -> Result<(), SendError> {
    let mut msg = msg;
    for _ in 0..RETRIES {
        match sender.try_send(msg) {
            Ok(_) => return Ok(()),
            // if the queue is full, try again (max 3 times)
            Err(mpsc::error::TrySendError::Full(m)) => msg = m,
            // only other option is `TrySendError::Closed`, report the
            // closed error
            Err(_) => return Err(SendError::SenderClosed),
        }
    }
    Err(SendError::PacketDropped)
}

#[derive(Debug)]
enum SendError {
    PacketDropped,
    SenderClosed,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use iroh_base::SecretKey;
    use tokio::io::DuplexStream;
    use tokio_util::codec::{Framed, FramedRead};

    use super::*;
    use crate::{
        protos::relay::{recv_frame, DerpCodec, Frame, FrameType},
        server::streams::{MaybeTlsStream, RelayedStream},
    };

    fn test_client_builder(key: NodeId) -> (ClientConnConfig, FramedRead<DuplexStream, DerpCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        let (server_channel, _) = mpsc::channel(10);
        (
            ClientConnConfig {
                node_id: key,
                stream: RelayedStream::Derp(Framed::new(
                    MaybeTlsStream::Test(io),
                    DerpCodec::default(),
                )),
                write_timeout: Duration::from_secs(1),
                channel_capacity: 10,
                rate_limit: None,
                server_channel,
            },
            FramedRead::new(test_io, DerpCodec::default()),
        )
    }

    #[tokio::test]
    async fn test_clients() -> Result<()> {
        let a_key = SecretKey::generate(rand::thread_rng()).public();
        let b_key = SecretKey::generate(rand::thread_rng()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let mut clients = Clients::default();
        clients.register(builder_a).await;

        // send packet
        let data = b"hello world!";
        let expect_packet = Packet {
            src: b_key,
            data: Bytes::from(&data[..]),
        };
        clients
            .send_packet(&a_key.clone(), expect_packet.clone())
            .await?;
        let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: b_key,
                content: data.to_vec().into(),
            }
        );

        // send disco packet
        clients
            .send_disco_packet(&a_key.clone(), expect_packet)
            .await?;
        let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: b_key,
                content: data.to_vec().into(),
            }
        );

        // send peer_gone
        clients.send_peer_gone(&a_key, b_key);
        let frame = recv_frame(FrameType::PeerGone, &mut a_rw).await?;
        assert_eq!(frame, Frame::NodeGone { node_id: b_key });

        clients.unregister(&a_key.clone()).await;

        assert!(!clients.inner.contains_key(&a_key));

        clients.shutdown().await;
        Ok(())
    }
}
