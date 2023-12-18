//! based on tailscale/derp/derp_server.go
//!
//! The "Server" side of the client. Uses the `ClientConnManager`.
use crate::key::PublicKey;
use std::collections::{HashMap, HashSet};

use futures::future::join_all;
use tokio::sync::mpsc;

use iroh_metrics::inc;
use tracing::{Instrument, Span};

use super::{
    client_conn::{ClientConnBuilder, ClientConnManager},
    metrics::Metrics,
    types::{Packet, PeerConnState},
    PacketForwarder,
};

/// Number of times we try to send to a client connection before dropping the data;
const RETRIES: usize = 3;

/// Represents a connection to a client.
///
// TODO: expand to allow for _multiple connections_ associated with a single PublicKey. This
// introduces some questions around which connection should be prioritized when forwarding packets
//
// From goimpl:
//
// "Represents one or more connections to a client
//
// In the common cast, the client should only have one connection to the DERP server for a given
// key. When they're connected multiple times, we record their set of connection, and keep their
// connections open to make them happy (to keep them from spinning, etc) and keep track of whihc
// is the lastest connection. If only the last is sending traffic, that last one is the active
// connection and it gets traffic. Otherwise, in the case of a cloned node key, the whole set of
// connections doesn't receive data frames."
#[derive(Debug)]
struct Client {
    /// The client connection associated with the [`PublicKey`]
    conn: ClientConnManager,
    /// list of peers we have sent messages to
    sent_to: HashSet<PublicKey>,
}

impl Client {
    pub fn new(conn: ClientConnManager) -> Self {
        Self {
            conn,
            sent_to: HashSet::default(),
        }
    }

    /// Record that this client sent a packet to the `dst` client
    pub fn record_send(&mut self, dst: PublicKey) {
        self.sent_to.insert(dst);
    }

    pub fn shutdown(self) {
        tokio::spawn(
            async move {
                self.conn.shutdown().await;
                // notify peers of disconnect?
            }
            .instrument(Span::current()),
        );
    }

    pub async fn shutdown_await(self) {
        self.conn.shutdown().await;
    }

    pub fn send_packet(&self, packet: Packet) -> Result<(), SendError> {
        let res = try_send(&self.conn.client_channels.send_queue, packet);
        if res.is_ok() {
            // there is a chance that we have a packet forwarder for
            // this peer, so we must check that route before
            // marking the packet as "dropped"
            inc!(Metrics, send_packets_sent);
        }
        res
    }

    pub fn send_disco_packet(&self, packet: Packet) -> Result<(), SendError> {
        let res = try_send(&self.conn.client_channels.disco_send_queue, packet);
        if res.is_ok() {
            // there is a chance that we have a packet forwarder for
            // this peer, so we must check that route before
            // marking the packet as "dropped"
            inc!(Metrics, disco_packets_sent);
        }
        res
    }

    pub fn send_peer_gone(&self, key: PublicKey) -> Result<(), SendError> {
        let res = try_send(&self.conn.client_channels.peer_gone, key);
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

    pub fn send_mesh_updates(&self, updates: Vec<PeerConnState>) -> Result<(), SendError> {
        let res = try_send(&self.conn.client_channels.mesh_update, updates);
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

// TODO: in the goimpl, it also tries 3 times to send a packet. But, in go we can clone receiver
// channels, so each client is able to drain any full channels of "older" packets
// & attempt to try to send the message again. We can't drain any channels here,
// so I'm not sure if we should come up with some mechanism to request the channel
// be drained, or just leave it
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

#[derive(Debug)]
pub(crate) struct Clients {
    inner: HashMap<PublicKey, Client>,
}

impl Drop for Clients {
    fn drop(&mut self) {}
}

impl Clients {
    pub fn new() -> Self {
        Self {
            inner: HashMap::default(),
        }
    }

    pub async fn shutdown(&mut self) {
        tracing::trace!("shutting down conn");
        let mut handles = Vec::new();
        for (_, client) in self.inner.drain() {
            handles.push(tokio::spawn(
                async move { client.shutdown_await().await }.instrument(Span::current()),
            ));
        }
        join_all(handles).await;
    }

    pub fn close_conn(&mut self, key: &PublicKey) {
        tracing::info!("closing conn {:?}", key);
        if let Some(client) = self.inner.remove(key) {
            client.shutdown();
        }
    }

    /// Record that `src` sent or forwarded a packet to `dst`
    pub fn record_send(&mut self, src: &PublicKey, dst: PublicKey) {
        if let Some(client) = self.inner.get_mut(src) {
            client.record_send(dst);
        }
    }

    pub fn all_clients(&self) -> impl Iterator<Item = &PublicKey> {
        self.inner.keys()
    }

    pub fn contains_key(&self, key: &PublicKey) -> bool {
        self.inner.contains_key(key)
    }

    pub fn has_client(&self, key: &PublicKey, conn_num: usize) -> bool {
        if let Some(client) = self.inner.get(key) {
            return client.conn.conn_num == conn_num;
        }
        false
    }

    pub fn broadcast_peer_state_change<'a>(
        &mut self,
        keys: impl Iterator<Item = &'a PublicKey>,
        updates: Vec<PeerConnState>,
    ) {
        for k in keys {
            self.send_mesh_updates(k, updates.clone());
        }
    }

    pub fn register<P: PacketForwarder>(&mut self, client_builder: ClientConnBuilder<P>) {
        // this builds the client handler & starts the read & write loops to that client connection
        let key = client_builder.key;
        tracing::trace!("registering client: {:?}", key);
        let client = client_builder.build();
        // TODO: in future, do not remove clients that share a publicKey, instead,
        // expand the `Client` struct to handle multiple connections & a policy for
        // how to handle who we write to when mulitple connections exist.
        let client = Client::new(client);
        if let Some(old_client) = self.inner.insert(key, client) {
            tracing::warn!("multiple connections found for {key:?}, pruning old connection",);
            old_client.shutdown();
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    pub fn unregister(&mut self, peer: &PublicKey) {
        tracing::trace!("unregistering client: {:?}", peer);
        if let Some(client) = self.inner.remove(peer) {
            for key in client.sent_to.iter() {
                self.send_peer_gone(key, *peer);
            }
            tracing::warn!("pruning connection {peer:?}");
            client.shutdown();
        }
    }

    /// Attempt to send a packet to client with [`PublicKey`] `key`
    pub fn send_packet(&mut self, key: &PublicKey, packet: Packet) -> anyhow::Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_packet(packet);
            return self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping packet");
        anyhow::bail!("Could not find client for {key:?}, dropped packet");
    }

    pub fn send_disco_packet(&mut self, key: &PublicKey, packet: Packet) -> anyhow::Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_disco_packet(packet);
            return self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping disco packet");
        anyhow::bail!("Could not find client for {key:?}, dropped packet");
    }

    pub fn send_peer_gone(&mut self, key: &PublicKey, peer: PublicKey) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_peer_gone(peer);
            let _ = self.process_result(key, res);
            return;
        };
        tracing::warn!("Could not find client for {key:?}, dropping peer gone packet");
    }

    pub fn send_mesh_updates(&mut self, key: &PublicKey, updates: Vec<PeerConnState>) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_mesh_updates(updates);
            let _ = self.process_result(key, res);
            return;
        };
        tracing::warn!("Could not find client for {key:?}, dropping mesh update packet",);
    }

    fn process_result(
        &mut self,
        key: &PublicKey,
        res: Result<(), SendError>,
    ) -> anyhow::Result<()> {
        match res {
            Ok(_) => return Ok(()),
            Err(SendError::PacketDropped) => {
                tracing::warn!("client {key:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                tracing::warn!("Can no longer write to client {key:?}, dropping message and pruning connection");
                self.unregister(key);
            }
        }
        anyhow::bail!("unable to send msg");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        derp::{
            client_conn::ClientConnBuilder,
            codec::{recv_frame, DerpCodec, Frame, FrameType},
            PacketForwarder,
        },
        key::SecretKey,
    };

    use anyhow::Result;
    use bytes::Bytes;
    use tokio::io::DuplexStream;
    use tokio_util::codec::{Framed, FramedRead};

    struct MockPacketForwarder {}
    impl PacketForwarder for MockPacketForwarder {
        fn forward_packet(&mut self, srckey: PublicKey, dstkey: PublicKey, _packet: Bytes) {
            tracing::info!("forwarding packet from {srckey:?} to {dstkey:?}");
        }
    }

    fn test_client_builder(
        key: PublicKey,
        conn_num: usize,
    ) -> (
        ClientConnBuilder<MockPacketForwarder>,
        FramedRead<DuplexStream, DerpCodec>,
    ) {
        let (test_io, io) = tokio::io::duplex(1024);
        let (server_channel, _) = mpsc::channel(10);
        (
            ClientConnBuilder {
                key,
                conn_num,
                io: Framed::new(crate::derp::server::MaybeTlsStream::Test(io), DerpCodec),
                can_mesh: true,
                write_timeout: None,
                channel_capacity: 10,
                server_channel,
            },
            FramedRead::new(test_io, DerpCodec),
        )
    }

    #[tokio::test]
    async fn test_clients() -> Result<()> {
        let a_key = SecretKey::generate().public();
        let b_key = SecretKey::generate().public();

        let (builder_a, mut a_rw) = test_client_builder(a_key, 0);

        let mut clients = Clients::new();
        clients.register(builder_a);

        // send packet
        let data = b"hello world!";
        let expect_packet = Packet {
            src: b_key,
            bytes: Bytes::from(&data[..]),
        };
        clients.send_packet(&a_key.clone(), expect_packet.clone())?;
        let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: b_key,
                content: data.to_vec().into(),
            }
        );

        // send disco packet
        clients.send_disco_packet(&a_key.clone(), expect_packet)?;
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
        assert_eq!(frame, Frame::PeerGone { peer: b_key });

        // send mesh_update
        let updates = vec![
            PeerConnState {
                peer: b_key,
                present: true,
            },
            PeerConnState {
                peer: b_key,
                present: false,
            },
        ];

        clients.send_mesh_updates(&a_key.clone(), updates);
        let frame = recv_frame(FrameType::PeerPresent, &mut a_rw).await?;
        assert_eq!(frame, Frame::PeerPresent { peer: b_key });

        let frame = recv_frame(FrameType::PeerGone, &mut a_rw).await?;
        assert_eq!(frame, Frame::PeerGone { peer: b_key });

        clients.unregister(&a_key.clone());

        assert!(clients.inner.get(&a_key).is_none());

        clients.shutdown().await;
        Ok(())
    }
}
