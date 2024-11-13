//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};
use iroh_base::key::PublicKey;
use iroh_metrics::inc;
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{trace, warn, Instrument, Span};

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
    inner: HashMap<PublicKey, Client>,
}

impl Clients {
    pub async fn shutdown(&mut self) {
        trace!("shutting down conn");
        let mut handles = JoinSet::default();
        for (_, client) in self.inner.drain() {
            handles.spawn(async move { client.shutdown().await }.instrument(Span::current()));
        }
        while let Some(t) = handles.join_next().await {
            if let Err(err) = t {
                trace!("shutdown error: {:?}", err);
            }
        }
    }

    /// Record that `src` sent or forwarded a packet to `dst`
    pub fn record_send(&mut self, src: &PublicKey, dst: PublicKey) {
        if let Some(client) = self.inner.get_mut(src) {
            client.record_send(dst);
        }
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

    pub async fn register(&mut self, client_config: ClientConnConfig) {
        // this builds the client handler & starts the read & write loops to that client connection
        let key = client_config.key;
        trace!("registering client: {:?}", key);
        let client = ClientConn::new(client_config);
        // TODO: in future, do not remove clients that share a publicKey, instead,
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
    pub async fn unregister(&mut self, peer: &PublicKey) {
        trace!("unregistering client: {:?}", peer);
        if let Some(client) = self.inner.remove(peer) {
            for key in client.sent_to.iter() {
                self.send_peer_gone(key, *peer);
            }
            warn!("pruning connection {peer:?}");
            client.shutdown().await;
        }
    }

    /// Attempt to send a packet to client with [`PublicKey`] `key`
    pub async fn send_packet(&mut self, key: &PublicKey, packet: Packet) -> Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_packet(packet);
            return self.process_result(key, res).await;
        };
        warn!("Could not find client for {key:?}, dropping packet");
        bail!("Could not find client for {key:?}, dropped packet");
    }

    pub async fn send_disco_packet(&mut self, key: &PublicKey, packet: Packet) -> Result<()> {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_disco_packet(packet);
            return self.process_result(key, res).await;
        };
        warn!("Could not find client for {key:?}, dropping disco packet");
        bail!("Could not find client for {key:?}, dropped packet");
    }

    fn send_peer_gone(&mut self, key: &PublicKey, peer: PublicKey) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_peer_gone(peer);
            let _ = self.process_result_no_fallback(key, res);
            return;
        };
        warn!("Could not find client for {key:?}, dropping peer gone packet");
    }

    async fn process_result(&mut self, key: &PublicKey, res: Result<(), SendError>) -> Result<()> {
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
        key: &PublicKey,
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
// TODO: expand to allow for _multiple connections_ associated with a single PublicKey. This
// introduces some questions around which connection should be prioritized when forwarding packets
//
// From goimpl:
//
// "Represents one or more connections to a client
//
// In the common cast, the client should only have one connection to the relay server for a given
// key. When they're connected multiple times, we record their set of connection, and keep their
// connections open to make them happy (to keep them from spinning, etc) and keep track of which
// is the latest connection. If only the last is sending traffic, that last one is the active
// connection and it gets traffic. Otherwise, in the case of a cloned node key, the whole set of
// connections doesn't receive data frames."
#[derive(Debug)]
pub(super) struct Client {
    /// The client connection associated with the [`PublicKey`]
    conn: ClientConn,
    /// list of peers we have sent messages to
    sent_to: HashSet<PublicKey>,
}

impl Client {
    fn new(conn: ClientConn) -> Self {
        Self {
            conn,
            sent_to: HashSet::default(),
        }
    }

    /// Record that this client sent a packet to the `dst` client
    fn record_send(&mut self, dst: PublicKey) {
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

    fn send_peer_gone(&self, key: PublicKey) -> Result<(), SendError> {
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh_base::key::SecretKey;
    use tokio::io::DuplexStream;
    use tokio_util::codec::{Framed, FramedRead};

    use super::*;
    use crate::{
        protos::relay::{recv_frame, DerpCodec, Frame, FrameType},
        server::streams::{MaybeTlsStream, RelayedStream},
    };

    fn test_client_builder(
        key: PublicKey,
    ) -> (ClientConnConfig, FramedRead<DuplexStream, DerpCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        let (server_channel, _) = mpsc::channel(10);
        (
            ClientConnConfig {
                key,
                stream: RelayedStream::Derp(Framed::new(MaybeTlsStream::Test(io), DerpCodec)),
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
        assert_eq!(frame, Frame::PeerGone { peer: b_key });

        clients.unregister(&a_key.clone()).await;

        assert!(!clients.inner.contains_key(&a_key));

        clients.shutdown().await;
        Ok(())
    }
}
