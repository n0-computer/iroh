//! based on tailscale/derp/derp_server.go
//!
//! The "Server" side of the client. Uses the `ClientConnManager`.
use crate::hp::key::node::PublicKey;
use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::{
    client_conn::{ClientBuilder, ClientConnManager, Packet, PeerConnState},
    conn::Conn,
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
struct Client<C>
where
    C: Conn,
{
    // The set of all connections associated with the PublicKey
    // conns: HashMap<usize, ClientConnManager<C>>,
    // The most recent edition to the set, or the last connection we have received data from. Can
    // be `None` if that particular connection has disconnected & we have no other previous
    // connections
    // last: Option<usize>,
    // the "home" connection for the client.
    // TODO: I do not see this used in the go impl, except for setting and un-setting.
    preferred: Option<usize>,
    /// the connection
    conn: ClientConnManager<C>,
}

impl<C> Client<C>
where
    C: Conn,
{
    pub fn new(conn: ClientConnManager<C>) -> Self {
        Self {
            preferred: None,
            conn,
        }
    }

    pub fn shutdown(self) {
        tokio::spawn(async move {
            self.conn.shutdown().await;
            // notify peers of disconnect?
        });
    }

    pub fn send_packet(&self, packet: Packet) -> Result<(), SendError> {
        try_send(&self.conn.client_channels.send_queue, packet)
    }

    pub fn send_disco_packet(&self, packet: Packet) -> Result<(), SendError> {
        try_send(&self.conn.client_channels.disco_send_queue, packet)
    }

    pub fn send_peer_gone(&self, key: PublicKey) -> Result<(), SendError> {
        try_send(&self.conn.client_channels.peer_gone, key)
    }

    pub fn send_mesh_updates(&self, updates: Vec<PeerConnState>) -> Result<(), SendError> {
        try_send(&self.conn.client_channels.mesh_update, updates)
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

enum SendError {
    PacketDropped,
    SenderClosed,
}

#[derive(Debug)]
pub(crate) struct Clients<C>
where
    C: Conn,
{
    inner: HashMap<PublicKey, Client<C>>,
}

impl<C> Drop for Clients<C>
where
    C: Conn,
{
    fn drop(&mut self) {}
}

impl<C> Clients<C>
where
    C: Conn,
{
    pub fn new() -> Self {
        Self {
            inner: HashMap::default(),
        }
    }

    pub fn shutdown(&mut self) {
        for (_, client) in self.inner.drain() {
            client.shutdown();
        }
    }

    pub fn register<R, W>(&mut self, client: ClientBuilder<C, R, W>)
    where
        R: AsyncRead + Unpin + Send + Sync + 'static,
        W: AsyncWrite + Unpin + Send + Sync + 'static,
    {
        // this builds the client handler & starts the read & write loops to that client connection
        let client = client.build();
        let key = client.key.clone();
        // TODO: in future, do not remove clients that share a publicKey, instead,
        // expand the `Client` struct to handle multiple connections & a policy for
        // how to handle who we write to when mulitple connections exist.
        let client = Client::new(client);
        if let Some(old_client) = self.inner.insert(key.clone(), client) {
            tracing::warn!("multiple connections found for {key:?}, pruning old connection",);
            old_client.shutdown();
        }
    }

    pub fn unregister(&mut self, key: &PublicKey) {
        if let Some(client) = self.inner.remove(key) {
            tracing::warn!("pruning connection {key:?}");
            client.shutdown();
        }
    }

    pub fn send_packet(&mut self, key: &PublicKey, packet: Packet) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_packet(packet);
            self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping packet");
    }

    pub fn send_disco_packet(&mut self, key: &PublicKey, packet: Packet) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_disco_packet(packet);
            self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping packet");
    }

    pub fn send_peer_gone(&mut self, key: &PublicKey, peer: PublicKey) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_peer_gone(peer);
            self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping packet");
    }

    pub fn send_mesh_updates(&mut self, key: &PublicKey, updates: Vec<PeerConnState>) {
        if let Some(client) = self.inner.get(key) {
            let res = client.send_mesh_updates(updates);
            self.process_result(key, res);
        };
        tracing::warn!("Could not find client for {key:?}, dropping packet");
    }

    fn process_result(&mut self, key: &PublicKey, res: Result<(), SendError>) {
        match res {
            Ok(_) => {}
            Err(SendError::PacketDropped) => {
                tracing::warn!("client {key:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                tracing::warn!("Can no longer write to client {key:?}, dropping message and pruning connection");
                self.unregister(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Instant;

    use super::*;

    use crate::hp::derp::{
        read_frame, FRAME_PEER_GONE, FRAME_PEER_PRESENT, FRAME_RECV_PACKET, MAX_PACKET_SIZE,
    };

    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use ed25519_dalek::PUBLIC_KEY_LENGTH;
    use tokio::io::DuplexStream;

    struct MockConn {}
    impl Conn for MockConn {
        fn close(&self) -> Result<()> {
            Ok(())
        }
        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:3000".parse().unwrap()
        }
    }

    async fn test_client_builder(
        key: PublicKey,
        conn_num: usize,
    ) -> (
        ClientBuilder<MockConn, DuplexStream, DuplexStream>,
        DuplexStream,
        DuplexStream,
    ) {
        let (test_reader, writer) = tokio::io::duplex(1024);
        let (reader, test_writer) = tokio::io::duplex(1024);
        let (server_channel, _) = mpsc::channel(10);
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
    async fn test_clients() -> Result<()> {
        let a_key = PublicKey::from([1u8; PUBLIC_KEY_LENGTH]);
        let b_key = PublicKey::from([10u8; PUBLIC_KEY_LENGTH]);
        let (builder_a, mut a_reader, _) = test_client_builder(a_key.clone(), 0).await;

        let mut clients = Clients::new();
        clients.register(builder_a);

        // send packet
        let data = b"hello world!";
        let expect_packet = Packet {
            src: b_key.clone(),
            enqueued_at: Instant::now(),
            bytes: Bytes::from(&data[..]),
        };
        clients.send_packet(&a_key.clone(), expect_packet.clone());
        let mut buf = BytesMut::new();
        let (frame_type, _) = read_frame(&mut a_reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_RECV_PACKET);

        // send disco packet
        clients.send_disco_packet(&a_key.clone(), expect_packet);
        let (frame_type, _) = read_frame(&mut a_reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_RECV_PACKET);

        // send peer_gone
        clients.send_peer_gone(&a_key.clone(), b_key.clone());
        let (frame_type, _) = read_frame(&mut a_reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);

        // send mesh_update
        let updates = vec![
            PeerConnState {
                peer: b_key.clone(),
                present: true,
            },
            PeerConnState {
                peer: b_key.clone(),
                present: false,
            },
        ];

        clients.send_mesh_updates(&a_key.clone(), updates);
        let (frame_type, _) = read_frame(&mut a_reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_PRESENT);

        let (frame_type, _) = read_frame(&mut a_reader, MAX_PACKET_SIZE, &mut buf).await?;
        assert_eq!(frame_type, FRAME_PEER_GONE);

        clients.unregister(&a_key.clone());

        assert!(clients.inner.get(&a_key).is_none());

        clients.shutdown();
        Ok(())
    }
}
