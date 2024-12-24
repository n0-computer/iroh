//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::AtomicUsize, Arc},
};

use anyhow::{bail, Result};
use bytes::Bytes;
use iroh_base::NodeId;
use iroh_metrics::inc;
use tokio::sync::{mpsc, RwLock};
use tracing::{trace, warn};

use super::{
    client_conn::{ClientConn, ClientConnConfig, Packet},
    metrics::Metrics,
};

/// Number of times we try to send to a client connection before dropping the data;
const RETRIES: usize = 3;

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default, Clone)]
pub(super) struct Clients {
    /// The list of all currently connected clients.
    inner: Arc<RwLock<HashMap<NodeId, Client>>>, // TODO: look into lock free
    /// The next connection number to use.
    conn_num: Arc<AtomicUsize>,
}

impl Clients {
    pub async fn shutdown(&self) {
        let mut clients = self.inner.write().await;
        trace!("shutting down {} clients", clients.len());
        futures_buffered::join_all(
            clients
                .drain()
                .map(|(_, client)| async move { client.shutdown().await }),
        )
        .await;
    }

    fn next_conn_num(&self) -> usize {
        self.conn_num
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub async fn register(&self, client_config: ClientConnConfig) {
        let key = client_config.node_id;
        trace!("registering client: {:?}", key);
        let conn_num = self.next_conn_num();
        let client = ClientConn::new(client_config, conn_num);
        // TODO: in future, do not remove clients that share a NodeId, instead,
        // expand the `Client` struct to handle multiple connections & a policy for
        // how to handle who we write to when multiple connections exist.
        let client = Client::new(client);
        if let Some(old_client) = self.inner.write().await.insert(key, client) {
            warn!("multiple connections found for {key:?}, pruning old connection",);
            old_client.shutdown().await;
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    pub async fn unregister(&self, dst: NodeId, conn_num: Option<usize>) {
        trace!("unregistering client: {:?}", dst);
        let mut clients = self.inner.write().await;
        if let Some(client) = clients.remove(&dst) {
            if let Some(conn_num) = conn_num {
                if client.conn.conn_num != conn_num {
                    // put it back
                    clients.insert(dst, client);
                    return;
                }
            }
            for key in client.sent_to.iter() {
                match client.send_peer_gone(dst) {
                    Ok(_) => {}
                    Err(SendError::PacketDropped) => {
                        warn!("client {key:?} too busy to receive packet, dropping packet");
                    }
                    Err(SendError::SenderClosed) => {
                        warn!("Can no longer write to client {key:?}");
                    }
                }
            }
            warn!("pruning connection {dst:?}");
            client.shutdown().await;
        }
    }

    /// Attempt to send a packet to client with [`NodeId`] `dst`
    pub async fn send_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        let clients = self.inner.read().await;
        if let Some(client) = clients.get(&dst) {
            let res = client.send_packet(src, data);
            drop(clients);
            return self.process_result(src, dst, res).await;
        }
        bail!("Could not find client for {dst:?}, dropped packet");
    }

    pub async fn send_disco_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        let clients = self.inner.read().await;
        if let Some(client) = clients.get(&dst) {
            let res = client.send_disco_packet(src, data);
            drop(clients);
            return self.process_result(src, dst, res).await;
        }
        bail!("Could not find client for {dst:?}, dropped disco packet");
    }

    async fn process_result(
        &self,
        src: NodeId,
        dst: NodeId,
        res: Result<(), SendError>,
    ) -> Result<()> {
        match res {
            Ok(_) => {
                if let Some(client) = self.inner.write().await.get_mut(&src) {
                    client.record_send(dst);
                }
                return Ok(());
            }
            Err(SendError::PacketDropped) => {
                warn!("client {dst:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                warn!("Can no longer write to client {dst:?}, dropping message and pruning connection");
                self.unregister(dst, None).await;
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

    fn send_packet(&self, src: NodeId, data: Bytes) -> Result<(), SendError> {
        try_send(&self.conn.send_queue, Packet { src, data })
    }

    fn send_disco_packet(&self, src: NodeId, data: Bytes) -> Result<(), SendError> {
        try_send(&self.conn.disco_send_queue, Packet { src, data })
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

// #[cfg(test)]
// mod tests {
//     use std::time::Duration;

//     use bytes::Bytes;
//     use iroh_base::SecretKey;
//     use tokio::io::DuplexStream;
//     use tokio_util::codec::{Framed, FramedRead};

//     use super::*;
//     use crate::{
//         protos::relay::{recv_frame, Frame, FrameType, RelayCodec},
//         server::streams::{MaybeTlsStream, RelayedStream},
//     };

//     fn test_client_builder(
//         key: NodeId,
//     ) -> (ClientConnConfig, FramedRead<DuplexStream, RelayCodec>) {
//         let (test_io, io) = tokio::io::duplex(1024);
//         // let (server_channel, _) = mpsc::channel(10);
//         (
//             ClientConnConfig {
//                 node_id: key,
//                 stream: RelayedStream::Relay(Framed::new(
//                     MaybeTlsStream::Test(io),
//                     RelayCodec::test(),
//                 )),
//                 write_timeout: Duration::from_secs(1),
//                 channel_capacity: 10,
//                 rate_limit: None,
//                 // server_channel,
//             },
//             FramedRead::new(test_io, RelayCodec::test()),
//         )
//     }

//     #[tokio::test]
//     async fn test_clients() -> Result<()> {
//         let a_key = SecretKey::generate(rand::thread_rng()).public();
//         let b_key = SecretKey::generate(rand::thread_rng()).public();

//         let (builder_a, mut a_rw) = test_client_builder(a_key);

//         let mut clients = Clients::default();
//         clients.register(builder_a).await;

//         // send packet
//         let data = b"hello world!";
//         let expect_packet = Packet {
//             src: b_key,
//             data: Bytes::from(&data[..]),
//         };
//         clients
//             .send_packet(&a_key.clone(), expect_packet.clone())
//             .await?;
//         let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
//         assert_eq!(
//             frame,
//             Frame::RecvPacket {
//                 src_key: b_key,
//                 content: data.to_vec().into(),
//             }
//         );

//         // send disco packet
//         clients
//             .send_disco_packet(&a_key.clone(), expect_packet)
//             .await?;
//         let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
//         assert_eq!(
//             frame,
//             Frame::RecvPacket {
//                 src_key: b_key,
//                 content: data.to_vec().into(),
//             }
//         );

//         // send peer_gone
//         clients.send_peer_gone(&a_key, b_key);
//         let frame = recv_frame(FrameType::PeerGone, &mut a_rw).await?;
//         assert_eq!(frame, Frame::NodeGone { node_id: b_key });

//         clients.unregister(&a_key.clone()).await;

//         assert!(!clients.inner.contains_key(&a_key));

//         clients.shutdown().await;
//         Ok(())
//     }
// }
