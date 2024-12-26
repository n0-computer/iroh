//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{collections::HashSet, sync::Arc};

use anyhow::{bail, Result};
use bytes::Bytes;
use dashmap::DashMap;
use iroh_base::NodeId;
use tracing::{trace, warn};

use super::client_conn::{ClientConn, ClientConnConfig, SendError};

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default, Clone)]
pub(super) struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<NodeId, ClientConn>,
    /// Map of which client has sent where
    sent_to: DashMap<NodeId, HashSet<NodeId>>,
}

impl Clients {
    pub async fn shutdown(&self) {
        trace!("shutting down {} clients", self.0.clients.len());
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));

        futures_buffered::join_all(
            clients.map(|(_, client)| async move { client.shutdown().await }),
        )
        .await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub async fn register(&self, client_config: ClientConnConfig) {
        let key = client_config.node_id;
        trace!("registering client: {:?}", key);
        let client = ClientConn::new(client_config, self);
        if let Some(old_client) = self.0.clients.insert(key, client) {
            warn!("multiple connections found for {key:?}, pruning old connection",);
            old_client.shutdown().await;
        }
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    async fn unregister(&self, dst: NodeId) {
        trace!("unregistering client: {:?}", dst);
        if let Some((_, client)) = self.0.clients.remove(&dst) {
            if let Some((_, sent_to)) = self.0.sent_to.remove(&dst) {
                for key in sent_to {
                    match client.send_peer_gone(key) {
                        Ok(_) => {}
                        Err(SendError::PacketDropped) => {
                            warn!("client {key:?} too busy to receive packet, dropping packet");
                        }
                        Err(SendError::SenderClosed) => {
                            warn!("Can no longer write to client {key:?}");
                        }
                    }
                }
            }
            warn!("pruning connection {dst:?}");
            client.shutdown().await;
        }
    }

    /// Attempt to send a packet to client with [`NodeId`] `dst`
    pub async fn send_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        if let Some(client) = self.0.clients.get(&dst) {
            let res = client.send_packet(src, data);
            return self.process_result(src, dst, res).await;
        }
        bail!("Could not find client for {dst:?}, dropped packet");
    }

    pub async fn send_disco_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        if let Some(client) = self.0.clients.get(&dst) {
            let res = client.send_disco_packet(src, data);
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
                // Record send_to relationship
                let mut e = self.0.sent_to.entry(src).or_default();
                e.insert(dst);
                return Ok(());
            }
            Err(SendError::PacketDropped) => {
                warn!("client {dst:?} too busy to receive packet, dropping packet");
            }
            Err(SendError::SenderClosed) => {
                warn!("Can no longer write to client {dst:?}, dropping message and pruning connection");
                self.unregister(dst).await;
            }
        }
        bail!("unable to send msg");
    }
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
        protos::relay::{recv_frame, Frame, FrameType, RelayCodec},
        server::streams::{MaybeTlsStream, RelayedStream},
    };

    fn test_client_builder(
        key: NodeId,
    ) -> (ClientConnConfig, FramedRead<DuplexStream, RelayCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        (
            ClientConnConfig {
                node_id: key,
                stream: RelayedStream::Relay(Framed::new(
                    MaybeTlsStream::Test(io),
                    RelayCodec::test(),
                )),
                write_timeout: Duration::from_secs(1),
                channel_capacity: 10,
                rate_limit: None,
            },
            FramedRead::new(test_io, RelayCodec::test()),
        )
    }

    #[tokio::test]
    async fn test_clients() -> Result<()> {
        let a_key = SecretKey::generate(rand::thread_rng()).public();
        let b_key = SecretKey::generate(rand::thread_rng()).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        clients.register(builder_a).await;

        // send packet
        let data = b"hello world!";
        clients
            .send_packet(a_key, Bytes::from(&data[..]), b_key)
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
            .send_disco_packet(a_key, Bytes::from(&data[..]), b_key)
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
        clients.unregister(a_key).await;

        assert!(!clients.0.clients.contains_key(&a_key));
        clients.shutdown().await;

        Ok(())
    }
}
