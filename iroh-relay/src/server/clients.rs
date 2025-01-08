//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{bail, Result};
use bytes::Bytes;
use dashmap::DashMap;
use iroh_base::NodeId;
use iroh_metrics::inc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::client::{Client, Config};
use crate::server::metrics::Metrics;

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default, Clone)]
pub(super) struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<NodeId, Client>,
    /// Map of which client has sent where
    sent_to: DashMap<NodeId, HashSet<NodeId>>,
    /// Connection ID Counter
    next_connection_id: AtomicU64,
}

impl Clients {
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));

        futures_buffered::join_all(
            clients.map(|(_, client)| async move { client.shutdown().await }),
        )
        .await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub async fn register(&self, client_config: Config) {
        let node_id = client_config.node_id;
        let connection_id = self.get_connection_id();
        trace!(remote_node = node_id.fmt_short(), "registering client");

        let client = Client::new(client_config, connection_id, self);
        if let Some(old_client) = self.0.clients.insert(node_id, client) {
            debug!(
                remote_node = node_id.fmt_short(),
                "multiple connections found, pruning old connection",
            );
            old_client.shutdown().await;
        }
    }

    fn get_connection_id(&self) -> u64 {
        self.0.next_connection_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Removes the client from the map of clients, & sends a notification
    /// to each client that peers has sent data to, to let them know that
    /// peer is gone from the network.
    ///
    /// Explicitly drops the reference to the client to avoid deadlock.
    pub(super) async fn unregister<'a>(&self, connection_id: u64, node_id: NodeId) {
        trace!(node_id = node_id.fmt_short(), "unregistering client");

        if let Some((_, client)) = self
            .0
            .clients
            .remove_if(&node_id, |_, c| c.connection_id() == connection_id)
        {
            if let Some((_, sent_to)) = self.0.sent_to.remove(&node_id) {
                for key in sent_to {
                    match client.try_send_peer_gone(key) {
                        Ok(_) => {}
                        Err(TrySendError::Full(_)) => {
                            debug!(
                                dst = key.fmt_short(),
                                "client too busy to receive packet, dropping packet"
                            );
                        }
                        Err(TrySendError::Closed(_)) => {
                            debug!(
                                dst = key.fmt_short(),
                                "can no longer write to client, dropping packet"
                            );
                        }
                    }
                }
            }
            client.shutdown().await;
        }
    }

    /// Attempt to send a packet to client with [`NodeId`] `dst`.
    pub(super) fn send_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = dst.fmt_short(), "no connected client, dropped packet");
            inc!(Metrics, send_packets_dropped);
            return Ok(());
        };
        match client.try_send_packet(src, data) {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                bail!("failed to send message: full");
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.start_shutdown();
                bail!("failed to send message: gone");
            }
        }
    }

    /// Attempt to send a disco packet to client with [`NodeId`] `dst`.
    pub(super) fn send_disco_packet(&self, dst: NodeId, data: Bytes, src: NodeId) -> Result<()> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(
                dst = dst.fmt_short(),
                "no connected client, dropped disco packet"
            );
            inc!(Metrics, disco_packets_dropped);
            return Ok(());
        };
        match client.try_send_disco_packet(src, data) {
            Ok(_) => {
                // Record sent_to relationship
                self.0.sent_to.entry(src).or_default().insert(dst);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                debug!(
                    dst = dst.fmt_short(),
                    "client too busy to receive disco packet, dropping packet"
                );
                bail!("failed to send message: full");
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = dst.fmt_short(),
                    "can no longer write to client, dropping disco message and pruning connection"
                );
                client.start_shutdown();
                bail!("failed to send message: gone");
            }
        }
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

    fn test_client_builder(key: NodeId) -> (Config, FramedRead<DuplexStream, RelayCodec>) {
        let (test_io, io) = tokio::io::duplex(1024);
        (
            Config {
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
        clients.send_packet(a_key, Bytes::from(&data[..]), b_key)?;
        let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: b_key,
                content: data.to_vec().into(),
            }
        );

        // send disco packet
        clients.send_disco_packet(a_key, Bytes::from(&data[..]), b_key)?;
        let frame = recv_frame(FrameType::RecvPacket, &mut a_rw).await?;
        assert_eq!(
            frame,
            Frame::RecvPacket {
                src_key: b_key,
                content: data.to_vec().into(),
            }
        );

        {
            let client = clients.0.clients.get(&a_key).unwrap();
            // shutdown client a, this should trigger the removal from the clients list
            client.start_shutdown();
        }

        // need to wait a moment for the removal to be processed
        let c = clients.clone();
        tokio::time::timeout(Duration::from_secs(1), async move {
            loop {
                if !c.0.clients.contains_key(&a_key) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;
        clients.shutdown().await;

        Ok(())
    }
}
