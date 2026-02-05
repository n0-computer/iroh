//! The "Server" side of the client. Uses the `ClientConnManager`.
// Based on tailscale/derp/derp_server.go

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use dashmap::DashMap;
use iroh_base::EndpointId;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::client::{Client, Config, ForwardPacketError};
use crate::{
    protos::relay::Datagrams,
    server::{client::SendError, metrics::Metrics},
};

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default, Clone)]
pub(super) struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, Client>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    /// Connection ID Counter
    next_connection_id: AtomicU64,
}

impl Clients {
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));

        n0_future::join_all(clients.map(|(_, client)| async move { client.shutdown().await }))
            .await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub async fn register(&self, client_config: Config, metrics: Arc<Metrics>) {
        let endpoint_id = client_config.endpoint_id;
        let connection_id = self.get_connection_id();
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, connection_id, self, metrics);
        if let Some(old_client) = self.0.clients.insert(endpoint_id, client) {
            debug!(
                remote_endpoint = %endpoint_id.fmt_short(),
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
    /// Must be passed a matching connection_id.
    pub(super) fn unregister(&self, connection_id: u64, endpoint_id: EndpointId) {
        trace!(
            endpoint_id = %endpoint_id.fmt_short(),
            connection_id, "unregistering client"
        );

        if let Some((_, client)) = self
            .0
            .clients
            .remove_if(&endpoint_id, |_, c| c.connection_id() == connection_id)
            && let Some((_, sent_to)) = self.0.sent_to.remove(&endpoint_id)
        {
            for key in sent_to {
                match client.try_send_peer_gone(key) {
                    Ok(_) => {}
                    Err(TrySendError::Full(_)) => {
                        debug!(
                            dst = %key.fmt_short(),
                            "client too busy to receive packet, dropping packet"
                        );
                    }
                    Err(TrySendError::Closed(_)) => {
                        debug!(
                            dst = %key.fmt_short(),
                            "can no longer write to client, dropping packet"
                        );
                    }
                }
            }
        }
    }

    /// Attempt to send a packet to client with [`EndpointId`] `dst`.
    pub(super) fn send_packet(
        &self,
        dst: EndpointId,
        data: Datagrams,
        src: EndpointId,
        metrics: &Metrics,
    ) -> Result<(), ForwardPacketError> {
        let Some(client) = self.0.clients.get(&dst) else {
            debug!(dst = %dst.fmt_short(), "no connected client, dropped packet");
            metrics.send_packets_dropped.inc();
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
                    dst = %dst.fmt_short(),
                    "client too busy to receive packet, dropping packet"
                );
                Err(ForwardPacketError::new(SendError::Full))
            }
            Err(TrySendError::Closed(_)) => {
                debug!(
                    dst = %dst.fmt_short(),
                    "can no longer write to client, dropping message and pruning connection"
                );
                client.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt};
    use n0_future::{Stream, StreamExt};
    use rand::SeedableRng;

    use super::*;
    use crate::{
        client::conn::Conn,
        protos::{common::FrameType, relay::RelayToClientMsg},
        server::streams::RelayedStream,
    };

    async fn recv_frame<
        E: std::error::Error + Sync + Send + 'static,
        S: Stream<Item = Result<RelayToClientMsg, E>> + Unpin,
    >(
        frame_type: FrameType,
        mut stream: S,
    ) -> Result<RelayToClientMsg> {
        match stream.next().await {
            Some(Ok(frame)) => {
                if frame_type != frame.typ() {
                    n0_error::bail_any!(
                        "Unexpected frame, got {:?}, but expected {:?}",
                        frame.typ(),
                        frame_type
                    );
                }
                Ok(frame)
            }
            Some(Err(err)) => Err(err).anyerr(),
            None => n0_error::bail_any!("Unexpected EOF, expected frame {frame_type:?}"),
        }
    }

    fn test_client_builder(key: EndpointId) -> (Config, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        (
            Config {
                endpoint_id: key,
                stream: RelayedStream::test(server),
                write_timeout: Duration::from_secs(1),
                channel_capacity: 10,
            },
            Conn::test(client),
        )
    }

    #[tokio::test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::generate(&mut rng).public();
        let b_key = SecretKey::generate(&mut rng).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone()).await;

        // send packet
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
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
        .await
        .std_context("timeout")?;
        clients.shutdown().await;

        Ok(())
    }
}
