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
use n0_future::IterExt;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{debug, trace};

use super::client::{Client, Config, ForwardPacketError};
use crate::{
    protos::{relay::Datagrams, streams::BytesStreamSink},
    server::{client::SendError, metrics::Metrics},
};

/// Manages the connections to all currently connected clients.
#[derive(Debug, Default, Clone)]
/// Registry of connected relay clients.
///
/// This type manages the collection of active client connections and
/// handles routing messages between them.
pub struct Clients(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    /// The list of all currently connected clients.
    clients: DashMap<EndpointId, ClientState>,
    /// Map of which client has sent where
    sent_to: DashMap<EndpointId, HashSet<EndpointId>>,
    /// Connection ID Counter
    next_connection_id: AtomicU64,
}

#[derive(Debug)]
struct ClientState {
    active: Client,
    inactive: Vec<Client>,
}

impl ClientState {
    async fn shutdown_all(mut self) {
        [self.active]
            .into_iter()
            .chain(self.inactive.drain(..))
            .map(Client::shutdown)
            .join_all()
            .await;
    }
}

impl Clients {
    /// Shuts down all connected clients.
    ///
    /// This method gracefully disconnects all active client connections managed by
    /// this registry. It will wait for all clients to complete their shutdown before
    /// returning.
    pub async fn shutdown(&self) {
        let keys: Vec<_> = self.0.clients.iter().map(|x| *x.key()).collect();
        trace!("shutting down {} clients", keys.len());
        let clients = keys.into_iter().filter_map(|k| self.0.clients.remove(&k));
        n0_future::join_all(clients.map(|(_, state)| state.shutdown_all())).await;
    }

    /// Builds the client handler and starts the read & write loops for the connection.
    pub fn register<S>(&self, client_config: Config<S>, metrics: Arc<Metrics>)
    where
        S: BytesStreamSink + Send + 'static,
    {
        let endpoint_id = client_config.endpoint_id;
        let connection_id = self.get_connection_id();
        trace!(remote_endpoint = %endpoint_id.fmt_short(), "registering client");

        let client = Client::new(client_config, connection_id, self, metrics);
        match self.0.clients.entry(endpoint_id) {
            dashmap::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                let old_client = std::mem::replace(&mut state.active, client);
                debug!(
                    remote_endpoint = %endpoint_id.fmt_short(),
                    "multiple connections found, deactivating old connection",
                );
                old_client
                    .try_send_health("Another endpoint connected with the same endpoint id. No more messages will be received".to_string())
                    .ok();
                state.inactive.push(old_client);
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ClientState {
                    active: client,
                    inactive: Vec::new(),
                });
            }
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

        self.0.clients.remove_if_mut(&endpoint_id, |_id, state| {
            if state.active.connection_id() == connection_id {
                // The unregistering client is the currently active client
                if let Some(last_inactive_client) = state.inactive.pop() {
                    // There is an inactive client, promote to active again.
                    state.active = last_inactive_client;
                    // Don't remove the entry from client map.
                    false
                } else {
                    // No inactive clients: Inform other peers that this peer is now gone.
                    if let Some((_, sent_to)) = self.0.sent_to.remove(&endpoint_id) {
                        for key in sent_to {
                            match state.active.try_send_peer_gone(key) {
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
                    // Remove entry from the client map.
                    true
                }
            } else {
                // The unregistering client is already inactive. Remove from the list of inactive clients.
                state
                    .inactive
                    .retain(|client| client.connection_id() != connection_id);
                // Active client is unmodified: keep entry in map.
                false
            }
        });
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
        match client.active.try_send_packet(src, data) {
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
                client.active.start_shutdown();
                Err(ForwardPacketError::new(SendError::Closed))
            }
        }
    }

    #[cfg(test)]
    fn active_connection_id(&self, endpoint_id: EndpointId) -> Option<u64> {
        self.0
            .clients
            .get(&endpoint_id)
            .map(|s| s.active.connection_id())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh_base::SecretKey;
    use n0_error::{Result, StdResultExt};
    use n0_future::{Stream, StreamExt};
    use n0_tracing_test::traced_test;
    use rand::SeedableRng;

    use super::*;
    use crate::{
        client::conn::Conn,
        protos::{common::FrameType, relay::RelayToClientMsg, streams::WsBytesFramed},
        server::streams::{MaybeTlsStream, RateLimited, ServerRelayedStream},
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

    fn test_client_builder(
        key: EndpointId,
    ) -> (Config<WsBytesFramed<RateLimited<MaybeTlsStream>>>, Conn) {
        let (server, client) = tokio::io::duplex(1024);
        (
            Config {
                endpoint_id: key,
                stream: ServerRelayedStream::test(server),
                write_timeout: Duration::from_secs(1),
                channel_capacity: 10,
            },
            Conn::test(client),
        )
    }

    #[tokio::test]
    #[traced_test]
    async fn test_clients() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::generate(&mut rng).public();
        let b_key = SecretKey::generate(&mut rng).public();

        let (builder_a, mut a_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());
        clients.register(builder_a, metrics.clone());

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
            client.active.start_shutdown();
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

    #[tokio::test]
    #[traced_test]
    async fn test_clients_same_endpoint_id() -> Result {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0u64);
        let a_key = SecretKey::generate(&mut rng).public();
        let b_key = SecretKey::generate(&mut rng).public();

        let (a1_builder, mut a1_rw) = test_client_builder(a_key);

        let clients = Clients::default();
        let metrics = Arc::new(Metrics::default());

        // register client a
        clients.register(a1_builder, metrics.clone());
        let a1_conn_id = clients.active_connection_id(a_key).unwrap();

        // send packet and verify it is send to a1
        let data = b"hello world!";
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // register new client with same endpoint id
        let (a2_builder, mut a2_rw) = test_client_builder(a_key);
        clients.register(a2_builder, metrics.clone());
        let a2_conn_id = clients.active_connection_id(a_key).unwrap();
        assert!(a2_conn_id != a1_conn_id);

        // a1 is marked inactive and should receive a health frame
        let _frame = recv_frame(FrameType::Health, &mut a1_rw).await?;

        // send packet and verify it is send to a2
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a2_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // disconnect a2
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.active_connection_id(a_key) == Some(a2_conn_id) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        // a1 should be marked active again now, and receive sent messages
        assert_eq!(clients.active_connection_id(a_key), Some(a1_conn_id));
        clients.send_packet(a_key, Datagrams::from(&data[..]), b_key, &metrics)?;
        let frame = recv_frame(FrameType::RelayToClientDatagram, &mut a1_rw).await?;
        assert_eq!(
            frame,
            RelayToClientMsg::Datagrams {
                remote_endpoint_id: b_key,
                datagrams: data.to_vec().into(),
            }
        );

        // after shutting down the now-active client, there should no longer be an entry for that endpoint id
        clients
            .0
            .clients
            .get(&a_key)
            .unwrap()
            .active
            .start_shutdown();

        // need to wait a moment for the removal to be processed
        tokio::time::timeout(Duration::from_secs(1), {
            let clients = clients.clone();
            async move {
                // wait until the active connection is no longer a2 (which we unregistered)
                while clients.0.clients.contains_key(&a_key) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        })
        .await
        .std_context("timeout")?;

        clients.shutdown().await;

        Ok(())
    }
}
