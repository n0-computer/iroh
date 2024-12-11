//! Actor which coordinates the congestion controller for the magic socket

use std::collections::HashMap;

use futures_concurrency::stream::stream_group;
use futures_lite::StreamExt;
use iroh_base::NodeId;
use iroh_metrics::inc;
use tokio::{
    sync::{mpsc, Notify},
    time::Duration,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{debug, error, info_span, trace, Instrument};

use crate::{
    magicsock::{ConnectionType, ConnectionTypeStream},
    metrics::MagicsockMetrics,
};

#[derive(Debug)]
pub(super) struct RttHandle {
    // We should and some point use this to propagate panics and errors.
    pub(super) _handle: AbortOnDropHandle<()>,
    pub(super) msg_tx: mpsc::Sender<RttMessage>,
}

impl RttHandle {
    pub(super) fn new() -> Self {
        let mut actor = RttActor {
            connection_events: stream_group::StreamGroup::new().keyed(),
            connections: HashMap::new(),
            tick: Notify::new(),
        };
        let (msg_tx, msg_rx) = mpsc::channel(16);
        let handle = tokio::spawn(
            async move {
                actor.run(msg_rx).await;
            }
            .instrument(info_span!("rtt-actor")),
        );
        Self {
            _handle: AbortOnDropHandle::new(handle),
            msg_tx,
        }
    }
}

/// Messages to send to the [`RttActor`].
#[derive(Debug)]
pub(super) enum RttMessage {
    /// Informs the [`RttActor`] of a new connection is should monitor.
    NewConnection {
        /// The connection.
        connection: quinn::WeakConnectionHandle,
        /// Path changes for this connection from the magic socket.
        conn_type_changes: ConnectionTypeStream,
        /// For reporting-only, the Node ID of this connection.
        node_id: NodeId,
    },
}

/// Actor to coordinate congestion controller state with magic socket state.
///
/// The magic socket can change the underlying network path, between two nodes.  If we can
/// inform the QUIC congestion controller of this event it will work much more efficiently.
#[derive(Debug)]
struct RttActor {
    /// Stream of connection type changes.
    connection_events: stream_group::Keyed<ConnectionTypeStream>,
    /// References to the connections.
    ///
    /// These are weak references so not to keep the connections alive.  The key allows
    /// removing the corresponding stream from `conn_type_changes`.
    /// The boolean is an indiciator of whether this connection was direct before.
    /// This helps establish metrics on number of connections that became direct.
    connections: HashMap<stream_group::Key, (quinn::WeakConnectionHandle, NodeId, bool)>,
    /// A way to notify the main actor loop to run over.
    ///
    /// E.g. when a new stream was added.
    tick: Notify,
}

impl RttActor {
    /// Runs the actor main loop.
    ///
    /// The main loop will finish when the sender is dropped.
    async fn run(&mut self, mut msg_rx: mpsc::Receiver<RttMessage>) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(5));
        cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                msg = msg_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg),
                        None => break,
                    }
                }
                item = self.connection_events.next(), if !self.connection_events.is_empty() => {
                    self.do_reset_rtt(item);
                }
                _ = cleanup_interval.tick() => self.do_connections_cleanup(),
                () = self.tick.notified() => continue,
            }
        }
        debug!("rtt-actor finished");
    }

    /// Handle actor messages.
    fn handle_msg(&mut self, msg: RttMessage) {
        match msg {
            RttMessage::NewConnection {
                connection,
                conn_type_changes,
                node_id,
            } => {
                self.handle_new_connection(connection, conn_type_changes, node_id);
            }
        }
    }

    /// Handles the new connection message.
    fn handle_new_connection(
        &mut self,
        connection: quinn::WeakConnectionHandle,
        conn_type_changes: ConnectionTypeStream,
        node_id: NodeId,
    ) {
        let key = self.connection_events.insert(conn_type_changes);
        self.connections.insert(key, (connection, node_id, false));
        self.tick.notify_one();
        inc!(MagicsockMetrics, connection_handshake_success);
    }

    /// Performs the congestion controller reset for a magic socket path change.
    ///
    /// Regardless of which kind of path we are changed to, the congestion controller needs
    /// resetting.  Even when switching to mixed we should reset the state as e.g. switching
    /// from direct to mixed back to direct should be a rare exception and is a bug if this
    /// happens commonly.
    fn do_reset_rtt(&mut self, item: Option<(stream_group::Key, ConnectionType)>) {
        match item {
            Some((key, new_conn_type)) => match self.connections.get_mut(&key) {
                Some((handle, node_id, was_direct_before)) => {
                    if handle.network_path_changed() {
                        debug!(
                            node_id = %node_id.fmt_short(),
                            new_type = ?new_conn_type,
                            "Congestion controller state reset",
                        );
                        if !*was_direct_before && matches!(new_conn_type, ConnectionType::Direct(_))
                        {
                            *was_direct_before = true;
                            inc!(MagicsockMetrics, connection_became_direct);
                        }
                    } else {
                        debug!(
                            node_id = %node_id.fmt_short(),
                            "removing dropped connection",
                        );
                        self.connection_events.remove(key);
                    }
                }
                None => error!("No connection found for stream item"),
            },
            None => {
                trace!("No more connections");
            }
        }
    }

    /// Performs cleanup for closed connection.
    fn do_connections_cleanup(&mut self) {
        for (key, (handle, node_id, _)) in self.connections.iter() {
            if !handle.is_alive() {
                trace!(node_id = %node_id.fmt_short(), "removing stale connection");
                self.connection_events.remove(*key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_actor_mspc_close() {
        let mut actor = RttActor {
            connection_events: stream_group::StreamGroup::new().keyed(),
            connections: HashMap::new(),
            tick: Notify::new(),
        };
        let (msg_tx, msg_rx) = mpsc::channel(16);
        let handle = tokio::spawn(async move {
            actor.run(msg_rx).await;
        });

        // Dropping the msg_tx should stop the actor
        drop(msg_tx);

        let task_res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("timeout - actor did not finish");
        assert!(task_res.is_ok());
    }
}
