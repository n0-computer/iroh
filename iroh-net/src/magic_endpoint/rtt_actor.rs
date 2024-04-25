//! Actor which coordinates the congestion controller for the magic socket

use std::collections::HashMap;
use std::sync::Weak;

use futures::StreamExt;
use futures_concurrency::stream::stream_group;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{debug, error, warn};

use crate::magicsock::{ConnectionType, ConnectionTypeStream};

#[derive(Debug)]
pub(super) struct RttHandle {
    pub(super) _handle: JoinHandle<()>,
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
        let _handle = tokio::spawn(async move {
            actor.run(msg_rx).await;
        });
        Self { _handle, msg_tx }
    }
}

/// Messages to send to the [`RttActor`].
#[derive(Debug)]
pub(super) enum RttMessage {
    /// Informs the [`RttActor`] of a new connection is should monitor.
    NewConnection {
        connection: Weak<quinn::ConnectionInner>,
        conn_type_changes: ConnectionTypeStream,
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
    connections: HashMap<stream_group::Key, Weak<quinn::ConnectionInner>>,
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
                Some(msg) = msg_rx.recv() => self.handle_msg(msg),
                item = self.connection_events.next(),
                    if !self.connection_events.is_empty() => self.do_reset_rtt(item),
                _ = cleanup_interval.tick() => self.do_connections_cleanup(),
                () = self.tick.notified() => continue,
                else => break,
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
            } => {
                self.handle_new_connection(connection, conn_type_changes);
            }
        }
    }

    /// Handles the new connection message.
    fn handle_new_connection(
        &mut self,
        connection: Weak<quinn::ConnectionInner>,
        conn_type_changes: ConnectionTypeStream,
    ) {
        let key = self.connection_events.insert(conn_type_changes);
        self.connections.insert(key, connection);
        self.tick.notify_one();
    }

    /// Performs the congestion controller reset for a magic socket path change.
    fn do_reset_rtt(&mut self, item: Option<(stream_group::Key, ConnectionType)>) {
        match item {
            Some((key, _new_conn_type)) => match self.connections.get(&key) {
                Some(conn) => match conn.upgrade() {
                    Some(conn) => conn.reset_congestion_state(),
                    None => {
                        self.connection_events.remove(key);
                    }
                },
                None => error!("No connection found for stream item"),
            },
            None => {
                warn!("self.conn_type_changes is empty but was polled");
            }
        }
    }

    /// Performs cleanup for closed connection.
    fn do_connections_cleanup(&mut self) {
        for (key, conn) in self.connections.iter() {
            if conn.upgrade().is_none() {
                self.connection_events.remove(*key);
            }
        }
    }
}
