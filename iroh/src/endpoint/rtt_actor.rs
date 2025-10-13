//! Actor which coordinates the congestion controller for the magic socket

use std::{pin::Pin, sync::Arc, task::Poll};

use iroh_base::NodeId;
use n0_future::{
    MergeUnbounded, Stream, StreamExt,
    task::{self, AbortOnDropHandle},
};
use tokio::sync::mpsc;
use tracing::{Instrument, debug, info_span};

use crate::{magicsock::ConnectionType, metrics::MagicsockMetrics};

#[derive(Debug)]
pub(super) struct RttHandle {
    // We should and some point use this to propagate panics and errors.
    pub(super) _handle: AbortOnDropHandle<()>,
    pub(super) msg_tx: mpsc::Sender<RttMessage>,
}

impl RttHandle {
    pub(super) fn new(metrics: Arc<MagicsockMetrics>) -> Self {
        let mut actor = RttActor {
            connection_events: Default::default(),
            metrics,
        };
        let (msg_tx, msg_rx) = mpsc::channel(16);
        let handle = task::spawn(
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
        conn_type_changes: n0_watcher::Stream<n0_watcher::Direct<ConnectionType>>,
        /// For reporting-only, the Node ID of this connection.
        node_id: NodeId,
    },
}

/// Actor to coordinate congestion controller state with magic socket state.
///
/// The magic socket can change the underlying network path, between two nodes.  If we can
/// inform the QUIC congestion controller of this event it will work much more efficiently.
#[derive(derive_more::Debug)]
struct RttActor {
    /// Stream of connection type changes.
    #[debug("MergeUnbounded<WatcherStream<ConnectionType>>")]
    connection_events: MergeUnbounded<MappedStream>,
    metrics: Arc<MagicsockMetrics>,
}

#[derive(Debug)]
struct MappedStream {
    stream: n0_watcher::Stream<n0_watcher::Direct<ConnectionType>>,
    node_id: NodeId,
    /// Reference to the connection.
    connection: quinn::WeakConnectionHandle,
    /// This an indiciator of whether this connection was direct before.
    /// This helps establish metrics on number of connections that became direct.
    was_direct_before: bool,
}

struct ConnectionEvent {
    became_direct: bool,
}

impl Stream for MappedStream {
    type Item = ConnectionEvent;

    /// Performs the congestion controller reset for a magic socket path change.
    ///
    /// Regardless of which kind of path we are changed to, the congestion controller needs
    /// resetting.  Even when switching to mixed we should reset the state as e.g. switching
    /// from direct to mixed back to direct should be a rare exception and is a bug if this
    /// happens commonly.
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(Some(new_conn_type)) => {
                let mut became_direct = false;
                if self.connection.network_path_changed() {
                    debug!(
                        node_id = %self.node_id.fmt_short(),
                        new_type = ?new_conn_type,
                        "Congestion controller state reset",
                    );
                    if !self.was_direct_before && matches!(new_conn_type, ConnectionType::Direct(_))
                    {
                        self.was_direct_before = true;
                        became_direct = true
                    }
                };
                Poll::Ready(Some(ConnectionEvent { became_direct }))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl RttActor {
    /// Runs the actor main loop.
    ///
    /// The main loop will finish when the sender is dropped.
    async fn run(&mut self, mut msg_rx: mpsc::Receiver<RttMessage>) {
        loop {
            tokio::select! {
                biased;
                msg = msg_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_msg(msg),
                        None => break,
                    }
                }
                event = self.connection_events.next(), if !self.connection_events.is_empty() => {
                    if event.map(|e| e.became_direct).unwrap_or(false) {
                        self.metrics.connection_became_direct.inc();
                    }
                }
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
        conn_type_changes: n0_watcher::Stream<n0_watcher::Direct<ConnectionType>>,
        node_id: NodeId,
    ) {
        self.connection_events.push(MappedStream {
            stream: conn_type_changes,
            connection,
            node_id,
            was_direct_before: false,
        });
        self.metrics.connection_handshake_success.inc();
    }
}
