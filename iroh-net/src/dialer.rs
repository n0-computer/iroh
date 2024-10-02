//! A dialer to conveniently dial many nodes.

use std::{collections::HashMap, pin::Pin, task::Poll};

use anyhow::anyhow;
use futures_lite::Stream;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::error;

use crate::{Endpoint, NodeId};

/// Dials nodes and maintains a queue of pending dials.
///
/// The [`Dialer`] wraps an [`Endpoint`], connects to nodes through the endpoint, stores the
/// pending connect futures and emits finished connect results.
///
/// The [`Dialer`] also implements [`Stream`] to retrieve the dialled connections.
#[derive(Debug)]
pub struct Dialer {
    endpoint: Endpoint,
    pending: JoinSet<(NodeId, anyhow::Result<quinn::Connection>)>,
    pending_dials: HashMap<NodeId, CancellationToken>,
}

impl Dialer {
    /// Create a new dialer for a [`Endpoint`]
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            pending: Default::default(),
            pending_dials: Default::default(),
        }
    }

    /// Starts to dial a node by [`NodeId`].
    ///
    /// Since this dials by [`NodeId`] the [`Endpoint`] must know how to contact the node by
    /// [`NodeId`] only.  This relies on addressing information being provided by either the
    /// [discovery service] or manually by calling [`Endpoint::add_node_addr`].
    ///
    /// [discovery service]: crate::discovery::Discovery
    pub fn queue_dial(&mut self, node_id: NodeId, alpn: &'static [u8]) {
        if self.is_pending(node_id) {
            return;
        }
        let cancel = CancellationToken::new();
        self.pending_dials.insert(node_id, cancel.clone());
        let endpoint = self.endpoint.clone();
        self.pending.spawn(async move {
            let res = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(anyhow!("Cancelled")),
                res = endpoint.connect(node_id, alpn) => res
            };
            (node_id, res)
        });
    }

    /// Aborts a pending dial.
    pub fn abort_dial(&mut self, node_id: NodeId) {
        if let Some(cancel) = self.pending_dials.remove(&node_id) {
            cancel.cancel();
        }
    }

    /// Checks if a node is currently being dialed.
    pub fn is_pending(&self, node: NodeId) -> bool {
        self.pending_dials.contains_key(&node)
    }

    /// Waits for the next dial operation to complete.
    pub async fn next_conn(&mut self) -> (NodeId, anyhow::Result<quinn::Connection>) {
        match self.pending_dials.is_empty() {
            false => {
                let (node_id, res) = loop {
                    match self.pending.join_next().await {
                        Some(Ok((node_id, res))) => {
                            self.pending_dials.remove(&node_id);
                            break (node_id, res);
                        }
                        Some(Err(e)) => {
                            error!("next conn error: {:?}", e);
                        }
                        None => {
                            error!("no more pending conns available");
                            std::future::pending().await
                        }
                    }
                };

                (node_id, res)
            }
            true => std::future::pending().await,
        }
    }

    /// Number of pending connections to be opened.
    pub fn pending_count(&self) -> usize {
        self.pending_dials.len()
    }

    /// Returns a reference to the endpoint used in this dialer.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
}

impl Stream for Dialer {
    type Item = (NodeId, anyhow::Result<quinn::Connection>);

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        match self.pending.poll_join_next(cx) {
            Poll::Ready(Some(Ok((node_id, result)))) => {
                self.pending_dials.remove(&node_id);
                Poll::Ready(Some((node_id, result)))
            }
            Poll::Ready(Some(Err(e))) => {
                error!("dialer error: {:?}", e);
                Poll::Pending
            }
            _ => Poll::Pending,
        }
    }
}
