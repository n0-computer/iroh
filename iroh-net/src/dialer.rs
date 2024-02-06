//! A dialer to dial nodes

use std::{collections::HashMap, pin::Pin, task::Poll};

use crate::{key::PublicKey, MagicEndpoint, NodeAddr, NodeId};
use anyhow::anyhow;
use futures::future::BoxFuture;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::error;

/// Dial nodes and maintain a queue of pending dials
///
/// This wraps a [`MagicEndpoint`], connects to nodes through the endpoint, stores
/// the pending connect futures and emits finished connect results.
#[derive(Debug)]
pub struct Dialer {
    endpoint: MagicEndpoint,
    pending: JoinSet<(PublicKey, anyhow::Result<quinn::Connection>)>,
    pending_dials: HashMap<PublicKey, CancellationToken>,
}

impl Dialer {
    /// Create a new dialer for a [`MagicEndpoint`]
    pub fn new(endpoint: MagicEndpoint) -> Self {
        Self {
            endpoint,
            pending: Default::default(),
            pending_dials: Default::default(),
        }
    }

    /// Start to dial a node.
    ///
    /// Note that the node's addresses and/or derp url must be added to the endpoint's
    /// addressbook for a dial to succeed, see [`MagicEndpoint::add_node_addr`].
    pub fn queue_dial(&mut self, node_id: NodeId, alpn: &'static [u8]) {
        if self.is_pending(&node_id) {
            return;
        }
        let cancel = CancellationToken::new();
        self.pending_dials.insert(node_id, cancel.clone());
        let endpoint = self.endpoint.clone();
        self.pending.spawn(async move {
            let res = tokio::select! {
                biased;
                _ = cancel.cancelled() => Err(anyhow!("Cancelled")),
                res = endpoint.connect(NodeAddr::new(node_id), alpn) => res
            };
            (node_id, res)
        });
    }

    /// Abort a pending dial
    pub fn abort_dial(&mut self, node_id: &NodeId) {
        if let Some(cancel) = self.pending_dials.remove(node_id) {
            cancel.cancel();
        }
    }

    /// Check if a node is currently being dialed
    pub fn is_pending(&self, node: &NodeId) -> bool {
        self.pending_dials.contains_key(node)
    }

    /// Wait for the next dial operation to complete
    pub async fn next_conn(&mut self) -> (PublicKey, anyhow::Result<quinn::Connection>) {
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
                            futures::future::pending().await
                        }
                    }
                };

                (node_id, res)
            }
            true => futures::future::pending().await,
        }
    }

    /// Number of pending connections to be opened.
    pub fn pending_count(&self) -> usize {
        self.pending_dials.len()
    }
}

impl futures::Stream for Dialer {
    type Item = (PublicKey, anyhow::Result<quinn::Connection>);

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

/// Future for a pending dial operation
pub type DialFuture = BoxFuture<'static, (PublicKey, anyhow::Result<quinn::Connection>)>;
