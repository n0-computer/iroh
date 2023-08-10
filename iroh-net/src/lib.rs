//! iroh-net provides connectivity for iroh.
//!
//! This crate is a collection of tools to establish connectivity between peers.  At
//! the high level [`MagicEndpoint`] is used to establish a QUIC connection with
//! authenticated peers, relaying and holepunching support.

#![recursion_limit = "256"]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

pub mod config;
pub mod defaults;
pub mod derp;
mod disco;
mod dns;
pub mod key;
pub mod magic_endpoint;
pub mod magicsock;
pub mod metrics;
pub mod net;
pub mod netcheck;
pub mod netmap;
pub mod ping;
pub mod portmapper;
pub mod stun;
pub mod tls;
pub mod util;

// TODO(@divma): move somewhere appropriate 
pub mod dialer {
    //! Dial queue
    use std::collections::HashMap;

    use anyhow::anyhow;
    use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
    use tokio_util::sync::CancellationToken;

    use crate::{tls::PeerId, MagicEndpoint};

    /// Future for a pending dial operation
    pub type DialFuture = BoxFuture<'static, (PeerId, anyhow::Result<quinn::Connection>)>;

    /// Dial peers and maintain a queue of pending dials
    ///
    /// This wraps a [MagicEndpoint], connects to peers through the endpoint, stores
    /// the pending connect futures and emits finished connect results.
    ///
    /// TODO: Move to iroh-net
    #[derive(Debug)]
    pub struct Dialer {
        endpoint: MagicEndpoint,
        pending: FuturesUnordered<DialFuture>,
        pending_peers: HashMap<PeerId, CancellationToken>,
    }
    impl Dialer {
        /// Create a new dialer for a [`MagicEndpoint`]
        pub fn new(endpoint: MagicEndpoint) -> Self {
            Self {
                endpoint,
                pending: Default::default(),
                pending_peers: Default::default(),
            }
        }

        /// Start to dial a peer
        ///
        /// Note that the peer's addresses and/or derp region must be added to the endpoint's
        /// addressbook for a dial to succeed, see [`MagicEndpoint::add_known_addrs`].
        pub fn queue_dial(&mut self, peer_id: PeerId, alpn_protocol: &'static [u8]) {
            if self.is_pending(&peer_id) {
                return;
            }
            let cancel = CancellationToken::new();
            self.pending_peers.insert(peer_id, cancel.clone());
            let endpoint = self.endpoint.clone();
            let fut = async move {
                let res = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => Err(anyhow!("Cancelled")),
                    res = endpoint.connect(peer_id, alpn_protocol, None, &[]) => res
                };
                (peer_id, res)
            }
            .boxed();
            self.pending.push(fut.boxed());
        }

        /// Abort a pending dial
        pub fn abort_dial(&mut self, peer_id: &PeerId) {
            if let Some(cancel) = self.pending_peers.remove(peer_id) {
                cancel.cancel();
            }
        }

        /// Check if a peer is currently being dialed
        pub fn is_pending(&self, peer: &PeerId) -> bool {
            self.pending_peers.contains_key(peer)
        }

        /// Wait for the next dial operation to complete
        pub async fn next(&mut self) -> (PeerId, anyhow::Result<quinn::Connection>) {
            match self.pending_peers.is_empty() {
                false => {
                    let (peer_id, res) = self.pending.next().await.unwrap();
                    self.pending_peers.remove(&peer_id);
                    (peer_id, res)
                }
                true => futures::future::pending().await,
            }
        }
    }
}

pub use magic_endpoint::MagicEndpoint;

#[cfg(test)]
pub(crate) mod test_utils;
