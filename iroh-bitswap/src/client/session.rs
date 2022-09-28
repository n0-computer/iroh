use std::{sync::Arc, time::Duration};

use cid::Cid;
use libp2p::PeerId;

use super::{
    peer_manager::PeerManager, provider_query_manager::ProviderQueryManager,
    session_interest_manager::SessionInterestManager, session_manager::SessionManager,
    session_peer_manager::SessionPeerManager, session_want_sender::SessionWantSender,
    session_wants::SessionWants,
};

/// The kind of operation being executed in the event loop.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Receive(Vec<Cid>),
    Want(Vec<Cid>),
    Cancel(Vec<Cid>),
    Broadcast(Vec<Cid>),
    WantsSent(Vec<Cid>),
}

impl Op {
    fn keys(&self) -> &[Cid] {
        match self {
            Op::Receive(ref keys) => keys,
            Op::Want(ref keys) => keys,
            Op::Cancel(ref keys) => keys,
            Op::Broadcast(ref keys) => keys,
            Op::WantsSent(ref keys) => keys,
        }
    }
}

/// Holds state for an individual bitswap transfer operation.
/// Allows bitswap to make smarter decisions about who to send what.
#[derive(Debug, Clone)]
pub struct Session {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    self_id: PeerId,
    id: u64,
    session_manager: SessionManager,
    peer_manager: PeerManager,
    session_peer_manager: SessionPeerManager,
    provider_finder: ProviderQueryManager,
    session_interest_manager: SessionInterestManager,
    session_wants: SessionWants,
    session_want_sender: SessionWantSender,
    latency_tracker: LatencyTracker,
}

impl Session {
    pub fn new() -> Self {
        todo!()
    }

    pub fn id(&self) -> u64 {
        self.inner.id
    }

    pub fn signal_availability(&self, peer: &PeerId, is_connected: bool) {
        todo!()
    }
}

#[derive(Debug)]
struct LatencyTracker {
    total_latency: Duration,
    count: usize,
}

impl LatencyTracker {
    fn has_latency(&self) -> bool {
        !self.total_latency.is_zero() && self.count > 0
    }

    fn average_latency(&self) -> Duration {
        Duration::from_secs_f64(self.total_latency.as_secs_f64() / self.count as f64)
    }

    fn receive_update(&mut self, count: usize, latency: Duration) {
        self.count += count;
        self.total_latency += latency;
    }
}
