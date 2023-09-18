//! Implementation of [`super::Dialer`] used for testing.

use std::{
    collections::HashSet,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use parking_lot::RwLock;

use super::*;

/// Dialer for testing that keeps track of the dialing history.
#[derive(Default, Clone)]
pub(super) struct TestingDialer(Arc<RwLock<TestingDialerInner>>);

struct TestingDialerInner {
    /// Peers that are being dialed.
    dialing: HashSet<PublicKey>,
    /// Queue of dials.
    dial_futs: delay_queue::DelayQueue<PublicKey>,
    /// History of attempted dials.
    dial_history: Vec<PublicKey>,
    /// How long does a dial last.
    dial_duration: Duration,
    /// Fn deciding if a dial is successful.
    dial_outcome: Box<fn(&PublicKey) -> bool>,
}

impl Default for TestingDialerInner {
    fn default() -> Self {
        TestingDialerInner {
            dialing: HashSet::default(),
            dial_futs: delay_queue::DelayQueue::default(),
            dial_history: Vec::default(),
            dial_duration: Duration::ZERO,
            dial_outcome: Box::new(|_| true),
        }
    }
}

impl Dialer for TestingDialer {
    type Connection = PublicKey;

    fn queue_dial(&mut self, peer_id: PublicKey) {
        let mut inner = self.0.write();
        inner.dial_history.push(peer_id);
        // for now assume every dial works
        let dial_duration = inner.dial_duration;
        if inner.dialing.insert(peer_id) {
            inner.dial_futs.insert(peer_id, dial_duration);
        }
    }

    fn pending_count(&self) -> usize {
        self.0.read().dialing.len()
    }

    fn is_pending(&self, peer: &PublicKey) -> bool {
        self.0.read().dialing.contains(peer)
    }
}

impl futures::Stream for TestingDialer {
    type Item = (PublicKey, anyhow::Result<PublicKey>);

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = self.0.write();
        match inner.dial_futs.poll_expired(cx) {
            Poll::Ready(Some(expired)) => {
                let peer = expired.into_inner();
                let report_ok = (inner.dial_outcome)(&peer);
                let result = report_ok
                    .then_some(peer)
                    .ok_or_else(|| anyhow::anyhow!("dialing test set to fail"));
                Poll::Ready(Some((peer, result)))
            }
            _ => Poll::Pending,
        }
    }
}

impl TestingDialer {
    #[track_caller]
    pub(super) fn assert_history(&self, history: &[PublicKey]) {
        assert_eq!(self.0.read().dial_history, history)
    }

    pub(super) fn set_dial_duration(&self, duration: Duration) {
        let mut inner = self.0.write();
        inner.dial_duration = duration;
    }
}
