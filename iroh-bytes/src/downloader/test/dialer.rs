//! Implementation of [`super::Dialer`] used for testing.

use std::{
    collections::HashSet,
    task::{Context, Poll},
};

use parking_lot::RwLock;

use super::*;

/// Dialer for testing that keeps track of the dialing history.
#[derive(Default, Clone)]
pub(super) struct TestingDialer(Arc<RwLock<TestingDialerInner>>);

struct TestingDialerInner {
    /// Peers that are being dialed.
    dialing: HashSet<NodeId>,
    /// Queue of dials.
    dial_futs: delay_queue::DelayQueue<NodeId>,
    /// History of attempted dials.
    dial_history: Vec<NodeId>,
    /// How long does a dial last.
    dial_duration: Duration,
    /// Fn deciding if a dial is successful.
    dial_outcome: Box<fn(&NodeId) -> bool>,
}

impl Default for TestingDialerInner {
    fn default() -> Self {
        TestingDialerInner {
            dialing: HashSet::default(),
            dial_futs: delay_queue::DelayQueue::default(),
            dial_history: Vec::default(),
            dial_duration: Duration::from_millis(10),
            dial_outcome: Box::new(|_| true),
        }
    }
}

impl Dialer for TestingDialer {
    type Connection = NodeId;

    fn queue_dial(&mut self, node_id: NodeId) {
        let mut inner = self.0.write();
        inner.dial_history.push(node_id);
        // for now assume every dial works
        let dial_duration = inner.dial_duration;
        if inner.dialing.insert(node_id) {
            inner.dial_futs.insert(node_id, dial_duration);
        }
    }

    fn pending_count(&self) -> usize {
        self.0.read().dialing.len()
    }

    fn is_pending(&self, node: &NodeId) -> bool {
        self.0.read().dialing.contains(node)
    }
}

impl futures::Stream for TestingDialer {
    type Item = (NodeId, anyhow::Result<NodeId>);

    fn poll_next(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut inner = self.0.write();
        match inner.dial_futs.poll_expired(cx) {
            Poll::Ready(Some(expired)) => {
                let node = expired.into_inner();
                let report_ok = (inner.dial_outcome)(&node);
                let result = report_ok
                    .then_some(node)
                    .ok_or_else(|| anyhow::anyhow!("dialing test set to fail"));
                inner.dialing.remove(&node);
                Poll::Ready(Some((node, result)))
            }
            _ => Poll::Pending,
        }
    }
}

impl TestingDialer {
    #[track_caller]
    pub(super) fn assert_history(&self, history: &[NodeId]) {
        assert_eq!(self.0.read().dial_history, history)
    }
}
