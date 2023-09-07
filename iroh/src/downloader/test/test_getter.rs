use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::anyhow;
use iroh_gossip::net::util::Timers;
use iroh_net::key::SecretKey;
use parking_lot::RwLock;

use super::*;

#[derive(Default, Clone)]
pub(super) struct TestingGetter(Arc<RwLock<TestingGetterInner>>);

#[derive(Default)]
struct TestingGetterInner {
    /// How long requests take.
    request_duration: Duration,
    /// History of requests performed by the [`Getter`] and if they were successful.
    request_history: Vec<(DownloadKind, PublicKey)>,
}

impl Getter for TestingGetter {
    // since for testing we don't need a real connection, just keep track of what peer is the
    // request being sent to
    type Connection = PublicKey;

    fn get(&mut self, kind: DownloadKind, peer: PublicKey) -> GetFut {
        let mut inner = self.0.write();
        inner.request_history.push((kind, peer));
        let request_duration = inner.request_duration;
        async move {
            tokio::time::sleep(request_duration).await;
            Ok(())
        }
        .boxed_local()
    }
}

impl TestingGetter {
    pub(super) fn set_request_duration(&self, request_duration: Duration) {
        self.0.write().request_duration = request_duration;
    }
    /// Verify that the request history is as expected
    #[track_caller]
    pub(super) fn assert_history(&self, history: &[(DownloadKind, PublicKey)]) {
        assert_eq!(self.0.read().request_history, history);
    }
}
