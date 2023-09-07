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
    /// Number in the [0, 100] range indicating how often should requests fail.
    failure_rate: u8,
    /// History of requests performed by the [`Getter`] and if they were successful.
    request_history: Vec<(DownloadKind, PublicKey)>,
}

impl Getter for TestingGetter {
    // since for testing we don't need a real connection, just keep track of what peer is the
    // request being sent to
    type Connection = PublicKey;

    fn get(&mut self, kind: DownloadKind, peer: PublicKey) -> GetFut {
        // for now, every download is successful
        self.0.write().request_history.push((kind, peer));
        async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            Ok(())
        }
        .boxed_local()
    }
}

impl TestingGetter {
    /// Verify that the request history is as expected
    #[track_caller]
    pub(super) fn assert_history(&self, history: &[(DownloadKind, PublicKey)]) {
        assert_eq!(self.0.read().request_history, history);
    }
}
