#![cfg(test)]
// WIP
#![allow(unused)]
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

mod test_dialer;
mod test_getter;
mod test_invariants;
mod testing_registry;

impl Downloader {
    fn spawn_for_test(
        dialer: test_dialer::TestingDialer,
        getter: test_getter::TestingGetter,
        concurrency_limits: ConcurrencyLimits,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(super::SERVICE_CHANNEL_CAPACITY);

        let availabiliy_registry = Registry::default();

        iroh_bytes::util::runtime::Handle::from_current(1)
            .unwrap()
            .local_pool()
            .spawn_pinned(move || async move {
                // we want to see the logs of the service
                let _guard = iroh_test::logging::setup();

                let mut service = Service::new(
                    getter,
                    availabiliy_registry,
                    dialer,
                    concurrency_limits,
                    msg_rx,
                );
                service.run().await
            });

        Downloader { next_id: 0, msg_tx }
    }
}

/// Tests that receiving a download request and performing it doesn't explode.
#[tokio::test]
async fn smoke_test() -> anyhow::Result<()> {
    let dialer = test_dialer::TestingDialer::default();
    let getter = test_getter::TestingGetter::default();
    let availabiliy_registry = Registry::default();
    let concurrency_limits = ConcurrencyLimits::default();

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send a request and make sure the peer is requested the corresponding download
    let peer = SecretKey::generate().public();
    let kind = DownloadKind::Blob {
        hash: Hash::new([0u8; 32]),
    };
    let handle = downloader.queue(kind.clone(), vec![peer]).await;
    // wait for the download result to be reported
    handle.await.expect("should report success");
    // verify that the peer was dialed
    dialer.assert_history(&[peer]);
    // verify that the request was sent
    getter.assert_history(&[(kind, peer)]);

    Ok(())
}
