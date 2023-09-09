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

mod dialer;
mod getter;
mod invariants;

impl Downloader {
    fn spawn_for_test(
        dialer: dialer::TestingDialer,
        getter: getter::TestingGetter,
        concurrency_limits: ConcurrencyLimits,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(super::SERVICE_CHANNEL_CAPACITY);

        iroh_bytes::util::runtime::Handle::from_current(1)
            .unwrap()
            .local_pool()
            .spawn_pinned(move || async move {
                // we want to see the logs of the service
                let _guard = iroh_test::logging::setup();

                let mut service = Service::new(getter, dialer, concurrency_limits, msg_rx);
                service.run().await
            });

        Downloader { next_id: 0, msg_tx }
    }
}

/// Tests that receiving a download request and performing it doesn't explode.
#[tokio::test]
async fn smoke_test() {
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
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
}

/// Tests that two intents produce a single request, and that the requesst is cancelled only when
/// all intents are cancelled.
#[tokio::test]
async fn deduplication() {
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure the intents are received before completion
    getter.set_request_duration(Duration::from_secs(1));
    let concurrency_limits = ConcurrencyLimits::default();

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    let peer = SecretKey::generate().public();
    let kind = DownloadKind::Blob {
        hash: Hash::new([0u8; 32]),
    };
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let h = downloader.queue(kind.clone(), vec![peer]).await;
        handles.push(h);
    }
    assert!(
        futures::future::join_all(handles)
            .await
            .into_iter()
            .all(|r| r.is_ok()),
        "all downloads should succeed"
    );
    // verify that the request was sent just once
    getter.assert_history(&[(kind, peer)]);
}

/// Tests that two intents produce a single request, and that the requesst is cancelled only when
/// all intents are cancelled.
#[tokio::test]
async fn cancellation() {
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure cancellations are received on time
    getter.set_request_duration(Duration::from_millis(500));
    let concurrency_limits = ConcurrencyLimits::default();

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    let peer = SecretKey::generate().public();
    let kind = DownloadKind::Blob {
        hash: Hash::new([0u8; 32]),
    };
    let handle_a = downloader.queue(kind.clone(), vec![peer]).await;
    let handle_b = downloader.queue(kind.clone(), vec![peer]).await;
    downloader.cancel(handle_a);

    // wait for the download result to be reported, a was cancelled but b should continue
    handle_b.await.expect("should report success");
    // verify that the request was sent just once
    getter.assert_history(&[(kind, peer)]);
}

/// Test that when the downloader receives a flood of requests, they are scheduled so that the
/// maximum number of concurrent requests is not exceed.
/// NOTE: This is internally tested by [`Service::check_invariants`].
#[tokio::test]
async fn max_concurrent_requests() {
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure concurreny limits are hit
    getter.set_request_duration(Duration::from_millis(500));
    // set the concurreny limit very low to ensure it's hit
    let concurrency_limits = ConcurrencyLimits {
        max_concurrent_requests: 2,
        ..Default::default()
    };

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send the downloads
    let peer = SecretKey::generate().public();
    let mut handles = Vec::with_capacity(5);
    let mut expected_history = Vec::with_capacity(5);
    for i in 0..5 {
        let kind = DownloadKind::Blob {
            hash: Hash::new([i; 32]),
        };
        let h = downloader.queue(kind.clone(), vec![peer]).await;
        expected_history.push((kind, peer));
        handles.push(h);
    }

    assert!(
        futures::future::join_all(handles)
            .await
            .into_iter()
            .all(|r| r.is_ok()),
        "all downloads should succeed"
    );

    // verify that the request was sent just once
    getter.assert_history(&expected_history);
}

/// Test that when the downloader receives a flood of requests, with only one peer to handle them,
/// the maximum number of requests per peer is still respected.
/// NOTE: This is internally tested by [`Service::check_invariants`].
#[tokio::test]
async fn max_concurrent_requests_per_peer() {
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure concurreny limits are hit
    getter.set_request_duration(Duration::from_millis(500));
    // set the concurreny limit very low to ensure it's hit
    let concurrency_limits = ConcurrencyLimits {
        max_concurrent_requests_per_peer: 1,
        max_concurrent_requests: 10000, // all requests can be performed at the same time
        ..Default::default()
    };

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send the downloads
    let peer = SecretKey::generate().public();
    let mut handles = Vec::with_capacity(5);
    for i in 0..5 {
        let kind = DownloadKind::Blob {
            hash: Hash::new([i; 32]),
        };
        let h = downloader.queue(kind.clone(), vec![peer]).await;
        handles.push(h);
    }

    // only the first
    // let expected_history = [(
    //     DownloadKind::Blob {
    //         hash: Hash::new([0; 32]),
    //     },
    //     peer,
    // )];
    //
    // assert!(
    futures::future::join_all(handles).await;
    //         .into_iter()
    //         .all(|r| r.is_ok()),
    //     "all downloads should succeed"
    // );
    //
    // verify that the request was sent just once
    // getter.assert_history(&expected_history);
}
