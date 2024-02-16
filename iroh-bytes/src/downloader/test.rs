#![cfg(test)]
use std::time::Duration;

use crate::Hash;
use iroh_net::key::SecretKey;

use super::*;

mod dialer;
mod getter;

impl Downloader {
    fn spawn_for_test(
        dialer: dialer::TestingDialer,
        getter: getter::TestingGetter,
        concurrency_limits: ConcurrencyLimits,
    ) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(super::SERVICE_CHANNEL_CAPACITY);

        LocalPoolHandle::new(1).spawn_pinned(move || async move {
            // we want to see the logs of the service
            let _guard = iroh_test::logging::setup();

            let service = Service::new(getter, dialer, concurrency_limits, msg_rx);
            service.run().await
        });

        Downloader {
            next_id: Arc::new(AtomicU64::new(0)),
            msg_tx,
        }
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
    let resource = HashAndFormat::raw(Hash::new([0u8; 32]));
    let handle = downloader
        .queue(resource, ResourceHints::with_node(peer), None)
        .await;
    // wait for the download result to be reported
    handle.await.expect("should report success");
    // verify that the peer was dialed
    dialer.assert_history(&[peer]);
    // verify that the request was sent
    getter.assert_history(&[(resource, peer)]);
}

/// Tests that multiple intents produce a single request.
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
    let resource = HashAndFormat::raw(Hash::new([0u8; 32]));
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let h = downloader
            .queue(resource, ResourceHints::with_node(peer), None)
            .await;
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
    getter.assert_history(&[(resource, peer)]);
}

/// Tests that the request is cancelled only when all intents are cancelled.
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
    let res_1 = HashAndFormat::raw(Hash::new([0u8; 32]));
    let handle_a = downloader
        .queue(res_1, ResourceHints::with_node(peer), None)
        .await;
    let handle_b = downloader
        .queue(res_1, ResourceHints::with_node(peer), None)
        .await;
    downloader.cancel(handle_a).await;

    // create a request with two intents and cancel them both
    let kind_2 = HashAndFormat::raw(Hash::new([1u8; 32]));
    let handle_c = downloader
        .queue(kind_2, ResourceHints::with_node(peer), None)
        .await;
    let handle_d = downloader
        .queue(kind_2, ResourceHints::with_node(peer), None)
        .await;
    downloader.cancel(handle_c).await;
    downloader.cancel(handle_d).await;

    // wait for the download result to be reported, a was cancelled but b should continue
    handle_b.await.expect("should report success");
    // verify that the request was sent just once, and that the second request was never sent
    getter.assert_history(&[(res_1, peer)]);
}

/// Test that when the downloader receives a flood of requests, they are scheduled so that the
/// maximum number of concurrent requests is not exceed.
/// NOTE: This is internally tested by [`Service::check_invariants`].
#[tokio::test]
async fn max_concurrent_requests_total() {
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
        let kind = HashAndFormat::raw(Hash::new([i; 32]));
        let h = downloader
            .queue(kind, ResourceHints::with_node(peer), None)
            .await;
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
        max_concurrent_requests_per_node: 1,
        max_concurrent_requests: 10000, // all requests can be performed at the same time
        ..Default::default()
    };

    let mut downloader =
        Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send the downloads
    let peer = SecretKey::generate().public();
    let mut handles = Vec::with_capacity(5);
    for i in 0..5 {
        let kind = HashAndFormat::raw(Hash::new([i; 32]));
        let h = downloader
            .queue(kind, ResourceHints::with_node(peer), None)
            .await;
        handles.push(h);
    }

    futures::future::join_all(handles).await;
}
