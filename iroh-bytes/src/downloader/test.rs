#![cfg(test)]
use anyhow::anyhow;
use futures::FutureExt;
use std::time::Duration;

use iroh_net::key::SecretKey;

use crate::{
    get::{db::BlobId, progress::TransferState},
    util::progress::{FlumeProgressSender, IdGenerator, ProgressSender},
};

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
        let db = crate::store::mem::Store::default();

        LocalPoolHandle::new(1).spawn_pinned(move || async move {
            // we want to see the logs of the service
            let _guard = iroh_test::logging::setup();

            let service = Service::new(db, getter, dialer, concurrency_limits, msg_rx);
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
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    let concurrency_limits = ConcurrencyLimits::default();

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send a request and make sure the peer is requested the corresponding download
    let peer = SecretKey::generate().public();
    let kind: DownloadKind = HashAndFormat::raw(Hash::new([0u8; 32])).into();
    let req = DownloadRequest::new(kind, vec![peer]);
    let handle = downloader.queue(req).await;
    // wait for the download result to be reported
    handle.await.expect("should report success");
    // verify that the peer was dialed
    dialer.assert_history(&[peer]);
    // verify that the request was sent
    getter.assert_history(&[(kind, peer)]);
}

/// Tests that multiple intents produce a single request.
#[tokio::test]
async fn deduplication() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure the intents are received before completion
    getter.set_request_duration(Duration::from_secs(1));
    let concurrency_limits = ConcurrencyLimits::default();

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    let peer = SecretKey::generate().public();
    let kind: DownloadKind = HashAndFormat::raw(Hash::new([0u8; 32])).into();
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let req = DownloadRequest::new(kind, vec![peer]);
        let h = downloader.queue(req).await;
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

/// Tests that the request is cancelled only when all intents are cancelled.
#[tokio::test]
async fn cancellation() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure cancellations are received on time
    getter.set_request_duration(Duration::from_millis(500));
    let concurrency_limits = ConcurrencyLimits::default();

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    let peer = SecretKey::generate().public();
    let kind_1: DownloadKind = HashAndFormat::raw(Hash::new([0u8; 32])).into();
    let req = DownloadRequest::new(kind_1, vec![peer]);
    let handle_a = downloader.queue(req.clone()).await;
    let handle_b = downloader.queue(req).await;
    downloader.cancel(handle_a).await;

    // create a request with two intents and cancel them both
    let kind_2 = HashAndFormat::raw(Hash::new([1u8; 32]));
    let req = DownloadRequest::new(kind_2, vec![peer]);
    let handle_c = downloader.queue(req.clone()).await;
    let handle_d = downloader.queue(req).await;
    downloader.cancel(handle_c).await;
    downloader.cancel(handle_d).await;

    // wait for the download result to be reported, a was cancelled but b should continue
    handle_b.await.expect("should report success");
    // verify that the request was sent just once, and that the second request was never sent
    getter.assert_history(&[(kind_1, peer)]);
}

/// Test that when the downloader receives a flood of requests, they are scheduled so that the
/// maximum number of concurrent requests is not exceed.
/// NOTE: This is internally tested by [`Service::check_invariants`].
#[tokio::test]
async fn max_concurrent_requests_total() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    // make request take some time to ensure concurreny limits are hit
    getter.set_request_duration(Duration::from_millis(500));
    // set the concurreny limit very low to ensure it's hit
    let concurrency_limits = ConcurrencyLimits {
        max_concurrent_requests: 2,
        ..Default::default()
    };

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send the downloads
    let peer = SecretKey::generate().public();
    let mut handles = Vec::with_capacity(5);
    let mut expected_history = Vec::with_capacity(5);
    for i in 0..5 {
        let kind: DownloadKind = HashAndFormat::raw(Hash::new([i; 32])).into();
        let req = DownloadRequest::new(kind, vec![peer]);
        let h = downloader.queue(req).await;
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
    let _guard = iroh_test::logging::setup();
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

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);

    // send the downloads
    let peer = SecretKey::generate().public();
    let mut handles = Vec::with_capacity(5);
    for i in 0..5 {
        let kind = HashAndFormat::raw(Hash::new([i; 32]));
        let req = DownloadRequest::new(kind, vec![peer]);
        let h = downloader.queue(req).await;
        handles.push(h);
    }

    futures::future::join_all(handles).await;
}

/// Tests concurrent progress reporting for multiple intents.
///
/// This first registers two intents for a download, and then proceeds until the `Found` event is
/// emitted, and verifies that both intents received the event.
/// It then registers a third intent mid-download, and makes sure it receives a correct ìnitial
/// state. The download then finishes, and we make sure that all events are emitted properly, and
/// the progress state of the handles converges.
#[tokio::test]
async fn concurrent_progress() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();

    let (start_tx, start_rx) = oneshot::channel();
    let start_rx = start_rx.shared();

    let (done_tx, done_rx) = oneshot::channel();
    let done_rx = done_rx.shared();

    getter.set_handler(Arc::new(move |hash, _peer, progress, _duration| {
        let start_rx = start_rx.clone();
        let done_rx = done_rx.clone();
        async move {
            let hash = hash.hash();
            start_rx.await.unwrap();
            let id = progress.new_id();
            progress
                .send(DownloadProgress::Found {
                    id,
                    child: BlobId::Root,
                    hash,
                    size: 100,
                })
                .await
                .unwrap();
            done_rx.await.unwrap();
            progress.send(DownloadProgress::Done { id }).await.unwrap();
            Ok(Stats::default())
        }
        .boxed()
    }));
    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), Default::default());

    let peer = SecretKey::generate().public();
    let hash = Hash::new([0u8; 32]);
    let kind_1 = HashAndFormat::raw(hash);

    let (prog_a_tx, prog_a_rx) = flume::bounded(64);
    let prog_a_tx = FlumeProgressSender::new(prog_a_tx);
    let req = DownloadRequest::new(kind_1, vec![peer]).progress_sender(prog_a_tx);
    let handle_a = downloader.queue(req).await;

    let (prog_b_tx, prog_b_rx) = flume::bounded(64);
    let prog_b_tx = FlumeProgressSender::new(prog_b_tx);
    let req = DownloadRequest::new(kind_1, vec![peer]).progress_sender(prog_b_tx);
    let handle_b = downloader.queue(req).await;

    start_tx.send(()).unwrap();

    let mut state_a = TransferState::new(hash);
    let mut state_b = TransferState::new(hash);
    let mut state_c = TransferState::new(hash);

    let prog1_a = prog_a_rx.recv_async().await.unwrap();
    let prog1_b = prog_b_rx.recv_async().await.unwrap();
    assert!(matches!(prog1_a, DownloadProgress::Found { hash, size: 100, ..} if hash == hash));
    assert!(matches!(prog1_b, DownloadProgress::Found { hash, size: 100, ..} if hash == hash));

    state_a.on_progress(prog1_a);
    state_b.on_progress(prog1_b);
    assert_eq!(state_a, state_b);

    let (prog_c_tx, prog_c_rx) = flume::bounded(64);
    let prog_c_tx = FlumeProgressSender::new(prog_c_tx);
    let req = DownloadRequest::new(kind_1, vec![peer]).progress_sender(prog_c_tx);
    let handle_c = downloader.queue(req).await;

    let prog1_c = prog_c_rx.recv_async().await.unwrap();
    assert!(matches!(&prog1_c, DownloadProgress::InitialState(state) if state == &state_a));
    state_c.on_progress(prog1_c);

    done_tx.send(()).unwrap();

    let (res_a, res_b, res_c) = futures::future::join3(handle_a, handle_b, handle_c).await;
    res_a.unwrap();
    res_b.unwrap();
    res_c.unwrap();

    let prog_a: Vec<_> = prog_a_rx.into_stream().collect().await;
    let prog_b: Vec<_> = prog_b_rx.into_stream().collect().await;
    let prog_c: Vec<_> = prog_c_rx.into_stream().collect().await;

    assert_eq!(prog_a.len(), 1);
    assert_eq!(prog_b.len(), 1);
    assert_eq!(prog_c.len(), 1);

    assert!(matches!(prog_a[0], DownloadProgress::Done { .. }));
    assert!(matches!(prog_b[0], DownloadProgress::Done { .. }));
    assert!(matches!(prog_c[0], DownloadProgress::Done { .. }));

    for p in prog_a {
        state_a.on_progress(p);
    }
    for p in prog_b {
        state_b.on_progress(p);
    }
    for p in prog_c {
        state_c.on_progress(p);
    }
    assert_eq!(state_a, state_b);
    assert_eq!(state_a, state_c);
}

#[tokio::test]
async fn long_queue() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    let concurrency_limits = ConcurrencyLimits {
        max_open_connections: 2,
        max_concurrent_requests_per_node: 2,
        max_concurrent_requests: 4, // all requests can be performed at the same time
        ..Default::default()
    };

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);
    // send the downloads
    let nodes = [
        SecretKey::generate().public(),
        SecretKey::generate().public(),
        SecretKey::generate().public(),
    ];
    let mut handles = vec![];
    for i in 0..100usize {
        let kind = HashAndFormat::raw(Hash::new(i.to_be_bytes()));
        let peer = nodes[i % 3];
        let req = DownloadRequest::new(kind, vec![peer]);
        let h = downloader.queue(req).await;
        handles.push(h);
    }

    let res = futures::future::join_all(handles).await;
    for res in res {
        res.expect("all downloads to succeed");
    }
}

#[tokio::test]
async fn fail_while_running() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), Default::default());

    let blob_fail = HashAndFormat::raw(Hash::new([1u8; 32]));
    let blob_success = HashAndFormat::raw(Hash::new([2u8; 32]));

    getter.set_handler(Arc::new(move |kind, _node, _progress_sender, _duration| {
        async move {
            if kind == blob_fail.into() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Err(FailureAction::DropPeer(anyhow!("bad!")))
            } else if kind == blob_success.into() {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(Default::default())
            } else {
                unreachable!("invalid blob")
            }
        }
        .boxed()
    }));

    let node = SecretKey::generate().public();
    let req_success = DownloadRequest::new(blob_success, vec![node]);
    let req_fail = DownloadRequest::new(blob_fail, vec![node]);
    let handle_success = downloader.queue(req_success).await;
    let handle_fail = downloader.queue(req_fail).await;

    let res_fail = handle_fail.await;
    let res_success = handle_success.await;

    assert!(res_fail.is_err());
    assert!(res_success.is_ok());
}

#[tokio::test]
async fn retry_nodes() {
    let _guard = iroh_test::logging::setup();
    let dialer = dialer::TestingDialer::default();
    let getter = getter::TestingGetter::default();
    let concurrency_limits = ConcurrencyLimits {
        max_open_connections: 2,
        max_concurrent_requests_per_node: 2,
        max_concurrent_requests: 4, // all requests can be performed at the same time
        ..Default::default()
    };

    let downloader = Downloader::spawn_for_test(dialer.clone(), getter.clone(), concurrency_limits);
    // send the downloads
    let good_nodes = [
        SecretKey::generate().public(),
        SecretKey::generate().public(),
    ];
    let bad_nodes = [
        SecretKey::generate().public(),
        SecretKey::generate().public(),
    ];

    dialer.set_dial_outcome(move |node| good_nodes.contains(&node));
    let kind1 = HashAndFormat::raw(Hash::new([0u8; 32]));
    let kind2 = HashAndFormat::raw(Hash::new([2u8; 32]));

    let req1 = DownloadRequest::new(kind1, vec![bad_nodes[0], bad_nodes[1]]);
    let h1 = downloader.queue(req1).await;

    let req2 = DownloadRequest::new(kind2, vec![bad_nodes[1], good_nodes[0]]);
    let h2 = downloader.queue(req2).await;

    // wait for req2 to complete - this tests that the "queue is jumped" and we are not
    // waiting for req1 to elapse all retries
    assert!(h2.await.is_ok());

    // now we make download2 succeed!
    dialer.set_dial_outcome(move |_node| true);

    assert!(h1.await.is_ok());
}
