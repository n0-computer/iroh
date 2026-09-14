// Local regression tests for iroh-proxy's relay recovery patch.
mod relay_recovery {
    use super::super::{
        ACTOR_REQUEST_TIMEOUT, ActiveRelayHandle, CLOSE_TIMEOUT, Config, HomeRelayWatch,
        RelayActor, RelayConnectionState, close_relay_sink,
    };
    use super::*;
    use n0_future::Sink;
    use std::{
        pin::Pin,
        task::{Context, Poll},
    };

    #[derive(Default)]
    struct PendingClose;

    impl Sink<iroh_relay::protos::relay::ClientToRelayMsg> for PendingClose {
        type Error = std::io::Error;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn start_send(
            self: Pin<&mut Self>,
            _: iroh_relay::protos::relay::ClientToRelayMsg,
        ) -> std::io::Result<()> {
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn relay_close_is_bounded_and_cancellable() {
        let started = tokio::time::Instant::now();
        close_relay_sink(&mut PendingClose, &CancellationToken::new()).await;
        assert_eq!(started.elapsed(), CLOSE_TIMEOUT);

        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            cancel.cancel();
        });
        let started = tokio::time::Instant::now();
        close_relay_sink(&mut PendingClose, &stop).await;
        assert_eq!(started.elapsed(), Duration::from_millis(10));
        task.await.unwrap();
    }

    fn manager(url: &RelayUrl) -> RelayActor {
        let (recv_tx, _recv_rx) = mpsc::channel(16);
        let my_relay = HomeRelayWatch::default();
        my_relay.set(url.clone(), RelayConnectionState::Connecting);
        RelayActor::new(
            Config {
                my_relay,
                secret_key: SecretKey::from_bytes(&[42; 32]),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                ipv6_reported: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .unwrap(),
                metrics: Default::default(),
                relay_map: iroh_relay::RelayMap::empty(),
            },
            recv_tx,
            CancellationToken::new(),
        )
    }

    // Keep every receiver alive, but never consume a message. Aborting this
    // task must drop the receivers before the home relay is recreated.
    fn stalled_actor(
        manager: &mut RelayActor,
        url: &RelayUrl,
        full_control: bool,
    ) -> ActiveRelayHandle {
        let (inbox_addr, inbox) = mpsc::channel(1);
        if full_control {
            inbox_addr
                .try_send(ActiveRelayMessage::SetHomeRelay(true))
                .unwrap();
        }
        let (prio_inbox_addr, prio) = mpsc::channel(1);
        let (datagrams_send_queue, datagrams) = mpsc::channel(1);
        let task = manager.active_relay_tasks.spawn(async move {
            let _receivers = (inbox, prio, datagrams);
            std::future::pending::<()>().await;
        });
        let handle = ActiveRelayHandle {
            task,
            inbox_addr,
            prio_inbox_addr,
            datagrams_send_queue,
        };
        manager.active_relays.insert(url.clone(), handle.clone());
        handle
    }

    #[tokio::test(start_paused = true)]
    async fn full_control_queue_retires_actor_and_shutdown_completes() {
        let url = "https://127.0.0.1:1".parse().unwrap();
        let mut manager = manager(&url);
        let old = stalled_actor(&mut manager, &url, true);
        let started = tokio::time::Instant::now();
        manager.set_home_relay(url.clone()).await;
        assert_eq!(started.elapsed(), ACTOR_REQUEST_TIMEOUT);
        // Shutdown can race with a retirement whose cancelled JoinError has
        // not yet been reaped. That expected cancellation must not panic.
        manager.close_all_active_relays().await;
        assert!(old.inbox_addr.is_closed());
        assert!(old.prio_inbox_addr.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_aborts_tasks_that_ignore_cancellation() {
        let url = "https://127.0.0.1:1".parse().unwrap();
        let mut manager = manager(&url);
        let old = stalled_actor(&mut manager, &url, false);
        let started = tokio::time::Instant::now();
        manager.close_all_active_relays().await;
        assert_eq!(started.elapsed(), ACTOR_REQUEST_TIMEOUT);
        assert!(old.task.is_finished());
        assert!(old.inbox_addr.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn route_timeout_covers_enqueue_as_well_as_reply() {
        let url = "https://127.0.0.1:1".parse().unwrap();
        let mut manager = manager(&url);
        let handle = stalled_actor(&mut manager, &url, false);
        let peer = SecretKey::from_bytes(&[43; 32]).public();
        let started = tokio::time::Instant::now();
        assert!(handle.has_endpoint_route(peer).await.is_err());
        assert_eq!(started.elapsed(), ACTOR_REQUEST_TIMEOUT);
        // The previous request is still queued: the second deadline expires
        // while enqueueing, before an answer can even be requested.
        let started = tokio::time::Instant::now();
        assert!(handle.has_endpoint_route(peer).await.is_err());
        assert_eq!(started.elapsed(), ACTOR_REQUEST_TIMEOUT);
        manager.retire_relay(&url);
        manager
            .active_relay_tasks
            .join_next()
            .await
            .unwrap()
            .unwrap_err();
    }

    #[tokio::test]
    async fn route_timeout_recreates_home_relay_and_delivers_datagrams() {
        let (_relay_map, url, _server) = test_utils::run_relay_server().await.unwrap();
        let (peer, _echo_task) = start_echo_endpoint(url.clone());
        let mut manager = manager(&url);
        let (recv_tx, mut recv_rx) = mpsc::channel(16);
        manager.relay_datagram_recv_queue = recv_tx;
        let old = stalled_actor(&mut manager, &url, false);
        let other_url = "https://127.0.0.1:1".parse().unwrap();

        // Freeze time only while waiting for the intentionally stuck task.
        tokio::time::pause();
        manager
            .active_relay_handle_for_endpoint(&other_url, &peer)
            .await;
        // The old actor was aborted. Await its completion before replacing it.
        while !old.task.is_finished() {
            if let Err(err) = manager.active_relay_tasks.join_next().await.unwrap() {
                assert!(err.is_cancelled(), "{err}");
            }
        }
        manager.reap_active_relays();
        tokio::time::resume();
        assert!(old.inbox_addr.is_closed());
        let fresh = manager.active_relays.get(&url).unwrap().clone();
        assert!(!fresh.inbox_addr.same_channel(&old.inbox_addr));
        assert_eq!(
            manager.config.secret_key.public(),
            SecretKey::from_bytes(&[42; 32]).public()
        );

        send_recv_echo(
            RelaySendItem {
                remote_endpoint: peer,
                url: url.clone(),
                datagrams: Datagrams::from(b"recovered"),
            },
            &fresh.datagrams_send_queue,
            &mut recv_rx,
        )
        .await
        .unwrap();
        assert!(manager.config.my_relay.get().unwrap().is_connected());
        tokio::time::timeout(Duration::from_secs(5), manager.close_all_active_relays())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn offline_backoff_answers_control_and_honors_cancellation() {
        let url = "https://127.0.0.1:1".parse().unwrap();
        let (recv_tx, _recv_rx) = mpsc::channel(16);
        let (_datagrams_tx, datagrams_rx) = mpsc::channel(16);
        let (inbox_tx, inbox_rx) = mpsc::channel(16);
        let (prio_tx, prio_rx) = mpsc::channel(16);
        let stop = CancellationToken::new();
        let mut actor = ActiveRelayActor::new(ActiveRelayActorOptions {
            url,
            prio_inbox_: prio_rx,
            inbox: inbox_rx,
            relay_datagrams_send: datagrams_rx,
            relay_datagrams_recv: recv_tx,
            connection_opts: RelayConnectionOptions {
                secret_key: SecretKey::from_bytes(&[44; 32]),
                dns_resolver: DnsResolver::new(),
                proxy_url: None,
                prefer_ipv6: Arc::new(AtomicBool::new(false)),
                tls_config: CaTlsConfig::insecure_skip_verify()
                    .client_config(default_provider())
                    .unwrap(),
                auth_token: None,
            },
            stop_token: stop.clone(),
            metrics: Default::default(),
            my_relay: Default::default(),
        });
        let task = tokio::spawn(async move { actor.sleep_backoff(Duration::from_secs(16)).await });
        inbox_tx
            .send(ActiveRelayMessage::SetHomeRelay(true))
            .await
            .unwrap();
        let (tx, rx) = oneshot::channel();
        prio_tx
            .send(ActiveRelayPrioMessage::HasEndpointRoute(
                SecretKey::from_bytes(&[45; 32]).public(),
                tx,
            ))
            .await
            .unwrap();
        assert!(!rx.await.unwrap());
        stop.cancel();
        assert!(!task.await.unwrap());
    }
}
