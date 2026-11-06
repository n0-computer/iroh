use std::time::Duration;

use n0_future::{FuturesUnorderedBounded, StreamExt, future::now_or_never};

use super::{
    HANDSHAKE_FALLBACK_DELAY, MAX_DATAGRAM_SEND_TASKS, OwnedTransmit, RemoteStateActor, Source,
    State, TransportsSender, transports,
};
use crate::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::presets,
    test_utils::test_transport::{TestNetwork, to_custom_addr},
};

const ALPN: &[u8] = b"restart-handshake-test";

#[tokio::test]
async fn new_handshake_reaches_restarted_peer_with_old_connection_open() {
    restarted_peer(false).await;
}

#[tokio::test]
async fn new_handshake_looks_up_restarted_peer_with_old_connection_open() {
    restarted_peer(true).await;
}

#[derive(Debug)]
struct RestartLookup(EndpointAddr);

impl crate::address_lookup::AddressLookup for RestartLookup {
    fn resolve(
        &self,
        endpoint_id: crate::EndpointId,
    ) -> Option<
        n0_future::boxed::BoxStream<
            Result<crate::address_lookup::Item, crate::address_lookup::Error>,
        >,
    > {
        assert_eq!(endpoint_id, self.0.id);
        let addr = self.0.clone();
        Some(Box::pin(n0_future::stream::once_future(async move {
            // The lookup completes after fallback starts, independently of QUIC retransmission.
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(crate::address_lookup::Item::new(
                addr.into(),
                "restart-test",
                None,
            ))
        })))
    }
}

async fn restarted_peer(use_lookup: bool) {
    let network = TestNetwork::new();
    let host_key = SecretKey::generate();
    let old_route = SecretKey::generate().public();
    let new_route = SecretKey::generate().public();
    let client_route = SecretKey::generate().public();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let host_thread = {
        let network = network.clone();
        let key = host_key.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let endpoint = runtime.block_on(async move {
                let endpoint = Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .clear_ip_transports()
                    .add_custom_transport(network.create_transport(old_route).unwrap())
                    .alpns(vec![ALPN.to_vec()])
                    .bind()
                    .await
                    .unwrap();
                ready_tx.send(()).unwrap();
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                stop_rx.await.unwrap();
                // Keep the endpoint and connection alive until their runtime is stopped,
                // so the peer disappears without sending CONNECTION_CLOSE.
                (endpoint, connection)
            });
            runtime.shutdown_background();
            drop(endpoint);
        })
    };
    ready_rx.await.unwrap();
    let client = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .add_custom_transport(network.create_transport(client_route).unwrap())
        .bind()
        .await
        .unwrap();
    let addr = |route| {
        EndpointAddr::new(host_key.public())
            .with_addrs([TransportAddr::Custom(to_custom_addr(route))])
    };
    let old_connection = client.connect(addr(old_route), ALPN).await.unwrap();
    stop_tx.send(()).unwrap();
    tokio::task::spawn_blocking(move || host_thread.join().unwrap())
        .await
        .unwrap();
    assert!(old_connection.close_reason().is_none());

    let host = Endpoint::builder(presets::Minimal)
        .secret_key(host_key.clone())
        .clear_ip_transports()
        .add_custom_transport(network.create_transport(new_route).unwrap())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .unwrap();
    let next_addr = if use_lookup {
        client
            .address_lookup()
            .unwrap()
            .add(RestartLookup(addr(new_route)));
        // Only discovery knows the new route; a selected path must not suppress it.
        addr(old_route)
    } else {
        addr(new_route)
    };
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(client.connect(next_addr, ALPN), async {
            host.accept().await.unwrap().await
        })
    })
    .await;
    assert!(old_connection.close_reason().is_none());
    let (outgoing, incoming) = result.expect("new handshake stayed on the old selected path");
    let outgoing = outgoing.unwrap();
    let incoming = incoming.unwrap();
    assert_eq!(outgoing.remote_id(), host.id());
    assert_eq!(incoming.remote_id(), client.id());
    tokio::join!(client.close(), host.close());
}

fn selected_state() -> State {
    let mut state = RemoteStateActor::new(
        SecretKey::generate().public(),
        n0_watcher::Watchable::new(Default::default()).watch(),
        Default::default(),
        Default::default(),
        Default::default(),
        std::sync::Arc::new(
            crate::socket::biased_rtt_path_selector::BiasedRttPathSelector::default(),
        ),
    )
    .state;
    let selected = transports::Addr::Relay(
        "https://selected.invalid".parse().unwrap(),
        state.endpoint_id,
    );
    let other =
        transports::Addr::Relay("https://other.invalid".parse().unwrap(), state.endpoint_id);
    state
        .paths
        .insert_multiple([selected.clone(), other].into_iter(), Source::App);
    state.selected_path = Some(transports::FourTuple::from_remote(selected));
    state
}

fn initial() -> OwnedTransmit {
    OwnedTransmit {
        ecn: None,
        contents: bytes::Bytes::from_static(b"initial"),
        segment_size: None,
    }
}

#[tokio::test(start_paused = true)]
async fn selected_path_gets_a_head_start_without_duplicate_fallback_sends() {
    let mut state = selected_state();
    let attempt = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    let (_, finished) = state
        .mapped_addrs
        .endpoint_addrs
        .lookup(&attempt.addr)
        .unwrap();
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    let mut sends = FuturesUnorderedBounded::new(MAX_DATAGRAM_SEND_TASKS);
    state.handle_msg_send_datagram(
        attempt.addr,
        finished,
        Box::new(sender),
        initial(),
        &mut sends,
    );

    assert!(now_or_never(sends.next()).is_none());
    assert_eq!(now_or_never(receiver.next()), Some(Some(())));
    assert_eq!(now_or_never(receiver.next()), None);
    assert!(state.address_lookup_stream.is_none());
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY - Duration::from_millis(1)).await;
    assert!(now_or_never(sends.next()).is_none());
    assert_eq!(now_or_never(receiver.next()), None);
    tokio::time::advance(Duration::from_millis(1)).await;
    let event = state.handshake_events.next().await.unwrap();
    state.handle_handshake_event(event);
    assert!(state.address_lookup_stream.is_some());
    sends.next().await;
    assert_eq!(now_or_never(receiver.next()), Some(Some(())));
    // The selected path was also in `paths`; it must not receive another copy.
    assert_ne!(now_or_never(receiver.next()), Some(Some(())));
}

#[tokio::test(start_paused = true)]
async fn completing_a_fast_handshake_cancels_its_fallback_and_lookup() {
    let mut state = selected_state();
    let attempt = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    let (_, finished) = state
        .mapped_addrs
        .endpoint_addrs
        .lookup(&attempt.addr)
        .unwrap();
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    let mut sends = FuturesUnorderedBounded::new(MAX_DATAGRAM_SEND_TASKS);
    state.handle_msg_send_datagram(
        attempt.addr,
        finished.clone(),
        Box::new(sender),
        initial(),
        &mut sends,
    );
    assert!(now_or_never(sends.next()).is_none());
    assert_eq!(now_or_never(receiver.next()), Some(Some(())));
    let id = attempt.addr;
    drop(attempt);
    assert!(finished.is_cancelled());
    assert!(state.mapped_addrs.endpoint_addrs.lookup(&id).is_none());
    let event = state.handshake_events.next().await.unwrap();
    state.handle_handshake_event(event);
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY).await;
    sends.next().await;
    assert_ne!(now_or_never(receiver.next()), Some(Some(())));
    assert!(state.handshakes.is_empty());
    assert!(state.address_lookup_stream.is_none());
}

#[tokio::test(start_paused = true)]
async fn completing_one_handshake_does_not_cancel_another_handshakes_lookup() {
    let mut state = selected_state();
    let first = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    let second = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    assert_ne!(first.addr, second.addr);
    let mut sends = FuturesUnorderedBounded::new(MAX_DATAGRAM_SEND_TASKS);
    let (sender, _receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    for attempt in [&first, &second] {
        let (_, finished) = state
            .mapped_addrs
            .endpoint_addrs
            .lookup(&attempt.addr)
            .unwrap();
        state.handle_msg_send_datagram(
            attempt.addr,
            finished,
            Box::new(sender.clone()),
            initial(),
            &mut sends,
        );
    }
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY).await;
    for _ in 0..2 {
        let event = state.handshake_events.next().await.unwrap();
        state.handle_handshake_event(event);
    }
    assert!(state.address_lookup_stream.is_some());
    drop(first);
    let event = state.handshake_events.next().await.unwrap();
    state.handle_handshake_event(event);
    assert!(state.address_lookup_stream.is_some());
    assert_eq!(state.handshakes.len(), 1);
    drop(second);
    let event = state.handshake_events.next().await.unwrap();
    state.handle_handshake_event(event);
    assert!(state.handshakes.is_empty());
    assert!(state.address_lookup_stream.is_none());
}

#[tokio::test]
async fn attempt_tracking_preserves_zero_rtt_with_another_connection_open() {
    use crate::endpoint::{ConnectOptions, ZeroRttStatus};

    tokio::time::timeout(Duration::from_secs(5), async {
        let network = TestNetwork::new();
        let host_route = SecretKey::generate().public();
        let client_route = SecretKey::generate().public();
        let host = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .add_custom_transport(network.create_transport(host_route).unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .add_custom_transport(network.create_transport(client_route).unwrap())
            .bind()
            .await
            .unwrap();
        let address = EndpointAddr::new(host.id())
            .with_addrs([TransportAddr::Custom(to_custom_addr(host_route))]);
        let server = tokio::spawn({
            let host = host.clone();
            async move {
                let mut held = Vec::new();
                for _ in 0..2 {
                    let connection = host.accept().await.unwrap().accept().unwrap().into_0rtt();
                    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                    let bytes = recv.read_to_end(16).await.unwrap();
                    send.write_all(&bytes).await.unwrap();
                    send.finish().unwrap();
                    held.push(connection);
                }
                held
            }
        });
        // A first connection cannot resume, and must retain its attempt on the error branch.
        let first = client
            .connect_with_opts(address.clone(), ALPN, ConnectOptions::new())
            .await
            .unwrap()
            .into_0rtt()
            .expect_err("no session ticket yet")
            .await
            .unwrap();
        let (mut send, mut recv) = first.open_bi().await.unwrap();
        send.write_all(b"first").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(16).await.unwrap(), b"first");

        let second = client
            .connect_with_opts(address, ALPN, ConnectOptions::new())
            .await
            .unwrap()
            .into_0rtt()
            .expect("resume while the first connection is still open");
        let (mut send, mut recv) = second.open_bi().await.unwrap();
        send.write_all(b"second").await.unwrap();
        send.finish().unwrap();
        assert!(matches!(
            second.handshake_completed().await.unwrap(),
            ZeroRttStatus::Accepted(_)
        ));
        assert_eq!(recv.read_to_end(16).await.unwrap(), b"second");
        assert!(first.close_reason().is_none());
        let _held = server.await.unwrap();
        tokio::join!(client.close(), host.close());
    })
    .await
    .expect("0-RTT handshake or echo stalled");
}
