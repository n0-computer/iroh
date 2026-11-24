use std::{collections::BTreeSet, sync::Arc, time::Duration};

use n0_future::{StreamExt, boxed::BoxStream, future::now_or_never};
use tokio::sync::{mpsc, oneshot};

use super::{
    DATAGRAM_SEND_TIMEOUT, HANDSHAKE_FALLBACK_DELAY, MAX_DATAGRAM_SEND_TASKS, MAX_FLIGHT_PACKETS,
    OwnedTransmit, RemoteStateActor, SendTasks, Source, State, TransportsSender, transports,
};
use crate::{
    Endpoint, EndpointAddr, SecretKey,
    address_lookup::{AddressLookup, AddressLookupFailed, Error, Item, memory::MemoryLookup},
    endpoint::presets,
    socket::mapped_addrs::ConnectionAttempt,
};
#[cfg(feature = "unstable-custom-transports")]
use crate::{
    TransportAddr,
    test_utils::test_transport::{TestNetwork, to_custom_addr},
};

const ALPN: &[u8] = b"restart-handshake-test";

#[cfg(feature = "unstable-custom-transports")]
#[tokio::test]
async fn new_handshake_reaches_restarted_peer_with_old_connection_open() {
    restarted_peer(false).await;
}

#[cfg(feature = "unstable-custom-transports")]
#[tokio::test]
async fn new_handshake_looks_up_restarted_peer_with_old_connection_open() {
    restarted_peer(true).await;
}

#[cfg(feature = "unstable-custom-transports")]
#[derive(Debug)]
struct RestartLookup(EndpointAddr);

#[cfg(feature = "unstable-custom-transports")]
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

#[cfg(feature = "unstable-custom-transports")]
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

fn actor() -> RemoteStateActor {
    RemoteStateActor::new(
        SecretKey::generate().public(),
        n0_watcher::Watchable::new(Default::default()).watch(),
        Default::default(),
        Default::default(),
        Default::default(),
        Arc::new(crate::socket::biased_rtt_path_selector::BiasedRttPathSelector::default()),
    )
}

fn relay(state: &State, name: &str) -> transports::Addr {
    transports::Addr::Relay(
        format!("https://{name}.invalid").parse().unwrap(),
        state.endpoint_id,
    )
}

fn selected_state() -> State {
    let mut state = actor().state;
    let selected = relay(&state, "selected");
    let other = relay(&state, "other");
    state
        .paths
        .insert_multiple([selected.clone(), other].into_iter(), Source::App);
    state.selected_path = Some(transports::FourTuple::from_remote(selected));
    state
}

fn resolve(
    state: &mut State,
) -> (
    ConnectionAttempt,
    oneshot::Receiver<Result<(), AddressLookupFailed>>,
) {
    let attempt = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    let (tx, rx) = oneshot::channel();
    state.handle_msg_resolve_remote(BTreeSet::new(), attempt.addr, attempt.finished.clone(), tx);
    (attempt, rx)
}

fn begin(state: &mut State) -> ConnectionAttempt {
    let (attempt, mut rx) = resolve(state);
    rx.try_recv().expect("known path").unwrap();
    attempt
}

fn send(
    state: &mut State,
    attempt: &ConnectionAttempt,
    sender: &TransportsSender,
    contents: &[u8],
    sends: &mut SendTasks,
) {
    state.handle_msg_send_datagram(
        attempt.addr,
        attempt.finished.clone(),
        Box::new(sender.clone()),
        OwnedTransmit {
            ecn: Some(noq_udp::EcnCodepoint::Ect0),
            contents: bytes::Bytes::copy_from_slice(contents),
            segment_size: Some(4),
        },
        sends,
    );
}

async fn next_event(state: &mut State, sends: &mut SendTasks) {
    loop {
        if let Some(event) = state.handshake_events.next().await.unwrap() {
            state.handle_handshake_event(event, sends);
            return;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn selected_path_gets_a_head_start_without_duplicate_fallback_sends() {
    let mut state = selected_state();
    let attempt = begin(&mut state);
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY * 2).await;
    assert!(now_or_never(state.handshake_events.next()).is_none());
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(64, std::iter::empty());
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    for i in 0..32 {
        send(&mut state, &attempt, &sender, &[i; 8], &mut sends);
        // Ready I/O frees its slot immediately, including after more than 16 datagrams.
        assert_eq!(now_or_never(sends.next()), Some(Some(())));
        let (url, packet) = receiver.next().await.unwrap();
        assert_eq!(url.host_str(), Some("selected.invalid"));
        assert_eq!(packet.contents.as_ref(), &[i; 8]);
    }
    assert_eq!(
        state.handshake_events.len(),
        2,
        "one timer and one completion watcher"
    );
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY - Duration::from_millis(1)).await;
    assert!(now_or_never(state.handshake_events.next()).is_none());
    assert!(state.address_lookup_stream.is_none());
    let late = relay(&state, "new");
    state
        .paths
        .insert_multiple([late.clone()].into_iter(), Source::App);
    state.selected_path = Some(transports::FourTuple::from_remote(late));
    tokio::time::advance(Duration::from_millis(1)).await;
    next_event(&mut state, &mut sends).await;
    assert!(state.address_lookup_stream.is_some());
    while sends.next().await.is_some() {}
    let mut deliveries = Vec::new();
    while let Some(Some((url, packet))) = now_or_never(receiver.next()) {
        assert_eq!(packet.ecn, Some(noq_proto::EcnCodepoint::Ect0));
        assert_eq!(packet.segment_size.unwrap().get(), 4);
        deliveries.push((url.host_str().unwrap().to_owned(), packet.contents));
    }
    deliveries.sort();
    let expected: Vec<_> = ["new.invalid", "other.invalid"]
        .into_iter()
        .flat_map(|url| {
            (0..MAX_FLIGHT_PACKETS as u8)
                .map(move |i| (url.to_owned(), bytes::Bytes::from(vec![i; 8])))
        })
        .collect();
    assert_eq!(deliveries, expected);
}

#[tokio::test(start_paused = true)]
async fn blocked_preferred_sends_leave_room_for_fallback_io() {
    // Saturate the relay, then add a loopback UDP route during the head start.
    let direct = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut state = selected_state();
    let attempt = begin(&mut state);
    let (sender, _blocked) = TransportsSender::with_bounded_relay(
        1,
        [transports::IpConfig::V4 {
            ip_net: "127.0.0.1/8".parse().unwrap(),
            port: 0,
            is_required: true,
            is_default: true,
        }]
        .into_iter(),
    );
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    for i in 0..32 {
        send(&mut state, &attempt, &sender, &[i; 4], &mut sends);
        now_or_never(sends.next());
    }
    assert!(sends.len() < MAX_DATAGRAM_SEND_TASKS);
    let late = transports::Addr::Ip(direct.local_addr().unwrap());
    state.paths.insert_multiple([late].into_iter(), Source::App);
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY).await;
    next_event(&mut state, &mut sends).await;
    let mut buf = [0; 8];
    // The relay stays blocked throughout, including for fallback sends to the other relay.
    tokio::select! {
        _ = sends.next() => panic!("relay send should remain blocked"),
        received = direct.recv(&mut buf) => assert_eq!(received.unwrap(), 4),
    }
}

#[tokio::test(start_paused = true)]
async fn expired_flight_is_not_sent_at_fallback() {
    let mut state = selected_state();
    let attempt = begin(&mut state);
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(2, std::iter::empty());
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    send(&mut state, &attempt, &sender, b"initial", &mut sends);
    sends.next().await.unwrap();
    receiver.next().await.unwrap();
    tokio::time::advance(DATAGRAM_SEND_TIMEOUT).await;
    next_event(&mut state, &mut sends).await;
    assert!(sends.is_empty());
    assert!(now_or_never(receiver.next()).is_none());
}

#[tokio::test(start_paused = true)]
async fn completing_a_fast_handshake_cancels_its_fallback_and_lookup() {
    let mut state = selected_state();
    let attempt = begin(&mut state);
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    send(&mut state, &attempt, &sender, b"initial", &mut sends);
    sends.next().await.unwrap();
    receiver.next().await.unwrap();
    let id = attempt.addr;
    drop(attempt);
    assert!(state.mapped_addrs.endpoint_addrs.lookup(&id).is_none());
    while let Some(event) = state.handshake_events.next().await {
        if let Some(event) = event {
            state.handle_handshake_event(event, &mut sends);
        }
    }
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY).await;
    assert!(now_or_never(receiver.next()).is_none());
    assert!(sends.is_empty());
    assert!(state.handshakes.is_empty());
    assert!(state.address_lookup_stream.is_none());
}

#[tokio::test(start_paused = true)]
async fn completing_one_handshake_does_not_cancel_another_handshakes_lookup() {
    let mut state = selected_state();
    let (tx, mut rounds) = mpsc::unbounded_channel();
    state.address_lookup.add(PendingLookup(tx));
    let first = begin(&mut state);
    let second = begin(&mut state);
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    let (sender, _receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    for attempt in [&first, &second] {
        send(&mut state, attempt, &sender, b"initial", &mut sends);
    }
    tokio::time::advance(HANDSHAKE_FALLBACK_DELAY).await;
    next_event(&mut state, &mut sends).await;
    next_event(&mut state, &mut sends).await;
    assert!(state.address_lookup_stream.is_some());
    let mut provider = rounds.try_recv().unwrap();
    assert!(rounds.try_recv().is_err(), "attempts must share one lookup");
    drop(first);
    next_event(&mut state, &mut sends).await;
    assert_eq!(
        provider.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    assert!(state.address_lookup_stream.is_some());
    drop(second);
    next_event(&mut state, &mut sends).await;
    assert_eq!(
        provider.try_recv(),
        Err(oneshot::error::TryRecvError::Closed)
    );
    assert!(state.address_lookup_stream.is_none());
}

#[tokio::test(start_paused = true)]
async fn selected_path_vanished_before_first_send() {
    let mut state = selected_state();
    let attempt = begin(&mut state);
    state.selected_path = None;
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    let (sender, mut receiver) = TransportsSender::with_bounded_relay(8, std::iter::empty());
    send(&mut state, &attempt, &sender, b"initial", &mut sends);
    assert!(state.address_lookup_stream.is_some());
    assert_eq!(now_or_never(sends.next()), Some(Some(())));
    let mut routes = Vec::new();
    while let Some(Some((url, _))) = now_or_never(receiver.next()) {
        routes.push(url.host_str().unwrap().to_owned());
    }
    routes.sort();
    assert_eq!(routes, ["other.invalid", "selected.invalid"]);
}

#[tokio::test(start_paused = true)]
async fn resolved_and_unresolved_attempts_prevent_idle_until_dropped() {
    let mut actor = actor();
    let (_tx, inbox) = mpsc::channel(1);
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    let (attempt, rx) = resolve(&mut actor.state);
    assert!(!actor.is_idle(&inbox));
    assert!(actor.state.paths.has_pending_resolve_requests());
    assert!(actor.state.address_lookup_stream.is_some());
    drop(rx);
    drop(attempt);
    next_event(&mut actor.state, &mut sends).await;
    assert!(actor.is_idle(&inbox));
    assert!(actor.state.address_lookup_stream.is_none());

    actor.state = selected_state();
    let attempt = begin(&mut actor.state);
    tokio::time::advance(super::ACTOR_MAX_IDLE_TIMEOUT * 2).await;
    assert!(!actor.is_idle(&inbox));
    drop(attempt);
    next_event(&mut actor.state, &mut sends).await;
    assert!(actor.is_idle(&inbox));
}

#[derive(Debug)]
struct PendingLookup(mpsc::UnboundedSender<oneshot::Receiver<()>>);

impl AddressLookup for PendingLookup {
    fn resolve(&self, _: crate::EndpointId) -> Option<BoxStream<Result<Item, Error>>> {
        let (tx, rx) = oneshot::channel();
        self.0.send(rx).unwrap();
        Some(Box::pin(n0_future::stream::once_future(async move {
            let _tx = tx;
            std::future::pending().await
        })))
    }
}

#[tokio::test]
async fn cancelled_or_failed_endpoint_resolve_releases_attempt() {
    let client = Endpoint::bind(presets::Minimal).await.unwrap();
    let inner = client.inner().unwrap();
    let id = SecretKey::generate().public();
    let (tx, mut rounds) = mpsc::unbounded_channel();
    client.address_lookup().unwrap().add(PendingLookup(tx));
    let mut dial = Box::pin(client.connect(id, ALPN));
    let round = tokio::select! {
        round = rounds.recv() => round.unwrap(),
        _ = &mut dial => panic!("lookup should be pending"),
    };
    assert_eq!(inner.mapped_addrs.endpoint_addrs.active_addrs().len(), 1);
    drop(dial);
    assert!(inner.mapped_addrs.endpoint_addrs.active_addrs().is_empty());
    tokio::time::timeout(Duration::from_secs(1), round)
        .await
        .expect("provider still active")
        .unwrap_err();
    client.address_lookup().unwrap().clear();
    assert!(matches!(
        inner.resolve_remote(id.into()).await.unwrap(),
        Err(AddressLookupFailed::NoServiceConfigured { .. })
    ));
    assert!(inner.mapped_addrs.endpoint_addrs.active_addrs().is_empty());
    client.close().await;
}

#[tokio::test]
async fn resolve_cancelled_before_delivery_does_not_create_state() {
    let mut state = actor().state;
    let attempt = state.mapped_addrs.endpoint_addrs.insert(state.endpoint_id);
    let id = attempt.addr;
    let finished = attempt.finished.clone();
    drop(attempt);
    let (tx, rx) = oneshot::channel();
    state.handle_msg_resolve_remote(BTreeSet::new(), id, finished, tx);
    assert!(rx.await.is_err());
    assert!(state.handshake_events.is_empty());
    assert!(state.handshakes.is_empty());
    assert!(!state.paths.has_pending_resolve_requests());
    assert!(state.address_lookup_stream.is_none());
}

#[tokio::test(start_paused = true)]
async fn redial_restarts_lookup_with_a_permanently_pending_provider() {
    let mut state = actor().state;
    let (tx, mut rounds) = mpsc::unbounded_channel();
    state.address_lookup.add(PendingLookup(tx));
    let memory = MemoryLookup::new();
    state.address_lookup.add(memory.clone());
    let mut sends = SendTasks::new(MAX_DATAGRAM_SEND_TASKS);
    for (round, port) in [1234, 5678].into_iter().enumerate() {
        let ip = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        memory.set_endpoint_info(EndpointAddr::new(state.endpoint_id).with_ip_addr(ip));
        let (attempt, rx) = resolve(&mut state);
        let mut provider = rounds.try_recv().expect("fresh lookup round");
        let stream = state.address_lookup_stream.as_mut().unwrap();
        let item = stream.next().await;
        state.handle_address_lookup_item(item);
        rx.await.unwrap().unwrap();
        assert!(
            state
                .paths
                .addrs()
                .any(|addr| *addr == transports::Addr::Ip(ip))
        );
        assert!(now_or_never(state.address_lookup_stream.as_mut().unwrap().next()).is_none());
        drop(attempt);
        next_event(&mut state, &mut sends).await;
        assert!(state.address_lookup_stream.is_none(), "round {round}");
        assert_eq!(
            provider.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        );
    }
}

#[derive(Clone, Copy)]
enum Completion {
    Await,
    UseStreams,
    DropBeforeAccept,
}

#[tokio::test]
async fn accepted_zero_rtt_releases_attempt() {
    zero_rtt(Completion::Await).await;
}

#[tokio::test]
async fn using_zero_rtt_without_awaiting_completion_releases_attempt() {
    zero_rtt(Completion::UseStreams).await;
}

#[tokio::test]
async fn dropping_zero_rtt_before_completion_releases_attempt() {
    zero_rtt(Completion::DropBeforeAccept).await;
}

async fn zero_rtt(completion: Completion) {
    use crate::endpoint::{ConnectOptions, ZeroRttStatus};

    tokio::time::timeout(Duration::from_secs(5), async {
        let endpoint = || {
            Endpoint::builder(presets::Minimal)
                .clear_ip_transports()
                .bind_addr("127.0.0.1:0")
                .unwrap()
        };
        let host = endpoint().alpns(vec![ALPN.to_vec()]).bind().await.unwrap();
        let client = endpoint().bind().await.unwrap();
        let address = EndpointAddr::new(host.id()).with_ip_addr(host.bound_sockets()[0]);
        let mapping = client.inner().unwrap().mapped_addrs.endpoint_addrs.clone();
        let attempt_finished = || {
            let addrs = mapping.active_addrs();
            let [addr] = addrs.as_slice() else {
                panic!("expected one live attempt: {addrs:?}")
            };
            mapping.lookup(addr).unwrap().1
        };
        let server = tokio::spawn({
            let host = host.clone();
            async move {
                let mut held = Vec::new();
                let dials = if matches!(completion, Completion::DropBeforeAccept) {
                    1
                } else {
                    2
                };
                for _ in 0..dials {
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

        let connecting = client
            .connect_with_opts(address, ALPN, ConnectOptions::new())
            .await
            .unwrap();
        let finished = attempt_finished();
        // into_0rtt can be called synchronously outside the Tokio runtime.
        let resumed = std::thread::spawn(move || connecting.into_0rtt().expect("session ticket"))
            .join()
            .unwrap();
        if matches!(completion, Completion::DropBeforeAccept) {
            // The stream keeps Noq alive even after the last 0-RTT handle goes away.
            let _stream = resumed.open_uni().await.unwrap();
            assert!(!finished.is_cancelled());
            drop(resumed);
            finished.cancelled().await;
        } else {
            let (mut send, mut recv) = resumed.open_bi().await.unwrap();
            send.write_all(b"resumed").await.unwrap();
            send.finish().unwrap();
            if matches!(completion, Completion::Await) {
                assert!(matches!(
                    resumed.handshake_completed().await.unwrap(),
                    ZeroRttStatus::Accepted(_)
                ));
            }
            assert_eq!(recv.read_to_end(16).await.unwrap(), b"resumed");
            finished.cancelled().await;
            assert!(resumed.close_reason().is_none());
        }
        assert!(mapping.active_addrs().is_empty());
        assert!(first.close_reason().is_none());
        let _held = server.await.unwrap();
        tokio::join!(client.close(), host.close());
    })
    .await
    .expect("0-RTT handshake or echo stalled");
}
