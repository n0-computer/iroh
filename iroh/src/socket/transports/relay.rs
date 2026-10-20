//! The relay transport: one noq socket per relay server.
//!
//! [`RelayConnections`] holds a [`RelayConnection`] per relay server, created the first time
//! its URL is used. The relay actor adds a [`RelaySocket`] to the noq endpoint for each one,
//! and connects it while it is used. Once connected, the noq socket receives straight from
//! the relay client, and the senders of the noq connections write straight into it.

use std::{
    io,
    num::NonZeroU16,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use bytes::Bytes;
use iroh_base::{EndpointId, RelayUrl};
use iroh_relay::{
    client::{ClientStream, RecvError},
    protos::relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
};
use n0_future::{
    Sink, Stream,
    task::{self, AbortOnDropHandle},
    time::{Duration, Instant},
};
use n0_watcher::Watcher as _;
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, info_span, warn};

use super::{Socket, Transmit};
use crate::{endpoint::RelayStatus, socket::Metrics as SocketMetrics};

mod actor;
mod socket;

pub(crate) use self::actor::{
    Config as RelayActorConfig, HomeRelayWatch, RelayConnectionFailure, RelayConnectionState,
};
use self::{
    actor::{RelayActor, RelayActorMessage},
    socket::RelaySocket,
};

type RelayAddrWatcher =
    n0_watcher::Map<n0_watcher::Direct<Option<RelayStatus>>, Option<(RelayUrl, EndpointId)>>;

/// How long a sender waits for its relay server to connect before it drops a transmit.
///
/// This value is set to 3 times the QUIC initial Probe Timeout (PTO).
const UNDELIVERABLE_DATAGRAM_TIMEOUT: Duration = Duration::from_secs(3);

/// The send half of a relay connection.
type RelaySink = Pin<Box<dyn Sink<ClientToRelayMsg, Error = io::Error> + Send>>;

#[derive(Debug)]
pub(crate) struct RelayTransport {
    actor_sender: mpsc::Sender<RelayActorMessage>,
    _actor_handle: AbortOnDropHandle<()>,
    my_relay: HomeRelayWatch,
    my_endpoint_id: EndpointId,
    connections: RelayConnections,
}

impl RelayTransport {
    /// Starts the relay actor.
    pub(crate) fn new(config: RelayActorConfig, cancel_token: CancellationToken) -> Self {
        let (actor_sender, actor_receiver) = mpsc::channel(256);
        let my_endpoint_id = config.secret_key.public();
        let my_relay = config.my_relay.clone();
        let connections = config.connections.clone();
        let relay_actor = RelayActor::new(config, cancel_token);
        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move { relay_actor.run(actor_receiver).await }
                .instrument(info_span!("relay-actor")),
        ));
        Self {
            actor_sender,
            _actor_handle: actor_handle,
            my_relay,
            my_endpoint_id,
            connections,
        }
    }

    /// Returns the connections to the relay servers.
    pub(crate) fn connections(&self) -> &RelayConnections {
        &self.connections
    }

    /// Hands `endpoint` to the relay actor, which adds a noq socket per relay server to it.
    pub(super) async fn start_sockets(&self, endpoint: noq::Endpoint, sock: Arc<Socket>) {
        let msg = RelayActorMessage::StartSockets { endpoint, sock };
        if self.actor_sender.send(msg).await.is_err() {
            warn!("relay actor is gone, relay servers get no sockets");
        }
    }

    pub(super) fn local_addr_watch(&self) -> RelayAddrWatcher {
        let my_endpoint_id = self.my_endpoint_id;
        self.my_relay
            .watch()
            .map(move |status| status.map(|status| (status.url().clone(), my_endpoint_id)))
    }

    pub(super) fn my_relay_status(&self) -> n0_watcher::Direct<Option<RelayStatus>> {
        self.my_relay.watch()
    }

    pub(super) fn create_network_change_sender(&self) -> RelayNetworkChangeSender {
        RelayNetworkChangeSender {
            sender: self.actor_sender.clone(),
        }
    }
}

/// The connections to the relay servers, one per relay URL.
///
/// A connection stays for the lifetime of the endpoint, even while it is disconnected. Its
/// index selects the range of relay mapped addresses that noq routes to its socket. The
/// relay actor watches for new connections and for requests to connect, see
/// [`Self::changed`].
#[derive(Debug, Clone, Default)]
pub(crate) struct RelayConnections(Arc<RelayConnectionsInner>);

#[derive(Debug, Default)]
struct RelayConnectionsInner {
    /// Indexed by [`RelayConnection::index`].
    connections: Mutex<Vec<Arc<RelayConnection>>>,
    /// Notified when a connection is added, or asks to connect.
    changed: Arc<Notify>,
    metrics: Arc<SocketMetrics>,
    /// Connects every new connection to this channel, to test backpressure.
    #[cfg(test)]
    test_sink: Option<mpsc::Sender<ClientToRelayMsg>>,
}

impl RelayConnections {
    pub(crate) fn new(metrics: Arc<SocketMetrics>) -> Self {
        Self(Arc::new(RelayConnectionsInner {
            metrics,
            ..Default::default()
        }))
    }

    /// Returns the connection to `url`, creating it if needed.
    pub(crate) fn get(&self, url: &RelayUrl) -> Arc<RelayConnection> {
        let mut connections = self.0.connections.lock().expect("poisoned");
        if let Some(connection) = connections.iter().find(|c| c.url == *url) {
            return connection.clone();
        }
        // More relay servers than this are not expected, they would share the last range.
        let index = u16::try_from(connections.len()).unwrap_or(u16::MAX);
        let connection = Arc::new(RelayConnection::new(
            url.clone(),
            index,
            self.0.changed.clone(),
            self.0.metrics.clone(),
        ));
        #[cfg(test)]
        if let Some(sink) = &self.0.test_sink {
            let sink = tokio_util::sync::PollSender::new(sink.clone());
            let sink = n0_future::SinkExt::sink_map_err(sink, io::Error::other);
            connection.send.lock().expect("poisoned").sink = Some(Box::pin(sink));
        }
        connections.push(connection.clone());
        self.0.changed.notify_one();
        connection
    }

    /// Returns all connections, in the order of their indices.
    fn all(&self) -> Vec<Arc<RelayConnection>> {
        self.0.connections.lock().expect("poisoned").clone()
    }

    /// Waits until a connection is added, or asks to connect.
    async fn changed(&self) {
        self.0.changed.notified().await
    }

    /// Creates connections that are always connected to a channel of `capacity` items.
    #[cfg(test)]
    pub(super) fn with_test_sink(capacity: usize) -> (Self, mpsc::Receiver<ClientToRelayMsg>) {
        let (sender, receiver) = mpsc::channel(capacity);
        let connections = Self(Arc::new(RelayConnectionsInner {
            test_sink: Some(sender),
            ..Default::default()
        }));
        (connections, receiver)
    }
}

/// The connection to one relay server.
///
/// Its noq socket receives from it, the senders of the noq connections send on it, and an
/// [`ActiveRelayActor`] connects it and hands it the halves of the relay client.
///
/// [`ActiveRelayActor`]: self::actor
#[derive(derive_more::Debug)]
pub(crate) struct RelayConnection {
    url: RelayUrl,
    index: u16,
    send: Mutex<SendHalf>,
    /// Wakes the senders that wait for the sink, and the relay actor.
    #[debug(skip)]
    sink_wakers: Arc<SinkWakers>,
    recv: Mutex<RecvHalf>,
    /// Set by a sender that found the connection down, cleared by the relay actor.
    connect_requested: AtomicBool,
    /// [`RelayConnectionsInner::changed`].
    #[debug(skip)]
    changed: Arc<Notify>,
    created: Instant,
    /// When a sender last used the connection, in milliseconds since `created`.
    last_used_ms: AtomicU64,
    #[debug(skip)]
    metrics: Arc<SocketMetrics>,
}

#[derive(derive_more::Debug, Default)]
struct SendHalf {
    /// The sink, while connected.
    #[debug(skip)]
    sink: Option<RelaySink>,
    /// Whether the sink holds frames that are not flushed yet.
    needs_flush: bool,
    /// The error that ended the connection, for the relay actor.
    error: Option<io::Error>,
}

#[derive(Debug, Default)]
struct RecvHalf {
    /// The stream, while connected.
    stream: Option<RelayStream>,
    /// The waker of the noq socket's receive task, woken on connect and disconnect.
    waker: Option<Waker>,
}

/// The stream half of a relay client, and where to pass its frames that are not datagrams.
#[derive(Debug)]
pub(super) struct RelayStream {
    pub(super) stream: ClientStream,
    pub(super) events: mpsc::Sender<RelayEvent>,
}

/// A frame for the relay actor, or the end of the stream.
#[derive(Debug)]
pub(super) enum RelayEvent {
    Frame(RelayToClientMsg),
    Closed(Option<RecvError>),
}

impl RelayConnection {
    fn new(url: RelayUrl, index: u16, changed: Arc<Notify>, metrics: Arc<SocketMetrics>) -> Self {
        Self {
            url,
            index,
            send: Default::default(),
            sink_wakers: Default::default(),
            recv: Default::default(),
            connect_requested: AtomicBool::new(false),
            changed,
            created: Instant::now(),
            last_used_ms: AtomicU64::new(0),
            metrics,
        }
    }

    pub(crate) fn url(&self) -> &RelayUrl {
        &self.url
    }

    /// Returns the index of this connection, which selects its relay mapped addresses.
    pub(crate) fn index(&self) -> u16 {
        self.index
    }

    /// Installs the halves of a new relay client.
    fn connect(&self, sink: RelaySink, stream: RelayStream) {
        *self.send.lock().expect("poisoned") = SendHalf {
            sink: Some(sink),
            ..Default::default()
        };
        self.set_stream(Some(stream));
        self.sink_wakers.wake_all();
    }

    /// Removes the halves of the relay client, and returns the sink to close it.
    fn disconnect(&self) -> Option<RelaySink> {
        let sink = self.send.lock().expect("poisoned").sink.take();
        self.set_stream(None);
        self.sink_wakers.wake_all();
        sink
    }

    fn set_stream(&self, stream: Option<RelayStream>) {
        let mut recv = self.recv.lock().expect("poisoned");
        recv.stream = stream;
        if let Some(waker) = recv.waker.take() {
            waker.wake();
        }
    }

    /// Returns when a sender last used this connection.
    fn last_used(&self) -> Instant {
        self.created + Duration::from_millis(self.last_used_ms.load(Ordering::Relaxed))
    }

    fn mark_used(&self) {
        let elapsed = u64::try_from(self.created.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_used_ms.store(elapsed, Ordering::Relaxed);
    }

    /// Asks the relay actor to connect.
    fn request_connect(&self) {
        if !self.connect_requested.swap(true, Ordering::Relaxed) {
            self.changed.notify_one();
        }
    }

    /// Returns whether a sender asked to connect since the last call.
    fn take_connect_request(&self) -> bool {
        self.connect_requested.swap(false, Ordering::Relaxed)
    }

    /// Sends the frame `make` returns, once the sink is ready.
    ///
    /// Fails with [`io::ErrorKind::NotConnected`] while disconnected, and then wakes `cx` on
    /// the next connect.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        make: impl FnOnce() -> ClientToRelayMsg,
    ) -> Poll<io::Result<()>> {
        let mut send = self.send.lock().expect("poisoned");
        let send = &mut *send;
        let Some(sink) = &mut send.sink else {
            self.sink_wakers.register(cx.waker());
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        // Several senders wait for the one sink, which keeps only one waker: give it one
        // that wakes them all.
        let waker = Waker::from(self.sink_wakers.clone());
        let mut sink_cx = Context::from_waker(&waker);
        let result = match sink.as_mut().poll_ready(&mut sink_cx) {
            Poll::Pending => {
                self.sink_wakers.register(cx.waker());
                return Poll::Pending;
            }
            Poll::Ready(result) => result.and_then(|()| sink.as_mut().start_send(make())),
        };
        // Flush right away. If that blocks, the relay actor finishes it.
        let result = result.and_then(|()| match sink.as_mut().poll_flush(&mut sink_cx) {
            Poll::Ready(result) => result,
            Poll::Pending => {
                send.needs_flush = true;
                Ok(())
            }
        });
        if let Err(err) = result {
            self.fail(send, err);
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        Poll::Ready(Ok(()))
    }

    /// Flushes the frames the senders left in the sink.
    ///
    /// Returns `Ok` once flushed, and the error once the connection failed. Pending while
    /// there is nothing to flush. Polled by the relay actor while connected.
    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut send = self.send.lock().expect("poisoned");
        let send = &mut *send;
        if let Some(err) = send.error.take() {
            return Poll::Ready(Err(err));
        }
        self.sink_wakers.register(cx.waker());
        let (true, Some(sink)) = (send.needs_flush, &mut send.sink) else {
            return Poll::Pending;
        };
        let waker = Waker::from(self.sink_wakers.clone());
        let result = std::task::ready!(sink.as_mut().poll_flush(&mut Context::from_waker(&waker)));
        send.needs_flush = false;
        if result.is_err() {
            send.sink = None;
        }
        Poll::Ready(result)
    }

    /// Ends the connection after a sink error, and wakes the relay actor to reconnect.
    fn fail(&self, send: &mut SendHalf, err: io::Error) {
        debug!(url = %self.url, "relay send failed: {err:#}");
        send.sink = None;
        send.error.get_or_insert(err);
        self.sink_wakers.wake_all();
    }

    /// Receives the next datagram, and hands other frames to the relay actor.
    ///
    /// Pending while disconnected, and then wakes `cx` on the next connect.
    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<(EndpointId, Datagrams)> {
        let mut recv = self.recv.lock().expect("poisoned");
        match &mut recv.waker {
            Some(waker) => waker.clone_from(cx.waker()),
            None => recv.waker = Some(cx.waker().clone()),
        }
        while let Some(stream) = &mut recv.stream {
            let event = match std::task::ready!(Pin::new(&mut stream.stream).poll_next(cx)) {
                Some(Ok(RelayToClientMsg::Datagrams {
                    remote_endpoint_id,
                    datagrams,
                })) => return Poll::Ready((remote_endpoint_id, datagrams)),
                Some(Ok(frame)) => RelayEvent::Frame(frame),
                Some(Err(err)) => RelayEvent::Closed(Some(err)),
                None => RelayEvent::Closed(None),
            };
            let closed = matches!(event, RelayEvent::Closed(_));
            if let Err(err) = stream.events.try_send(event) {
                warn!(url = %self.url, "dropping relay frame for the relay actor: {err:#}");
            }
            if closed {
                recv.stream = None;
            }
        }
        Poll::Pending
    }
}

/// The wakers waiting for a relay sink, woken all at once.
#[derive(Debug, Default)]
struct SinkWakers(Mutex<Vec<Waker>>);

impl SinkWakers {
    fn register(&self, waker: &Waker) {
        let mut wakers = self.0.lock().expect("poisoned");
        if !wakers.iter().any(|w| w.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    fn wake_all(&self) {
        let wakers = std::mem::take(&mut *self.0.lock().expect("poisoned"));
        for waker in wakers {
            waker.wake();
        }
    }
}

impl Wake for SinkWakers {
    fn wake(self: Arc<Self>) {
        self.wake_all();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_all();
    }
}

/// Sends datagrams on one relay connection, for one sending task.
#[derive(Debug, Clone)]
pub(crate) struct RelayDatagramSender {
    connection: Arc<RelayConnection>,
    /// Since when this sender waits for the relay server to connect.
    waiting_since: Option<Instant>,
}

impl RelayDatagramSender {
    pub(crate) fn new(connection: Arc<RelayConnection>) -> Self {
        Self {
            connection,
            waiting_since: None,
        }
    }

    pub(crate) fn url(&self) -> &RelayUrl {
        &self.connection.url
    }

    /// Sends `transmit` to `dst` through the relay server.
    ///
    /// While the relay server is disconnected, asks to connect and waits, but drops the
    /// transmit after [`UNDELIVERABLE_DATAGRAM_TIMEOUT`].
    pub(crate) fn poll_send(
        &mut self,
        cx: &mut Context,
        dst: EndpointId,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let connection = &self.connection;
        connection.mark_used();
        let result = std::task::ready!(connection.poll_send(cx, || {
            ClientToRelayMsg::Datagrams {
                dst_endpoint_id: dst,
                datagrams: datagrams_from_transmit(transmit),
            }
        }));
        match result {
            Err(err) if err.kind() == io::ErrorKind::NotConnected => {
                connection.request_connect();
                let since = *self.waiting_since.get_or_insert_with(Instant::now);
                if since.elapsed() < UNDELIVERABLE_DATAGRAM_TIMEOUT {
                    return Poll::Pending;
                }
                debug!(url = %connection.url, "relay server not connected, dropping transmit");
                self.waiting_since = None;
                Poll::Ready(Ok(()))
            }
            result => {
                self.waiting_since = None;
                if result.is_ok() {
                    connection
                        .metrics
                        .send_relay
                        .inc_by(transmit.contents.len() as _);
                }
                Poll::Ready(result)
            }
        }
    }
}

#[derive(Debug)]
pub(super) struct RelayNetworkChangeSender {
    sender: mpsc::Sender<RelayActorMessage>,
}

impl RelayNetworkChangeSender {
    pub(super) fn on_network_change(&self, report: &crate::socket::Report) {
        self.send_relay_actor(RelayActorMessage::NetworkChange {
            report: report.clone(),
        });
    }

    /// Triggers an immediate health check on relay connections after a network change.
    pub(super) fn check_connection_after_network_change(&self) {
        self.send_relay_actor(RelayActorMessage::CheckConnectionAfterNetworkChange);
    }

    pub(super) fn rebind(&self) -> io::Result<()> {
        self.send_relay_actor(RelayActorMessage::MaybeCloseRelaysOnRebind);

        Ok(())
    }

    fn send_relay_actor(&self, msg: RelayActorMessage) {
        match self.sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to relay actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for relay actor, channel is full");
            }
        }
    }
}

/// Translate a UDP transmit to the `Datagrams` type for sending over the relay.
fn datagrams_from_transmit(transmit: &Transmit<'_>) -> Datagrams {
    Datagrams {
        ecn: transmit.ecn.map(|ecn| match ecn {
            noq_udp::EcnCodepoint::Ect0 => noq_proto::EcnCodepoint::Ect0,
            noq_udp::EcnCodepoint::Ect1 => noq_proto::EcnCodepoint::Ect1,
            noq_udp::EcnCodepoint::Ce => noq_proto::EcnCodepoint::Ce,
        }),
        segment_size: transmit
            .segment_size
            .map(|ss| ss as u16)
            .and_then(NonZeroU16::new),
        contents: Bytes::copy_from_slice(transmit.contents),
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;

    use iroh_base::SecretKey;

    use super::*;
    use crate::{defaults::staging, socket::mapped_addrs::relay_mapped_net};

    fn transmit(contents: &[u8]) -> Transmit<'_> {
        Transmit {
            ecn: None,
            contents,
            segment_size: None,
        }
    }

    #[test]
    fn connections_get_one_index_per_url() {
        let connections = RelayConnections::default();
        let a: RelayUrl = "https://a.example.com".parse().unwrap();
        let b: RelayUrl = "https://b.example.com".parse().unwrap();
        assert_eq!(connections.get(&a).index(), 0);
        assert_eq!(connections.get(&b).index(), 1);
        assert_eq!(connections.get(&a).index(), 0);
        assert!(Arc::ptr_eq(&connections.get(&b), &connections.get(&b)));
        // The ranges of two relays are disjoint /80s of the relay /64.
        let (net_a, net_b) = (relay_mapped_net(0), relay_mapped_net(1));
        assert_eq!(net_a.prefix_len(), 80);
        assert!(!net_a.contains(&net_b.addr()));
    }

    /// A sender waits while the sink is full, and continues once it has room.
    #[tokio::test]
    async fn sender_waits_for_sink() {
        let (connections, mut sink) = RelayConnections::with_test_sink(1);
        let url = staging::default_na_east_relay().url;
        let dst = SecretKey::from_bytes(&[1u8; 32]).public();
        let mut sender = RelayDatagramSender::new(connections.get(&url));
        let mut cx = Context::from_waker(Waker::noop());

        assert!(matches!(
            sender.poll_send(&mut cx, dst, &transmit(b"one")),
            Poll::Ready(Ok(()))
        ));
        assert!(
            sender
                .poll_send(&mut cx, dst, &transmit(b"two"))
                .is_pending()
        );
        let Some(ClientToRelayMsg::Datagrams { datagrams, .. }) = sink.recv().await else {
            panic!("expected datagrams");
        };
        assert_eq!(datagrams.contents.as_ref(), b"one");
        poll_fn(|cx| sender.poll_send(cx, dst, &transmit(b"two")))
            .await
            .unwrap();
    }

    /// A sender of a disconnected relay asks to connect, and waits.
    #[tokio::test]
    async fn disconnected_sender_requests_connect() {
        let connections = RelayConnections::default();
        let url = staging::default_na_east_relay().url;
        let dst = SecretKey::from_bytes(&[1u8; 32]).public();
        let connection = connections.get(&url);
        let mut sender = RelayDatagramSender::new(connection.clone());
        let mut cx = Context::from_waker(Waker::noop());

        assert!(
            sender
                .poll_send(&mut cx, dst, &transmit(b"one"))
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(1), connections.changed())
            .await
            .expect("not notified");
        assert!(connection.take_connect_request());
        assert!(!connection.take_connect_request());
    }
}
