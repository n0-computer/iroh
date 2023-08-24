//! Networking for the `iroh-gossip` protocol

use std::{
    collections::HashMap, fmt, future::Future, net::SocketAddr, sync::Arc, task::Poll,
    time::Instant,
};

use anyhow::{anyhow, Context};
use bytes::{Bytes, BytesMut};
use futures::{stream::Stream, FutureExt};
use genawaiter::sync::{Co, Gen};
use iroh_net::{key::PublicKey, magic_endpoint::get_peer_id, MagicEndpoint};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch},
    task::JoinHandle,
};
use tracing::{debug, warn};

use self::util::{read_message, write_message, Dialer, Timers};
use crate::proto::{self, TopicId};

pub mod util;

/// ALPN protocol name
pub const GOSSIP_ALPN: &[u8] = b"n0/iroh-gossip/0";
/// Maximum message size is limited to 1024 bytes.
pub const MAX_MESSAGE_SIZE: usize = 1024;

/// Channel capacity for topic subscription broadcast channels (one per topic)
const SUBSCRIBE_ALL_CAP: usize = 64;
/// Channel capacity for all subscription broadcast channels (single)
const SUBSCRIBE_TOPIC_CAP: usize = 64;
/// Channel capacity for the send queue (one per connection)
const SEND_QUEUE_CAP: usize = 64;
/// Channel capacity for the ToActor message queue (single)
const TO_ACTOR_CAP: usize = 64;
/// Channel capacity for the InEvent message queue (single)
const IN_EVENT_CAP: usize = 1024;

/// Events emitted from the gossip protocol
pub type Event = proto::Event<PublicKey>;
/// Commands for the gossip protocol
pub type Command = proto::Command<PublicKey>;

type InEvent = proto::InEvent<PublicKey>;
type OutEvent = proto::OutEvent<PublicKey>;
type Timer = proto::Timer<PublicKey>;
type ProtoMessage = proto::Message<PublicKey>;

/// Publish and subscribe on gossiping topics.
///
/// Each topic is a separate broadcast tree with separate memberships.
///
/// A topic has to be joined before you can publish or subscribe on the topic.
/// To join the swarm for a topic, you have to know the [PublicKey] of at least one peer that also joined the topic.
///
/// Messages published on the swarm will be delivered to all peers that joined the swarm for that
/// topic. You will also be relaying (gossiping) messages published by other peers.
///
/// With the default settings, the protocol will maintain up to 5 peer connections per topic.
///
/// Even though the [`Gossip`] is created from a [MagicEndpoint], it does not accept connections
/// itself. You should run an accept loop on the MagicEndpoint yourself, check the ALPN protocol of incoming
/// connections, and if the ALPN protocol equals [GOSSIP_ALPN], forward the connection to the
/// gossip actor through [Self::handle_connection].
///
/// The gossip actor will, however, initiate new connections to other peers by itself.
#[derive(Debug, Clone)]
pub struct Gossip {
    to_actor_tx: mpsc::Sender<ToActor>,
    on_endpoints_tx: Arc<watch::Sender<Vec<iroh_net::config::Endpoint>>>,
    _actor_handle: Arc<JoinHandle<anyhow::Result<()>>>,
}

impl Gossip {
    /// Spawn a gossip actor and get a handle for it
    pub fn from_endpoint(endpoint: MagicEndpoint, config: proto::Config) -> Self {
        let peer_id = endpoint.peer_id();
        let dialer = Dialer::new(endpoint.clone());
        let peer_data = Default::default();
        let state = proto::State::new(
            peer_id,
            peer_data,
            config,
            rand::rngs::StdRng::from_entropy(),
        );
        let (to_actor_tx, to_actor_rx) = mpsc::channel(TO_ACTOR_CAP);
        let (in_event_tx, in_event_rx) = mpsc::channel(IN_EVENT_CAP);
        let (on_endpoints_tx, on_endpoints_rx) = watch::channel(Default::default());
        let actor = Actor {
            endpoint,
            state,
            dialer,
            to_actor_rx,
            in_event_rx,
            in_event_tx,
            on_endpoints_rx,
            conns: Default::default(),
            conn_send_tx: Default::default(),
            pending_sends: Default::default(),
            timers: Timers::new(),
            subscribers_all: None,
            subscribers_topic: Default::default(),
        };
        let actor_handle = tokio::spawn(async move {
            if let Err(err) = actor.run().await {
                warn!("gossip actor closed with error: {err:?}");
                Err(err)
            } else {
                Ok(())
            }
        });
        Self {
            to_actor_tx,
            on_endpoints_tx: Arc::new(on_endpoints_tx),
            _actor_handle: Arc::new(actor_handle),
        }
    }

    /// Join a topic and connect to peers.
    ///
    ///
    /// This method only asks for [`PublicKey`]s. You must supply information on how to
    /// connect to these peers manually before, by calling [`MagicEndpoint::add_known_addrs`] on
    /// the underlying [`MagicEndpoint`].
    ///
    /// This method returns a future that completes once the request reached the local actor.
    /// This completion returns a [`JoinTopicFut`] which completes once at least peer was joined
    /// successfully and the swarm thus becomes operational.
    ///
    /// The [`JoinTopicFut`] has no timeout, so it will remain pending indefinitely if no peer
    /// could be contacted. Usually you will want to add a timeout yourself.
    ///
    /// TODO: Resolve to an error once all connection attempts failed.
    pub async fn join(
        &self,
        topic: TopicId,
        peers: Vec<PublicKey>,
    ) -> anyhow::Result<JoinTopicFut> {
        let (tx, rx) = oneshot::channel();
        self.send(ToActor::Join(topic, peers, tx)).await?;
        Ok(JoinTopicFut(rx))
    }

    /// Quit a topic.
    ///
    /// This sends a disconnect message to all active peers and then drops the state
    /// for this topic.
    pub async fn quit(&self, topic: TopicId) -> anyhow::Result<()> {
        self.send(ToActor::Quit(topic)).await?;
        Ok(())
    }

    /// Broadcast a message on a topic.
    ///
    /// This does not join the topic automatically, so you have to call [Self::join] yourself
    /// for messages to be broadcast to peers.
    pub async fn broadcast(&self, topic: TopicId, message: Bytes) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(ToActor::Broadcast(topic, message, tx)).await?;
        rx.await??;
        Ok(())
    }

    /// Subscribe to messages and event notifications for a topic.
    ///
    /// Does not join the topic automatically, so you have to call [Self::join] yourself
    /// to actually receive messages.
    pub async fn subscribe(&self, topic: TopicId) -> anyhow::Result<broadcast::Receiver<Event>> {
        let (tx, rx) = oneshot::channel();
        self.send(ToActor::Subscribe(topic, tx)).await?;
        let res = rx.await.map_err(|_| anyhow!("subscribe_tx dropped"))??;
        Ok(res)
    }

    /// Subscribe to all events published on topics that you joined.
    ///
    /// Note that this method takes self by value. Usually you would clone the [Gossip] handle.
    /// before.
    pub fn subscribe_all(self) -> impl Stream<Item = anyhow::Result<(TopicId, Event)>> {
        Gen::new(|co| async move {
            if let Err(cause) = self.subscribe_all0(&co).await {
                co.yield_(Err(cause)).await
            }
        })
    }

    async fn subscribe_all0(
        &self,
        co: &Co<anyhow::Result<(TopicId, Event)>>,
    ) -> anyhow::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.send(ToActor::SubscribeAll(tx)).await?;
        let mut res = rx.await.map_err(|_| anyhow!("subscribe_tx dropped"))??;
        loop {
            let event = res.recv().await?;
            co.yield_(Ok(event)).await;
        }
    }

    /// Pass an incoming [quinn::Connection] to the gossip actor.
    ///
    /// Make sure to check the ALPN protocol yourself before passing the connection.
    pub async fn handle_connection(&self, conn: quinn::Connection) -> anyhow::Result<()> {
        let peer_id = get_peer_id(&conn).await?;
        self.send(ToActor::ConnIncoming(peer_id, ConnOrigin::Accept, conn))
            .await?;
        Ok(())
    }

    /// Set info on our local endpoints.
    ///
    /// This will be sent to peers on Neighbor and Join requests so that they can connect directly
    /// to us.
    pub fn update_endpoints(&self, endpoints: &[iroh_net::config::Endpoint]) -> anyhow::Result<()> {
        self.on_endpoints_tx
            .send(endpoints.to_vec())
            .map_err(|_| anyhow!("gossip actor dropped"))
    }

    async fn send(&self, event: ToActor) -> anyhow::Result<()> {
        self.to_actor_tx
            .send(event)
            .await
            .map_err(|_| anyhow!("gossip actor dropped"))
    }
}

/// Future that completes once at least one peer is joined for this topic.
///
/// The future has no timeout, so it will remain pending indefinitely if no peer
/// could be contacted. Usually you will want to add a timeout yourself.
///
/// TODO: Optionally resolve to an error once all connection attempts failed.
#[derive(Debug)]
pub struct JoinTopicFut(oneshot::Receiver<anyhow::Result<()>>);
impl Future for JoinTopicFut {
    type Output = anyhow::Result<()>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let res = self.0.poll_unpin(cx);
        match res {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_err)) => Poll::Ready(Err(anyhow!("gossip actor dropped"))),
            Poll::Ready(Ok(res)) => Poll::Ready(res),
        }
    }
}

/// Addressing information for peers.
///
/// This struct is serialized and transmitted to peers in `Join` and `ForwardJoin` messages.
/// It contains the information needed by `iroh-net` to connect to peers.
///
/// TODO: Replace with type from iroh-net
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IrohInfo {
    addrs: Vec<SocketAddr>,
    derp_region: Option<u16>,
}

/// Whether a connection is initiated by us (Dial) or by the remote peer (Accept)
#[derive(Debug)]
enum ConnOrigin {
    Accept,
    Dial,
}

/// Input messages for the gossip [`Actor`].
enum ToActor {
    /// Handle a new QUIC connection, either from accept (external to the actor) or from connect
    /// (happens internally in the actor).
    ConnIncoming(PublicKey, ConnOrigin, quinn::Connection),
    /// Join a topic with a list of peers. Reply with oneshot once at least one peer joined.
    Join(TopicId, Vec<PublicKey>, oneshot::Sender<anyhow::Result<()>>),
    /// Leave a topic, send disconnect messages and drop all state.
    Quit(TopicId),
    /// Broadcast a message on a topic.
    Broadcast(TopicId, Bytes, oneshot::Sender<anyhow::Result<()>>),
    /// Subscribe to a topic. Return oneshot which resolves to a broadcast receiver for events on a
    /// topic.
    Subscribe(
        TopicId,
        oneshot::Sender<anyhow::Result<broadcast::Receiver<Event>>>,
    ),
    /// Subscribe to a topic. Return oneshot which resolves to a broadcast receiver for events on a
    /// topic.
    SubscribeAll(oneshot::Sender<anyhow::Result<broadcast::Receiver<(TopicId, Event)>>>),
}

impl fmt::Debug for ToActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToActor::ConnIncoming(peer_id, origin, _conn) => {
                write!(f, "ConnIncoming({peer_id:?}, {origin:?})")
            }
            ToActor::Join(topic, peers, _reply) => write!(f, "Join({topic:?}, {peers:?})"),
            ToActor::Quit(topic) => write!(f, "Quit({topic:?})"),
            ToActor::Broadcast(topic, message, _reply) => {
                write!(f, "Broadcast({topic:?}, bytes<{}>)", message.len())
            }
            ToActor::Subscribe(topic, _reply) => write!(f, "Subscribe({topic:?})"),
            ToActor::SubscribeAll(_reply) => write!(f, "SubscribeAll"),
        }
    }
}

/// Actor that sends and handles messages between the connection and main state loops
struct Actor {
    /// Protocol state
    state: proto::State<PublicKey, StdRng>,
    endpoint: MagicEndpoint,
    /// Dial machine to connect to peers
    dialer: Dialer,
    /// Input messages to the actor
    to_actor_rx: mpsc::Receiver<ToActor>,
    /// Sender for the state input (cloned into the connection loops)
    in_event_tx: mpsc::Sender<InEvent>,
    /// Input events to the state (emitted from the connection loops)
    in_event_rx: mpsc::Receiver<InEvent>,
    /// Watcher for updates of discovered endpoint addresses
    on_endpoints_rx: watch::Receiver<Vec<iroh_net::config::Endpoint>>,
    /// Queued timers
    timers: Timers<Timer>,
    /// Currently opened quinn connections to peers
    conns: HashMap<PublicKey, quinn::Connection>,
    /// Channels to send outbound messages into the connection loops
    conn_send_tx: HashMap<PublicKey, mpsc::Sender<ProtoMessage>>,
    /// Queued messages that were to be sent before a dial completed
    pending_sends: HashMap<PublicKey, Vec<ProtoMessage>>,
    /// Broadcast senders for active topic subscriptions from the application
    subscribers_topic: HashMap<TopicId, broadcast::Sender<Event>>,
    /// Broadcast senders for wildcard subscriptions from the application
    subscribers_all: Option<broadcast::Sender<(TopicId, Event)>>,
}

impl Actor {
    pub async fn run(mut self) -> anyhow::Result<()> {
        let me = *self.state.me();
        loop {
            tokio::select! {
                biased;
                msg = self.to_actor_rx.recv() => {
                    match msg {
                        Some(msg) => self.handle_to_actor_msg(msg, Instant::now()).await?,
                        None => {
                            debug!(?me, "all gossip handles dropped, stop gossip actor");
                            break;
                        }
                    }
                },
                _ = self.on_endpoints_rx.changed() => {
                    let endpoints = self.on_endpoints_rx.borrow().clone();
                    let info = IrohInfo {
                        addrs: endpoints.iter().map(|ep| ep.addr).collect(),
                        derp_region: self.endpoint.my_derp().await
                    };
                    let peer_data = postcard::to_stdvec(&info)?;
                    self.handle_in_event(InEvent::UpdatePeerData(peer_data.into()), Instant::now()).await?;
                }
                (peer_id, res) = self.dialer.next() => {
                    match res {
                        Ok(conn) => {
                            debug!(?me, peer = ?peer_id, "dial successfull");
                            self.handle_to_actor_msg(ToActor::ConnIncoming(peer_id, ConnOrigin::Dial, conn), Instant::now()).await.context("dialer.next -> conn -> handle_to_actor_msg")?;
                        }
                        Err(err) => {
                            warn!(?me, peer = ?peer_id, "dial failed: {err}");
                        }
                    }
                }
                event = self.in_event_rx.recv() => {
                    match event {
                        Some(event) => {
                            self.handle_in_event(event, Instant::now()).await.context("in_event_rx.recv -> handle_in_event")?;
                        }
                        None => unreachable!()
                    }
                }
                drain = self.timers.wait_and_drain() => {
                    let now = Instant::now();
                    for (_instant, timer) in drain {
                        self.handle_in_event(InEvent::TimerExpired(timer), now).await.context("timers.drain_expired -> handle_in_event")?;
                    }
                }

            }
        }
        Ok(())
    }

    async fn handle_to_actor_msg(&mut self, msg: ToActor, now: Instant) -> anyhow::Result<()> {
        let me = *self.state.me();
        debug!(?me, "handle to_actor  {msg:?}");
        match msg {
            ToActor::ConnIncoming(peer_id, origin, conn) => {
                self.conns.insert(peer_id, conn.clone());
                self.dialer.abort_dial(&peer_id);
                let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_CAP);
                self.conn_send_tx.insert(peer_id, send_tx.clone());

                // Spawn a task for this connection
                let in_event_tx = self.in_event_tx.clone();
                tokio::spawn(async move {
                    debug!(?me, peer = ?peer_id, "connection established, start loop");
                    match connection_loop(peer_id, conn, origin, send_rx, &in_event_tx).await {
                        Ok(()) => {
                            debug!(?me, peer = ?peer_id, "connection closed without error")
                        }
                        Err(err) => {
                            debug!(?me, peer = ?peer_id, "connection closed with error {err:?}")
                        }
                    }
                    in_event_tx
                        .send(InEvent::PeerDisconnected(peer_id))
                        .await
                        .ok();
                });

                // Forward queued pending sends
                if let Some(send_queue) = self.pending_sends.remove(&peer_id) {
                    for msg in send_queue {
                        send_tx.send(msg).await?;
                    }
                }
            }
            ToActor::Join(topic_id, peers, reply) => {
                self.handle_in_event(InEvent::Command(topic_id, Command::Join(peers)), now)
                    .await?;
                if self.state.has_active_peers(&topic_id) {
                    // If the active_view contains at least one peer, reply now
                    reply.send(Ok(())).ok();
                } else {
                    // Otherwise, wait for any peer to come up as neighbor.
                    let sub = self.subscribe(topic_id);
                    tokio::spawn(async move {
                        let res = wait_for_neighbor_up(sub).await;
                        reply.send(res).ok();
                    });
                }
            }
            ToActor::Quit(topic_id) => {
                self.handle_in_event(InEvent::Command(topic_id, Command::Quit), now)
                    .await?;
                self.subscribers_topic.remove(&topic_id);
            }
            ToActor::Broadcast(topic_id, message, reply) => {
                self.handle_in_event(InEvent::Command(topic_id, Command::Broadcast(message)), now)
                    .await?;
                reply.send(Ok(())).ok();
            }
            ToActor::Subscribe(topic_id, reply) => {
                let rx = self.subscribe(topic_id);
                reply.send(Ok(rx)).ok();
            }
            ToActor::SubscribeAll(reply) => {
                let rx = self.subscribe_all();
                reply.send(Ok(rx)).ok();
            }
        };
        Ok(())
    }

    async fn handle_in_event(&mut self, event: InEvent, now: Instant) -> anyhow::Result<()> {
        let me = *self.state.me();
        debug!(?me, "handle in_event  {event:?}");
        if let InEvent::PeerDisconnected(peer) = &event {
            self.conn_send_tx.remove(peer);
        }
        let out = self.state.handle(event, now);
        for event in out {
            debug!(?me, "handle out_event {event:?}");
            match event {
                OutEvent::SendMessage(peer_id, message) => {
                    if let Some(send) = self.conn_send_tx.get(&peer_id) {
                        if let Err(_err) = send.send(message).await {
                            warn!("conn receiver for {peer_id:?} dropped");
                            self.conn_send_tx.remove(&peer_id);
                        }
                    } else {
                        debug!(?me, peer = ?peer_id, "dial");
                        self.dialer.queue_dial(peer_id, GOSSIP_ALPN);
                        // TODO: Enforce max length
                        self.pending_sends.entry(peer_id).or_default().push(message);
                    }
                }
                OutEvent::EmitEvent(topic_id, event) => {
                    if let Some(sender) = self.subscribers_all.as_mut() {
                        if let Err(_event) = sender.send((topic_id, event.clone())) {
                            self.subscribers_all = None;
                        }
                    }
                    if let Some(sender) = self.subscribers_topic.get(&topic_id) {
                        // Only error case is that all [broadcast::Receivers] have been dropped.
                        // If so, remove the sender as well.
                        if let Err(_event) = sender.send(event) {
                            self.subscribers_topic.remove(&topic_id);
                        }
                    }
                }
                OutEvent::ScheduleTimer(delay, timer) => {
                    self.timers.insert(now + delay, timer);
                }
                OutEvent::DisconnectPeer(peer) => {
                    if let Some(conn) = self.conns.remove(&peer) {
                        conn.close(0u8.into(), b"close from disconnect");
                    }
                    self.conn_send_tx.remove(&peer);
                    self.pending_sends.remove(&peer);
                    self.dialer.abort_dial(&peer);
                }
                OutEvent::PeerData(peer, data) => match postcard::from_bytes::<IrohInfo>(&data) {
                    Err(err) => warn!("Failed to decode PeerData from {peer}: {err}"),
                    Ok(info) => {
                        debug!("add known addrs for {peer}: {info:?}...");
                        self.endpoint
                            .add_known_addrs(peer, info.derp_region, &info.addrs)
                            .await?;
                    }
                },
            }
        }
        Ok(())
    }

    fn subscribe_all(&mut self) -> broadcast::Receiver<(TopicId, Event)> {
        if let Some(tx) = self.subscribers_all.as_mut() {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(SUBSCRIBE_ALL_CAP);
            self.subscribers_all = Some(tx);
            rx
        }
    }

    fn subscribe(&mut self, topic_id: TopicId) -> broadcast::Receiver<Event> {
        if let Some(tx) = self.subscribers_topic.get(&topic_id) {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(SUBSCRIBE_TOPIC_CAP);
            self.subscribers_topic.insert(topic_id, tx);
            rx
        }
    }
}

async fn wait_for_neighbor_up(mut sub: broadcast::Receiver<Event>) -> anyhow::Result<()> {
    loop {
        match sub.recv().await {
            Ok(Event::NeighborUp(_neighbor)) => break Ok(()),
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => {
                break Err(anyhow!("Failed to join swarm: Gossip actor dropped"))
            }
        }
    }
}

async fn connection_loop(
    from: PublicKey,
    conn: quinn::Connection,
    origin: ConnOrigin,
    mut send_rx: mpsc::Receiver<ProtoMessage>,
    in_event_tx: &mpsc::Sender<InEvent>,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = match origin {
        ConnOrigin::Accept => conn.accept_bi().await?,
        ConnOrigin::Dial => conn.open_bi().await?,
    };
    let mut send_buf = BytesMut::new();
    let mut recv_buf = BytesMut::new();
    loop {
        tokio::select! {
            biased;
            msg = send_rx.recv() => {
                match msg {
                    None => break,
                    Some(msg) =>  write_message(&mut send, &mut send_buf, &msg).await?,
                }
            }

            msg = read_message(&mut recv, &mut recv_buf) => {
                let msg = msg?;
                match msg {
                    None => break,
                    Some(msg) => in_event_tx.send(InEvent::RecvMessage(from, msg)).await?
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use iroh_net::{derp::DerpMap, MagicEndpoint};
    use tokio::spawn;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use tracing::info;

    use super::*;

    async fn create_endpoint(derp_map: DerpMap) -> anyhow::Result<MagicEndpoint> {
        MagicEndpoint::builder()
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .derp_map(Some(derp_map))
            .bind(0)
            .await
    }

    async fn endpoint_loop(
        endpoint: MagicEndpoint,
        gossip: Gossip,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                conn = endpoint.accept() => match conn {
                    None => break,
                    Some(conn) => gossip.handle_connection(conn.await?).await?
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn gossip_net_smoke() {
        let _guard = iroh_test::logging::setup();
        let (derp_map, derp_region, cleanup) = util::run_derp_and_stun([127, 0, 0, 1].into())
            .await
            .unwrap();

        let ep1 = create_endpoint(derp_map.clone()).await.unwrap();
        let ep2 = create_endpoint(derp_map.clone()).await.unwrap();
        let ep3 = create_endpoint(derp_map.clone()).await.unwrap();

        let go1 = Gossip::from_endpoint(ep1.clone(), Default::default());
        let go2 = Gossip::from_endpoint(ep2.clone(), Default::default());
        let go3 = Gossip::from_endpoint(ep3.clone(), Default::default());
        debug!("peer1 {:?}", ep1.peer_id());
        debug!("peer2 {:?}", ep2.peer_id());
        debug!("peer3 {:?}", ep3.peer_id());
        let pi1 = ep1.peer_id();

        let cancel = CancellationToken::new();
        let tasks = [
            spawn(endpoint_loop(ep1.clone(), go1.clone(), cancel.clone())),
            spawn(endpoint_loop(ep2.clone(), go3.clone(), cancel.clone())),
            spawn(endpoint_loop(ep3.clone(), go2.clone(), cancel.clone())),
        ];

        let topic: TopicId = blake3::hash(b"foobar").into();
        // share info that pi1 is on the same derp_region
        ep2.add_known_addrs(pi1, derp_region, &[]).await.unwrap();
        ep3.add_known_addrs(pi1, derp_region, &[]).await.unwrap();
        // join the topics and wait for the connection to succeed
        go1.join(topic, vec![]).await.unwrap();
        go2.join(topic, vec![pi1]).await.unwrap().await.unwrap();
        go3.join(topic, vec![pi1]).await.unwrap().await.unwrap();

        let len = 10;

        // subscribe nodes 2 and 3 to the topic
        let mut stream2 = go2.subscribe(topic).await.unwrap();
        let mut stream3 = go3.subscribe(topic).await.unwrap();

        // publish messages on node1
        let pub1 = spawn(async move {
            for i in 0..len {
                let message = format!("hi{}", i);
                info!("go1 broadcast: {message:?}");
                go1.broadcast(topic, message.into_bytes().into())
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_micros(1)).await;
            }
        });

        // wait for messages on node2
        let sub2 = spawn(async move {
            let mut recv = vec![];
            loop {
                let ev = stream2.recv().await.unwrap();
                info!("go2 event: {ev:?}");
                if let Event::Received(msg, _prev_peer) = ev {
                    recv.push(msg);
                }
                if recv.len() == len {
                    return recv;
                }
            }
        });

        // wait for messages on node3
        let sub3 = spawn(async move {
            let mut recv = vec![];
            loop {
                let ev = stream3.recv().await.unwrap();
                info!("go3 event: {ev:?}");
                if let Event::Received(msg, _prev_peer) = ev {
                    recv.push(msg);
                }
                if recv.len() == len {
                    return recv;
                }
            }
        });

        timeout(Duration::from_secs(10), pub1)
            .await
            .unwrap()
            .unwrap();
        let recv2 = timeout(Duration::from_secs(10), sub2)
            .await
            .unwrap()
            .unwrap();
        let recv3 = timeout(Duration::from_secs(10), sub3)
            .await
            .unwrap()
            .unwrap();

        let expected: Vec<Bytes> = (0..len)
            .map(|i| Bytes::from(format!("hi{i}").into_bytes()))
            .collect();
        assert_eq!(recv2, expected);
        assert_eq!(recv3, expected);

        cancel.cancel();
        for t in tasks {
            timeout(Duration::from_secs(10), t)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
        drop(cleanup);
    }

    // This is copied from iroh-net/src/hp/magicsock/conn.rs
    // TODO: Move into a public test_utils module in iroh-net?
    mod util {
        use std::net::{IpAddr, SocketAddr};

        use anyhow::Result;
        use iroh_net::{
            derp::{DerpMap, UseIpv4, UseIpv6},
            key::SecretKey,
            stun::{is, parse_binding_request, response},
        };
        use tokio::sync::oneshot;
        use tracing::{debug, info, trace};

        /// A drop guard to clean up test infrastructure.
        ///
        /// After dropping the test infrastructure will asynchronously shutdown and release its
        /// resources.
        #[derive(Debug)]
        pub(crate) struct CleanupDropGuard(pub(crate) oneshot::Sender<()>);

        /// Runs a  DERP server with STUN enabled suitable for tests.
        ///
        /// The returned `u16` is the region ID of the DERP server in the returned [`DerpMap`], it
        /// is always `Some` as that is how the [`MagicEndpoint::connect`] API expects it.
        ///
        /// [`MagicEndpoint::connect`]: crate::magic_endpoint::MagicEndpoint
        pub(crate) async fn run_derp_and_stun(
            stun_ip: IpAddr,
        ) -> Result<(DerpMap, Option<u16>, CleanupDropGuard)> {
            // TODO: pass a mesh_key?

            let server_key = SecretKey::generate();
            let server = iroh_net::derp::http::ServerBuilder::new("127.0.0.1:0".parse().unwrap())
                .secret_key(Some(server_key))
                .tls_config(None)
                .spawn()
                .await?;

            let http_addr = server.addr();
            info!("DERP listening on {:?}", http_addr);

            let (stun_addr, stun_drop_guard) = serve(stun_ip).await?;
            let region_id = 1;
            let derp_url = format!("http://localhost:{}", http_addr.port())
                .parse()
                .unwrap();
            let m = DerpMap::default_from_node(
                derp_url,
                stun_addr.port(),
                UseIpv4::TryDns,
                UseIpv6::Disabled,
                region_id,
            );

            let (tx, rx) = oneshot::channel();
            tokio::spawn(async move {
                let _stun_cleanup = stun_drop_guard; // move into this closure

                // Wait until we're dropped or receive a message.
                rx.await.ok();
                server.shutdown().await;
            });

            Ok((m, Some(region_id), CleanupDropGuard(tx)))
        }

        /// Sets up a simple STUN server.
        async fn serve(ip: IpAddr) -> Result<(SocketAddr, CleanupDropGuard)> {
            let pc = tokio::net::UdpSocket::bind((ip, 0)).await?;
            let mut addr = pc.local_addr()?;
            match addr.ip() {
                IpAddr::V4(ip) => {
                    if ip.octets() == [0, 0, 0, 0] {
                        addr.set_ip("127.0.0.1".parse().unwrap());
                    }
                }
                _ => unreachable!("using ipv4"),
            }

            info!("STUN listening on {}", addr);
            let (s, r) = oneshot::channel();
            tokio::task::spawn(async move {
                run_stun(pc, r).await;
            });

            Ok((addr, CleanupDropGuard(s)))
        }

        async fn run_stun(pc: tokio::net::UdpSocket, mut done: oneshot::Receiver<()>) {
            let mut buf = vec![0u8; 64 << 10];
            loop {
                trace!("read loop");
                tokio::select! {
                    _ = &mut done => {
                        debug!("shutting down");
                        break;
                    }
                    res = pc.recv_from(&mut buf) => match res {
                        Ok((n, addr)) => {
                            trace!("read packet {}bytes from {}", n, addr);
                            let pkt = &buf[..n];
                            if !is(pkt) {
                                debug!("received non STUN pkt");
                                continue;
                            }
                            if let Ok(txid) = parse_binding_request(pkt) {
                                debug!("received binding request");

                                let res = response(txid, addr);
                                if let Err(err) = pc.send_to(&res, addr).await {
                                    eprintln!("STUN server write failed: {:?}", err);
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("failed to read: {:?}", err);
                        }
                    }
                }
            }
        }
    }
}
