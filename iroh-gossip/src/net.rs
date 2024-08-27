//! Networking for the `iroh-gossip` protocol

use anyhow::{anyhow, Context as _, Result};
use bytes::BytesMut;
use futures_concurrency::{
    future::TryJoin,
    stream::{stream_group, StreamGroup},
};
use futures_lite::{stream::Stream, StreamExt};
use futures_util::TryFutureExt;
use iroh_metrics::inc;
use iroh_net::{
    dialer::Dialer,
    endpoint::{get_remote_node_id, Connection},
    key::PublicKey,
    util::SharedAbortingJoinHandle,
    AddrInfo, Endpoint, NodeAddr, NodeId,
};
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, error_span, trace, warn, Instrument};

use self::util::{read_message, write_message, Timers};
use crate::{
    metrics::Metrics,
    proto::{self, PeerData, Scope, TopicId},
};

mod handles;
pub mod util;

pub use self::handles::{
    Command, CommandStream, Event, GossipEvent, GossipReceiver, GossipSender, GossipTopic,
    JoinOptions, Message,
};

/// ALPN protocol name
pub const GOSSIP_ALPN: &[u8] = b"/iroh-gossip/0";
/// Default channel capacity for topic subscription channels (one per topic)
const TOPIC_EVENTS_DEFAULT_CAP: usize = 2048;
/// Default channel capacity for topic subscription channels (one per topic)
const TOPIC_COMMANDS_DEFAULT_CAP: usize = 2048;
/// Channel capacity for the send queue (one per connection)
const SEND_QUEUE_CAP: usize = 64;
/// Channel capacity for the ToActor message queue (single)
const TO_ACTOR_CAP: usize = 64;
/// Channel capacity for the InEvent message queue (single)
const IN_EVENT_CAP: usize = 1024;
/// Channel capacity for endpoint change message queue (single)
const ON_ENDPOINTS_CAP: usize = 64;
/// Name used for logging when new node addresses are added from gossip.
const SOURCE_NAME: &str = "gossip";

/// Events emitted from the gossip protocol
pub type ProtoEvent = proto::Event<PublicKey>;
/// Commands for the gossip protocol
pub type ProtoCommand = proto::Command<PublicKey>;

type InEvent = proto::InEvent<PublicKey>;
type OutEvent = proto::OutEvent<PublicKey>;
type Timer = proto::Timer<PublicKey>;
type ProtoMessage = proto::Message<PublicKey>;

/// Publish and subscribe on gossiping topics.
///
/// Each topic is a separate broadcast tree with separate memberships.
///
/// A topic has to be joined before you can publish or subscribe on the topic.
/// To join the swarm for a topic, you have to know the [`PublicKey`] of at least one peer that also joined the topic.
///
/// Messages published on the swarm will be delivered to all peers that joined the swarm for that
/// topic. You will also be relaying (gossiping) messages published by other peers.
///
/// With the default settings, the protocol will maintain up to 5 peer connections per topic.
///
/// Even though the [`Gossip`] is created from a [`Endpoint`], it does not accept connections
/// itself. You should run an accept loop on the [`Endpoint`] yourself, check the ALPN protocol of incoming
/// connections, and if the ALPN protocol equals [`GOSSIP_ALPN`], forward the connection to the
/// gossip actor through [Self::handle_connection].
///
/// The gossip actor will, however, initiate new connections to other peers by itself.
#[derive(Debug, Clone)]
pub struct Gossip {
    to_actor_tx: mpsc::Sender<ToActor>,
    on_direct_addrs_tx: mpsc::Sender<Vec<iroh_net::endpoint::DirectAddr>>,
    _actor_handle: SharedAbortingJoinHandle<()>,
    max_message_size: usize,
}

impl Gossip {
    /// Spawn a gossip actor and get a handle for it
    pub fn from_endpoint(endpoint: Endpoint, config: proto::Config, my_addr: &AddrInfo) -> Self {
        let peer_id = endpoint.node_id();
        let dialer = Dialer::new(endpoint.clone());
        let state = proto::State::new(
            peer_id,
            encode_peer_data(my_addr).unwrap(),
            config,
            rand::rngs::StdRng::from_entropy(),
        );
        let (to_actor_tx, to_actor_rx) = mpsc::channel(TO_ACTOR_CAP);
        let (in_event_tx, in_event_rx) = mpsc::channel(IN_EVENT_CAP);
        let (on_endpoints_tx, on_endpoints_rx) = mpsc::channel(ON_ENDPOINTS_CAP);

        let me = endpoint.node_id().fmt_short();
        let max_message_size = state.max_message_size();
        let actor = Actor {
            endpoint,
            state,
            dialer,
            to_actor_rx,
            in_event_rx,
            in_event_tx,
            on_direct_addr_rx: on_endpoints_rx,
            timers: Timers::new(),
            command_rx: StreamGroup::new().keyed(),
            peers: Default::default(),
            topics: Default::default(),
            quit_queue: Default::default(),
            connection_tasks: Default::default(),
        };

        let actor_handle = tokio::spawn(
            async move {
                if let Err(err) = actor.run().await {
                    warn!("gossip actor closed with error: {err:?}");
                }
            }
            .instrument(error_span!("gossip", %me)),
        );
        Self {
            to_actor_tx,
            on_direct_addrs_tx: on_endpoints_tx,
            _actor_handle: actor_handle.into(),
            max_message_size,
        }
    }

    /// Get the maximum message size configured for this gossip actor.
    pub fn max_message_size(&self) -> usize {
        self.max_message_size
    }

    /// Handle an incoming [`Connection`].
    ///
    /// Make sure to check the ALPN protocol yourself before passing the connection.
    pub async fn handle_connection(&self, conn: Connection) -> anyhow::Result<()> {
        let peer_id = get_remote_node_id(&conn)?;
        self.send(ToActor::HandleConnection(peer_id, ConnOrigin::Accept, conn))
            .await?;
        Ok(())
    }

    /// Join a gossip topic with the default options and wait for at least one active connection.
    pub async fn join(&self, topic_id: TopicId, bootstrap: Vec<NodeId>) -> Result<GossipTopic> {
        let mut sub = self.join_with_opts(topic_id, JoinOptions::with_bootstrap(bootstrap));
        sub.joined().await?;
        Ok(sub)
    }

    /// Join a gossip topic with options.
    ///
    /// Returns a [`GossipTopic`] instantly. To wait for at least one connection to be established,
    /// you can await [`GossipTopic::joined`].
    ///
    /// Messages will be queued until a first connection is available. If the internal channel becomes full,
    /// the oldest messages will be dropped from the channel.
    pub fn join_with_opts(&self, topic_id: TopicId, opts: JoinOptions) -> GossipTopic {
        let (command_tx, command_rx) = async_channel::bounded(TOPIC_COMMANDS_DEFAULT_CAP);
        let command_rx: CommandStream = Box::pin(command_rx);
        let event_rx = self.join_with_stream(topic_id, opts, command_rx);
        GossipTopic::new(command_tx, Box::pin(event_rx))
    }

    /// Join a gossip topic with options and an externally-created update stream.
    ///
    /// This method differs from [`Self::join_with_opts`] by letting you pass in a `updates` command stream yourself
    /// instead of using a channel created for you.
    ///
    /// It returns a stream of events. If you want to wait for the topic to become active, wait for
    /// the [`GossipEvent::Joined`] event.
    pub fn join_with_stream(
        &self,
        topic_id: TopicId,
        options: JoinOptions,
        updates: CommandStream,
    ) -> impl Stream<Item = Result<Event>> + Send + 'static {
        let (event_tx, event_rx) = async_channel::bounded(options.subscription_capacity);
        let to_actor_tx = self.to_actor_tx.clone();
        let channels = SubscriberChannels {
            command_rx: updates,
            event_tx,
        };
        // We spawn a task to send the subscribe action to the actor, because we want the send to
        // succeed even if the returned stream is dropped right away without being polled, because
        // it is legit to keep only the `updates` stream and drop the event stream. This situation
        // is handled fine within the actor, but we have to make sure that the message reaches the
        // actor.
        let task = tokio::task::spawn(async move {
            to_actor_tx
                .send(ToActor::Join {
                    topic_id,
                    bootstrap: options.bootstrap,
                    channels,
                })
                .await
                .map_err(|_| anyhow!("Gossip actor dropped"))
        });
        async move {
            task.await
                .map_err(|err| anyhow!("Task for sending to gossip actor failed: {err:?}"))??;
            Ok(event_rx)
        }
        .try_flatten_stream()
    }

    /// Set info on our direct addresses.
    ///
    /// This will be sent to peers on Neighbor and Join requests so that they can connect directly
    /// to us.
    ///
    /// This is only best effort, and will drop new events if backed up.
    pub fn update_direct_addresses(
        &self,
        addrs: &[iroh_net::endpoint::DirectAddr],
    ) -> anyhow::Result<()> {
        let addrs = addrs.to_vec();
        self.on_direct_addrs_tx
            .try_send(addrs)
            .map_err(|_| anyhow!("endpoints channel dropped"))?;
        Ok(())
    }

    async fn send(&self, event: ToActor) -> anyhow::Result<()> {
        self.to_actor_tx
            .send(event)
            .await
            .map_err(|_| anyhow!("gossip actor dropped"))
    }
}

/// Input messages for the gossip [`Actor`].
#[derive(derive_more::Debug)]
enum ToActor {
    /// Handle a new QUIC connection, either from accept (external to the actor) or from connect
    /// (happens internally in the actor).
    HandleConnection(PublicKey, ConnOrigin, #[debug("Connection")] Connection),
    Join {
        topic_id: TopicId,
        bootstrap: BTreeSet<NodeId>,
        channels: SubscriberChannels,
    },
}

/// Actor that sends and handles messages between the connection and main state loops
struct Actor {
    /// Protocol state
    state: proto::State<PublicKey, StdRng>,
    /// The endpoint through which we dial peers
    endpoint: Endpoint,
    /// Dial machine to connect to peers
    dialer: Dialer,
    /// Input messages to the actor
    to_actor_rx: mpsc::Receiver<ToActor>,
    /// Sender for the state input (cloned into the connection loops)
    in_event_tx: mpsc::Sender<InEvent>,
    /// Input events to the state (emitted from the connection loops)
    in_event_rx: mpsc::Receiver<InEvent>,
    /// Updates of discovered endpoint addresses
    on_direct_addr_rx: mpsc::Receiver<Vec<iroh_net::endpoint::DirectAddr>>,
    /// Queued timers
    timers: Timers<Timer>,
    /// Map of topics to their state.
    topics: HashMap<TopicId, TopicState>,
    /// Map of peers to their state.
    peers: HashMap<NodeId, PeerInfo>,
    /// Stream of commands from topic handles.
    command_rx: stream_group::Keyed<TopicCommandStream>,
    /// Internal queue of topic to close because all handles were dropped.
    quit_queue: VecDeque<TopicId>,
    /// Tasks for the connection loops, to keep track of panics.
    connection_tasks: JoinSet<()>,
}

impl Actor {
    pub async fn run(mut self) -> anyhow::Result<()> {
        let mut i = 0;
        loop {
            i += 1;
            trace!(?i, "tick");
            inc!(Metrics, actor_tick_main);
            tokio::select! {
                biased;
                msg = self.to_actor_rx.recv() => {
                    trace!(?i, "tick: to_actor_rx");
                    inc!(Metrics, actor_tick_rx);
                    match msg {
                        Some(msg) => self.handle_to_actor_msg(msg, Instant::now()).await?,
                        None => {
                            debug!("all gossip handles dropped, stop gossip actor");
                            break;
                        }
                    }
                },
                Some((key, (topic, command))) = self.command_rx.next(), if !self.command_rx.is_empty() => {
                    trace!(?i, "tick: command_rx");
                    self.handle_command(topic, key, command).await?;
                },
                new_endpoints = self.on_direct_addr_rx.recv() => {
                    trace!(?i, "tick: new_endpoints");
                    match new_endpoints {
                        Some(endpoints) => {
                            inc!(Metrics, actor_tick_endpoint);
                            let addr = NodeAddr::from_parts(
                                self.endpoint.node_id(),
                                self.endpoint.home_relay(),
                                endpoints.into_iter().map(|x| x.addr).collect(),
                            );
                            let peer_data = encode_peer_data(&addr.info)?;
                            self.handle_in_event(InEvent::UpdatePeerData(peer_data), Instant::now()).await?;
                        }
                        None => {
                            debug!("endpoint change handle dropped, stopping gossip actor");
                            break;
                        }
                    }
                }
                (peer_id, res) = self.dialer.next_conn() => {
                    trace!(?i, "tick: dialer");
                    inc!(Metrics, actor_tick_dialer);
                    match res {
                        Ok(conn) => {
                            debug!(peer = ?peer_id, "dial successful");
                            inc!(Metrics, actor_tick_dialer_success);
                            self.handle_connection(peer_id, ConnOrigin::Dial, conn);
                        }
                        Err(err) => {
                            warn!(peer = ?peer_id, "dial failed: {err}");
                            inc!(Metrics, actor_tick_dialer_failure);
                        }
                    }
                }
                event = self.in_event_rx.recv() => {
                    trace!(?i, "tick: in_event_rx");
                    inc!(Metrics, actor_tick_in_event_rx);
                    match event {
                        Some(event) => {
                            self.handle_in_event(event, Instant::now()).await.context("in_event_rx.recv -> handle_in_event")?;
                        }
                        None => unreachable!()
                    }
                }
                drain = self.timers.wait_and_drain() => {
                    trace!(?i, "tick: timers");
                    inc!(Metrics, actor_tick_timers);
                    let now = Instant::now();
                    for (_instant, timer) in drain {
                        self.handle_in_event(InEvent::TimerExpired(timer), now).await.context("timers.drain_expired -> handle_in_event")?;
                    }
                }
                Some(res) = self.connection_tasks.join_next(), if !self.connection_tasks.is_empty() => {
                    if let Err(err) = res {
                        if !err.is_cancelled() {
                            warn!("connection task panicked: {err:?}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_command(
        &mut self,
        topic: TopicId,
        key: stream_group::Key,
        command: Option<Command>,
    ) -> anyhow::Result<()> {
        debug!(?topic, ?key, ?command, "handle command");
        let Some(state) = self.topics.get_mut(&topic) else {
            // TODO: unreachable?
            warn!("received command for unknown topic");
            return Ok(());
        };
        let TopicState {
            command_rx_keys,
            event_senders,
            ..
        } = state;
        match command {
            Some(command) => {
                let command = match command {
                    Command::Broadcast(message) => ProtoCommand::Broadcast(message, Scope::Swarm),
                    Command::BroadcastNeighbors(message) => {
                        ProtoCommand::Broadcast(message, Scope::Neighbors)
                    }
                    Command::JoinPeers(peers) => ProtoCommand::Join(peers),
                };
                self.handle_in_event(proto::InEvent::Command(topic, command), Instant::now())
                    .await?;
            }
            None => {
                command_rx_keys.remove(&key);
                if command_rx_keys.is_empty() && event_senders.is_empty() {
                    self.quit_queue.push_back(topic);
                    self.process_quit_queue().await?;
                }
            }
        }
        Ok(())
    }

    fn handle_connection(&mut self, peer_id: NodeId, origin: ConnOrigin, conn: Connection) {
        // Check that we only keep one connection per peer per direction.
        if let Some(peer_info) = self.peers.get(&peer_id) {
            if matches!(origin, ConnOrigin::Dial) && peer_info.conn_dialed.is_some() {
                warn!(?peer_id, ?origin, "ignoring connection: already accepted");
                return;
            }
            if matches!(origin, ConnOrigin::Accept) && peer_info.conn_accepted.is_some() {
                warn!(?peer_id, ?origin, "ignoring connection: already accepted");
                return;
            }
        }

        let mut peer_info = self.peers.remove(&peer_id).unwrap_or_default();

        // Store the connection so that we can terminate it when the peer is removed.
        match origin {
            ConnOrigin::Dial => {
                peer_info.conn_dialed = Some(conn.clone());
            }
            ConnOrigin::Accept => {
                peer_info.conn_accepted = Some(conn.clone());
            }
        }

        // Extract the queue of pending messages.
        let queue = match &mut peer_info.state {
            PeerState::Pending { queue } => std::mem::take(queue),
            PeerState::Active { .. } => Default::default(),
        };

        let (send_tx, send_rx) = mpsc::channel(SEND_QUEUE_CAP);
        let max_message_size = self.state.max_message_size();
        let in_event_tx = self.in_event_tx.clone();

        // Spawn a task for this connection
        self.connection_tasks.spawn(
            async move {
                match connection_loop(
                    peer_id,
                    conn,
                    origin,
                    send_rx,
                    &in_event_tx,
                    max_message_size,
                    queue,
                )
                .await
                {
                    Ok(()) => debug!("connection closed without error"),
                    Err(err) => warn!("connection closed: {err:?}"),
                }
                in_event_tx
                    .send(InEvent::PeerDisconnected(peer_id))
                    .await
                    .ok();
            }
            .instrument(error_span!("gossip_conn", peer = %peer_id.fmt_short())),
        );

        peer_info.state = match peer_info.state {
            PeerState::Pending { .. } => PeerState::Active { send_tx },
            PeerState::Active { send_tx } => PeerState::Active { send_tx },
        };

        self.peers.insert(peer_id, peer_info);
    }

    async fn handle_to_actor_msg(&mut self, msg: ToActor, now: Instant) -> anyhow::Result<()> {
        trace!("handle to_actor  {msg:?}");
        match msg {
            ToActor::HandleConnection(peer_id, origin, conn) => {
                self.handle_connection(peer_id, origin, conn)
            }
            ToActor::Join {
                topic_id,
                bootstrap,
                channels,
            } => {
                let state = self.topics.entry(topic_id).or_default();
                let TopicState {
                    neighbors,
                    event_senders,
                    command_rx_keys,
                    joined,
                } = state;
                if *joined {
                    let neighbors = neighbors.iter().copied().collect();
                    channels
                        .event_tx
                        .try_send(Ok(Event::Gossip(GossipEvent::Joined(neighbors))))
                        .ok();
                }

                event_senders.push(channels.event_tx);
                let command_rx = TopicCommandStream::new(topic_id, channels.command_rx);
                let key = self.command_rx.insert(command_rx);
                command_rx_keys.insert(key);

                self.handle_in_event(
                    InEvent::Command(
                        topic_id,
                        ProtoCommand::Join(bootstrap.into_iter().collect()),
                    ),
                    now,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn handle_in_event(&mut self, event: InEvent, now: Instant) -> anyhow::Result<()> {
        self.handle_in_event_inner(event, now).await?;
        self.process_quit_queue().await?;
        Ok(())
    }

    async fn process_quit_queue(&mut self) -> anyhow::Result<()> {
        while let Some(topic_id) = self.quit_queue.pop_front() {
            self.handle_in_event_inner(
                InEvent::Command(topic_id, ProtoCommand::Quit),
                Instant::now(),
            )
            .await?;
            self.topics.remove(&topic_id);
        }
        Ok(())
    }

    async fn handle_in_event_inner(&mut self, event: InEvent, now: Instant) -> anyhow::Result<()> {
        if matches!(event, InEvent::TimerExpired(_)) {
            trace!(?event, "handle in_event");
        } else {
            debug!(?event, "handle in_event");
        };
        if let InEvent::PeerDisconnected(peer) = &event {
            self.peers.remove(peer);
        }
        let out = self.state.handle(event, now);
        for event in out {
            if matches!(event, OutEvent::ScheduleTimer(_, _)) {
                trace!(?event, "handle out_event");
            } else {
                debug!(?event, "handle out_event");
            };
            match event {
                OutEvent::SendMessage(peer_id, message) => {
                    let info = self.peers.entry(peer_id).or_default();
                    match &mut info.state {
                        PeerState::Active { send_tx } => {
                            if let Err(_err) = send_tx.send(message).await {
                                // Removing the peer is handled by the in_event PeerDisconnected sent
                                // at the end of the connection task.
                                warn!("connection loop for {peer_id:?} dropped");
                            }
                        }
                        PeerState::Pending { queue } => {
                            if queue.is_empty() {
                                self.dialer.queue_dial(peer_id, GOSSIP_ALPN);
                            }
                            queue.push(message);
                        }
                    }
                }
                OutEvent::EmitEvent(topic_id, event) => {
                    let Some(state) = self.topics.get_mut(&topic_id) else {
                        // TODO: unreachable?
                        warn!(?topic_id, "gossip state emitted event for unknown topic");
                        continue;
                    };
                    let TopicState {
                        joined,
                        neighbors,
                        event_senders,
                        command_rx_keys,
                    } = state;
                    let event = if let ProtoEvent::NeighborUp(neighbor) = event {
                        neighbors.insert(neighbor);
                        if !*joined {
                            *joined = true;
                            GossipEvent::Joined(vec![neighbor])
                        } else {
                            GossipEvent::NeighborUp(neighbor)
                        }
                    } else {
                        event.into()
                    };
                    event_senders.send(&event);
                    if event_senders.is_empty() && command_rx_keys.is_empty() {
                        self.quit_queue.push_back(topic_id);
                    }
                }
                OutEvent::ScheduleTimer(delay, timer) => {
                    self.timers.insert(now + delay, timer);
                }
                OutEvent::DisconnectPeer(peer_id) => {
                    if let Some(peer) = self.peers.remove(&peer_id) {
                        if let Some(conn) = peer.conn_dialed {
                            conn.close(0u8.into(), b"close from disconnect");
                        }
                        if let Some(conn) = peer.conn_accepted {
                            conn.close(0u8.into(), b"close from disconnect");
                        }
                        drop(peer.state);
                    }
                }
                OutEvent::PeerData(node_id, data) => match decode_peer_data(&data) {
                    Err(err) => warn!("Failed to decode {data:?} from {node_id}: {err}"),
                    Ok(info) => {
                        debug!(peer = ?node_id, "add known addrs: {info:?}");
                        let node_addr = NodeAddr { node_id, info };
                        if let Err(err) = self
                            .endpoint
                            .add_node_addr_with_source(node_addr, SOURCE_NAME)
                        {
                            debug!(peer = ?node_id, "add known failed: {err:?}");
                        }
                    }
                },
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PeerInfo {
    state: PeerState,
    conn_dialed: Option<Connection>,
    conn_accepted: Option<Connection>,
}

#[derive(Debug)]
enum PeerState {
    Pending { queue: Vec<ProtoMessage> },
    Active { send_tx: mpsc::Sender<ProtoMessage> },
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Pending { queue: Vec::new() }
    }
}

#[derive(Debug, Default)]
struct TopicState {
    joined: bool,
    neighbors: BTreeSet<NodeId>,
    event_senders: EventSenders,
    command_rx_keys: HashSet<stream_group::Key>,
}

/// Whether a connection is initiated by us (Dial) or by the remote peer (Accept)
#[derive(Debug, Clone, Copy)]
enum ConnOrigin {
    Accept,
    Dial,
}
#[derive(derive_more::Debug)]
struct SubscriberChannels {
    event_tx: async_channel::Sender<Result<Event>>,
    #[debug("CommandStream")]
    command_rx: CommandStream,
}

async fn connection_loop(
    from: PublicKey,
    conn: Connection,
    origin: ConnOrigin,
    mut send_rx: mpsc::Receiver<ProtoMessage>,
    in_event_tx: &mpsc::Sender<InEvent>,
    max_message_size: usize,
    queue: Vec<ProtoMessage>,
) -> anyhow::Result<()> {
    let (mut send, mut recv) = match origin {
        ConnOrigin::Accept => conn.accept_bi().await?,
        ConnOrigin::Dial => conn.open_bi().await?,
    };
    debug!("connection established");
    let mut send_buf = BytesMut::new();
    let mut recv_buf = BytesMut::new();

    let send_loop = async {
        for msg in queue {
            write_message(&mut send, &mut send_buf, &msg, max_message_size).await?
        }
        while let Some(msg) = send_rx.recv().await {
            write_message(&mut send, &mut send_buf, &msg, max_message_size).await?
        }
        Ok::<_, anyhow::Error>(())
    };

    let recv_loop = async {
        loop {
            let msg = read_message(&mut recv, &mut recv_buf, max_message_size).await?;
            match msg {
                None => break,
                Some(msg) => in_event_tx.send(InEvent::RecvMessage(from, msg)).await?,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    (send_loop, recv_loop).try_join().await?;

    Ok(())
}

fn encode_peer_data(info: &AddrInfo) -> anyhow::Result<PeerData> {
    let bytes = postcard::to_stdvec(info)?;
    anyhow::ensure!(!bytes.is_empty(), "encoding empty peer data: {:?}", info);
    Ok(PeerData::new(bytes))
}

fn decode_peer_data(peer_data: &PeerData) -> anyhow::Result<AddrInfo> {
    let bytes = peer_data.as_bytes();
    if bytes.is_empty() {
        return Ok(AddrInfo::default());
    }
    let info = postcard::from_bytes(bytes)?;
    Ok(info)
}

#[derive(Debug, Default)]
struct EventSenders {
    senders: Vec<(async_channel::Sender<Result<Event>>, bool)>,
}

impl EventSenders {
    fn is_empty(&self) -> bool {
        self.senders.is_empty()
    }

    fn push(&mut self, sender: async_channel::Sender<Result<Event>>) {
        self.senders.push((sender, false));
    }

    /// Send an event to all subscribers.
    ///
    /// This will not wait until the sink is full, but send a `Lagged` response if the sink is almost full.
    fn send(&mut self, event: &GossipEvent) {
        self.senders.retain_mut(|(send, lagged)| {
            // If the stream is disconnected, we don't need to send to it.
            if send.is_closed() {
                return false;
            }

            // Check if the send buffer is almost full, and send a lagged response if it is.
            let cap = send.capacity().expect("we only use bounded channels");
            let event = if send.len() >= cap - 1 {
                if *lagged {
                    return true;
                }
                *lagged = true;
                Event::Lagged
            } else {
                *lagged = false;
                Event::Gossip(event.clone())
            };
            match send.try_send(Ok(event)) {
                Ok(()) => true,
                Err(async_channel::TrySendError::Full(_)) => true,
                Err(async_channel::TrySendError::Closed(_)) => false,
            }
        })
    }
}

#[derive(derive_more::Debug)]
struct TopicCommandStream {
    topic_id: TopicId,
    #[debug("CommandStream")]
    stream: CommandStream,
    closed: bool,
}

impl TopicCommandStream {
    fn new(topic_id: TopicId, stream: CommandStream) -> Self {
        Self {
            topic_id,
            stream,
            closed: false,
        }
    }
}

impl Stream for TopicCommandStream {
    type Item = (TopicId, Option<Command>);
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.stream).poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some((self.topic_id, Some(item)))),
            Poll::Ready(None) => {
                self.closed = true;
                Poll::Ready(Some((self.topic_id, None)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use bytes::Bytes;
    use futures_concurrency::future::TryJoin;
    use iroh_net::key::SecretKey;
    use iroh_net::relay::{RelayMap, RelayMode};
    use tokio::spawn;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;
    use tracing::info;

    use super::*;

    async fn create_endpoint(
        rng: &mut rand_chacha::ChaCha12Rng,
        relay_map: RelayMap,
    ) -> anyhow::Result<Endpoint> {
        let ep = Endpoint::builder()
            .secret_key(SecretKey::generate_with_rng(rng))
            .alpns(vec![GOSSIP_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map))
            .insecure_skip_relay_cert_verify(true)
            .bind(0)
            .await?;

        ep.watch_home_relay().next().await;
        Ok(ep)
    }

    async fn endpoint_loop(
        endpoint: Endpoint,
        gossip: Gossip,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                incoming = endpoint.accept() => match incoming {
                    None => break,
                    Some(incoming) => {
                        let connecting = match incoming.accept() {
                            Ok(connecting) => connecting,
                            Err(err) => {
                                warn!("incoming connection failed: {err:#}");
                                // we can carry on in these cases:
                                // this can be caused by retransmitted datagrams
                                continue;
                            }
                        };
                        gossip.handle_connection(connecting.await?).await?
                    }
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn gossip_net_smoke() {
        let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(1);
        let _guard = iroh_test::logging::setup();
        let (relay_map, relay_url, _guard) =
            iroh_net::test_utils::run_relay_server().await.unwrap();

        let ep1 = create_endpoint(&mut rng, relay_map.clone()).await.unwrap();
        let ep2 = create_endpoint(&mut rng, relay_map.clone()).await.unwrap();
        let ep3 = create_endpoint(&mut rng, relay_map.clone()).await.unwrap();
        let addr1 = AddrInfo {
            relay_url: Some(relay_url.clone()),
            direct_addresses: Default::default(),
        };
        let addr2 = AddrInfo {
            relay_url: Some(relay_url.clone()),
            direct_addresses: Default::default(),
        };
        let addr3 = AddrInfo {
            relay_url: Some(relay_url.clone()),
            direct_addresses: Default::default(),
        };

        let go1 = Gossip::from_endpoint(ep1.clone(), Default::default(), &addr1);
        let go2 = Gossip::from_endpoint(ep2.clone(), Default::default(), &addr2);
        let go3 = Gossip::from_endpoint(ep3.clone(), Default::default(), &addr3);
        debug!("peer1 {:?}", ep1.node_id());
        debug!("peer2 {:?}", ep2.node_id());
        debug!("peer3 {:?}", ep3.node_id());
        let pi1 = ep1.node_id();
        let pi2 = ep2.node_id();

        let cancel = CancellationToken::new();
        let tasks = [
            spawn(endpoint_loop(ep1.clone(), go1.clone(), cancel.clone())),
            spawn(endpoint_loop(ep2.clone(), go2.clone(), cancel.clone())),
            spawn(endpoint_loop(ep3.clone(), go3.clone(), cancel.clone())),
        ];

        debug!("----- adding peers  ----- ");
        let topic: TopicId = blake3::hash(b"foobar").into();

        let addr1 = NodeAddr::new(pi1).with_relay_url(relay_url.clone());
        let addr2 = NodeAddr::new(pi2).with_relay_url(relay_url);
        ep2.add_node_addr(addr1.clone()).unwrap();
        ep3.add_node_addr(addr2).unwrap();

        debug!("----- joining  ----- ");
        // join the topics and wait for the connection to succeed
        let [sub1, mut sub2, mut sub3] = [
            go1.join(topic, vec![]),
            go2.join(topic, vec![pi1]),
            go3.join(topic, vec![pi2]),
        ]
        .try_join()
        .await
        .unwrap();

        let (sink1, _stream1) = sub1.split();

        let len = 2;

        // publish messages on node1
        let pub1 = spawn(async move {
            for i in 0..len {
                let message = format!("hi{}", i);
                info!("go1 broadcast: {message:?}");
                sink1.broadcast(message.into_bytes().into()).await.unwrap();
                tokio::time::sleep(Duration::from_micros(1)).await;
            }
        });

        // wait for messages on node2
        let sub2 = spawn(async move {
            let mut recv = vec![];
            loop {
                let ev = sub2.next().await.unwrap().unwrap();
                info!("go2 event: {ev:?}");
                if let Event::Gossip(GossipEvent::Received(msg)) = ev {
                    recv.push(msg.content);
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
                let ev = sub3.next().await.unwrap().unwrap();
                info!("go3 event: {ev:?}");
                if let Event::Gossip(GossipEvent::Received(msg)) = ev {
                    recv.push(msg.content);
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
    }
}
