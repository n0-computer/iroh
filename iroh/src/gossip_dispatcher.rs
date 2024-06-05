//! A gossip engine that manages gossip subscriptions and updates.
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use futures_util::Stream;
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_gossip::{
    net::{Event, Gossip},
    proto::{DeliveryScope, TopicId},
};
use iroh_net::{key::PublicKey, util::AbortingJoinHandle, NodeId};
use serde::{Deserialize, Serialize};

/// Join a gossip topic
#[derive(Serialize, Deserialize, Debug)]
pub struct GossipSubscribeRequest {
    /// The topic to join
    pub topic: TopicId,
    /// The initial bootstrap nodes
    pub bootstrap: BTreeSet<PublicKey>,
}

/// Send a gossip message
#[derive(Serialize, Deserialize, Debug)]
pub enum GossipSubscribeUpdate {
    /// Broadcast a message to all nodes in the swarm
    Broadcast(Bytes),
    /// Broadcast a message to all direct neighbors
    BroadcastNeighbors(Bytes),
}

/// Update from a subscribed gossip topic
#[derive(Serialize, Deserialize, Debug)]
pub enum GossipSubscribeResponse {
    /// A message was received
    Event(GossipEvent),
    /// We missed some messages
    Lagged,
}

/// Gossip event
/// An event to be emitted to the application for a particular topic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum GossipEvent {
    /// We have a new, direct neighbor in the swarm membership layer for this topic
    NeighborUp(NodeId),
    /// We dropped direct neighbor in the swarm membership layer for this topic
    NeighborDown(NodeId),
    /// A gossip message was received for this topic
    Received(GossipMessage),
}

/// A gossip message
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct GossipMessage {
    /// The content of the message
    pub content: Bytes,
    /// The scope of the message.
    /// This tells us if the message is from a direct neighbor or actual gossip.
    pub scope: DeliveryScope,
    /// The node that delivered the message. This is not the same as the original author.
    pub delivered_from: NodeId,
}

/// A gossip engine that manages gossip subscriptions and updates.
#[derive(Debug, Clone)]
pub struct GossipDispatcher {
    gossip: Gossip,
    inner: Arc<Mutex<State>>,
}

/// The mutable state of the gossip engine.
#[derive(Debug)]
struct State {
    current_subscriptions: BTreeMap<TopicId, TopicState>,
    /// the single task that dispatches gossip events to all subscribed streams
    ///
    /// this isn't really part of the mutable state, but it needs to live somewhere
    task: Option<AbortingJoinHandle<()>>,
}

/// The maximum number of messages that can be buffered in a subscription.
///
/// If this limit is reached, the subscriber will receive a `Lagged` response,
/// the message will be dropped, and the subscriber will be closed.
///
/// This is to prevent a single slow subscriber from blocking the dispatch loop.
/// If a subscriber is lagging, it should be closed and re-opened.
const SUBSCRIPTION_CAPACITY: usize = 128;
/// Type alias for a stream of gossip updates, so we don't have to repeat all the bounds.
type UpdateStream = Box<dyn Stream<Item = GossipSubscribeUpdate> + Send + Sync + Unpin + 'static>;
/// Type alias for a sink of gossip responses.
type ResponseSink = flume::Sender<RpcResult<GossipSubscribeResponse>>;

#[derive(derive_more::Debug)]
enum TopicState {
    /// The topic is currently joining.
    /// Making new subscriptions is allowed, but they will have to wait for the join to finish.
    Joining {
        /// Stream/sink pairs that are waiting for the topic to become live.
        #[debug(skip)]
        waiting: Vec<(UpdateStream, ResponseSink)>,
        /// Set of bootstrap nodes we are using.
        bootstrap: BTreeSet<NodeId>,
        /// The task that is driving the join future.
        #[allow(dead_code)]
        join_task: AbortingJoinHandle<()>,
    },
    /// The topic is currently live.
    /// New subscriptions can be immediately added.
    Live {
        /// Task/sink pairs that are currently live.
        /// The task is the task that is sending broadcast messages to the topic.
        live: Vec<(AbortingJoinHandle<()>, ResponseSink)>,
    },
    /// The topic is currently quitting.
    /// We can't make new subscriptions without waiting for the quit to finish.
    Quitting {
        /// Stream/sink pairs that are waiting for the topic to quit so
        /// it can be joined again.
        #[debug(skip)]
        waiting: Vec<(UpdateStream, ResponseSink)>,
        /// Set of bootstrap nodes we are using.
        ///
        /// This is used to re-join the topic after quitting.
        bootstrap: BTreeSet<NodeId>,
        /// The task that is driving the quit future.
        #[allow(dead_code)]
        quit_task: AbortingJoinHandle<()>,
    },
}

impl TopicState {
    /// Extract all senders from the state.
    fn into_senders(self) -> Vec<ResponseSink> {
        match self {
            TopicState::Joining { waiting, .. } | TopicState::Quitting { waiting, .. } => {
                waiting.into_iter().map(|(_, send)| send).collect()
            }
            TopicState::Live { live } => live.into_iter().map(|(_, send)| send).collect(),
        }
    }
}

impl GossipDispatcher {
    /// Create a new gossip dispatcher with the given gossip instance.
    pub fn spawn(gossip: Gossip) -> Self {
        let inner = Arc::new(Mutex::new(State {
            current_subscriptions: BTreeMap::new(),
            task: None,
        }));
        let res = Self { gossip, inner };
        let dispatch_task = spawn_owned(res.clone().dispatch_task());
        res.inner.lock().unwrap().task = Some(dispatch_task);
        res
    }

    /// Quit a gossip topic and handle the result of the quitting.
    ///
    /// On quit success, will try to join the topic again with the bootstrap nodes we have accumulated while waiting for quit to finish.
    /// On quit failure, all waiting streams will be notified with the error and removed.
    async fn quit_task(self, topic: TopicId) {
        let res = self.gossip.quit(topic).await;
        let mut inner = self.inner.lock().unwrap();
        if let Some(TopicState::Quitting {
            waiting,
            bootstrap: peers,
            ..
        }) = inner.current_subscriptions.remove(&topic)
        {
            match res {
                Ok(()) => {
                    if waiting.is_empty() {
                        return;
                    }
                    let bootstrap = peers.clone();
                    let join_task = spawn_owned(self.clone().join_task(topic, bootstrap));
                    inner.current_subscriptions.insert(
                        topic,
                        TopicState::Joining {
                            waiting,
                            bootstrap: peers,
                            join_task,
                        },
                    );
                }
                Err(e) => {
                    // notify all waiting streams that there is something wrong with the topic
                    let error = RpcError::from(e);
                    for (_, send) in waiting {
                        send.try_send(Err(error.clone())).ok();
                    }
                }
            }
        }
    }

    /// Try to send an event to a sink.
    ///
    /// This will not wait until the sink is full, but send a `Lagged` response if the sink is almost full.
    fn try_send(entry: &(AbortingJoinHandle<()>, ResponseSink), event: &Event) -> bool {
        let (task, send) = entry;
        // This means that we stop sending to the stream when the update side is finished.
        if task.is_finished() {
            return false;
        }
        // If the stream is disconnected, we don't need to send to it.
        if send.is_disconnected() {
            return false;
        }
        // Check if the send buffer is almost full, and send a lagged response if it is.
        if let Some(cap) = send.capacity() {
            if send.len() >= cap - 1 {
                send.try_send(Ok(GossipSubscribeResponse::Lagged)).ok();
                return false;
            }
        }
        // Send the event to the stream.
        // We are the owner of the stream, so we can be sure that there is still room.
        send.try_send(Ok(GossipSubscribeResponse::Event(event.clone().into())))
            .is_ok()
    }

    /// Dispatch gossip events to all subscribed streams.
    ///
    /// This should not fail unless the gossip instance is faulty.
    async fn dispatch_loop(self) -> anyhow::Result<()> {
        use futures_lite::stream::StreamExt;
        let stream = self.gossip.clone().subscribe_all();
        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            let (topic, event) = item?;
            let mut inner = self.inner.lock().unwrap();
            if let Some(TopicState::Live { live }) = inner.current_subscriptions.get_mut(&topic) {
                live.retain(|entry| Self::try_send(entry, &event));
                if live.is_empty() {
                    let quit_task = tokio::task::spawn(self.clone().quit_task(topic));
                    inner.current_subscriptions.insert(
                        topic,
                        TopicState::Quitting {
                            waiting: vec![],
                            bootstrap: BTreeSet::new(),
                            quit_task: quit_task.into(),
                        },
                    );
                }
            } else {
                tracing::trace!(
                    "Received event for unknown topic, possibly sync {}",
                    hex::encode(topic)
                );
            }
        }
        Ok(())
    }

    /// Dispatch gossip events to all subscribed streams, and handle the unlikely case of a dispatch loop failure.
    async fn dispatch_task(self) {
        if let Err(cause) = self.clone().dispatch_loop().await {
            // dispatch task failed. Not sure what to do here.
            tracing::error!("Gossip dispatch task failed: {}", cause);
            let mut inner = self.inner.lock().unwrap();
            let error = RpcError::from(cause);
            for (_, state) in std::mem::take(&mut inner.current_subscriptions) {
                for sender in state.into_senders() {
                    sender.try_send(Err(error.clone())).ok();
                }
            }
        }
    }

    /// Handle updates from the client.
    async fn update_loop(
        gossip: Gossip,
        topic: TopicId,
        mut updates: UpdateStream,
    ) -> anyhow::Result<()> {
        use futures_lite::stream::StreamExt;
        while let Some(update) = Pin::new(&mut updates).next().await {
            match update {
                GossipSubscribeUpdate::Broadcast(msg) => {
                    gossip.broadcast(topic, msg).await?;
                }
                GossipSubscribeUpdate::BroadcastNeighbors(msg) => {
                    gossip.broadcast_neighbors(topic, msg).await?;
                }
            }
        }
        Ok(())
    }

    /// Handle updates from the client, and handle update loop failure.
    async fn update_task(self, topic: TopicId, updates: UpdateStream) {
        let Err(e) = Self::update_loop(self.gossip.clone(), topic, updates).await else {
            return;
        };
        let mut inner = self.inner.lock().unwrap();
        // we got an error while sending to the topic
        if let Some(TopicState::Live { live }) = inner.current_subscriptions.remove(&topic) {
            let error = RpcError::from(e);
            // notify all live streams that sending to the topic failed
            for (_, send) in live {
                send.try_send(Err(error.clone())).ok();
            }
        }
    }

    /// Call join, then await the result.
    ///
    /// Basically just flattens the two stages of joining into one.
    async fn join(gossip: Gossip, topic: TopicId, bootstrap: Vec<NodeId>) -> anyhow::Result<()> {
        tracing::error!("Joining gossip topic {:?}", topic);
        let join = gossip.join(topic, bootstrap).await?;
        tracing::error!("Waiting for joint to gossip topic {:?} to succeed", topic);
        join.await?;
        tracing::error!("Joined gossip topic {:?}", topic);
        Ok(())
    }

    /// Join a gossip topic and handle turning waiting streams into live streams.
    async fn join_task(self, topic: TopicId, bootstrap: BTreeSet<NodeId>) {
        let res = Self::join(self.gossip.clone(), topic, bootstrap.into_iter().collect()).await;
        let mut inner = self.inner.lock().unwrap();
        if let Some(TopicState::Joining { waiting, .. }) =
            inner.current_subscriptions.remove(&topic)
        {
            match res {
                Ok(()) => {
                    let mut live = vec![];
                    for (updates, send) in waiting {
                        // if the stream is disconnected, we don't need to keep it and start the update task
                        if send.is_disconnected() {
                            continue;
                        }
                        let task = spawn_owned(self.clone().update_task(topic, updates));
                        live.push((task, send));
                    }
                    inner
                        .current_subscriptions
                        .insert(topic, TopicState::Live { live });
                }
                Err(e) => {
                    // notify all waiting streams that the subscription failed
                    let error = RpcError::from(e);
                    for (_, send) in waiting {
                        send.try_send(Err(error.clone())).ok();
                    }
                }
            }
        }
    }

    /// Subscribe to a gossip topic.
    pub fn subscribe(
        &self,
        msg: GossipSubscribeRequest,
        updates: UpdateStream,
    ) -> impl Stream<Item = RpcResult<GossipSubscribeResponse>> {
        let topic = msg.topic;
        let mut inner = self.inner.lock().unwrap();
        let (send, recv) = flume::bounded(SUBSCRIPTION_CAPACITY);
        match inner.current_subscriptions.entry(topic) {
            Entry::Vacant(entry) => {
                // There is no existing subscription, so we need to start a new one.
                let waiting = vec![(updates, send)];
                let this = self.clone();
                let join_task = spawn_owned(this.clone().join_task(topic, msg.bootstrap.clone()));
                entry.insert(TopicState::Joining {
                    waiting,
                    bootstrap: msg.bootstrap,
                    join_task,
                });
            }
            Entry::Occupied(mut entry) => {
                // There is already a subscription
                let state = entry.get_mut();
                match state {
                    TopicState::Joining {
                        waiting,
                        bootstrap: peers,
                        ..
                    } => {
                        // We are joining, so we need to wait with creating the update task.
                        //
                        // TODO: should we merge the bootstrap nodes and try to join with all of them?
                        peers.extend(msg.bootstrap);
                        waiting.push((updates, send));
                    }
                    TopicState::Quitting {
                        waiting,
                        bootstrap: peers,
                        ..
                    } => {
                        // We are quitting, so we need to wait with creating the update task.
                        peers.extend(msg.bootstrap);
                        waiting.push((updates, send));
                    }
                    TopicState::Live { live } => {
                        // There is already a live subscription, so we can immediately start the update task.
                        let task = spawn_owned(self.clone().update_task(topic, updates));
                        live.push((task, send));
                    }
                }
            }
        }
        recv.into_stream()
    }
}

/// tokio::spawn but returns an `AbortingJoinHandle` that owns the task.
fn spawn_owned<F, T>(f: F) -> AbortingJoinHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(f).into()
}
