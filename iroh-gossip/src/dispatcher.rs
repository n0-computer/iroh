//! A higher level wrapper for the gossip engine that manages multiple gossip subscriptions and updates.
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use crate::{
    net::{Event as IrohGossipEvent, Gossip},
    proto::{DeliveryScope, TopicId},
};
use bytes::Bytes;
use futures_lite::StreamExt;
use futures_util::Stream;
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_net::{key::PublicKey, util::AbortingJoinHandle, NodeId};
use serde::{Deserialize, Serialize};

/// Join a gossip topic
#[derive(Serialize, Deserialize, Debug)]
pub struct SubscribeOptions {
    /// The initial bootstrap nodes
    pub bootstrap: BTreeSet<PublicKey>,
    /// The maximum number of messages that can be buffered in a subscription.
    ///
    /// If this limit is reached, the subscriber will receive a `Lagged` response,
    /// the message will be dropped, and the subscriber will be closed.
    ///
    /// This is to prevent a single slow subscriber from blocking the dispatch loop.
    /// If a subscriber is lagging, it should be closed and re-opened.
    pub subscription_capacity: usize,
}

/// Send a gossip message
#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    /// Broadcast a message to all nodes in the swarm
    Broadcast(Bytes),
    /// Broadcast a message to all direct neighbors
    BroadcastNeighbors(Bytes),
}

/// Update from a subscribed gossip topic
#[derive(Serialize, Deserialize, Debug)]
pub enum Event {
    /// A message was received
    Gossip(GossipEvent),
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
    Received(Message),
}

impl From<crate::proto::Event<NodeId>> for GossipEvent {
    fn from(event: crate::proto::Event<NodeId>) -> Self {
        match event {
            crate::proto::Event::NeighborUp(node_id) => Self::NeighborUp(node_id),
            crate::proto::Event::NeighborDown(node_id) => Self::NeighborDown(node_id),
            crate::proto::Event::Received(message) => Self::Received(Message {
                content: message.content,
                scope: message.scope,
                delivered_from: message.delivered_from,
            }),
        }
    }
}

/// A gossip message
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct Message {
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

/// Type alias for a stream of gossip updates, so we don't have to repeat all the bounds.
type CommandStream = Box<dyn Stream<Item = Command> + Send + Sync + Unpin + 'static>;
/// Type alias for a sink of gossip events.
type EventSink = async_channel::Sender<RpcResult<Event>>;

#[derive(derive_more::Debug)]
enum TopicState {
    /// The topic is currently joining.
    /// Making new subscriptions is allowed, but they will have to wait for the join to finish.
    Joining {
        /// Stream/sink pairs that are waiting for the topic to become live.
        #[debug(skip)]
        waiting: Vec<(CommandStream, EventSink)>,
        /// Set of bootstrap nodes we are using.
        bootstrap: BTreeSet<NodeId>,
        /// The task that is driving the join future.
        _join_task: AbortingJoinHandle<()>,
    },
    /// The topic is currently live.
    /// New subscriptions can be immediately added.
    Live {
        update_tasks: Vec<AbortingJoinHandle<()>>,
        event_sinks: Vec<EventSink>,
    },
    /// The topic is currently quitting.
    /// We can't make new subscriptions without waiting for the quit to finish.
    Quitting {
        /// Stream/sink pairs that are waiting for the topic to quit so
        /// it can be joined again.
        #[debug(skip)]
        waiting: Vec<(CommandStream, EventSink)>,
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
    fn into_senders(self) -> Vec<EventSink> {
        match self {
            TopicState::Joining { waiting, .. } | TopicState::Quitting { waiting, .. } => {
                waiting.into_iter().map(|(_, send)| send).collect()
            }
            TopicState::Live { event_sinks, .. } => event_sinks,
        }
    }
}

impl GossipDispatcher {
    /// Create a new gossip dispatcher with the given gossip instance.
    pub fn new(gossip: Gossip) -> Self {
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
                    let _join_task = spawn_owned(self.clone().join_task(topic, bootstrap));
                    inner.current_subscriptions.insert(
                        topic,
                        TopicState::Joining {
                            waiting,
                            bootstrap: peers,
                            _join_task,
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
    fn try_send(send: &EventSink, event: &IrohGossipEvent) -> bool {
        // If the stream is disconnected, we don't need to send to it.
        if send.is_closed() {
            return false;
        }
        // Check if the send buffer is almost full, and send a lagged response if it is.
        if let Some(cap) = send.capacity() {
            if send.len() >= cap - 1 {
                send.try_send(Ok(Event::Lagged)).ok();
                return false;
            }
        }
        // Send the event to the stream.
        // We are the owner of the stream, so we can be sure that there is still room.
        send.try_send(Ok(Event::Gossip(event.clone().into())))
            .is_ok()
    }

    /// Dispatch gossip events to all subscribed streams.
    ///
    /// This should not fail unless the gossip instance is faulty.
    async fn dispatch_loop(mut self) -> anyhow::Result<()> {
        let stream = self.gossip.clone().subscribe_all();
        tokio::pin!(stream);
        while let Some(item) = stream.next().await {
            let (topic, event) = item?;
            // The loop is only for the case that the topic is still in joining state,
            // where we switch it to live here and have to re-lock the mutex afterwards.
            loop {
                let mut inner = self.inner.lock().unwrap();
                let Some(state) = inner.current_subscriptions.get_mut(&topic) else {
                    tracing::trace!("Received event for unknown topic, possibly sync {topic}",);
                    break;
                };
                match state {
                    // The topic is in joining state. It can happen that we receive an event before
                    // our join task completed. In this case, we switch the topic to live here.
                    TopicState::Joining { .. } => {
                        drop(inner);
                        self.on_join(topic, Ok(()));
                        continue;
                    }
                    TopicState::Live {
                        update_tasks,
                        event_sinks,
                    } => {
                        // Send the message to all our senders, and remove disconnected senders.
                        event_sinks.retain(|sink| Self::try_send(sink, &event));
                        // If no senders are left, and all update tasks are finished, we can quit
                        // the topic.
                        if event_sinks.is_empty()
                            && update_tasks.iter().all(|task| task.is_finished())
                        {
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
                    }
                    _ => {}
                }
                break;
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
        mut updates: CommandStream,
    ) -> anyhow::Result<()> {
        while let Some(update) = Pin::new(&mut updates).next().await {
            match update {
                Command::Broadcast(msg) => {
                    gossip.broadcast(topic, msg).await?;
                }
                Command::BroadcastNeighbors(msg) => {
                    gossip.broadcast_neighbors(topic, msg).await?;
                }
            }
        }
        Ok(())
    }

    /// Handle updates from the client, and handle update loop failure.
    async fn update_task(self, topic: TopicId, updates: CommandStream) {
        let res = Self::update_loop(self.gossip.clone(), topic, updates).await;
        let mut inner = self.inner.lock().unwrap();

        match res {
            Err(err) => {
                // we got an error while sending to the topic
                if let Some(TopicState::Live { event_sinks, .. }) =
                    inner.current_subscriptions.remove(&topic)
                {
                    let error = RpcError::from(err);
                    // notify all live streams that sending to the topic failed
                    for send in event_sinks {
                        send.try_send(Err(error.clone())).ok();
                    }
                }
            }
            Ok(()) => {
                // check if we should quit the topic.
                if let Some(TopicState::Live {
                    event_sinks,
                    update_tasks,
                }) = inner.current_subscriptions.get(&topic)
                {
                    if event_sinks.is_empty() && update_tasks.iter().all(|t| t.is_finished()) {
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
                }
            }
        }
    }

    /// Call join, then await the result.
    ///
    /// Basically just flattens the two stages of joining into one.
    async fn join(gossip: Gossip, topic: TopicId, bootstrap: Vec<NodeId>) -> anyhow::Result<()> {
        let join = gossip.join(topic, bootstrap).await?;
        join.await?;
        Ok(())
    }

    /// Join a gossip topic and handle turning waiting streams into live streams.
    async fn join_task(mut self, topic: TopicId, bootstrap: BTreeSet<NodeId>) {
        let res = Self::join(self.gossip.clone(), topic, bootstrap.into_iter().collect()).await;
        self.on_join(topic, res);
    }

    /// Switch the state of a topic to live.
    ///
    /// If the topic is already live, this is a noop.
    fn on_join(&mut self, topic: TopicId, res: anyhow::Result<()>) {
        let mut inner = self.inner.lock().unwrap();
        let Some(state) = inner.current_subscriptions.remove(&topic) else {
            return;
        };
        match state {
            TopicState::Live {
                update_tasks,
                event_sinks,
            } => {
                inner.current_subscriptions.insert(
                    topic,
                    TopicState::Live {
                        update_tasks,
                        event_sinks,
                    },
                );
            }
            TopicState::Joining { waiting, .. } => {
                match res {
                    Ok(()) => {
                        let mut event_sinks = vec![];
                        let mut update_tasks = vec![];
                        for (updates, event_sink) in waiting {
                            // if the stream is disconnected, we don't need to keep it and start the update task
                            if event_sink.is_closed() {
                                continue;
                            }
                            event_sinks.push(event_sink);
                            let task = spawn_owned(self.clone().update_task(topic, updates));
                            update_tasks.push(task);
                        }
                        inner.current_subscriptions.insert(
                            topic,
                            TopicState::Live {
                                event_sinks,
                                update_tasks,
                            },
                        );
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
            TopicState::Quitting { .. } => {}
        }
    }

    /// Subscribe to a gossip topic.
    pub fn subscribe_with_opts(
        &self,
        topic: TopicId,
        options: SubscribeOptions,
        updates: CommandStream,
    ) -> impl Stream<Item = RpcResult<Event>> + Unpin {
        let mut inner = self.inner.lock().unwrap();
        let (send, recv) = async_channel::bounded(options.subscription_capacity);
        match inner.current_subscriptions.entry(topic) {
            Entry::Vacant(entry) => {
                // There is no existing subscription, so we need to start a new one.
                let waiting = vec![(updates, send)];
                let this = self.clone();
                let _join_task =
                    spawn_owned(this.clone().join_task(topic, options.bootstrap.clone()));
                entry.insert(TopicState::Joining {
                    waiting,
                    bootstrap: options.bootstrap,
                    _join_task,
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
                        peers.extend(options.bootstrap);
                        waiting.push((updates, send));
                    }
                    TopicState::Quitting {
                        waiting,
                        bootstrap: peers,
                        ..
                    } => {
                        // We are quitting, so we need to wait with creating the update task.
                        peers.extend(options.bootstrap);
                        waiting.push((updates, send));
                    }
                    TopicState::Live {
                        event_sinks,
                        update_tasks,
                    } => {
                        // There is already a live subscription, so we can immediately start the update task.
                        let task = spawn_owned(self.clone().update_task(topic, updates));
                        event_sinks.push(send);
                        update_tasks.push(task);
                    }
                }
            }
        }
        recv.boxed()
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
