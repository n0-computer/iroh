//! A gossip engine that manages gossip subscriptions and updates.
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    pin::Pin,
    sync::{Arc, Mutex},
};

use futures_util::Stream;
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_gossip::{
    net::{Event, Gossip},
    proto::TopicId,
};
use iroh_net::{util::AbortingJoinHandle, NodeId};

use crate::rpc_protocol::{GossipSubscribeRequest, GossipSubscribeResponse, GossipSubscribeUpdate};

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
type UpdateStream = Box<dyn Stream<Item = GossipSubscribeUpdate> + Send + Sync + Unpin + 'static>;
type ResponseSink = flume::Sender<RpcResult<GossipSubscribeResponse>>;

#[derive(derive_more::Debug)]
enum TopicState {
    /// The topic is currently joining.
    /// Making new subscriptions is allowed, but they will have to wait for the join to finish.
    Joining {
        #[debug(skip)]
        waiting: Vec<(UpdateStream, ResponseSink)>,
        peers: BTreeSet<NodeId>,
        #[allow(dead_code)]
        join_task: AbortingJoinHandle<()>,
    },
    /// The topic is currently live.
    /// New subscriptions can be immediately added.
    Live {
        live: Vec<(AbortingJoinHandle<()>, ResponseSink)>,
    },
    /// The topic is currently quitting.
    /// We can't make new subscriptions without waiting for the quit to finish.
    Quitting {
        #[debug(skip)]
        waiting: Vec<(UpdateStream, ResponseSink)>,
        peers: BTreeSet<NodeId>,
        #[allow(dead_code)]
        quit_task: AbortingJoinHandle<()>,
    },
}

impl TopicState {
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
    /// Create a new gossip engine with the given gossip instance.
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

    async fn quit_task(self, topic: TopicId) {
        let res = self.gossip.quit(topic).await;
        let mut inner = self.inner.lock().unwrap();
        if let Some(TopicState::Quitting { waiting, peers, .. }) =
            inner.current_subscriptions.remove(&topic)
        {
            match res {
                Ok(()) => {
                    if waiting.is_empty() {
                        return;
                    }
                    let bootstrap = peers.iter().copied().collect();
                    let join_task = spawn_owned(self.clone().join_task(topic, bootstrap));
                    inner.current_subscriptions.insert(
                        topic,
                        TopicState::Joining {
                            waiting,
                            peers,
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

    fn try_send(entry: &(AbortingJoinHandle<()>, ResponseSink), event: &Event) -> bool {
        let (task, send) = entry;
        if task.is_finished() {
            return false;
        }
        if send.is_disconnected() {
            return false;
        }
        if let Some(cap) = send.capacity() {
            if send.len() >= cap - 1 {
                send.try_send(Ok(GossipSubscribeResponse::Lagged)).ok();
                return false;
            }
        }
        send.try_send(Ok(GossipSubscribeResponse::Event(event.clone())))
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
                            peers: BTreeSet::new(),
                            quit_task: quit_task.into(),
                        },
                    );
                }
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
    async fn join(gossip: Gossip, topic: TopicId, bootstrap: Vec<NodeId>) -> anyhow::Result<()> {
        gossip.join(topic, bootstrap).await?.await?;
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
                    peers: msg.bootstrap,
                    join_task,
                });
            }
            Entry::Occupied(mut entry) => {
                // There is already a subscription
                let state = entry.get_mut();
                match state {
                    TopicState::Joining { waiting, peers, .. } => {
                        // We are joining, so we need to wait with creating the update task.
                        peers.extend(msg.bootstrap.into_iter());
                        waiting.push((updates, send));
                    }
                    TopicState::Quitting { waiting, peers, .. } => {
                        // We are quitting, so we need to wait with creating the update task.
                        peers.extend(msg.bootstrap.into_iter());
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

fn spawn_owned<F, T>(f: F) -> AbortingJoinHandle<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    tokio::spawn(f).into()
}
