//! Topic handles for sending and receiving on a gossip topic.
//!
//! These are returned from [`super::Gossip`].

use std::{
    collections::{BTreeSet, HashSet},
    pin::Pin,
    task::{Context, Poll},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh_net::NodeId;
use serde::{Deserialize, Serialize};

use crate::{net::TOPIC_EVENTS_DEFAULT_CAP, proto::DeliveryScope};

/// Sender for a gossip topic.
#[derive(Debug)]
pub struct GossipSender(async_channel::Sender<Command>);

impl GossipSender {
    pub(crate) fn new(sender: async_channel::Sender<Command>) -> Self {
        Self(sender)
    }

    /// Broadcast a message to all nodes.
    pub async fn broadcast(&self, message: Bytes) -> anyhow::Result<()> {
        self.0
            .send(Command::Broadcast(message))
            .await
            .map_err(|_| anyhow!("Gossip actor dropped"))
    }

    /// Broadcast a message to our direct neighbors.
    pub async fn broadcast_neighbors(&self, message: Bytes) -> anyhow::Result<()> {
        self.0
            .send(Command::BroadcastNeighbors(message))
            .await
            .map_err(|_| anyhow!("Gossip actor dropped"))
    }

    /// Join a set of peers.
    pub async fn join_peers(&self, peers: Vec<NodeId>) -> anyhow::Result<()> {
        self.0
            .send(Command::JoinPeers(peers))
            .await
            .map_err(|_| anyhow!("Gossip actor dropped"))
    }
}

type EventStream = Pin<Box<dyn Stream<Item = Result<Event>> + Send + 'static>>;

/// Subscribed gossip topic.
///
/// This handle is a [`Stream`] of [`Event`]s from the topic, and can be used to send messages.
///
/// It may be split into sender and receiver parts with [`Self::split`].
#[derive(Debug)]
pub struct GossipTopic {
    sender: GossipSender,
    receiver: GossipReceiver,
}

impl GossipTopic {
    pub(crate) fn new(sender: async_channel::Sender<Command>, receiver: EventStream) -> Self {
        Self {
            sender: GossipSender::new(sender),
            receiver: GossipReceiver::new(Box::pin(receiver)),
        }
    }

    /// Splits `self` into [`GossipSender`] and [`GossipReceiver`] parts.
    pub fn split(self) -> (GossipSender, GossipReceiver) {
        (self.sender, self.receiver)
    }

    /// Sends a message to all peers.
    pub async fn broadcast(&self, message: Bytes) -> anyhow::Result<()> {
        self.sender.broadcast(message).await
    }

    /// Sends a message to our direct neighbors in the swarm.
    pub async fn broadcast_neighbors(&self, message: Bytes) -> anyhow::Result<()> {
        self.sender.broadcast_neighbors(message).await
    }

    /// Waits until we are connected to at least one node.
    pub async fn joined(&mut self) -> Result<()> {
        self.receiver.joined().await
    }

    /// Returns true if we are connected to at least one node.
    pub fn is_joined(&self) -> bool {
        self.receiver.is_joined()
    }
}

impl Stream for GossipTopic {
    type Item = Result<Event>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}

/// Receiver for gossip events on a topic.
///
/// This is a [`Stream`] of [`Event`]s emitted from the topic.
#[derive(derive_more::Debug)]
pub struct GossipReceiver {
    #[debug("EventStream")]
    stream: EventStream,
    neighbors: HashSet<NodeId>,
}

impl GossipReceiver {
    pub(crate) fn new(events_rx: EventStream) -> Self {
        Self {
            stream: events_rx,
            neighbors: Default::default(),
        }
    }

    /// Lists our current direct neighbors.
    pub fn neighbors(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.neighbors.iter().copied()
    }

    /// Waits until we are connected to at least one node.
    pub async fn joined(&mut self) -> Result<()> {
        while self.neighbors.is_empty() {
            let _ = self.try_next().await?;
        }
        Ok(())
    }

    /// Returns true if we are connected to at least one node.
    pub fn is_joined(&self) -> bool {
        !self.neighbors.is_empty()
    }
}

impl Stream for GossipReceiver {
    type Item = Result<Event>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let item = std::task::ready!(Pin::new(&mut self.stream).poll_next(cx));
        if let Some(Ok(item)) = &item {
            match item {
                Event::Gossip(GossipEvent::Joined(neighbors)) => {
                    self.neighbors.extend(neighbors.iter().copied());
                }
                Event::Gossip(GossipEvent::NeighborUp(node_id)) => {
                    self.neighbors.insert(*node_id);
                }
                Event::Gossip(GossipEvent::NeighborDown(node_id)) => {
                    self.neighbors.remove(node_id);
                }
                _ => {}
            }
        }
        Poll::Ready(item)
    }
}

/// Update from a subscribed gossip topic.
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub enum Event {
    /// A message was received.
    Gossip(GossipEvent),
    /// We missed some messages.
    Lagged,
}

/// Gossip event
/// An event to be emitted to the application for a particular topic.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum GossipEvent {
    /// We joined the topic with at least one peer.
    Joined(Vec<NodeId>),
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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, derive_more::Debug, Serialize, Deserialize)]
pub struct Message {
    /// The content of the message
    #[debug("Bytes({})", self.content.len())]
    pub content: Bytes,
    /// The scope of the message.
    /// This tells us if the message is from a direct neighbor or actual gossip.
    pub scope: DeliveryScope,
    /// The node that delivered the message. This is not the same as the original author.
    pub delivered_from: NodeId,
}

/// A stream of commands for a gossip subscription.
pub type CommandStream = Pin<Box<dyn Stream<Item = Command> + Send + Sync + 'static>>;

/// Send a gossip message
#[derive(Serialize, Deserialize, derive_more::Debug)]
pub enum Command {
    /// Broadcast a message to all nodes in the swarm
    Broadcast(#[debug("Bytes({})", _0.len())] Bytes),
    /// Broadcast a message to all direct neighbors
    BroadcastNeighbors(#[debug("Bytes({})", _0.len())] Bytes),
    /// Connect to a set of peers
    JoinPeers(Vec<NodeId>),
}

/// Options for joining a gossip topic.
#[derive(Serialize, Deserialize, Debug)]
pub struct JoinOptions {
    /// The initial bootstrap nodes
    pub bootstrap: BTreeSet<NodeId>,
    /// The maximum number of messages that can be buffered in a subscription.
    ///
    /// If this limit is reached, the subscriber will receive a `Lagged` response,
    /// the message will be dropped, and the subscriber will be closed.
    ///
    /// This is to prevent a single slow subscriber from blocking the dispatch loop.
    /// If a subscriber is lagging, it should be closed and re-opened.
    pub subscription_capacity: usize,
}

impl JoinOptions {
    /// Creates [`JoinOptions`] with the provided bootstrap nodes and the default subscription
    /// capacity.
    pub fn with_bootstrap(nodes: impl IntoIterator<Item = NodeId>) -> Self {
        Self {
            bootstrap: nodes.into_iter().collect(),
            subscription_capacity: TOPIC_EVENTS_DEFAULT_CAP,
        }
    }
}
