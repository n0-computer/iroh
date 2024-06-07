//! Gossip client.
use std::collections::BTreeSet;

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use futures_util::{Sink, SinkExt};
use iroh_gossip::proto::TopicId;
use iroh_net::NodeId;
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{GossipSubscribeRequest, GossipSubscribeResponse, GossipSubscribeUpdate};

use super::RpcService;

/// Iroh gossip client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<RpcService, C>,
}

/// Options for subscribing to a gossip topic.
#[derive(Debug, Clone)]
pub struct SubscribeOpts {
    /// Bootstrap nodes to connect to.
    pub bootstrap: BTreeSet<NodeId>,
    /// Subscription capacity.
    pub subscription_capacity: usize,
}

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Subscribe to a gossip topic.
    ///
    /// Returns a sink to send updates to the topic and a stream of responses.
    ///
    /// Updates are either [Broadcast](iroh_gossip::dispatcher::Command::Broadcast)
    /// or [BroadcastNeighbors](iroh_gossip::dispatcher::Command::BroadcastNeighbors).
    ///
    /// Broadcasts are gossiped to the entire swarm, while BroadcastNeighbors are sent to
    /// just the immediate neighbors of the node.
    ///
    /// Responses are either [Gossip](iroh_gossip::dispatcher::Event::Gossip) or
    /// [Lagged](iroh_gossip::dispatcher::Event::Lagged).
    ///
    /// Gossip events contain the actual message content, as well as information about the
    /// immediate neighbors of the node.
    ///
    /// A Lagged event indicates that the gossip stream has not been consumed quickly enough.
    /// You can adjust the buffer size with the [] option.
    pub async fn subscribe_with_opts(
        &self,
        topic: TopicId,
        opts: SubscribeOpts,
    ) -> Result<(
        impl Sink<GossipSubscribeUpdate, Error = anyhow::Error>,
        impl Stream<Item = Result<GossipSubscribeResponse>>,
    )> {
        let (sink, stream) = self
            .rpc
            .bidi(GossipSubscribeRequest {
                topic,
                bootstrap: opts.bootstrap,
                subscription_capacity: opts.subscription_capacity,
            })
            .await?;
        let stream = stream.map(|item| anyhow::Ok(item??));
        let sink = sink.sink_map_err(|_| anyhow::anyhow!("send error"));
        Ok((sink, stream))
    }
}
