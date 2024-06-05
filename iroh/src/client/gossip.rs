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

impl<C> Client<C>
where
    C: ServiceConnection<RpcService>,
{
    /// Subscribe to a gossip topic.
    pub async fn subscribe(
        &self,
        topic: TopicId,
        bootstrap: BTreeSet<NodeId>,
    ) -> Result<(
        impl Sink<GossipSubscribeUpdate, Error = anyhow::Error>,
        impl Stream<Item = Result<GossipSubscribeResponse>>,
    )> {
        let (sink, stream) = self
            .rpc
            .bidi(GossipSubscribeRequest {
                topic,
                bootstrap,
                subscription_capacity: 1024,
            })
            .await?;
        let stream = stream.map(|item| anyhow::Ok(item??));
        let sink = sink.sink_map_err(|_| anyhow::anyhow!("send error"));
        Ok((sink, stream))
    }
}
