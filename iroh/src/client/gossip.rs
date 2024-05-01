use std::collections::BTreeSet;

use anyhow::Result;
use futures_lite::{Stream, StreamExt};
use futures_util::Sink;
use iroh_gossip::proto::TopicId;
use iroh_net::NodeId;
use quic_rpc::{RpcClient, ServiceConnection};

use crate::rpc_protocol::{
    GossipSubscribeRequest, GossipSubscribeResponse, GossipSubscribeUpdate, ProviderService,
};

/// Iroh gossip client.
#[derive(Debug, Clone)]
pub struct Client<C> {
    pub(super) rpc: RpcClient<ProviderService, C>,
}

impl<C> Client<C>
where
    C: ServiceConnection<ProviderService>,
{
    /// Subscribe to a gossip topic.
    pub async fn subscribe(
        &self,
        topic: TopicId,
        bootstrap: BTreeSet<NodeId>,
    ) -> Result<(
        impl Sink<GossipSubscribeUpdate>,
        impl Stream<Item = Result<GossipSubscribeResponse>>,
    )> {
        let (sink, stream) = self
            .rpc
            .bidi(GossipSubscribeRequest { topic, bootstrap })
            .await?;
        let stream = stream.map(|item| anyhow::Ok(item??));
        Ok((sink, stream))
    }
}
