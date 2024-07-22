//! Gossip client.
//!
//! The gossip client allows you to subscribe to gossip topics and send updates to them.
//!
//! The main entry point is the [`Client`].
//!
//! The gossip API is extremely simple. You use [`subscribe`](Client::subscribe)
//! to subscribe to a topic. This returns a sink to send updates to the topic
//! and a stream of responses.
//!
//! [`Client::subscribe_with_opts`] allows you to specify advanced options
//! such as the buffer size.
use anyhow::Result;
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh_net::NodeId;
use ref_cast::RefCast;

use crate::rpc_protocol::gossip::{
    BroadcastNeighboursRequest, BroadcastRequest, QuitRequest, SubscribeRequest,
};

pub use crate::rpc_protocol::gossip::SubscribeResponse;
pub use iroh_gossip::proto::TopicId;

use super::RpcClient;

/// Iroh gossip client.
#[derive(Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct Client {
    pub(super) rpc: RpcClient,
}

/// Options for subscribing to a gossip topic.
#[derive(Debug, Clone)]
pub struct SubscribeOpts {
    /// Bootstrap nodes to connect to.
    pub bootstrap: Vec<NodeId>,
    /// Subscription capacity.
    pub subscription_capacity: usize,
}

impl Default for SubscribeOpts {
    fn default() -> Self {
        Self {
            bootstrap: Default::default(),
            subscription_capacity: 256,
        }
    }
}

impl Client {
    /// Subscribe to a gossip topic.
    pub async fn subscribe_with_opts(
        &self,
        topic: TopicId,
        opts: SubscribeOpts,
    ) -> Result<impl Stream<Item = Result<SubscribeResponse>>> {
        let stream = self
            .rpc
            .try_server_streaming(SubscribeRequest {
                topic,
                bootstrap: opts.bootstrap,
                subscription_capacity: opts.subscription_capacity,
            })
            .await?;
        let stream = stream.map(|item| anyhow::Ok(item?));
        Ok(stream)
    }

    /// Subscribe to a gossip topic with default options.
    pub async fn subscribe(
        &self,
        topic: impl Into<TopicId>,
        bootstrap: impl IntoIterator<Item = impl Into<NodeId>>,
    ) -> Result<impl Stream<Item = Result<SubscribeResponse>>> {
        let bootstrap = bootstrap.into_iter().map(Into::into).collect();
        self.subscribe_with_opts(
            topic.into(),
            SubscribeOpts {
                bootstrap,
                ..Default::default()
            },
        )
        .await
    }

    /// Broadcast a message on the given topic
    pub async fn broadcast(&self, topic: impl Into<TopicId>, msg: impl Into<Bytes>) -> Result<()> {
        self.rpc
            .rpc(BroadcastRequest {
                topic: topic.into(),
                message: msg.into(),
            })
            .await??;
        Ok(())
    }

    /// Broadcast a message to all neighbours on the given topic
    pub async fn broadcast_neighbours(
        &self,
        topic: impl Into<TopicId>,
        msg: impl Into<Bytes>,
    ) -> Result<()> {
        self.rpc
            .rpc(BroadcastNeighboursRequest {
                topic: topic.into(),
                message: msg.into(),
            })
            .await??;
        Ok(())
    }

    /// Quit the subscription to the given topic.
    pub async fn quit(&self, topic: impl Into<TopicId>) -> Result<()> {
        self.rpc
            .rpc(QuitRequest {
                topic: topic.into(),
            })
            .await??;
        Ok(())
    }
}
