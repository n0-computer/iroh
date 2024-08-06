use std::collections::BTreeSet;

use iroh_base::rpc::RpcResult;
use iroh_gossip::proto::TopicId;
use iroh_net::NodeId;
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;

pub use iroh_gossip::net::Command as SubscribeUpdate;
pub use iroh_gossip::net::Event as SubscribeResponse;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[bidi_streaming(update = SubscribeUpdate, response = RpcResult<SubscribeResponse>)]
    Subscribe(SubscribeRequest),
    Update(SubscribeUpdate),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    Subscribe(RpcResult<SubscribeResponse>),
}

/// A request to the node to subscribe to gossip events.
///
/// This is basically a topic and additional options
#[derive(Serialize, Deserialize, Debug)]
pub struct SubscribeRequest {
    /// The topic to subscribe to
    pub topic: TopicId,
    /// The nodes to bootstrap the subscription from
    pub bootstrap: BTreeSet<NodeId>,
    /// The capacity of the subscription
    pub subscription_capacity: usize,
}
