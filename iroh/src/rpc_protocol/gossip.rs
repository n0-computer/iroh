use bytes::Bytes;
use iroh_base::rpc::{RpcError, RpcResult};
use iroh_gossip::proto::TopicId;
use iroh_net::NodeId;
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::RpcService;

pub use iroh_gossip::net::Event as SubscribeResponse;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[try_server_streaming(create_error = RpcError, item_error = RpcError, item = SubscribeResponse)]
    Subscribe(SubscribeRequest),
    #[rpc(response = RpcResult<()>)]
    Broadcast(BroadcastRequest),
    #[rpc(response = RpcResult<()>)]
    BroadcastNeighbours(BroadcastNeighboursRequest),
    #[rpc(response = RpcResult<()>)]
    Quit(QuitRequest),
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
    pub bootstrap: Vec<NodeId>,
    /// The capacity of the subscription
    pub subscription_capacity: usize,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug)]
pub struct QuitRequest {
    pub topic: TopicId,
}

#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcastRequest {
    pub topic: TopicId,
    pub message: Bytes,
}

#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize)]
pub struct BroadcastNeighboursRequest {
    pub topic: TopicId,
    pub message: Bytes,
}
