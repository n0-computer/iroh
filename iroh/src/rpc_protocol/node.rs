use std::collections::BTreeMap;

use iroh_base::rpc::RpcResult;
use iroh_net::{endpoint::ConnectionInfo, key::PublicKey, relay::RelayUrl, NodeAddr, NodeId};
use quic_rpc::message::{Msg, RpcMsg, ServerStreaming, ServerStreamingMsg};
use serde::{Deserialize, Serialize};

use crate::client::NodeStatus;

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Request)]
pub enum Request {
    Status(NodeStatusRequest),
    Id(NodeIdRequest),
    Addr(NodeAddrRequest),
    AddAddr(NodeAddAddrRequest),
    Relay(NodeRelayRequest),
    Stats(NodeStatsRequest),
    Shutdown(NodeShutdownRequest),
    Connections(NodeConnectionsRequest),
    ConnectionInfo(NodeConnectionInfoRequest),
    Watch(NodeWatchRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[nested_enum_utils::enum_conversions(super::Response)]
pub enum Response {
    Status(RpcResult<NodeStatus>),
    Id(RpcResult<NodeId>),
    Addr(RpcResult<NodeAddr>),
    Relay(RpcResult<Option<RelayUrl>>),
    Stats(RpcResult<NodeStatsResponse>),
    Connections(RpcResult<NodeConnectionsResponse>),
    ConnectionInfo(RpcResult<NodeConnectionInfoResponse>),
    Shutdown(()),
    Watch(NodeWatchResponse),
}

/// List connection information about all the nodes we know about
///
/// These can be nodes that we have explicitly connected to or nodes
/// that have initiated connections to us.
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionsRequest;

/// A response to a connections request
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionsResponse {
    /// Information about a connection
    pub conn_info: ConnectionInfo,
}

impl Msg<RpcService> for NodeConnectionsRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for NodeConnectionsRequest {
    type Response = RpcResult<NodeConnectionsResponse>;
}

/// Get connection information about a specific node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConnectionInfoRequest {
    /// The node identifier
    pub node_id: PublicKey,
}

/// A response to a connection request
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConnectionInfoResponse {
    /// Information about a connection to a node
    pub conn_info: Option<ConnectionInfo>,
}

impl RpcMsg<RpcService> for NodeConnectionInfoRequest {
    type Response = RpcResult<NodeConnectionInfoResponse>;
}

/// A request to shutdown the node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeShutdownRequest {
    /// Force shutdown
    pub force: bool,
}

impl RpcMsg<RpcService> for NodeShutdownRequest {
    type Response = ();
}

/// A request to get information about the status of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatusRequest;

impl RpcMsg<RpcService> for NodeStatusRequest {
    type Response = RpcResult<NodeStatus>;
}

/// A request to get information the identity of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeIdRequest;

impl RpcMsg<RpcService> for NodeIdRequest {
    type Response = RpcResult<NodeId>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeAddrRequest;

impl RpcMsg<RpcService> for NodeAddrRequest {
    type Response = RpcResult<NodeAddr>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeAddAddrRequest {
    pub addr: NodeAddr,
}

impl RpcMsg<RpcService> for NodeAddAddrRequest {
    type Response = RpcResult<()>;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeRelayRequest;

impl RpcMsg<RpcService> for NodeRelayRequest {
    type Response = RpcResult<Option<RelayUrl>>;
}

/// A request to watch for the node status
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchRequest;

impl Msg<RpcService> for NodeWatchRequest {
    type Pattern = ServerStreaming;
}

impl ServerStreamingMsg<RpcService> for NodeWatchRequest {
    type Response = NodeWatchResponse;
}

/// The response to a watch request
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchResponse {
    /// The version of the node
    pub version: String,
}

/// The response to a version request
#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    /// The version of the node
    pub version: String,
}

/// Get stats for the running Iroh node
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatsRequest {}

impl RpcMsg<RpcService> for NodeStatsRequest {
    type Response = RpcResult<NodeStatsResponse>;
}

/// Counter stats
#[derive(Serialize, Deserialize, Debug)]
pub struct CounterStats {
    /// The counter value
    pub value: u64,
    /// The counter description
    pub description: String,
}

/// Response to [`NodeStatsRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeStatsResponse {
    /// Map of statistics
    pub stats: BTreeMap<String, CounterStats>,
}
