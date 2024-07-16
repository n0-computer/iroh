use std::collections::BTreeMap;

use iroh_base::rpc::RpcResult;
use iroh_net::{endpoint::ConnectionInfo, key::PublicKey, relay::RelayUrl, NodeAddr, NodeId};
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use crate::client::NodeStatus;

use super::RpcService;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<NodeStatus>)]
    Status(StatusRequest),
    #[rpc(response = RpcResult<NodeId>)]
    Id(IdRequest),
    #[rpc(response = RpcResult<NodeAddr>)]
    Addr(AddrRequest),
    #[rpc(response = RpcResult<()>)]
    AddAddr(AddAddrRequest),
    #[rpc(response = RpcResult<Option<RelayUrl>>)]
    Relay(RelayRequest),
    #[rpc(response = RpcResult<StatsResponse>)]
    Stats(StatsRequest),
    #[rpc(response = ())]
    Shutdown(ShutdownRequest),
    #[server_streaming(response = RpcResult<ConnectionsResponse>)]
    Connections(ConnectionsRequest),
    #[rpc(response = RpcResult<ConnectionInfoResponse>)]
    ConnectionInfo(ConnectionInfoRequest),
    #[server_streaming(response = WatchResponse)]
    Watch(NodeWatchRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    Status(RpcResult<NodeStatus>),
    Id(RpcResult<NodeId>),
    Addr(RpcResult<NodeAddr>),
    Relay(RpcResult<Option<RelayUrl>>),
    Stats(RpcResult<StatsResponse>),
    Connections(RpcResult<ConnectionsResponse>),
    ConnectionInfo(RpcResult<ConnectionInfoResponse>),
    Shutdown(()),
    Watch(WatchResponse),
}

/// List connection information about all the nodes we know about
///
/// These can be nodes that we have explicitly connected to or nodes
/// that have initiated connections to us.
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionsRequest;

/// A response to a connections request
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionsResponse {
    /// Information about a connection
    pub conn_info: ConnectionInfo,
}

/// Get connection information about a specific node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfoRequest {
    /// The node identifier
    pub node_id: PublicKey,
}

/// A response to a connection request
#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionInfoResponse {
    /// Information about a connection to a node
    pub conn_info: Option<ConnectionInfo>,
}

/// A request to shutdown the node
#[derive(Serialize, Deserialize, Debug)]
pub struct ShutdownRequest {
    /// Force shutdown
    pub force: bool,
}

/// A request to get information about the status of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct StatusRequest;

/// A request to get information the identity of the node.
#[derive(Serialize, Deserialize, Debug)]
pub struct IdRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct AddrRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct AddAddrRequest {
    pub addr: NodeAddr,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RelayRequest;

/// A request to watch for the node status
#[derive(Serialize, Deserialize, Debug)]
pub struct NodeWatchRequest;

/// The response to a watch request
#[derive(Serialize, Deserialize, Debug)]
pub struct WatchResponse {
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
pub struct StatsRequest {}

/// Counter stats
#[derive(Serialize, Deserialize, Debug)]
pub struct CounterStats {
    /// The counter value
    pub value: u64,
    /// The counter description
    pub description: String,
}

/// Response to [`StatsRequest`]
#[derive(Serialize, Deserialize, Debug)]
pub struct StatsResponse {
    /// Map of statistics
    pub stats: BTreeMap<String, CounterStats>,
}
