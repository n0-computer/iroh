//! RPC calls to control an iroh-net endpoint.
#![allow(missing_docs)]
use iroh_net::{endpoint::RemoteInfo, key::PublicKey, relay::RelayUrl, NodeAddr, NodeId};
use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::{RpcResult, RpcService};

#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<NodeId>)]
    Id(IdRequest),
    #[rpc(response = RpcResult<NodeAddr>)]
    Addr(AddrRequest),
    #[rpc(response = RpcResult<()>)]
    AddAddr(AddAddrRequest),
    #[rpc(response = RpcResult<Option<RelayUrl>>)]
    Relay(RelayRequest),
    #[server_streaming(response = RpcResult<RemoteInfosIterResponse>)]
    RemoteInfosIter(RemoteInfosIterRequest),
    #[rpc(response = RpcResult<RemoteInfoResponse>)]
    RemoteInfo(RemoteInfoRequest),
    #[server_streaming(response = WatchResponse)]
    Watch(NodeWatchRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    Id(RpcResult<NodeId>),
    Addr(RpcResult<NodeAddr>),
    Relay(RpcResult<Option<RelayUrl>>),
    RemoteInfosIter(RpcResult<RemoteInfosIterResponse>),
    RemoteInfo(RpcResult<RemoteInfoResponse>),
    Watch(WatchResponse),
    Unit(RpcResult<()>),
}

/// List network path information about all the remote nodes known by this node.
///
/// There may never have been connections to these nodes, and connections may not even be
/// possible. Nodes can also become known due to discovery mechanisms
/// or be added manually.
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteInfosIterRequest;

/// A response to a [`Request::RemoteInfosIter`].
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteInfosIterResponse {
    /// Information about a node.
    pub info: RemoteInfo,
}

/// Get information about a specific remote node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteInfoRequest {
    /// The node identifier
    pub node_id: PublicKey,
}

/// A response to a [`Request::RemoteInfo`] request
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteInfoResponse {
    /// Information about a node
    pub info: Option<RemoteInfo>,
}

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
