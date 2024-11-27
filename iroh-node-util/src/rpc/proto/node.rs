//! RPC calls to control a generic node.
use std::collections::BTreeMap;

use nested_enum_utils::enum_conversions;
use quic_rpc_derive::rpc_requests;
use serde::{Deserialize, Serialize};

use super::{RpcResult, RpcService};
use crate::rpc::client::net::NodeStatus;

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Request)]
#[rpc_requests(RpcService)]
pub enum Request {
    #[rpc(response = RpcResult<NodeStatus>)]
    Status(StatusRequest),
    #[rpc(response = RpcResult<StatsResponse>)]
    Stats(StatsRequest),
    #[rpc(response = ())]
    Shutdown(ShutdownRequest),
}

#[allow(missing_docs)]
#[derive(strum::Display, Debug, Serialize, Deserialize)]
#[enum_conversions(super::Response)]
pub enum Response {
    Status(RpcResult<NodeStatus>),
    Stats(RpcResult<StatsResponse>),
    Shutdown(()),
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
