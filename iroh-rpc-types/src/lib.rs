pub mod addr;
pub mod gateway;
mod gossipsub_event;
pub mod p2p;
pub mod store;

use std::fmt;

pub use addr::Addr;
pub use gossipsub_event::{GossipsubEvent, GossipsubEventStream};

use serde::{Deserialize, Serialize};

pub trait NamedService {
    const NAME: &'static str;
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RpcError(serde_error::Error);

impl std::error::Error for RpcError {}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        RpcError(serde_error::Error::new(&*e))
    }
}

pub type RpcResult<T> = std::result::Result<T, RpcError>;

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct WatchResponse {
    pub version: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct VersionResponse {
    pub version: String,
}
