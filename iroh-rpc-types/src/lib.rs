use serde::{Deserialize, Serialize};

#[macro_use]
pub mod macros;

pub mod gateway;
pub mod p2p;
pub mod store;

#[cfg(feature = "testing")]
pub mod test;

mod addr;
pub use crate::addr::{Addr, Channel, ChannelError};

#[derive(thiserror::Error, Debug, Clone, Serialize, Deserialize)]
#[error("Rpc: {0}")]
pub struct RpcError(String);

impl RpcError {
    pub fn from_any<T: Into<anyhow::Error> + Send + Sync + 'static + std::error::Error>(
        t: T,
    ) -> Self {
        RpcError(anyhow::Error::from(t).to_string())
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        RpcError(e.to_string())
    }
}

impl From<String> for RpcError {
    fn from(e: String) -> Self {
        RpcError(e)
    }
}
