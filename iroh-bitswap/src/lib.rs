//! Implementation of [bitswap](https://github.com/ipfs/specs/blob/master/BITSWAP.md).

mod behaviour;
mod block;
mod error;
mod message;
mod metrics;
mod prefix;
mod protocol;
// mod query;
// mod session;
mod handler;

pub use crate::behaviour::{
    Bitswap, BitswapConfig, BitswapEvent, CancelResult, FindProvidersResult, InboundRequest,
    QueryError, QueryResult, SendHaveResult, SendResult, WantResult,
};
pub use crate::block::tests::{
    create_block_v0 as create_test_block_v0, create_block_v1 as create_test_block_v1,
};
pub use crate::block::Block;
pub use crate::error::BitswapError;
pub use crate::message::{BitswapMessage, Priority};
pub use crate::metrics::*;
pub use crate::protocol::ProtocolId;
// pub use crate::query::QueryId;
