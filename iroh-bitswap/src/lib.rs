//! Implementation of [bitswap](https://github.com/ipfs/specs/blob/master/BITSWAP.md).

mod behaviour;
mod block;
mod error;
mod ledger;
mod message;
mod prefix;
mod protocol;

pub use crate::behaviour::{Bitswap, BitswapEvent};
pub use crate::block::tests::create_block as create_test_block;
pub use crate::block::Block;
pub use crate::error::BitswapError;
pub use crate::message::{BitswapMessage, Priority};
