//! Send data over the internet.
// #![deny(missing_docs)] TODO: fix me before merging
#![recursion_limit = "256"]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod blobs;
pub mod cid;
pub mod get;
pub mod progress;
pub mod protocol;
pub mod provider;
pub mod runtime;
pub mod tokio_util;
pub mod util;

#[cfg(test)]
pub(crate) mod test_utils;

pub use crate::util::Hash;
pub use iroh_net as net;

use bao_tree::BlockSize;

/// Block size used by iroh, 2^4*1024 = 16KiB
pub const IROH_BLOCK_SIZE: BlockSize = match BlockSize::new(4) {
    Some(bs) => bs,
    None => panic!(),
};
