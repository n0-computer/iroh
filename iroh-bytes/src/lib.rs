//! Send data over the internet.

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![recursion_limit = "256"]

pub mod get;
pub mod hashseq;
pub mod protocol;
pub mod provider;
pub mod store;
pub mod util;

pub use crate::util::{Tag, TempTag};
pub use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};

use bao_tree::BlockSize;

/// Block size used by iroh, 2^4*1024 = 16KiB
pub const IROH_BLOCK_SIZE: BlockSize = BlockSize(4);
