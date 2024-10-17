//! Blobs layer for iroh.
//!
//! The crate is designed to be used from the [iroh] crate, which provides a
//! [high level interface](https://docs.rs/iroh/latest/iroh/client/blobs/index.html),
//! but can also be used standalone.
//!
//! It implements a [protocol] for streaming content-addressed data transfer using
//! [BLAKE3] verified streaming.
//!
//! It also provides a [store] interface for storage of blobs and outboards,
//! as well as a [persistent](crate::store::fs) and a [memory](crate::store::mem)
//! store implementation.
//!
//! To implement a server, the [provider] module provides helpers for handling
//! connections and individual requests given a store.
//!
//! To perform get requests, the [get] module provides utilities to perform
//! requests and store the result in a store, as well as a low level state
//! machine for executing requests.
//!
//! The [downloader] module provides a component to download blobs from
//! multiple sources and store them in a store.
//!
//! [BLAKE3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
//! [iroh]: https://docs.rs/iroh
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]
#![recursion_limit = "256"]
#![cfg_attr(iroh_docsrs, feature(doc_cfg))]

#[cfg(feature = "downloader")]
#[cfg_attr(iroh_docsrs, doc(cfg(feature = "downloader")))]
pub mod downloader;
pub mod export;
pub mod format;
pub mod get;
pub mod hashseq;
pub mod metrics;
pub mod protocol;
pub mod provider;
pub mod store;
pub mod util;

use bao_tree::BlockSize;
pub use iroh_base::hash::{BlobFormat, Hash, HashAndFormat};

pub use crate::util::{Tag, TempTag};

/// Block size used by iroh, 2^4*1024 = 16KiB
pub const IROH_BLOCK_SIZE: BlockSize = BlockSize::from_chunk_log(4);
