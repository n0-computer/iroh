//! Send data over the internet.
//!
//! # Getting started
//!
//! ## Example
//!
//! Create a new node and add some data to the blobs store. This data will be
//! available over the network.
//!
//! ```rust
//! # async fn run() -> anyhow::Result<()> {
//! let node = iroh::node::Node::memory().spawn().await?;
//! let client = node.client();
//! let hash = client.blobs().add_bytes(b"some data".to_vec()).await?.hash;
//! println!("hash: {}", hash);
//! # Ok(())
//! # }
//! ```
//!
//! ## Explanation
//!
//! ### Iroh node
//!
//! To create an iroh [Node](crate::node::Node), you use the
//! [Builder](crate::node::Builder) to configure the node and to spawn it.
//!
//! There are also shortcuts to create an in [memory](crate::node::Node::memory)
//! or [persistent](crate::node::Node::persistent) node with default settings.
//!
//! ## Iroh client
//!
//! A node is controlled via a **client**. The client provides the main API to
//! interact with a node, no matter if it is a local in-process node or a node
//! in a different process. All clients are cheaply cloneable and can be shared
//! across threads.
//!
//! A handle to the client is available via the
//! [client](crate::node::Node::client) method on the node.
//!
//! Node also implements [Deref](std::ops::Deref) to the client, so you can call
//! client methods directly on the node.
//!
//! ## Subsystems
//!
//! The client provides access to various subsystems:
//! - [net](crate::client::net):
//!   information and control of the iroh network
//! - [blobs](crate::client::blobs):
//!   manage and share content-addressed blobs of data
//! - [tags](crate::client::tags):
//!   tags to tell iroh what data is important
//! - [gossip](crate::client::gossip):
//!   exchange data with other nodes via a gossip protocol
//!
//! - [authors](crate::client::authors):
//!   interact with document authors
//! - [docs](crate::client::docs):
//!   interact with documents
//!
//! The subsystem clients can be obtained cheaply from the main iroh client.
//! They are also cheaply cloneable and can be shared across threads.
//!
//! So if you have code that only needs to interact with one subsystem, pass
//! it just the subsystem client.
//!
//! ## Remote nodes
//!
//! To obtain a client to a remote node, you can use
//! [connect](crate::client::Iroh::connect_path) to connect to a node running on
//! the same machine, using the given data directory, or
//! [connect_addr](crate::client::Iroh::connect_addr) to connect to a node at a
//! known address.
//!
//! **Important**: the protocol to a remote node is not stable and will
//! frequently change. So the client and server must be running the same version of iroh.
//!
//! ## Reexports
//!
//! The iroh crate re-exports the following crates:
//! - [iroh_base] as [`base`]
//! - [iroh_blobs] as [`blobs`]
//! - [iroh_docs] as [`docs`]
//! - [iroh_gossip] as [`gossip`]
//! - [iroh_net] as [`net`]
//!
//! ## Feature Flags
//!
//! - `metrics`: Enable metrics collection. Enabled by default.
//! - `fs-store`: Enables the disk based storage backend for `iroh-blobs`. Enabled by default.
//!
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

// re-export the iroh crates
#[doc(inline)]
pub use iroh_base as base;
#[doc(inline)]
pub use iroh_blobs as blobs;
#[doc(inline)]
pub use iroh_docs as docs;
#[doc(inline)]
pub use iroh_gossip as gossip;
#[doc(inline)]
pub use iroh_net as net;

pub mod client;
pub mod node;
pub mod util;

mod rpc_protocol;

/// Expose metrics module
#[cfg(feature = "metrics")]
#[cfg_attr(all(docsrs, feature = "metrics"), doc(cfg(feature = "metrics")))]
pub mod metrics;
