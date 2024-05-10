//! Defines data formats for HashSeq.
//!
//! The exact details how to use a HashSeq for specific purposes is up to the
//! user. However, the following approach is used by iroh formats:
//!
//! The first child blob is a metadata blob. It starts with a header, followed
//! by serialized metadata. We mostly use [postcard] for serialization. The
//! metadata either implicitly or explicitly refers to the other blobs in the
//! HashSeq by index.
//!
//! In a very simple case, the metadata just an array of items, where each item
//! is the metadata for the corresponding blob. The metadata array will have
//! n-1 items, where n is the number of blobs in the HashSeq.
//!
//! [postcard]: https://docs.rs/postcard/latest/postcard/
pub mod collection;
