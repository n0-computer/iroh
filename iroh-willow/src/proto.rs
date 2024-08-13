//! Protocol data types used in willow.
//!
//! These are mostly type aliases onto [`willow-rs`] types, with some additional helpers.
//!
//! This module also contains the crypthographic primitives for fingerprints and private area
//! intersection.

pub mod data_model;
pub mod grouping;
pub mod keys;
pub mod meadowcap;
pub mod pai;
pub mod wgps;
