//! Implementation of the [car](https://ipld.io/specs/transport/car/) format.

mod error;
mod header;
mod reader;
mod util;
mod writer;

pub use crate::header::CarHeader;
pub use crate::reader::CarReader;
pub use crate::writer::CarWriter;

/// IPLD Block
// TODO: find a better home for this
#[derive(Clone, Debug)]
pub struct Block {
    pub cid: cid::Cid,
    pub data: Vec<u8>,
}
