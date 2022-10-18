use thiserror::Error;

use crate::message::{BlockPresenceType, WantType};

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error while reading from socket: {0}")]
    Read(#[from] std::io::Error),
    #[error("Error while decoding bitswap message: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("Error while parsing cid: {0}")]
    Cid(#[from] cid::Error),
    #[error("Error while parsing multihash: {0}")]
    Multihash(#[from] multihash::Error),
    #[error("Invalid block presence type {0}")]
    InvalidBlockPresenceType(#[from] num_enum::TryFromPrimitiveError<BlockPresenceType>),
    #[error("Invalid want type {0}")]
    InvalidWantType(#[from] num_enum::TryFromPrimitiveError<WantType>),
}
