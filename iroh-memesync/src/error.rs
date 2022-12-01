use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Error while reading from socket: {0}")]
    ReadError(#[from] std::io::Error),
    #[error("Error while parsing cid: {0}")]
    Cid(#[from] cid::Error),
    #[error("Error while parsing multihash: {0}")]
    Multihash(#[from] multihash::Error),
    #[error("Invalid block presence type {0}")]
    ReponseError(#[from] crate::message::ResponseError),
    #[error("invalid message {0}")]
    DecodeError(#[from] bincode::Error),
}
