use async_channel::RecvError;
use async_channel::SendError;
use libp2p::PeerId;
use thiserror::Error;
use tokio::task::JoinError;

use crate::{
    message::{BlockPresenceType, WantType},
    network::OutEvent,
};

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

    #[error(transparent)]
    TokioOneshotRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("engine refs not shutdown yet")]
    EngineRefsNotShutdown,

    #[error("server refs not shutdown yet")]
    ServerRefsNotShutdown,

    #[error("blockstore manager refs not shutdown")]
    BlockstoreManagerRefsNotShutdown,

    #[error("Failed to send close")]
    FailedToSendClose,

    #[error("Session refs not shutdown ({})", .0)]
    SessionRefsNotShutdown(usize),

    #[error("Session manager refs not shutdown")]
    SessionManagerRefsNotShutdown,

    #[error("failed to stop worker")]
    FailedToStopWorker,

    #[error(transparent)]
    Join(#[from] JoinError),

    #[error("Sending Operation failed")]
    SendOp,

    #[error("Channel send")]
    ChannelSendOutEvent(#[from] SendError<OutEvent>),

    #[error("No Ping available")]
    NoPingAvailable,

    #[error("send:{}: channel send failed", .0)]
    ChannelSendFailed(PeerId, #[source] SendError<OutEvent>),

    #[error("send:{}: channel gone", .0)]
    SendChannelGone(PeerId, #[source] tokio::sync::oneshot::error::RecvError),

    #[error("send:{}: failed: {:?}", .0, .1)]
    SendFailed(PeerId, Vec<Error>),

    #[error("dial:{}: error", .0)]
    DialError(usize, #[source] tokio::time::error::Elapsed),

    #[error("dial:{}: failed: {}", .0, .1)]
    DialFailed(usize, String),

    #[error("dial:{}: channel send", .0)]
    DialChannelSend(usize, #[source] SendError<OutEvent>),

    #[error(transparent)]
    SendError(#[from] crate::network::SendError),

    #[error("Error receiving block")]
    RecvBlock(#[source] RecvError),

    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Missing keys")]
    MissingKeys,

    #[error("Message queue {} already stopped", .0)]
    MessageQueueAlreadyStopped(PeerId),

    #[error("Session {} too many refs", .0)]
    SessionTooManyRefs(u64),
}
