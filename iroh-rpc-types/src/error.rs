use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("memory addresses can not be serialized or deserialized")]
    MemAddrSerde,

    #[error("Invalid addr: {}", .0)]
    InvalidAddr(String),

    #[error("cannot bind socket to directory: {}", .0.display())]
    SocketToDir(PathBuf),

    #[error("cannot bind socket: already exists: {}", .0.display())]
    SocketExists(PathBuf),

    #[error("socket parent directory doesn't exist: {}", .0.display())]
    SocketParentDirDoesNotExist(PathBuf),

    #[error("Failed to bind to {}", .0.display())]
    FailedToBind(PathBuf, #[source] std::io::Error),

    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),

    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),

    #[error(transparent)]
    TokioOneshotRecv(#[from] tokio::sync::oneshot::error::RecvError),

    #[error("Send failed")]
    SendFailed,

    #[error("Invalid Response")]
    InvalidResponse,

    // TODO: Why do we need this?
    #[error("{}", .0)]
    Str(String),
}
