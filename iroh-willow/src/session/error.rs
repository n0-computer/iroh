use ed25519_dalek::SignatureError;

use crate::{
    proto::{
        meadowcap::{self, UserId},
        sync::ResourceHandle,
        willow::Unauthorised,
    },
    store::traits::SecretStoreError,
    util::channel::{ReadError, WriteError},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local store failed: {0}")]
    Store(#[from] anyhow::Error),
    #[error("authentication error: {0}")]
    Auth(#[from] crate::store::auth::AuthError),
    #[error("payload store failed: {0}")]
    PayloadStore(std::io::Error),
    #[error("payload digest does not match expected digest")]
    PayloadDigestMismatch,
    #[error("payload size does not match expected size")]
    PayloadSizeMismatch,
    #[error("local store failed: {0}")]
    KeyStore(#[from] SecretStoreError),
    #[error("failed to receive data: {0}")]
    Receive(#[from] ReadError),
    #[error("failed to send data: {0}")]
    Write(#[from] WriteError),
    #[error("wrong secret key for capability")]
    WrongSecretKeyForCapability,
    #[error("missing resource {0:?}")]
    MissingResource(ResourceHandle),
    #[error("received capability is invalid")]
    InvalidCapability,
    #[error("received capability has an invalid signature")]
    InvalidSignature,
    #[error("missing resource")]
    RangeOutsideCapability,
    #[error("received a message that is not valid in the current session state")]
    InvalidMessageInCurrentState,
    #[error("our and their area of interests refer to different namespaces")]
    AreaOfInterestNamespaceMismatch,
    #[error("our and their area of interests do not overlap")]
    AreaOfInterestDoesNotOverlap,
    #[error("received an entry which is not authorised")]
    UnauthorisedEntryReceived,
    #[error("received an unsupported message type")]
    UnsupportedMessage,
    #[error("received a message that is intended for another channel")]
    WrongChannel,
    #[error("the received nonce does not match the received committment")]
    BrokenCommittement,
    #[error("received an actor message for unknown session")]
    SessionNotFound,
    #[error("invalid parameters: {0}")]
    InvalidParameters(&'static str),
    #[error("reached an invalid state")]
    InvalidState(&'static str),
    #[error("actor failed to respond")]
    ActorFailed,
    #[error("missing user secret key for {0:?}")]
    MissingUserKey(UserId),
    #[error("a task failed to join")]
    TaskFailed(#[from] tokio::task::JoinError),
}

impl From<Unauthorised> for Error {
    fn from(_value: Unauthorised) -> Self {
        Self::UnauthorisedEntryReceived
    }
}
impl From<meadowcap::InvalidCapability> for Error {
    fn from(_value: meadowcap::InvalidCapability) -> Self {
        Self::InvalidCapability
    }
}

impl From<SignatureError> for Error {
    fn from(_value: SignatureError) -> Self {
        Self::InvalidSignature
    }
}

impl From<meadowcap::InvalidParams> for Error {
    fn from(_value: meadowcap::InvalidParams) -> Self {
        Self::InvalidParameters("")
    }
}
