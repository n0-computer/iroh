use ed25519_dalek::SignatureError;

use crate::{
    proto::{
        meadowcap::{self, UserId},
        sync::ResourceHandle,
        willow::Unauthorised,
    },
    session::{pai_finder::PaiError, resource::MissingResource},
    store::traits::SecretStoreError,
    util::channel::{ReadError, WriteError},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local store failed: {0}")]
    Store(#[from] anyhow::Error),
    #[error("authentication error: {0}")]
    Auth(#[from] crate::auth::AuthError),
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
    #[error("no known interests for given capability")]
    NoKnownInterestsForCapability,
    #[error("private area intersection error: {0}")]
    Pai(#[from] PaiError),
    #[error("net failed: {0}")]
    Net(anyhow::Error),
    #[error("channel receiver dropped")]
    ChannelDropped,
    #[error("our node is shutting down")]
    ShuttingDown,
}

#[derive(Debug, thiserror::Error)]
#[error("channel receiver dropped")]
pub struct ChannelReceiverDropped;
impl From<ChannelReceiverDropped> for Error {
    fn from(_: ChannelReceiverDropped) -> Self {
        Self::ChannelDropped
    }
}

// TODO: Remove likely?
// Added this to be able to implement PartialEq on EventKind for tests
// but many errors are not PartialEq, so we just return false for them, always
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Store(_), Self::Store(_)) => false,
            (Self::Auth(_), Self::Auth(_)) => false,
            (Self::PayloadStore(_), Self::PayloadStore(_)) => false,
            (Self::KeyStore(_), Self::KeyStore(_)) => false,
            (Self::Receive(_), Self::Receive(_)) => false,
            (Self::Write(_), Self::Write(_)) => false,
            (Self::TaskFailed(_), Self::TaskFailed(_)) => false,
            (Self::Pai(_), Self::Pai(_)) => false,
            (Self::Net(_), Self::Net(_)) => false,
            (Self::MissingResource(l0), Self::MissingResource(r0)) => l0 == r0,
            (Self::InvalidParameters(l0), Self::InvalidParameters(r0)) => l0 == r0,
            (Self::InvalidState(l0), Self::InvalidState(r0)) => l0 == r0,
            (Self::MissingUserKey(l0), Self::MissingUserKey(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl Eq for Error {}

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

impl From<MissingResource> for Error {
    fn from(value: MissingResource) -> Self {
        Self::MissingResource(value.0)
    }
}
