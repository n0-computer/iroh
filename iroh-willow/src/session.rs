use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use ed25519_dalek::SignatureError;

use iroh_base::{hash::Hash, key::NodeId};
use tokio::sync::Notify;
use tracing::{debug, info, instrument, trace, warn};

use crate::{
    proto::{
        grouping::{AreaOfInterest, NamespacedRange, ThreeDRange},
        keys::{NamespaceId, NamespacePublicKey, UserPublicKey, UserSecretKey, UserSignature},
        meadowcap::InvalidCapability,
        wgps::{
            AccessChallenge, AreaOfInterestHandle, CapabilityHandle, ChallengeHash,
            CommitmentReveal, Fingerprint, HandleType, LengthyEntry, LogicalChannel, Message,
            ReadCapability, ReconciliationAnnounceEntries, ReconciliationSendEntry,
            ReconciliationSendFingerprint, ResourceHandle, SetupBindAreaOfInterest,
            SetupBindReadCapability, SetupBindStaticToken, StaticToken, StaticTokenHandle,
        },
        willow::{AuthorisationToken, AuthorisedEntry, Unauthorised},
    },
    store::{
        actor::{StoreHandle, ToActor},
        SplitAction, Store, SyncConfig,
    },
    util::channel::ReadOutcome,
};

use self::{
    coroutine::{Channels, SessionState, SessionStateInner},
    resource::ScopedResources,
};

pub mod coroutine;
pub mod resource;
mod util;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("local store failed")]
    Store(#[from] anyhow::Error),
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
    #[error("the received nonce does not match the received committment")]
    BrokenCommittement,
    #[error("received an actor message for unknown session")]
    SessionNotFound,
}

impl From<Unauthorised> for Error {
    fn from(_value: Unauthorised) -> Self {
        Self::UnauthorisedEntryReceived
    }
}
impl From<InvalidCapability> for Error {
    fn from(_value: InvalidCapability) -> Self {
        Self::InvalidCapability
    }
}

impl From<SignatureError> for Error {
    fn from(_value: SignatureError) -> Self {
        Self::InvalidSignature
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    Betty,
    Alfie,
}

#[derive(Copy, Clone, Debug)]
pub enum Scope {
    Ours,
    Theirs,
}

#[derive(Debug)]
pub struct SessionInit {
    pub user_secret_key: UserSecretKey,
    // TODO: allow multiple capabilities?
    pub capability: ReadCapability,
    // TODO: allow multiple areas of interest?
    pub area_of_interest: AreaOfInterest,
}
