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

use self::{coroutine::Channels, resource::ScopedResources};

pub mod coroutine;
mod error;
pub mod resource;
mod state;
mod util;

pub use self::error::Error;
pub use self::state::{SharedSessionState, SessionState};

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
