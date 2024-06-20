use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::proto::grouping::{Area, AreaOfInterest};
use crate::proto::keys::NamespaceId;
use crate::proto::sync::{AccessChallenge, AreaOfInterestHandle, ChallengeHash, ReadAuthorisation};

pub mod channels;
mod data;
mod error;
mod payload;
mod reconciler;
mod resource;
mod run;
mod state;

pub use self::channels::Channels;
pub use self::error::Error;
pub use self::state::Session;

pub type SessionId = u64;

/// Data from the initial transmission
///
/// This happens before the session is initialized.
#[derive(Debug)]
pub struct InitialTransmission {
    /// The [`AccessChallenge`] nonce, whose hash we sent to the remote.
    pub our_nonce: AccessChallenge,
    /// The [`ChallengeHash`] we received from the remote.
    pub received_commitment: ChallengeHash,
    /// The maximum payload size we received from the remote.
    pub their_max_payload_size: u64,
}

/// To break symmetry, we refer to the peer that initiated the synchronisation session as Alfie,
/// and the other peer as Betty.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// The peer that initiated the synchronisation session.
    Alfie,
    /// The peer that accepted the synchronisation session.
    Betty,
}

impl Role {
    /// Returns `true` if we initiated the session.
    pub fn is_alfie(&self) -> bool {
        matches!(self, Role::Alfie)
    }
    /// Returns `true` if we accepted the session.
    pub fn is_betty(&self) -> bool {
        matches!(self, Role::Betty)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionMode {
    /// Run a single, full reconciliation, and then quit.
    ReconcileOnce,
    /// Run reconciliations and data mode, until intentionally closed.
    Live,
}

impl SessionMode {
    pub fn is_live(&self) -> bool {
        *self == Self::Live
    }
}

#[derive(Debug, Default, Clone)]
pub enum Interests {
    #[default]
    All,
    Some(BTreeMap<NamespaceId, BTreeSet<AreaOfInterest>>),
    // TODO: Remove?
    Explicit(HashMap<ReadAuthorisation, BTreeSet<AreaOfInterest>>),
}

// TODO: I think the interests would be better represented like this maybe?
// #[derive(Debug, Default, Clone)]
// pub enum Interests2 {
//     #[default]
//     All,
//     Some(Vec<(CapSelector, AreaOfInterestSelector)>),
// }
//
// #[derive(Debug, Default, Clone)]
// pub enum AreaOfInterestSelector {
//     #[default]
//     Widest,
//     Exact(BTreeSet<AreaOfInterest>),
// }

/// Options to initialize a session with.
#[derive(Debug)]
pub struct SessionInit {
    /// List of interests we wish to synchronize, together with our capabilities to read them.
    pub interests: Interests,
    pub mode: SessionMode,
}

impl SessionInit {
    /// Returns a [`SessionInit`] with a single interest.
    pub fn with_interest(
        mode: SessionMode,
        namespace: NamespaceId,
        area_of_interest: AreaOfInterest,
    ) -> Self {
        Self {
            mode,
            interests: Interests::Some(BTreeMap::from_iter([(
                namespace,
                BTreeSet::from_iter([area_of_interest]),
            )])),
        }
    }

    pub fn with_explicit_interest(
        mode: SessionMode,
        authorisation: ReadAuthorisation,
        area_of_interest: AreaOfInterest,
    ) -> Self {
        Self {
            mode,
            interests: Interests::Explicit(HashMap::from_iter([(
                authorisation,
                BTreeSet::from_iter([area_of_interest]),
            )])),
        }
    }
}

/// The bind scope for resources.
///
/// Resources are bound by either peer
#[derive(Copy, Clone, Debug)]
pub enum Scope {
    /// Resources bound by ourselves.
    Ours,
    /// Resources bound by the other peer.
    Theirs,
}

/// Intersection between two areas of interest.
#[derive(Debug, Clone)]
pub struct AreaOfInterestIntersection {
    pub our_handle: AreaOfInterestHandle,
    pub their_handle: AreaOfInterestHandle,
    pub intersection: Area,
    pub namespace: NamespaceId,
}
