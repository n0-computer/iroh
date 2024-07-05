use std::collections::{BTreeMap, BTreeSet};

use crate::{auth::CapSelector, proto::grouping::AreaOfInterest};

mod aoi_finder;
mod capabilities;
pub mod channels;
mod data;
mod error;
mod pai_finder;
mod payload;
mod reconciler;
mod resource;
mod run;
mod static_tokens;

pub use self::channels::Channels;
pub use self::error::Error;
pub use self::run::run_session;

pub type SessionId = u64;

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
        matches!(self, Self::Live)
    }
}

#[derive(Debug, Default, Clone)]
pub enum Interests {
    #[default]
    All,
    Some(BTreeMap<CapSelector, AreaOfInterestSelector>),
}

#[derive(Debug, Default, Clone)]
pub enum AreaOfInterestSelector {
    #[default]
    Widest,
    Exact(BTreeSet<AreaOfInterest>),
}

/// Options to initialize a session with.
#[derive(Debug)]
pub struct SessionInit {
    /// List of interests we wish to synchronize, together with our capabilities to read them.
    pub interests: Interests,
    pub mode: SessionMode,
}

impl SessionInit {
    pub fn new(interests: Interests, mode: SessionMode) -> Self {
        Self { interests, mode }
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
