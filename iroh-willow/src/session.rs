use std::collections::{hash_map, BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    auth::CapSelector,
    proto::{grouping::AreaOfInterest, sync::ReadAuthorisation},
};

mod aoi_finder;
mod capabilities;
pub mod channels;
mod data;
mod error;
pub mod events;
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
    Select(HashMap<CapSelector, AreaOfInterestSelector>),
    Exact(HashMap<ReadAuthorisation, HashSet<AreaOfInterest>>),
}

impl Interests {
    pub fn select() -> SelectBuilder {
        SelectBuilder::default()
    }
}

#[derive(Default, Debug)]
pub struct SelectBuilder(HashMap<CapSelector, AreaOfInterestSelector>);

impl SelectBuilder {
    pub fn add_full(mut self, cap: impl Into<CapSelector>) -> Self {
        let cap = cap.into();
        self.0.insert(cap, AreaOfInterestSelector::Widest);
        self
    }

    pub fn area(
        mut self,
        cap: impl Into<CapSelector>,
        aois: impl IntoIterator<Item = impl Into<AreaOfInterest>>,
    ) -> Self {
        let cap = cap.into();
        let aois = aois.into_iter();
        let aois = aois.map(|aoi| aoi.into());
        match self.0.entry(cap) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(AreaOfInterestSelector::Exact(aois.collect()));
            }
            hash_map::Entry::Occupied(mut entry) => match entry.get_mut() {
                AreaOfInterestSelector::Widest => {}
                AreaOfInterestSelector::Exact(existing) => existing.extend(aois),
            },
        }
        self
    }

    pub fn build(self) -> Interests {
        Interests::Select(self.0)
    }
}

impl From<SelectBuilder> for Interests {
    fn from(builder: SelectBuilder) -> Self {
        builder.build()
    }
}

#[derive(Debug, Clone)]
pub enum SessionUpdate {
    AddInterests(Interests),
}

// impl Interest {
//     pub fn merge(&self, other: &Interests) -> Self {
//         match (self, other) {
//             (Self::All, _) => Self::All,
//             (_, Self::All) => Self::All,
//             (Self::Some(a), Self::Some(b)) => {
//
//             }
//
//         }
//     }
// }

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
    pub fn new(interests: impl Into<Interests>, mode: SessionMode) -> Self {
        let interests = interests.into();
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
