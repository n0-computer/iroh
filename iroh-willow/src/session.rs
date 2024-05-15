use std::collections::{HashMap, HashSet};

use crate::proto::{grouping::AreaOfInterest, wgps::ReadCapability};

pub mod aoi_finder;
pub mod channels;
pub mod coroutine;
mod error;
pub mod resource;
mod state;
mod util;

pub use self::channels::Channels;
pub use self::error::Error;
pub use self::state::{SessionState, Session};

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
    pub fn is_alfie(&self) -> bool {
        matches!(self, Role::Alfie)
    }
    pub fn is_betty(&self) -> bool {
        matches!(self, Role::Betty)
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

#[derive(Debug)]
pub struct SessionInit {
    pub interests: HashMap<ReadCapability, HashSet<AreaOfInterest>>,
}

impl SessionInit {
    pub fn with_interest(capability: ReadCapability, area_of_interest: AreaOfInterest) -> Self {
        Self {
            interests: HashMap::from_iter([(capability, HashSet::from_iter([area_of_interest]))]),
        }
    }
}
