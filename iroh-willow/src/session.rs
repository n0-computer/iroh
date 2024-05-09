use std::collections::{HashMap, HashSet};

use crate::proto::{grouping::AreaOfInterest, keys::UserSecretKey, wgps::ReadCapability};

pub mod coroutine;
mod error;
pub mod resource;
mod state;
mod util;

pub use self::error::Error;
pub use self::state::{SessionState, SharedSessionState};

/// To break symmetry, we refer to the peer that initiated the synchronisation session as Alfie,
/// and the other peer as Betty.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// The peer that initiated the synchronisation session.
    Alfie,
    /// The peer that accepted the synchronisation session.
    Betty,
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
    pub user_secret_key: UserSecretKey,
    pub interests: HashMap<ReadCapability, HashSet<AreaOfInterest>>,
}

impl SessionInit {
    pub fn with_interest(
        user_secret_key: UserSecretKey,
        capability: ReadCapability,
        area_of_interest: AreaOfInterest,
    ) -> Self {
        Self {
            user_secret_key,
            interests: HashMap::from_iter([(capability, HashSet::from_iter([area_of_interest]))]),
        }
    }
}
