use crate::proto::{grouping::AreaOfInterest, keys::UserSecretKey, wgps::ReadCapability};

pub mod coroutine;
mod error;
pub mod resource;
mod state;
mod util;

pub use self::error::Error;
pub use self::state::{SessionState, SharedSessionState};

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
