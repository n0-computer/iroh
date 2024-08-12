//! Implementation of willow

#![allow(missing_docs)]
#![deny(unsafe_code)]

// pub mod engine;
pub mod form;
// pub mod net;
pub mod proto;
// pub mod session;
pub mod interest;
pub mod store;
pub mod util;

/// To break symmetry, we refer to the peer that initiated the synchronisation session as Alfie,
/// and the other peer as Betty.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Role {
    /// The peer that initiated the synchronisation session.
    Alfie,
    /// The peer that accepted the synchronisation session.
    Betty,
}
