//! Protocol implementation, as a state machine without IO

use std::{fmt, hash::Hash};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

mod hyparview;
mod plumtree;
pub mod topic;
pub mod state;
pub mod util;

pub use state::{InEvent, Message, OutEvent, State, Timer, TopicId};
pub use topic::{Command, Config, Event, IO};

/// A peer's identifier or address
///
/// The protocol implementation is generic over this trait. When implementing the protocol,
/// a concrete type must be chosen that will then be used throughout the implementation to identify
/// and index individual peers.
///
/// Note that the concrete type will be used in protocol messages. Therefore, implementations of
/// the protocol are only compatible if the same concrete type is supplied for this trait.
///
/// TODO: Rename to `PeerIdT`?
pub trait PeerAddress: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
impl<T> PeerAddress for T where T: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}

/// Opaque binary data that is transmitted on messages that introduce new peers.
///
/// Implementations may use these bytes to supply addresses or other information needed to connect
/// to a peer that is not included in the peer's [`PeerAddress`].
pub type PeerData = bytes::Bytes;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PeerInfo<PA> {
    pub id: PA,
    pub data: PeerData,
}

impl<PA> From<(PA, PeerData)> for PeerInfo<PA> {
    fn from((id, data): (PA, PeerData)) -> Self {
        Self { id, data }
    }
}
