use std::{fmt, hash::Hash};

use serde::{de::DeserializeOwned, Serialize};

pub mod gossipswarm;
pub mod hyparview;
pub mod plumtree;
pub mod topicswarm;
pub(crate) mod util;

pub use gossipswarm::{Command, Config, Event, IO};
pub use topicswarm::{TopicId, TopicSwarm};

pub trait PeerAddress: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
impl<T> PeerAddress for T where T: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
