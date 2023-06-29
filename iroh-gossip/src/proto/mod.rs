use std::{fmt, hash::Hash};

use serde::{de::DeserializeOwned, Serialize};

pub mod hyparview;
pub mod plumtree;
pub mod state;
pub mod topic;
pub mod util;

pub use state::{InEvent, Message, OutEvent, State, Timer, TopicId};
pub use topic::{Command, Config, Event, IO};

pub trait PeerAddress: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
impl<T> PeerAddress for T where T: Hash + Eq + Copy + fmt::Debug + Serialize + DeserializeOwned {}
