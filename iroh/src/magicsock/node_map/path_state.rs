//! The state kept for each network path to a remote node.

use std::collections::{BTreeMap, HashMap};

use iroh_base::NodeId;
use n0_future::time::{Duration, Instant};

use super::{
    IpPort, Source,
    node_state::{ControlMsg, SESSION_ACTIVE_TIMEOUT},
};
use crate::disco::{self, SendAddr};

/// The state of a single path to the remote endpoint.
///
/// Each path is identified by the destination [`transports::Addr`] and they are stored in
/// the [`NodeStateActor::paths`] map.
///
/// [`NodeStateActor::paths`]: super::node_state::NodeStateActor
#[derive(Debug, Default)]
pub(super) struct NewPathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
    /// The last ping sent on this path.
    pub(super) ping_sent: Option<disco::Ping>,
}
