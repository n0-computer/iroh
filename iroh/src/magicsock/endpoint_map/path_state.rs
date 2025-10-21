//! The state kept for each network path to a remote endpoint.

use std::collections::HashMap;

use n0_future::time::Instant;

use super::Source;
use crate::disco::TransactionId;

/// The state of a single path to the remote endpoint.
///
/// Each path is identified by the destination [`transports::Addr`] and they are stored in
/// the [`NodeStateActor::paths`] map.
///
/// [`NodeStateActor::paths`]: super::node_state::NodeStateActor
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
    /// The last ping sent on this path.
    pub(super) ping_sent: Option<TransactionId>,
}
