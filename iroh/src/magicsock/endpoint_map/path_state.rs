//! The state kept for each network path to a remote endpoint.

use std::collections::HashMap;

use n0_future::time::Instant;

use super::Source;

/// The state of a single path to the remote endpoint.
///
/// Each path is identified by the destination [`transports::Addr`] and they are stored in
/// the [`EndpointStateActor::paths`] map.
///
/// [`transports::Addr`]: super::transports::Addr
/// [`EndpointStateActor::paths`]: super::endpoint_state::EndpointStateActor
#[derive(Debug, Default)]
pub(super) struct PathState {
    /// How we learned about this path, and when.
    ///
    /// We keep track of only the latest [`Instant`] for each [`Source`], keeping the size
    /// of the map of sources down to one entry per type of source.
    pub(super) sources: HashMap<Source, Instant>,
}
