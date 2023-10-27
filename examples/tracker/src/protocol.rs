//! The protocol for communicating with the tracker.
use std::collections::BTreeSet;

use iroh_bytes::HashAndFormat;
use iroh_net::key::PublicKey;
use serde::{Deserialize, Serialize};

/// The ALPN string for this protocol
pub const TRACKER_ALPN: &[u8] = b"n0/tracker/1";
/// Maximum size of a request
pub const REQUEST_SIZE_LIMIT: usize = 1024 * 16;

/// Announce kind
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnnounceKind {
    /// The peer supposedly has some of the data.
    Partial,
    /// The peer supposedly has the complete data.
    Complete,
}

impl AnnounceKind {
    pub fn from_complete(complete: bool) -> Self {
        if complete {
            Self::Complete
        } else {
            Self::Partial
        }
    }
}

/// Announce that a peer claims to have some blobs or set of blobs.
///
/// A peer can announce having some data, but it should also be able to announce
/// that another peer has the data. This is why the peer is included.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Announce {
    /// The peer that supposedly has the data.
    pub peer: PublicKey,
    /// The blobs or sets that the peer claims to have.
    pub content: BTreeSet<HashAndFormat>,
    /// The kind of the announcement.
    pub kind: AnnounceKind,
}

///
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFlags {
    /// Only return peers that supposedly have the complete data.
    ///
    /// If this is false, the response might contain peers that only have some of the data.
    pub complete: bool,

    /// Only return peers that have been validated.
    ///
    /// In case of a partial query, validation just means a check that the peer exists
    /// and returns the size for the data.
    ///
    /// In case of a complete query, validation means that the peer has been randomly
    /// probed for the data.
    pub validated: bool,
}

/// Query a peer for a blob or set of blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {
    /// The content we want to find.
    ///
    /// It's a difference if a peer has a blob or a hash seq and all of its children.
    pub content: HashAndFormat,
    /// The mode of the query.
    pub flags: QueryFlags,
}

/// A response to a query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// The content that was queried.
    pub content: HashAndFormat,
    /// The peers that supposedly have the content.
    ///
    /// If there are any addrs, they are as seen from the tracker,
    /// so they might or might not be useful.
    pub peers: Vec<PublicKey>,
}

/// A request to the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    /// Announce info
    Announce(Announce),
    /// Query info
    Query(Query),
}

/// A response from the tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    /// Response to a query
    QueryResponse(QueryResponse),
}
