use std::fmt::{Debug, Display};

use bytes::{Bytes, BytesMut};
use cid::Cid;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Response(Response),
    Request(Request),
}

impl Message {
    /// Decoding from a given `BytesMut`.
    pub fn from_bytes(bytes: BytesMut) -> Result<Self, Error> {
        let msg = bincode::deserialize(&bytes)?;
        Ok(msg)
    }

    /// Decode into a `BytesMut` buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        let out = bincode::serialize(&self).expect("should always succeed");
        out
    }

    pub fn id(&self) -> QueryId {
        match self {
            Message::Request(r) => r.id,
            Message::Response(r) => r.id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct QueryId(u64);

impl From<u64> for QueryId {
    fn from(id: u64) -> Self {
        QueryId(id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Request ID, should be unique for the tripple
    /// (Sender PeerID, Receiver PeerID, id)
    pub id: QueryId,
    /// Query.
    pub query: Query,
}

impl Request {
    pub fn from_query(id: QueryId, query: Query) -> Self {
        Request { id, query }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    /// Path for the query.
    pub path: Path,
    /// Recursion configuration.
    pub recursion: Recursion,
}

impl Query {
    pub fn from_path(path: Path) -> Self {
        Query {
            path,
            recursion: Recursion::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Recursion {
    None,
    Some {
        /// Maximum depth of recursion.
        depth: u8,
        /// Recursion direction.
        direction: RecursionDirection,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RecursionDirection {
    BreadthFirst = 0,
    DepthFirst = 1,
}

impl From<bool> for RecursionDirection {
    fn from(val: bool) -> Self {
        if val {
            RecursionDirection::DepthFirst
        } else {
            RecursionDirection::BreadthFirst
        }
    }
}

impl From<RecursionDirection> for bool {
    fn from(dir: RecursionDirection) -> Self {
        match dir {
            RecursionDirection::BreadthFirst => false,
            RecursionDirection::DepthFirst => true,
        }
    }
}

/// Represents something like `/ipfs/<cid>/foo/bar/3/link.txt`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Path {
    pub root: Cid,
    pub tail: Vec<String>,
}

impl Path {
    pub fn join(mut self, el: impl Into<String>) -> Self {
        self.tail.push(el.into());
        self
    }
}

impl From<Cid> for Path {
    fn from(cid: Cid) -> Self {
        Path {
            root: cid,
            tail: vec![],
        }
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.root)?;
        for part in &self.tail {
            write!(f, "/{}", part)?;
        }

        Ok(())
    }
}

/// There will be many responses sent for each requests
/// If invalid/not supported 1 error response, otherwise
/// - for each query
///   - either an error or
///   - for each path segment
///     - ResponseOk
///   - for each block (breadth first) at the end for recursion
///     - ResponseOk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: QueryId,
    pub response: Result<ResponseOk, ResponseError>,
}

impl Response {
    /// Is this the last response?
    pub fn is_last(&self) -> bool {
        match &self.response {
            Ok(res) => res.last,
            Err(_) => true,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseOk {
    /// 0-index of which block this is
    pub index: u32,
    /// Is this the last response (for this query)
    pub last: bool,
    /// The actual data
    pub data: Bytes,
}

impl Debug for ResponseOk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseOk")
            .field("index", &self.index)
            .field("last", &self.last)
            .field("data", &self.data.len())
            .finish()
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseError {
    /// The request itself is invalid
    #[error("invalid request")]
    InvalidRequest,
    /// Limit reached
    #[error("block limit reached: {limit}")]
    BlockLimit {
        /// the limit the responder has
        limit: u32,
    },
    /// A part of the path was invalid.
    #[error("invalid link, valid up to: {valid_up_to}")]
    InvalidLink {
        /// The number of segments of the path that were valid, 0-indexed.
        valid_up_to: u32,
    },
    /// Something in the path/query is not supported.
    #[error("unusupported query")]
    UnsupportedQuery,
    /// Data is actually not available.
    #[error("not found: {0}")]
    NotFound(Path),
    /// The responder is under too much load.
    #[error("too much load")]
    TooMuchLoad,
    /// Any other type of failure.
    #[error("other")]
    Other,
}
