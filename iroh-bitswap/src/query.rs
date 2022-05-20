use ahash::AHashSet;
use cid::Cid;
use libp2p::PeerId;

use crate::{Block, Priority};

#[derive(Default, Debug)]
pub struct QueryManager {
    queries: Vec<Query>,
}

impl QueryManager {
    pub fn new_query(&mut self, query: Query) {
        self.queries.push(query);
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Query> {
        self.queries.iter_mut()
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&Query) -> bool,
    {
        self.queries.retain(f);
    }
}

#[derive(Debug)]
pub enum Query {
    /// Fetch a single CID.
    Get {
        providers: AHashSet<PeerId>,
        cid: Cid,
        priority: Priority,
        state: QueryState,
    },
    /// Cancel a single CID.
    Cancel {
        providers: AHashSet<PeerId>,
        cid: Cid,
        state: QueryState,
    },
    /// Sends a single Block.
    Send {
        receiver: PeerId,
        block: Block,
        state: QueryState,
    },
}

#[derive(Debug)]
pub enum QueryState {
    New,
    Sent(AHashSet<PeerId>),
}
