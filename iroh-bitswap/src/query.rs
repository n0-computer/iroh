use ahash::AHashSet;
use cid::Cid;
use libp2p::PeerId;

use crate::{Block, Priority};

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
