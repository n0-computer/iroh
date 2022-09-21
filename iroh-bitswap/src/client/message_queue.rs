use ahash::AHashSet;
use cid::Cid;

#[derive(Debug, Clone)]
pub struct MessageQueue {}

impl MessageQueue {
    pub fn new() -> Self {
        todo!()
    }

    pub fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        todo!()
    }

    pub fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        todo!()
    }

    pub fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        todo!()
    }
}
