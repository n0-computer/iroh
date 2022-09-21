use ahash::AHashSet;
use cid::Cid;

#[derive(Debug, Clone)]
pub struct MessageQueue {}

impl MessageQueue {
    pub fn new() -> Self {
        MessageQueue {}
    }

    pub fn startup(&mut self) {
        // TODO
    }

    pub fn add_broadcast_want_haves(&self, want_haves: &AHashSet<Cid>) {
        // TODO
    }

    pub fn add_wants(&self, want_blocks: &[Cid], want_haves: &[Cid]) {
        // TODO
    }

    pub fn add_cancels(&self, cancels: &AHashSet<Cid>) {
        // TODO
    }

    pub fn response_received(&self, cids: &[Cid]) {
        // TODO
    }

    pub fn shutdown(self) {
        // TODO
    }
}
