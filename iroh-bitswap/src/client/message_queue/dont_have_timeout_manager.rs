use std::time::Duration;

use ahash::AHashSet;
use cid::Cid;

#[derive(Debug, Clone)]
pub struct DontHaveTimeoutManager {}

impl DontHaveTimeoutManager {
    pub fn new() -> Self {
        todo!()
    }

    pub fn add_pending(&self, wants: &[Cid]) {
        todo!()
    }

    pub fn cancel_pending(&self, cancels: &AHashSet<Cid>) {
        todo!()
    }

    pub fn update_message_latency(&self, latency: Duration) {
        todo!()
    }
}
