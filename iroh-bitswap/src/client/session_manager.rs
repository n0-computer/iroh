use cid::Cid;
use libp2p::PeerId;

#[derive(Debug, Clone)]
pub struct SessionManager {}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {}
    }

    pub fn receive_from(&self, peer: &PeerId, blocks: &[Cid], haves: &[Cid], dont_haves: &[Cid]) {
        todo!()
    }
}
