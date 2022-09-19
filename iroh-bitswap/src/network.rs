use anyhow::Result;
use cid::Cid;
use libp2p::PeerId;

use crate::message::BitswapMessage;

#[derive(Debug, Clone)]
pub struct Network {}

impl Network {
    pub fn stop(self) {
        todo!()
    }

    pub fn self_id(&self) -> &PeerId {
        todo!()
    }

    pub fn send_message(&self, peer: PeerId, message: BitswapMessage) -> Result<()> {
        todo!()
    }

    pub fn provide(&self, key: Cid) -> Result<()> {
        todo!()
    }
}
