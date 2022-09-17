use anyhow::Result;
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
}
