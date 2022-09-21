use libp2p::PeerId;

#[derive(Debug, Clone)]
pub struct Session {}

impl Session {
    pub fn new() -> Self {
        todo!()
    }

    pub fn id(&self) -> u64 {
        todo!()
    }

    pub fn signal_availability(&self, peer: &PeerId, is_connected: bool) {
        todo!()
    }
}
