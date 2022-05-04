use libp2p::NetworkBehaviour;

pub mod rpc;

use crate::behaviour::rpc::{new_behaviour, RpcBehaviour, RpcEvent};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
pub struct Behaviour {
    pub rpc: RpcBehaviour,
}

impl Behaviour {
    pub fn new() -> Self {
        Behaviour {
            rpc: new_behaviour(),
        }
    }
}

impl Default for Behaviour {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum Event {
    Rpc(RpcEvent),
}

impl From<RpcEvent> for Event {
    fn from(event: RpcEvent) -> Self {
        Event::Rpc(event)
    }
}
