pub mod core;
use libp2p::NetworkBehaviour;

use crate::behaviour::core::{new_core_behaviour, CoreBehaviour, CoreEvent};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
pub struct Behaviour {
    pub core: CoreBehaviour,
}

impl Behaviour {
    pub fn new() -> Self {
        Behaviour {
            core: new_core_behaviour(),
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
    Core(CoreEvent),
}

impl From<CoreEvent> for Event {
    fn from(event: CoreEvent) -> Self {
        Event::Core(event)
    }
}
