use std::collections::HashMap;

use libp2p::swarm::Swarm;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::behaviour::Behaviour;
use crate::handler::{Namespace, State};

pub struct RpcConfig<T> {
    pub(crate) client: ClientConfig,
    pub(crate) server: ServerConfig<T>,
}

pub struct ClientConfig {
    // TODO: should be refactored to accept a list of multiaddrs
    pub(crate) addrs: HashMap<String, (Multiaddr, PeerId)>,
}

pub struct ServerConfig<T> {
    pub(crate) swarm: Option<Swarm<Behaviour>>,
    pub(crate) state: Option<State<T>>,
    pub(crate) namespaces: HashMap<String, Namespace<T>>,
}

impl<T> RpcConfig<T> {
    pub fn new() -> Self {
        RpcConfig {
            client: ClientConfig {
                addrs: Default::default(),
            },
            server: ServerConfig {
                swarm: None,
                state: None,
                namespaces: Default::default(),
            },
        }
    }

    pub fn with_swarm<I: Into<Swarm<Behaviour>>>(mut self, swarm: I) -> Self {
        self.server.swarm = Some(swarm.into());
        self
    }

    pub fn with_state<I: Into<State<T>>>(mut self, state: I) -> Self {
        self.server.state = Some(state.into());
        self
    }

    pub fn with_namespace<S, F>(mut self, name: S, with_methods: F) -> Self
    where
        S: Into<String>,
        F: FnOnce(Namespace<T>) -> Namespace<T>,
    {
        let name = name.into();
        let n = Namespace::new(name.clone());
        let n = with_methods(n);
        self.server.namespaces.insert(name, n);
        self
    }

    // TODO: should be a list of possible addrs `with_addrs`
    pub fn with_addr(mut self, name: String, addr: Multiaddr, peer_id: PeerId) -> Self {
        self.client.addrs.insert(name, (addr, peer_id));
        self
    }
}
