use std::collections::HashMap;

use futures::channel::mpsc;
use libp2p::swarm::Swarm;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::behaviour::Behaviour;
use crate::client::Client;
use crate::error::RpcError;
use crate::handler::{Namespace, State};
use crate::server::Server;

pub struct RpcBuilder<T> {
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
    // default 64
    pub(crate) capacity: usize,
    // default 64
    pub(crate) stream_capacity: usize,
}

impl<T> RpcBuilder<T> {
    pub fn new() -> Self {
        RpcBuilder {
            client: ClientConfig {
                addrs: Default::default(),
            },
            server: ServerConfig {
                swarm: None,
                state: None,
                namespaces: Default::default(),
                capacity: 64,
                stream_capacity: 64,
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
    pub fn with_addr<S>(mut self, name: S, addr: Multiaddr, peer_id: PeerId) -> Self
    where
        S: Into<String>,
    {
        self.client.addrs.insert(name.into(), (addr, peer_id));
        self
    }

    /// Set the capacity of the event loop channel. Default is 64
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.server.capacity = capacity;
        self
    }

    /// Set the capacity of the stream channel. Default is 64
    pub fn with_stream_capacity(mut self, capacity: usize) -> Self {
        self.server.stream_capacity = capacity;
        self
    }

    pub fn build(self) -> Result<(Client, Server<T>), RpcError> {
        let (sender, receiver) = mpsc::channel(self.server.capacity);
        let server = Server::server_from_config(receiver, self.server)?;
        let mut client = Client::new(sender);
        for (namespace, addrs) in self.client.addrs.iter() {
            client.with_addrs(namespace.to_owned(), addrs.0.clone(), addrs.1);
        }
        Ok((client, server))
    }
}

impl<T> Default for RpcBuilder<T> {
    fn default() -> Self {
        Self::new()
    }
}
