use std::collections::HashMap;

use futures::channel::mpsc;
use libp2p::swarm::Swarm;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::behaviour::Behaviour;
use crate::client::Client;
use crate::error::RpcError;
use crate::handler::{Namespace, State};
use crate::server::{AddressBook, Server};

pub struct RpcBuilder<T> {
    pub(crate) _client: ClientConfig,
    pub(crate) server: ServerConfig<T>,
}

pub struct ClientConfig {}

pub struct ServerConfig<T> {
    pub(crate) swarm: Option<Swarm<Behaviour>>,
    pub(crate) my_namespace: String,
    pub(crate) addresses: AddressBook,
    pub(crate) state: Option<State<T>>,
    pub(crate) namespaces: HashMap<String, Namespace<T>>,
    // default 64
    pub(crate) capacity: usize,
    // default 64
    pub(crate) stream_capacity: usize,
}

impl<T> RpcBuilder<T> {
    pub fn new<I: Into<String>>(namespace: I) -> Self {
        RpcBuilder {
            _client: ClientConfig {},
            server: ServerConfig {
                swarm: None,
                my_namespace: namespace.into(),
                addresses: Default::default(),
                state: None,
                namespaces: Default::default(),
                capacity: 64,
                stream_capacity: 64,
            },
        }
    }

    pub fn with_swarm(mut self, swarm: Swarm<Behaviour>) -> Self {
        self.server.swarm = Some(swarm);
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

    pub fn with_addr<S>(mut self, name: S, addr: Vec<Multiaddr>, peer_id: PeerId) -> Self
    where
        S: Into<String>,
    {
        self.server.addresses.insert(name.into(), addr, peer_id);
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
        let server = Server::server_from_config(sender.clone(), receiver, self.server)?;
        Ok((Client::new(sender), server))
    }
}
