use std::collections::HashMap;

use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::commands::{Command, SenderType};
use crate::config::RpcConfig;
use crate::error::RpcError;
use crate::serde::{deserialize_response, serialize_request, DeserializeOwned, Serialize};
use crate::server::Server;
use crate::stream::InStream;

/// The Rpc Client manages outgoing and incoming calls over rpc
/// It knows how to reach the different Iroh processes, and knows
/// how to handle incoming requests
pub struct Client<T> {
    command_sender: mpsc::Sender<Command>,
    // TODO: should be a list of addrs per namespace (not just one)
    addresses: HashMap<String, (Multiaddr, PeerId)>,
    server: Server<T>,
    next_id: Iter,
}

impl<T> Client<T> {
    /// Create a new client. Not recommended. It is perfered to use `rpc_from_config`
    pub fn new(command_sender: mpsc::Sender<Command>, server: Server<T>) -> Client<T> {
        Client {
            command_sender,
            addresses: Default::default(),
            server,
            next_id: Iter::new(),
        }
    }

    pub fn rpc_from_config(cfg: RpcConfig<T>) -> Result<Client<T>, RpcError> {
        let (sender, receiver) = mpsc::channel(0);
        let server = Server::server_from_config(receiver, cfg.server)?;
        let mut client = Client::new(sender, server);
        for (namespace, addrs) in cfg.client.addrs.iter() {
            client.with_addrs(namespace.to_owned(), addrs.0.clone(), addrs.1);
        }
        Ok(client)
    }

    /// Run the event/command loop, should be spawned in an thread
    pub async fn run(self) {
        self.server.run().await;
    }

    /// Dial all known addresses associated with the given namespaces
    pub async fn dial_all(&mut self) -> Result<(), RpcError> {
        let mut dials = Vec::new();
        for (_, (addr, peer_id)) in self.addresses.to_owned() {
            let handle = tokio::spawn(dial(self.command_sender.clone(), addr, peer_id));
            dials.push(handle);
        }
        let outcomes = futures::future::join_all(dials).await;
        if outcomes.iter().any(|o| o.is_err()) {
            return Err(RpcError::TODO);
        };
        Ok(())
    }

    /// Listen on a particular multiaddress
    pub async fn listen(&mut self, addr: Multiaddr) -> Result<(), RpcError> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::StartListening { sender, addr })
            .await
            .expect("Receiver to not be dropped.");
        match receiver.await.expect("Sender to not be dropped") {
            SenderType::Ack => Ok(()),
            SenderType::Error(_) => Err(RpcError::TODO),
            _ => Err(RpcError::TODO),
        }
    }

    /// Signal the Rpc event loop to stop listening
    pub async fn shutdown(mut self) {
        self.command_sender
            .send(Command::ShutDown)
            .await
            .expect("Receiver to still be active.");
    }

    /// Add an address and peer id associated with a particular namespace
    pub fn with_connection_to(
        mut self,
        namespace: String,
        address: Multiaddr,
        peer_id: PeerId,
    ) -> Self {
        self.with_addrs(namespace, address, peer_id);
        self
    }

    // with_addrs is a private helper function that add a namespace/address association
    // without taking ownership
    fn with_addrs(&mut self, namespace: String, address: Multiaddr, peer_id: PeerId) {
        self.addresses.insert(namespace, (address, peer_id));
    }

    /// Send a single request and expects a single response
    pub async fn call<U, V>(
        &mut self,
        namespace: String,
        method: String,
        params: U,
    ) -> Result<V, RpcError>
    where
        U: Serialize + Send + Sync,
        V: DeserializeOwned + Send + Sync,
    {
        let v = serialize_request(params)?;
        let peer_id = self.get_peer_id(&namespace)?;
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::SendRequest {
                namespace,
                method,
                peer_id,
                params: v,
                sender,
            })
            .await
            .expect("Receiver not to be dropped.");
        let res = match receiver.await.expect("Sender not to be dropped.") {
            SenderType::Res(res) => res,
            SenderType::Error(_) => return Err(RpcError::TODO),
            _ => return Err(RpcError::TODO),
        };
        deserialize_response::<V>(&res)
    }

    /// Send a request & expects a stream of bytes as a response
    pub async fn streaming_call<U>(
        &mut self,
        namespace: String,
        method: String,
        params: U,
    ) -> Result<InStream, RpcError>
    where
        U: Serialize + Send + Sync,
    {
        let peer_id = self.get_peer_id(&namespace)?;
        let v = match serialize_request(params) {
            Ok(v) => v,
            Err(_) => return Err(RpcError::BadRequest),
        };

        let (sender, receiver) = oneshot::channel();
        let id = self.next_id.next().unwrap();

        self.command_sender
            .send(Command::StreamRequest {
                namespace,
                method,
                id,
                peer_id,
                params: v,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");

        let (header, stream) = match receiver.await.expect("Sender not to be dropped.") {
            SenderType::Stream { header, stream } => (header, stream),
            SenderType::Error(e) => return Err(e),
            _ => return Err(RpcError::TODO),
        };
        // examine header here and determine if we want to accept file
        Ok(InStream::new(header, stream, self.command_sender.clone()))
    }

    /// Get the peer id from the Client's address book, based on the namespace
    fn get_peer_id(&self, namespace: &str) -> Result<PeerId, RpcError> {
        match self.addresses.get(namespace) {
            Some((_, id)) => Ok(*id),
            None => Err(RpcError::NamespaceNotFound(namespace.into())),
        }
    }

    /// Get the multiaddr from the Client's address book, based on the namespace
    fn get_multiaddr(&self, namespace: &str) -> Result<Multiaddr, RpcError> {
        match self.addresses.get(namespace) {
            Some((addr, _)) => Ok(addr.clone()),
            None => Err(RpcError::NamespaceNotFound(namespace.into())),
        }
    }
}

struct Iter {
    num: u64,
}

impl Iter {
    fn new() -> Self {
        Iter { num: 0 }
    }
}

impl Iterator for Iter {
    type Item = u64;
    fn next(&mut self) -> Option<Self::Item> {
        self.num += 1;
        Some(self.num)
    }
}

/// Dial a single address
async fn dial(
    mut command_sender: mpsc::Sender<Command>,
    addr: Multiaddr,
    peer_id: PeerId,
) -> Result<(), RpcError> {
    let (sender, receiver) = oneshot::channel();
    command_sender
        .send(Command::Dial {
            peer_id,
            peer_addr: addr,
            sender,
        })
        .await
        .expect("Receiver to not be dropped.");
    match receiver.await.expect("Sender to not be dropped.") {
        SenderType::Ack => Ok(()),
        SenderType::Error(_) => Err(RpcError::TODO),
        _ => Err(RpcError::TODO),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::Arc;

    use libp2p::identity::Keypair;

    use crate::config::RpcConfig;
    use crate::handler;
    use crate::serde::{deserialize_request, serialize_response, Deserialize};
    use crate::swarm;

    #[derive(Deserialize, Serialize, Debug, Clone)]
    struct GetParams {
        resource_id: String,
    }

    #[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
    struct GetPayload {
        response: String,
    }

    struct Get;

    // DIG! I am struggling
    // I'm also not sure if I just don't know what's going on, or if this is a bad arrangement (or
    // both)
    // Trying to implement Factory for Get, implying that it will be the `Get` handler that is added
    // to one of the test rpc clients. Namespace "a", method "get", to be added to the b_rpc_config
    // using
    // `b_rpc_config.with_namespace("a", |namespace| {
    //     namespace.with_method("get", Get)
    // })`
    // Confused about some things that aren't compiling & also how we ensure that `handler::State<T>`
    // is a String in this case, is there a way to connect the State concrete type with the
    // implementation of Get?
    // anyway, would love some imput!
    async fn get(
        state: handler::State<String>,
        stream_id: Option<u64>,
        param: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        // not sure where to include that param needs to have DeserializeOwned trait. I keep
        // googling in circles, which makes me think I'm coming from it at the wrong angle,
        // would love some guidance.
        let req: GetParams = deserialize_request(&param)?;

        let bytes = serialize_response(GetPayload {
            response: state.clone(),
        })?;
        Ok(bytes)
    }

    #[tokio::test]
    async fn client_example() {
        let state = handler::State::new("Wooo!".to_string());
        let multiaddr: Multiaddr = "/memory/1234".parse().unwrap();
        let peer_id: PeerId = "12D3KooWGQmdpzHXCqLno4mMxWXKNFQHASBeF99gTm2JR8Vu5Bdc"
            .parse()
            .unwrap();
        let namespace = String::from("namespace");
        let keypair = Keypair::generate_ed25519();

        let mut client = Client::rpc_from_config(
            RpcConfig::new()
                .with_swarm(swarm::new_mem_swarm(keypair))
                .with_state(state)
                .with_namespace("a", |n| n.with_method("get", get)),
        )
        .expect("rpc client to be created");

        // create 2 rpc clients `a` & `b`
        // `a` has handlers to handle `b`'s methods
        // call from `b`, get response
        // call from `b` on nonsense namespace, get error
    }
}
