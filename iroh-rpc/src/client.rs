use std::collections::HashMap;

use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::commands::{Command, SenderType};
use crate::error::RpcError;
use crate::serde::{deserialize_response, serialize_request, DeserializeOwned, Serialize};
use crate::stream::InStream;

/// The Rpc Client manages outgoing and incoming calls over rpc
/// It knows how to reach the different Iroh processes, and knows
/// how to handle incoming requests
pub struct Client {
    command_sender: mpsc::Sender<Command>,
    // TODO: should be a list of addrs per namespace (not just one)
    addresses: HashMap<String, (Multiaddr, PeerId)>,
    next_id: Iter,
}

impl Client {
    /// Create a new client. Not recommended. It is perfered to use `rpc_from_config`
    pub fn new(command_sender: mpsc::Sender<Command>) -> Client {
        Client {
            command_sender,
            addresses: Default::default(),
            next_id: Iter::new(),
        }
    }

    /// Dial all known addresses associated with the given namespaces
    pub async fn dial_all(&mut self) -> Result<(), RpcError> {
        let mut dials = Vec::new();
        for (_, (addr, peer_id)) in self.addresses.to_owned() {
            let handle = tokio::spawn(dial(self.command_sender.clone(), addr, peer_id));
            dials.push(handle);
        }
        let outcomes = futures::future::join_all(dials).await;
        if outcomes.iter().any(|o| match o {
            Ok(_) => false,
            Err(_) => true,
        }) {
            return Err(RpcError::TODO);
        };

        Ok(())
    }

    /// Listen on a particular multiaddress
    pub async fn listen(&mut self, addr: Multiaddr) -> Result<Multiaddr, RpcError> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::StartListening { sender, addr })
            .await
            .expect("Receiver to not be dropped.");
        match receiver.await.expect("Sender to not be dropped") {
            SenderType::Multiaddr(m) => Ok(m),
            SenderType::Error(e) => Err(e),
            _ => Err(RpcError::UnexpectedResponseType),
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
    pub(crate) fn with_addrs(&mut self, namespace: String, address: Multiaddr, peer_id: PeerId) {
        self.addresses.insert(namespace, (address, peer_id));
    }

    /// Send a single request and expects a single response
    pub async fn call<U, V, S, I>(
        &mut self,
        namespace: S,
        method: I,
        params: U,
    ) -> Result<V, RpcError>
    where
        U: Serialize + Send + Sync,
        V: DeserializeOwned + Send + Sync,
        S: Into<String>,
        I: Into<String>,
    {
        let v = serialize_request(params)?;
        let n: String = namespace.into();
        let peer_id = self.get_peer_id(&n)?;
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::SendRequest {
                namespace: n,
                method: method.into(),
                peer_id,
                params: v,
                sender,
            })
            .await
            .expect("Receiver not to be dropped.");
        let res = match receiver.await.expect("Sender not to be dropped.") {
            SenderType::Res(res) => res,
            SenderType::Error(e) => return Err(e),
            _ => return Err(RpcError::UnexpectedResponseType),
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
            _ => return Err(RpcError::UnexpectedResponseType),
        };
        // examine header here and determine if we want to accept file
        Ok(InStream::new(header, stream, self.command_sender.clone()))
    }

    /// Get the peer id from the Client's address book, based on the namespace
    pub fn get_peer_id(&self, namespace: &str) -> Result<PeerId, RpcError> {
        match self.addresses.get(namespace) {
            Some((_, id)) => Ok(*id),
            None => Err(RpcError::NamespaceNotFound(namespace.into())),
        }
    }

    /// Get the multiaddr from the Client's address book, based on the namespace
    pub fn get_multiaddr(&self, namespace: &str) -> Result<Multiaddr, RpcError> {
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
        SenderType::Error(e) => Err(e),
        _ => Err(RpcError::UnexpectedResponseType),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use libp2p::identity::Keypair;

    use crate::config::RpcConfig;
    use crate::handler;
    use crate::rpc_from_config;
    use crate::serde::{deserialize_request, serialize_response, Deserialize};
    use crate::swarm;

    #[derive(Deserialize, Serialize, Debug, Clone)]
    struct GetRequest {
        resource_id: String,
    }

    #[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
    struct GetResponse {
        response: String,
    }

    async fn get(
        state: handler::State<String>,
        _stream_id: Option<u64>,
        param: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        let _: GetRequest = deserialize_request(&param)?;

        let bytes = serialize_response(GetResponse {
            response: state.clone(),
        })?;
        Ok(bytes)
    }

    #[tokio::test]
    async fn client_example() {
        let a_state = handler::State::new(());
        let a_keypair = Keypair::generate_ed25519();
        let a_peer_id = a_keypair.public().to_peer_id();
        let a_addr: Multiaddr = "/memory/1234".parse().unwrap();

        let b_state = handler::State::new("Wooo!".to_string());
        let b_addr: Multiaddr = "/memory/4321".parse().unwrap();
        let b_keypair = Keypair::generate_ed25519();
        let b_peer_id = b_keypair.public().to_peer_id();

        let (mut a_client, a_server) = rpc_from_config(
            RpcConfig::new()
                .with_swarm(swarm::new_mem_swarm(a_keypair))
                .with_state(a_state)
                // can add the addrs here, or after the client has already
                // been constructed
                .with_addr("b", b_addr.clone(), b_peer_id),
        )
        .expect("rpc client to be created");
        let (mut b_client, b_server) = rpc_from_config(
            RpcConfig::new()
                .with_swarm(swarm::new_mem_swarm(b_keypair))
                .with_state(b_state)
                .with_namespace("b", |n| n.with_method("get", get))
                // can add the addrs here, or after the client has already
                // been constructed
                .with_addr("a", a_addr.clone(), a_peer_id),
        )
        .expect("rpc client to be created");

        // run server
        let a_thread_handle = tokio::spawn(async move {
            a_server.run().await;
        });
        let b_thread_handle = tokio::spawn(async move {
            b_server.run().await;
        });

        // listen on addr
        a_client.listen(a_addr).await.expect("unsuccessful dial");
        b_client.listen(b_addr).await.expect("unsuccessful dial");

        // dial all addrs
        a_client
            .dial_all()
            .await
            .expect("to dial all namespace addrs");
        b_client
            .dial_all()
            .await
            .expect("to dial all namespace addrs");

        // make request
        let res: GetResponse = a_client
            .call(
                "b",
                "get",
                GetRequest {
                    resource_id: "test".into(),
                },
            )
            .await
            .expect("call to client b to function");

        assert_eq!(res.response, "Wooo!".to_string());

        // shutdown client
        a_client.shutdown().await;
        b_client.shutdown().await;
        a_thread_handle.await.unwrap();
        b_thread_handle.await.unwrap();
    }
}
