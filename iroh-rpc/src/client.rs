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
    /// Returns the first error it finds
    pub async fn dial_all(&mut self) -> Result<(), RpcError> {
        let mut dials = Vec::new();
        for (_, (addr, peer_id)) in self.addresses.clone().into_iter() {
            let handle = tokio::spawn(dial(self.command_sender.clone(), addr, peer_id));
            dials.push(handle);
        }
        let outcomes = futures::future::join_all(dials).await;
        for outcome in outcomes.into_iter() {
            match outcome {
                Ok(res) => match res {
                    Ok(_) => (),
                    Err(err) => return Err(err),
                },
                Err(join_err) => return Err(RpcError::JoinError(join_err.to_string())),
            }
        }

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
    pub(crate) fn with_addrs<I: Into<String>>(
        &mut self,
        namespace: I,
        address: Multiaddr,
        peer_id: PeerId,
    ) {
        self.addresses.insert(namespace.into(), (address, peer_id));
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
    use libp2p::swarm::Swarm;

    use crate::behaviour::Behaviour;
    use crate::builder::RpcBuilder;
    use crate::handler;
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

    // TODO: next improvement should be that the serialization and deserialization happen
    // for you in the rpc library, rather than having to do it yourself in the handler function
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

    #[derive(Deserialize, Serialize, Debug, Clone)]
    struct Ping;

    #[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
    struct Pong;

    // TODO: next improvement should be that the serialization and deserialization happen
    // for you in the rpc library, rather than having to do it yourself in the handler function
    async fn ping(
        _state: handler::State<()>,
        _stream_id: Option<u64>,
        param: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        let _: Pong = deserialize_request(&param)?;

        let bytes = serialize_response(Pong)?;
        Ok(bytes)
    }

    struct TestConfig {
        addr: Multiaddr,
        peer_id: PeerId,
        swarm: Swarm<Behaviour>,
    }

    #[tokio::test]
    async fn mem_client_example() {
        let a_addr: Multiaddr = "/memory/1234".parse().unwrap();
        let b_addr: Multiaddr = "/memory/4321".parse().unwrap();
        let b_keypair = Keypair::generate_ed25519();
        let b_peer_id = b_keypair.public().to_peer_id();
        let a_keypair = Keypair::generate_ed25519();
        let a_peer_id = a_keypair.public().to_peer_id();
        client_example(
            TestConfig {
                addr: a_addr,
                peer_id: a_peer_id,
                swarm: swarm::new_mem_swarm(a_keypair),
            },
            TestConfig {
                addr: b_addr,
                peer_id: b_peer_id,
                swarm: swarm::new_mem_swarm(b_keypair),
            },
        )
        .await;
    }

    #[tokio::test]
    async fn tcp_client_example() {
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
        let b_keypair = Keypair::generate_ed25519();
        let b_peer_id = b_keypair.public().to_peer_id();
        let a_keypair = Keypair::generate_ed25519();
        let a_peer_id = a_keypair.public().to_peer_id();
        client_example(
            TestConfig {
                addr: addr.clone(),
                peer_id: a_peer_id,
                swarm: swarm::new_swarm(a_keypair)
                    .await
                    .expect("swarm build failed"),
            },
            TestConfig {
                addr,
                peer_id: b_peer_id,
                swarm: swarm::new_swarm(b_keypair)
                    .await
                    .expect("swarm build failed"),
            },
        )
        .await;
    }

    async fn client_example(a: TestConfig, b: TestConfig) {
        let a_state = handler::State::new(());
        let b_state = handler::State::new("Wooo!".to_string());

        let (mut a_client, a_server) = RpcBuilder::new()
            .with_swarm(a.swarm)
            .with_state(a_state)
            .with_namespace("a", |n| n.with_method("ping", ping))
            .build()
            .expect("failed to build rpc");
        let (mut b_client, b_server) = RpcBuilder::new()
            .with_swarm(b.swarm)
            .with_state(b_state)
            .with_namespace("b", |n| n.with_method("get", get))
            .build()
            .expect("failed to build rpc");

        // run server
        let a_task_handle = tokio::spawn(async move {
            a_server.run().await;
        });
        let b_task_handle = tokio::spawn(async move {
            b_server.run().await;
        });

        // listen on addr
        let a_addr = a_client.listen(a.addr).await.expect("unsuccessful dial");
        let b_addr = b_client.listen(b.addr).await.expect("unsuccessful dial");

        // add addresses
        a_client.with_addrs("b", b_addr, b.peer_id);
        b_client.with_addrs("a", a_addr, a.peer_id);

        // dial all addrs
        a_client
            .dial_all()
            .await
            .expect("dial all namespace addrs failed");
        b_client
            .dial_all()
            .await
            .expect("dial all namespace addrs failed");

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
            .expect("call to client b failed");

        assert_eq!("Wooo!".to_string(), res.response);

        let _: Pong = b_client
            .call("a", "ping", Ping)
            .await
            .expect("call to client a failed");

        let err = a_client
            .call::<_, Pong, _, _>("b", "ping", Ping)
            .await
            .unwrap_err();
        assert_eq!(RpcError::MethodNotFound("ping".into()), err);

        // shutdown client
        a_client.shutdown().await;
        b_client.shutdown().await;
        a_task_handle.await.unwrap();
        b_task_handle.await.unwrap();
    }
}
