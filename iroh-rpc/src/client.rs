use crate::commands::{Command, SenderType};
use crate::error::RPCError;
use crate::serde::{deserialize_response, serialize_request, DeserializeOwned, Serialize};
use crate::server::Server;
use crate::stream::InStream;

use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::Multiaddr;
use libp2p::PeerId;
use rand::{thread_rng, Rng};
use std::collections::HashMap;

/// The RPC Client is the half of the RPC client that
/// knows how to communicate to different iroh processes.
/// The Client knows how to translate from strings and params to
/// events that gets sent over libp2p
pub struct Client<T> {
    command_sender: mpsc::Sender<Command>,
    addresses: HashMap<String, (Multiaddr, PeerId)>,
    server: Server<T>,
}

impl<T> Client<T> {
    /// Create a new client
    pub fn new(command_sender: mpsc::Sender<Command>) -> Client<T> {
        Client {
            command_sender,
            addresses: Default::default(),
        }
    }

    /// Dial all known addresses associated with the given namespaces
    pub async fn dial_all(&mut self) -> Result<(), RPCError> {
        let mut dials = Vec::new();
        for (_, (addr, peer_id)) in self.addresses.to_owned() {
            let handle = tokio::spawn(Client::dial(self.command_sender.clone(), addr, peer_id));
            dials.push(handle);
        }
        let outcomes = futures::future::join_all(dials).await;
        if outcomes.iter().any(|o| match o {
            Ok(_) => false,
            Err(_) => true,
        }) {
            return Err(RPCError::TODO);
        };
        Ok(())
    }

    /// Listen on a particular multiaddress
    pub async fn listen(&mut self, addr: Multiaddr) -> Result<(), RPCError> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::StartListening { sender, addr })
            .await
            .expect("Receiver to not be dropped.");
        match receiver.await.expect("Sender to not be dropped") {
            SenderType::Ack => Ok(()),
            SenderType::Error(_) => Err(RPCError::TODO),
            _ => Err(RPCError::TODO),
        }
    }

    /// Dial a single address
    async fn dial(
        mut command_sender: mpsc::Sender<Command>,
        addr: Multiaddr,
        peer_id: PeerId,
    ) -> Result<(), RPCError> {
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
            SenderType::Error(_) => Err(RPCError::TODO),
            _ => Err(RPCError::TODO),
        }
    }

    /// Signal the RPC event loop to stop listening
    pub async fn shutdown(mut self) {
        self.command_sender
            .send(Command::ShutDown)
            .await
            .expect("Receiver to still be active.");
    }

    /// Add an address and peer id associated with a particular namespace
    pub fn with_namespace(
        mut self,
        namespace: String,
        address: Multiaddr,
        peer_id: PeerId,
    ) -> Self {
        self.addresses.insert(namespace, (address, peer_id));
        self
    }

    /// Send a single request and expects a single response
    pub async fn call<T, U>(
        &mut self,
        namespace: String,
        method: String,
        params: T,
    ) -> Result<U, RPCError>
    where
        T: Serialize + Send + Sync,
        U: DeserializeOwned + Send + Sync,
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
            SenderType::Error(_) => return Err(RPCError::TODO),
            _ => return Err(RPCError::TODO),
        };
        deserialize_response::<U>(&res)
    }

    /// Send a request & expects a stream of bytes as a response
    pub async fn streaming_call<T>(
        &mut self,
        namespace: String,
        method: String,
        params: T,
    ) -> Result<InStream, RPCError>
    where
        T: Serialize + Send + Sync,
    {
        let peer_id = self.get_peer_id(&namespace)?;
        let v = match serialize_request(params) {
            Ok(v) => v,
            Err(_) => return Err(RPCError::BadRequest),
        };

        let (sender, receiver) = oneshot::channel();
        let id: u64 = {
            let mut rng = thread_rng();
            rng.gen()
        };

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
            _ => return Err(RPCError::TODO),
        };
        // examine header here and determine if we want to accept file
        Ok(InStream::new(header, stream, self.command_sender.clone()))
    }

    /// Get the peer id from the Client's address book, based on the namespace
    fn get_peer_id(&self, namespace: &str) -> Result<PeerId, RPCError> {
        match self.addresses.get(namespace) {
            Some((_, id)) => Ok(*id),
            None => Err(RPCError::NamespaceNotFound),
        }
    }

    /// Get the multiaddr from the Client's address book, based on the namespace
    fn get_multiaddr(&self, namespace: &str) -> Result<Multiaddr, RPCError> {
        match self.addresses.get(namespace) {
            Some((addr, _)) => Ok(addr.clone()),
            None => Err(RPCError::NamespaceNotFound),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::serde::Deserialize;

    #[derive(Serialize, Debug, Clone)]
    struct Params {
        resource_id: String,
        num: u8,
    }

    #[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
    struct Payload {
        resource_id: String,
        active: bool,
    }

    #[tokio::test]
    async fn client_example() {
        let (sender, receiver) = mpsc::channel(0);
        let multiaddr: Multiaddr = format!("/memory/1234").parse().unwrap();
        let peer_id: PeerId = format!("12D3KooWGQmdpzHXCqLno4mMxWXKNFQHASBeF99gTm2JR8Vu5Bdc")
            .parse()
            .unwrap();
        let namespace = String::from("namespace");
        let mut client =
            Client::new(sender).with_namespace(namespace.clone(), multiaddr.clone(), peer_id);
        let got_multiaddr = client
            .get_multiaddr(&namespace)
            .expect("Namespace to exist.");
        assert_eq!(multiaddr, got_multiaddr);
        let got_peer_id = client.get_peer_id(&namespace).expect("Namespace to exist.");
        assert_eq!(peer_id, got_peer_id);

        let expect_payload = Payload {
            resource_id: String::from("payload_id"),
            active: true,
        };
        let v = serialize_request(expect_payload.clone()).unwrap();

        // does this go, or do I need to await/join it?
        //
        // handle is also its own future
        let handle = tokio::spawn(async move {
            server_response(receiver, v).await;
        });

        let params = Params {
            resource_id: String::from("params_id"),
            num: 5,
        };
        let res: Payload = match client.call(namespace, String::from("method"), params).await {
            Ok(res) => res,
            Err(e) => panic!("Unexpected call error: {:?}", e),
        };
        assert_eq!(res, expect_payload);
        client.shutdown().await;
        handle.await.unwrap()
    }

    async fn server_response(mut receiver: mpsc::Receiver<Command>, response_bytes: Vec<u8>) {
        loop {
            match receiver.next().await {
                Some(command) => match command {
                    Command::SendRequest { sender, .. } => {
                        sender
                            .send(SenderType::Res(response_bytes.clone()))
                            .expect("Receiver to be active.");
                    }
                    Command::ShutDown => break,
                    c => panic!("received unexpected command {:?}", c),
                },
                None => panic!("Command Receiver unexpectedly empty"),
            }
        }
    }
}
