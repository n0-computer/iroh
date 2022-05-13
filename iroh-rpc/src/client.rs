use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::Multiaddr;
use libp2p::PeerId;

use crate::commands::{Command, SenderType};
use crate::error::RpcError;
use crate::serde::{deserialize_response, serialize_request, DeserializeOwned, Serialize};
use crate::stream;

/// The Rpc Client manages outgoing and incoming calls over rpc
/// It knows how to reach the different Iroh processes, and knows
/// how to handle incoming requests
pub struct Client {
    command_sender: mpsc::Sender<Command>,
    next_id: Iter,
}

impl Client {
    /// Create a new client. Not recommended. It is perfered to use `rpc_from_config`
    pub fn new(command_sender: mpsc::Sender<Command>) -> Client {
        Client {
            command_sender,
            next_id: Iter::new(),
        }
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
            s => Err(RpcError::UnexpectedResponseType(s.to_string())),
        }
    }

    /// Signal the Rpc event loop to stop listening
    pub async fn shutdown(&mut self) {
        self.command_sender
            .send(Command::ShutDown)
            .await
            .expect("Receiver to still be active.");
    }

    /// dial dials a namespace & adds that namespace into the address book
    pub async fn dial<I: Into<String>>(
        &mut self,
        namespace: I,
        address: Multiaddr,
        peer_id: PeerId,
    ) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        self.command_sender
            .send(Command::Dial {
                namespace: namespace.into(),
                address,
                peer_id,
                sender: s,
            })
            .await
            .expect("Receiver to still be active");
        match r.await.expect("Sender dropped.") {
            SenderType::Ack => Ok(()),
            SenderType::Error(e) => Err(e),
            s => Err(RpcError::UnexpectedResponseType(s.to_string())),
        }
    }

    /// send this rpc client's address book to all of it's connected peers
    /// will cause it's peer's to add any unknown namespaces to their own
    /// address book
    pub async fn send_address_book<I: Into<String>>(
        &mut self,
        namespace: I,
    ) -> Result<(), RpcError> {
        let (s, r) = oneshot::channel();
        self.command_sender
            .send(Command::SendAddressBook {
                namespace: namespace.into(),
                sender: s,
            })
            .await
            .expect("Receiver to still be active.");

        match r.await.expect("Sender dropped.") {
            SenderType::Ack => Ok(()),
            SenderType::Error(e) => Err(e),
            s => Err(RpcError::UnexpectedResponseType(s.to_string())),
        }
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
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::SendRequest {
                namespace: n,
                method: method.into(),
                params: v,
                sender,
            })
            .await
            .expect("Receiver not to be dropped.");
        let res = match receiver.await.expect("Sender not to be dropped.") {
            SenderType::Res(res) => res,
            SenderType::Error(e) => return Err(e),
            s => return Err(RpcError::UnexpectedResponseType(s.to_string())),
        };
        deserialize_response::<V>(&res)
    }

    /// Send a request & expects a stream of bytes as a response
    pub async fn streaming_call<U, N, M>(
        &mut self,
        namespace: N,
        method: M,
        params: U,
    ) -> Result<impl Stream<Item = Result<Vec<u8>, RpcError>>, RpcError>
    where
        U: Serialize + Send + Sync,
        N: Into<String>,
        M: Into<String>,
    {
        let namespace = namespace.into();
        let method = method.into();
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
                params: v,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");

        let (_, packet_receiver) = match receiver.await.expect("Sender not to be dropped.") {
            SenderType::Stream { header, stream } => (header, stream),
            SenderType::Error(e) => return Err(e),
            s => return Err(RpcError::UnexpectedResponseType(s.to_string())),
        };
        //
        // possibly examine header here and determine if we want to accept file before creating the
        // stream
        //
        let s = stream::make_order(packet_receiver);
        Ok(s)
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

#[cfg(test)]
mod test {
    use super::*;

    use futures::pin_mut;
    use libp2p::identity::Keypair;
    use libp2p::swarm::Swarm;

    use crate::behaviour::Behaviour;
    use crate::builder::RpcBuilder;
    use crate::handler;
    use crate::serde::{deserialize_request, serialize_response, Deserialize};
    use crate::stream::{Header, OutStream, StreamConfig};
    use crate::swarm;

    #[derive(Deserialize, Serialize, Debug, Clone)]
    struct StreamRequest {
        size: u64,
        chunk_size: u64,
    }

    struct TestReader {
        chunk_size: usize,
        num_chunks: usize,
    }

    impl std::io::Read for TestReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.num_chunks == 0 {
                return Ok(0);
            };
            let len = self.chunk_size;
            let new_data = vec![0xf; len];
            buf[..len].copy_from_slice(&new_data);
            self.num_chunks -= 1;
            Ok(len)
        }
    }

    // TODO: next improvement should be that the serialization and deserialization happen
    // for you in the rpc library, rather than having to do it yourself in the handler function
    async fn stream_bytes(
        _state: handler::State<String>,
        cfg: Option<StreamConfig>,
        param: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        let req: StreamRequest = deserialize_request(&param)?;
        let size = req.size;
        let chunk_size = req.chunk_size;

        // get config
        let cfg = match cfg {
            Some(c) => c,
            None => return Err(RpcError::NoStreamConfig),
        };

        // typically this is where you would load the content,
        // determine the size of the content & specify what
        // chunk sizes you are sending back
        // then, construct a header based on these specifications
        // in this example, we are pulling the size & chunk_size
        // from the request
        let header = Header::new(cfg.id, size, chunk_size);

        // construct BufReader from the loaded content
        let r = TestReader {
            num_chunks: (size as f64 / chunk_size as f64).ceil() as usize,
            chunk_size: chunk_size as usize,
        };
        let r = std::io::BufReader::new(r);

        // construct stream
        let mut stream = OutStream::new(cfg, header.clone(), Box::new(r));

        // send packets in a different task, so you don't block
        // the event loop
        // TODO: handle task handler, should keep track of it (based on stream id?) and make sure
        // it is closed when we close down the server
        let _ = tokio::spawn(async move {
            stream.send_packets().await;
        });

        // TODO: serializing should happen outside of the handler
        // also, we may want 2 different kinds of handlers, one for a normal
        // request response and one for streaming
        let header = rkyv::to_bytes::<_, 1024>(&header).expect("header to serialize");
        Ok(header.to_vec())
    }

    #[derive(Deserialize, Serialize, Debug, Clone)]
    struct Ping;

    #[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
    struct Pong;

    // TODO: next improvement should be that the serialization and deserialization happen
    // for you in the rpc library, rather than having to do it yourself in the handler function
    async fn ping(
        _state: handler::State<()>,
        _cfg: Option<StreamConfig>,
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

        let (mut a_client, a_server) = RpcBuilder::new("a")
            .with_swarm(a.swarm)
            .with_state(a_state)
            .with_namespace("a", |n| n.with_method("ping", ping))
            .with_capacity(2)
            .build()
            .expect("failed to build rpc");
        let (mut b_client, b_server) = RpcBuilder::new("b")
            .with_swarm(b.swarm)
            .with_state(b_state)
            .with_namespace("b", |n| n.with_method("stream", stream_bytes))
            .with_capacity(2)
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
        a_client.dial("b", b_addr, b.peer_id);
        b_client.dial("a", a_addr, a.peer_id);

        let size = 4_048;
        let chunk_size = 1_024;
        // make request
        let s = a_client
            .streaming_call("b", "stream", StreamRequest { size, chunk_size })
            .await
            .expect("call to client b failed");

        let mut res = Vec::new();

        let mut num_chunks = 0;
        pin_mut!(s);
        while let Some(r) = s.next().await {
            match r {
                Ok(d) => {
                    num_chunks += 1;
                    res.extend(d);
                }
                Err(e) => panic!("unexpected error {}", e),
            }
        }

        assert_eq!(num_chunks, (size as f64 / chunk_size as f64).ceil() as i32);
        assert_eq!(res.len(), size as usize);

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
