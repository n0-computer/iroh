pub mod network;

pub mod database_rpc {
    use crate::core;
    use crate::core::Keypair;
    use futures::channel::mpsc;
    use tokio::task::spawn;

    // eventually this will be custom for a database process
    pub async fn new(id_keys: Keypair) -> Result<core::Client, Box<dyn std::error::Error>> {
        let swarm = core::new_swarm(id_keys).await?;

        let (command_from_client_sender, command_from_client_receiver) = mpsc::channel(0);
        // let (command_from_network_sender, command_from_network_receiver) = mpsc::channel(0);

        let server = core::Server::new(
            swarm,
            command_from_client_receiver,
            // command_from_network_sender,
        );
        spawn(server.run());
        Ok(core::Client::new(
            command_from_client_sender,
            // command_from_network_receiver,
        ))
    }
}

pub mod cli_rpc {
    use crate::core;
    use crate::core::Keypair;
    use futures::channel::mpsc;
    use tokio::task::spawn;

    // eventually this will be custom for a cli process
    pub async fn new(id_keys: Keypair) -> Result<core::Client, Box<dyn std::error::Error>> {
        let swarm = core::new_swarm(id_keys).await?;

        let (command_from_client_sender, command_from_client_receiver) = mpsc::channel(0);
        // let (command_from_network_sender, command_from_network_receiver) = mpsc::channel(0);

        let server = core::Server::new(
            swarm,
            command_from_client_receiver,
            // command_from_network_sender,
        );
        spawn(server.run());
        Ok(core::Client::new(
            command_from_client_sender,
            // command_from_network_receiver,
        ))
    }
}

mod core {
    use async_trait::async_trait;
    use bytecheck::CheckBytes;
    use futures::channel::mpsc;
    use futures::channel::oneshot;
    use futures::prelude::*;
    use futures::select;
    use libp2p::core::connection::ListenerId;
    use libp2p::core::upgrade::{read_length_prefixed, write_length_prefixed, ProtocolName};
    use libp2p::multiaddr::Protocol;
    use libp2p::request_response::{
        ProtocolSupport, RequestId, RequestResponse, RequestResponseCodec, RequestResponseEvent,
        RequestResponseMessage,
    };
    use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmBuilder, SwarmEvent};
    use libp2p::Multiaddr;
    use libp2p::{NetworkBehaviour, PeerId, Swarm};
    use rkyv;
    use rkyv::{Archive, Deserialize, Serialize};
    use std::collections::HashMap;
    use std::error::Error;
    use std::iter;
    use tokio::io;

    pub use libp2p::identity::Keypair;

    // Commands are the way the Client communicates with the Server
    pub enum Command {
        StartListening {
            addr: Multiaddr,
            sender: oneshot::Sender<Result<Multiaddr, Box<dyn Error + Send>>>,
        },
        Dial {
            peer_id: PeerId,
            peer_addr: Multiaddr,
            sender: oneshot::Sender<Result<(), Box<dyn Error + Send>>>,
        },
        Ping {
            message: String,
            peer_id: PeerId,
            sender: oneshot::Sender<Result<(), Box<dyn Error + Send>>>,
        },
        PeerId {
            sender: oneshot::Sender<PeerId>,
        },
    }

    pub struct Server {
        swarm: Swarm<CoreBehaviour>,
        // commands received from the client aka user
        command_receiver: mpsc::Receiver<Command>,
        // commands sent to the client from the network
        // command_sender: mpsc::Sender<Command>,
        // all of these "pending" maps seems untenable. Is this a hard requierment? If so, is one
        // per protocol enough? It means that as we add specific protocols to a server, we need a
        // new map for each one.
        pending_listen:
            HashMap<ListenerId, oneshot::Sender<Result<Multiaddr, Box<dyn Error + Send>>>>,
        pending_dial: HashMap<PeerId, oneshot::Sender<Result<(), Box<dyn Error + Send>>>>,
        pending_core_request:
            HashMap<RequestId, oneshot::Sender<Result<(), Box<dyn Error + Send>>>>,
    }

    impl Server {
        pub fn new(
            swarm: Swarm<CoreBehaviour>,
            command_receiver: mpsc::Receiver<Command>,
            // command_sender: mpsc::Sender<Command>,
        ) -> Self {
            Server {
                swarm,
                // command_sender,
                command_receiver,
                pending_listen: Default::default(),
                pending_dial: Default::default(),
                pending_core_request: Default::default(),
            }
        }
        pub async fn run(mut self) {
            loop {
                select! {
                    event = self.swarm.next() => {
                        let event = event.expect("Swarm stream to be infinite.");
                        self.handle_event(event).await
                    }
                    command = self.command_receiver.next() => match command {
                        Some(c) => self. handle_client_command(c).await,
                        // channel has been closed
                        None => {
                            println!("{} shutting down", self.swarm.local_peer_id());
                            return;
                        }
                    }
                }
            }
        }

        async fn handle_client_command(&mut self, command: Command) {
            match command {
                Command::StartListening { addr, sender } => match self.swarm.listen_on(addr) {
                    Ok(listener_id) => {
                        self.pending_listen.insert(listener_id, sender);
                    }
                    Err(e) => {
                        let _ = sender.send(Err(Box::new(e)));
                    }
                },
                Command::Dial {
                    peer_id,
                    peer_addr,
                    sender,
                } => {
                    if self.pending_dial.contains_key(&peer_id) {
                        todo!("Already dialing peer")
                    } else {
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .add_address(&peer_id, peer_addr.clone());
                        match self
                            .swarm
                            .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                        {
                            Ok(()) => {
                                self.pending_dial.insert(peer_id, sender);
                            }
                            Err(e) => {
                                let _ = sender.send(Err(Box::new(e)));
                            }
                        }
                    }
                }
                Command::Ping {
                    message,
                    peer_id,
                    sender,
                } => {
                    let request_id = self
                        .swarm
                        .behaviour_mut()
                        .request_response
                        .send_request(&peer_id, CoreRequest(RequestEvent::Ping { message }));
                    self.pending_core_request.insert(request_id, sender);
                }
                Command::PeerId { sender } => {
                    let _ = sender.send(*self.swarm.local_peer_id());
                }
            }
        }

        async fn handle_event(
            &mut self,
            event: SwarmEvent<CoreEvent, ConnectionHandlerUpgrErr<io::Error>>,
        ) {
            match event {
                SwarmEvent::NewListenAddr {
                    address,
                    listener_id,
                } => {
                    let local_peer_id = *self.swarm.local_peer_id();
                    if let Some(sender) = self.pending_listen.remove(&listener_id) {
                        let _ = sender.send(Ok(address.with(Protocol::P2p(local_peer_id.into()))));
                    }
                }
                SwarmEvent::IncomingConnection { .. } => {}
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    println!("Connection with {:?} established", peer_id);
                    if endpoint.is_dialer() {
                        if let Some(sender) = self.pending_dial.remove(&peer_id) {
                            let _ = sender.send(Ok(()));
                        }
                    }
                }
                SwarmEvent::ConnectionClosed { .. } => {}
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    if let Some(peer_id) = peer_id {
                        if let Some(sender) = self.pending_dial.remove(&peer_id) {
                            let _ = sender.send(Err(Box::new(error)));
                        }
                    }
                }
                SwarmEvent::IncomingConnectionError { .. } => {}
                SwarmEvent::Dialing(peer_id) => println!("Dialing {}", peer_id),
                SwarmEvent::Behaviour(CoreEvent::RequestResponse(
                    RequestResponseEvent::Message { message, .. },
                )) => self.handle_core_message(message).await,

                SwarmEvent::Behaviour(CoreEvent::RequestResponse(
                    RequestResponseEvent::OutboundFailure {
                        request_id, error, ..
                    },
                )) => {
                    let _ = self
                        .pending_core_request
                        .remove(&request_id)
                        .expect("Request to still be pending.")
                        .send(Err(Box::new(error)));
                }
                SwarmEvent::Behaviour(CoreEvent::RequestResponse(
                    RequestResponseEvent::ResponseSent { .. },
                )) => {}
                e => panic!("{:?}", e),
            }
        }

        async fn handle_core_message(
            &mut self,
            message: RequestResponseMessage<CoreRequest, CoreResponse>,
        ) {
            match message {
                RequestResponseMessage::Request {
                    request, channel, ..
                } => match request.0 {
                    RequestEvent::Ping { message } => {
                        println!("{:?} received '{}'", self.swarm.local_peer_id(), message);
                        // under different circumstances, we may want to send this down another
                        // channel that is listening for network commands, to deal with responding
                        // somewhere else.
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(
                                channel,
                                CoreResponse(ResponseEvent::Pong {
                                    message: String::from("pong"),
                                }),
                            )
                            .expect("Connection to peer to still be open.");
                    }
                },
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => match response.0 {
                    ResponseEvent::Pong { message } => {
                        println!("{:?} received '{}'", self.swarm.local_peer_id(), message);
                        let _ = self
                            .pending_core_request
                            .remove(&request_id)
                            .expect("Request to still be pending.")
                            .send(Ok(()));
                    }
                },
            }
        }
    }

    // eventually generalize, pass in config etc
    pub async fn new_swarm(id_keys: Keypair) -> Result<Swarm<CoreBehaviour>, Box<dyn Error>> {
        let peer_id = id_keys.public().to_peer_id();
        Ok(SwarmBuilder::new(
            libp2p::development_transport(id_keys).await?,
            CoreBehaviour::new(),
            peer_id,
        )
        .build())
    }

    pub struct Client {
        command_sender: mpsc::Sender<Command>,
        // command_receiver is potentially where we listen for requests that come from the network
        // and need to be responded to.Eg, where a DatabaseEvent::RequestFile might be handled by
        // the database to actually go in a get the file & then respond with a
        // DatabaseEvent::RespondFile sent over the given response channel
        // this current working example only works through Ping and Pong events, handling the Pong
        // response right after the Ping request is found
        // command_receiver: mpsc::Receiver<Command>,
    }

    impl Client {
        pub fn new(
            command_from_client_sender: mpsc::Sender<Command>,
            // command_from_network_receiver: mpsc::Receiver<Command>,
        ) -> Self {
            Self {
                command_sender: command_from_client_sender,
                // command_receiver: command_from_network_receiver,
            }
        }

        pub async fn start_listening(
            &mut self,
            addr: Multiaddr,
        ) -> Result<Multiaddr, Box<dyn Error + Send>> {
            let (sender, rec) = oneshot::channel();
            self.command_sender
                .send(Command::StartListening { addr, sender })
                .await
                .expect("Command receiver not to be dropped.");
            rec.await.expect("Sender not to be dropped.")
        }

        pub async fn dial(
            &mut self,
            peer_id: PeerId,
            peer_addr: Multiaddr,
        ) -> Result<(), Box<dyn Error + Send>> {
            let (sender, rec) = oneshot::channel();
            self.command_sender
                .send(Command::Dial {
                    peer_id,
                    peer_addr,
                    sender,
                })
                .await
                .expect("Command receiver not to be dropped.");
            rec.await.expect("Sender not to be dropped.")
        }

        pub async fn ping(&mut self, peer_id: PeerId) -> Result<(), Box<dyn Error + Send>> {
            let (sender, rec) = oneshot::channel();
            self.command_sender
                .send(Command::Ping {
                    peer_id,
                    message: String::from("ping"),
                    sender,
                })
                .await
                .expect("Command receiver not to be dropped");
            rec.await.expect("Sender not to be dropped.")
        }

        pub async fn peer_id(&mut self) -> PeerId {
            let (sender, rec) = oneshot::channel();
            self.command_sender
                .send(Command::PeerId { sender })
                .await
                .expect("Command receiver not to be dropped");
            rec.await.expect("Sender not to be dropped")
        }
    }

    // Events are how one server communicates with another
    #[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
    #[archive(compare(PartialEq))]
    #[archive_attr(derive(Debug, CheckBytes))]
    pub enum RequestEvent {
        Ping { message: String },
    }

    #[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
    #[archive(compare(PartialEq))]
    #[archive_attr(derive(Debug, CheckBytes))]
    pub enum ResponseEvent {
        Pong { message: String },
    }

    #[derive(NetworkBehaviour)]
    #[behaviour(out_event = "CoreEvent")]
    pub struct CoreBehaviour {
        request_response: RequestResponse<CoreCodec>,
    }

    impl CoreBehaviour {
        pub fn new() -> Self {
            CoreBehaviour {
                request_response: RequestResponse::new(
                    CoreCodec(),
                    iter::once((CoreProtocol(), ProtocolSupport::Full)),
                    Default::default(),
                ),
            }
        }
    }

    #[derive(Debug)]
    pub enum CoreEvent {
        RequestResponse(RequestResponseEvent<CoreRequest, CoreResponse>),
    }

    impl From<RequestResponseEvent<CoreRequest, CoreResponse>> for CoreEvent {
        fn from(event: RequestResponseEvent<CoreRequest, CoreResponse>) -> Self {
            CoreEvent::RequestResponse(event)
        }
    }

    #[derive(Debug, Clone)]
    pub struct CoreProtocol();
    #[derive(Clone)]
    pub struct CoreCodec();
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CoreRequest(RequestEvent);
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct CoreResponse(ResponseEvent);

    impl ProtocolName for CoreProtocol {
        fn protocol_name(&self) -> &[u8] {
            "/iroh/v1/core/v1".as_bytes()
        }
    }

    #[async_trait]
    impl RequestResponseCodec for CoreCodec {
        type Protocol = CoreProtocol;
        type Request = CoreRequest;
        type Response = CoreResponse;

        async fn read_request<T>(
            &mut self,
            _: &CoreProtocol,
            io: &mut T,
        ) -> io::Result<Self::Request>
        where
            T: AsyncRead + Unpin + Send,
        {
            let vec = read_length_prefixed(io, 1_000_000).await?;
            // Need to better understand rkyv and our options to make serializing & deserializing
            // more specific and efficient
            let event = rkyv::check_archived_root::<RequestEvent>(&vec)
                .expect("Error converting bytes to archived CoreRequest")
                .deserialize(&mut rkyv::Infallible)
                .expect("Error deserializing CoreResponse.");
            Ok(CoreRequest(event))
        }

        async fn read_response<T>(
            &mut self,
            _: &CoreProtocol,
            io: &mut T,
        ) -> io::Result<Self::Response>
        where
            T: AsyncRead + Unpin + Send,
        {
            let vec = read_length_prefixed(io, 1_000_000).await?;
            // Need to better understand rkyv and our options to make serializing & deserializing
            // more specific and efficient
            let event = rkyv::check_archived_root::<ResponseEvent>(&vec)
                .expect("Error converting bytes to archived CoreResponse")
                .deserialize(&mut rkyv::Infallible)
                .expect("Error deserializing CoreResponse");
            Ok(CoreResponse(event))
        }

        async fn write_request<T>(
            &mut self,
            _: &CoreProtocol,
            io: &mut T,
            CoreRequest(data): CoreRequest,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            // Need to better understand rkyv and our options to make serializing & deserializing
            // more specific and efficient
            let vec = rkyv::to_bytes::<_, 1024>(&data).expect("Error serializing CoreRequest.");
            write_length_prefixed(io, vec).await?;
            io.close().await?;
            Ok(())
        }

        async fn write_response<T>(
            &mut self,
            _: &CoreProtocol,
            io: &mut T,
            CoreResponse(data): CoreResponse,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            // Need to better understand rkyv and our options to make serializing & deserializing
            // more specific and efficient
            let vec = rkyv::to_bytes::<_, 1024>(&data).expect("Error serializing CoreRequest.");
            write_length_prefixed(io, vec).await?;
            io.close().await?;
            Ok(())
        }
    }
}
