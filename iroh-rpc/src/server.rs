use crate::behaviour::core::{
    CoreEvent, CoreRequest, CoreRequestEvent, CoreResponse, CoreResponseEvent,
};
use crate::behaviour::{Behaviour, Event};
use crate::commands::{ActiveStreams, Command, PendingId, PendingMap, SenderType};
use crate::error::RPCError;
use crate::serde::{Deserialize, Serialize};
use crate::stream::StreamType;

use futures::channel::mpsc;
use futures::prelude::*;
use futures::select;
use futures::Future;
pub use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::RequestResponseMessage;
use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmEvent};
use libp2p::Swarm;
use log::{debug, error, trace};
use std::collections::HashMap;

/// The Server manages the swarm, gets commands from the client & translates
/// those into events to send over rpc to the correct recepient. It listens for
/// events from the network to give to the client. It also tracks any pending
/// requests we are still waiting on a response for and any active streams
/// that we are still currently listening for.
pub struct Server<T> {
    swarm: Swarm<Behaviour>,
    command_rec: mpsc::Receiver<Command>,
    pending_requests: PendingMap,
    active_streams: ActiveStreams,
    state: State<T>,
    handlers: HashMap<String, Namespace<T>>,
}

impl<T> Server<T> {
    pub fn server_from_config(config: ServerConfig<T>) -> Result<Self, Box<dyn std::error::Error>> {
        let swarm = match config.swarm {
            Some(s) => s,
            None => return Err("no swarm given".into()),
        };
        let command_rec = match config.commands_receiver {
            Some(c) => c,
            None => return Err("no command receiver specified".into()),
        };
        let state = match config.state {
            Some(s) => s,
            None => return Err("no server state specified".into()),
        };
        Ok(Server {
            swarm,
            command_rec,
            state,
            handlers: config.namespaces,
            pending_requests: Default::default(),
            active_streams: Default::default(),
        })
    }

    // TODO: should each `self.handle_event` and `self.handle_command`
    // be spawned in their own thread? Or does it make sense to handle each command or event
    // iteratively?
    pub async fn run(mut self) {
        loop {
            select! {
                event = self.swarm.next() => {
                    let event = event.expect("Swarm stream to be infinite.");
                    self.handle_event(event).await
                }
                command = self.command_rec.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // channel has been closed
                    None => {
                        println!("{} shutting down", self.swarm.local_peer_id());
                        return;
                    }
                }
            }
        }
    }

    pub async fn handle_event(
        &mut self,
        event: SwarmEvent<Event, ConnectionHandlerUpgrErr<std::io::Error>>,
    ) {
        match event {
            SwarmEvent::NewListenAddr {
                address,
                listener_id,
            } => {
                let local_peer_id = *self.swarm.local_peer_id();
                if let Some(sender) = self
                    .pending_requests
                    .remove(&PendingId::ListenerId(listener_id))
                {
                    let _ = sender.send(SenderType::Multiaddr(
                        address.with(Protocol::P2p(local_peer_id.into())),
                    ));
                }
            }
            SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                println!("Connection with {:?} established", peer_id);
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::PeerId(peer_id))
                    {
                        let _ = sender.send(SenderType::Ack);
                    }
                }
            }
            SwarmEvent::ConnectionClosed { .. } => {}
            SwarmEvent::OutgoingConnectionError { peer_id, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::PeerId(peer_id))
                    {
                        // TODO: add error for connection failure, that contains the actual
                        // connection error
                        let _ = sender.send(SenderType::Error(RPCError::TODO));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(peer_id) => {
                println!("{} - Dialing {}", self.swarm.local_peer_id(), peer_id)
            }
            SwarmEvent::Behaviour(Event::Core(e)) => match e {
                CoreEvent::Message { message, .. } => match message {
                    RequestResponseMessage::Request {
                        request, channel, ..
                    } => match request.0 {
                        CoreRequestEvent::Request {
                            namespace,
                            method,
                            params,
                            stream_id,
                        } => {
                            match self
                                .handle_request(namespace, method, stream_id, params)
                                .await
                            {
                                Ok(res) => {
                                    self.swarm
                                        .behaviour_mut()
                                        .core
                                        .send_response(
                                            channel,
                                            CoreResponse(CoreResponseEvent::Payload(res)),
                                        )
                                        .expect("Connection to peer to still be open.");
                                }
                                Err(e) => {
                                    self.swarm
                                        .behaviour_mut()
                                        .core
                                        .send_response(
                                            channel,
                                            // TODO: is BadRequest the right error? The idea is
                                            // that the requester made an error in requesting that
                                            // particular action from the server. Could be a new
                                            // error `RPCError::HandlerNotFound`, but not sure if
                                            CoreResponse(CoreResponseEvent::RPCError(e)),
                                        )
                                        .expect("Connection to peer to still be open.");
                                    return;
                                }
                            };
                        }
                        CoreRequestEvent::Packet(packet) => {
                            let stream_id = packet.id;
                            let index = packet.index;
                            debug!(target: "inbound streaming", "Received Packet {} for stream {}", index, stream_id);
                            let sender = match self.active_streams.get_mut(&stream_id) {
                                Some(s) => s,
                                None => {
                                    error!(target: "inbound streaming", "Packet {} could not be delievered because stream {} no longer in active stream list", index, stream_id);
                                    self.swarm
                                        .behaviour_mut()
                                        .core
                                        .send_response(
                                            channel,
                                            CoreResponse(CoreResponseEvent::RPCError(
                                                RPCError::StreamClosed,
                                            )),
                                        )
                                        .expect("Connection to peer to still be open.");
                                    return;
                                }
                            };

                            if let Err(e) = sender.try_send(StreamType::Packet(packet)) {
                                // TODO: recover from error
                                // send error back instead of panicing
                                error!(target: "inbound streaming", "Error sending packet from wire to stream {}: {}", stream_id, e);
                                panic!("Error sending packet off the wire to stream {}", stream_id);
                            }
                            // only ack for now, send back error if we cannot send to stream
                            debug!(target: "inbound streaming", "Acknowledging Packet {} from stream {}", index, stream_id);
                            self.swarm
                                .behaviour_mut()
                                .core
                                .send_response(channel, CoreResponse(CoreResponseEvent::Ack))
                                .expect("Connection to peer to still be open.");
                        }
                    },
                    RequestResponseMessage::Response {
                        request_id,
                        response,
                    } => match response.0 {
                        CoreResponseEvent::Payload(payload) => {
                            let _ = self
                                .pending_requests
                                .remove(&PendingId::RequestId(request_id))
                                .expect("Request to still be pending.")
                                .send(SenderType::Res(payload));
                        }
                        CoreResponseEvent::RPCError(error) => {
                            let _ = self
                                .pending_requests
                                .remove(&PendingId::RequestId(request_id))
                                .expect("Request to still be pending.")
                                .send(SenderType::Error(error));
                        }
                        CoreResponseEvent::Header(header) => {
                            let (sender, receiver) = mpsc::channel(1000);
                            debug!(target: "inbound streaming", "Received header: Adding active stream {}", header.id);
                            self.active_streams.insert(header.id, sender);
                            debug!(target: "inbound streaming", "Sending stream receiver to client");
                            let _ = self
                                .pending_requests
                                .remove(&PendingId::RequestId(request_id))
                                .expect("Request to still be pending.")
                                .send(SenderType::Stream {
                                    header,
                                    stream: receiver,
                                });
                        }
                        CoreResponseEvent::Ack => {
                            debug!(target: "inbound streaming", "Received Ack for request {}", request_id);
                            let _ = self
                                .pending_requests
                                .remove(&PendingId::RequestId(request_id))
                                .expect("Request to still be pending.")
                                .send(SenderType::Ack);
                        }
                    },
                },
                CoreEvent::OutboundFailure { request_id, .. } => {
                    let _ = self
                        .pending_requests
                        .remove(&PendingId::RequestId(request_id))
                        .expect("Request to still be pending.")
                        // TODO: add error for outbound failure containing the outbound failure
                        // error
                        .send(SenderType::Error(RPCError::TODO));
                }
                CoreEvent::InboundFailure {
                    peer,
                    request_id,
                    error,
                } => {
                    debug!(
                        "CoreEvent::InboundFailure:\npeer_id: {}\nrequest_id: {}\nerror: {}",
                        peer, request_id, error
                    );
                }
                CoreEvent::ResponseSent { peer, request_id } => {
                    trace!("Response for request {} sent to peer {}", request_id, peer);
                }
            },
            e => panic!("{:?}", e),
        }
    }

    pub async fn handle_command(&mut self, command: Command) {
        match command {
            Command::StartListening { addr, sender } => match self.swarm.listen_on(addr) {
                Ok(listener_id) => {
                    self.pending_requests
                        .insert(PendingId::ListenerId(listener_id), sender);
                }
                Err(_e) => {
                    // TODO: add listening error
                    let _ = sender.send(SenderType::Error(RPCError::TODO));
                }
            },
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(_e) =
                    self.pending_requests.entry(PendingId::PeerId(peer_id))
                {
                    self.swarm
                        .behaviour_mut()
                        .core
                        .add_address(&peer_id, peer_addr.clone());

                    match self
                        .swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                    {
                        Ok(()) => {
                            self.pending_requests
                                .insert(PendingId::PeerId(peer_id), sender);
                        }
                        Err(_e) => {
                            // TODO: add dial error
                            let _ = sender.send(SenderType::Error(RPCError::TODO));
                        }
                    }
                }
            }
            Command::PeerId { sender } => {
                let _ = sender.send(SenderType::PeerId(*self.swarm.local_peer_id()));
            }
            Command::SendRequest {
                namespace,
                method,
                peer_id,
                params,
                sender,
            } => {
                let request_id = self.swarm.behaviour_mut().core.send_request(
                    &peer_id,
                    CoreRequest(CoreRequestEvent::Request {
                        stream_id: None,
                        namespace,
                        method,
                        params,
                    }),
                );
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound request", "Sent SendRequest {} to peer {}", request_id, peer_id);
            }
            Command::SendResponse { payload, channel } => {
                self.swarm
                    .behaviour_mut()
                    .core
                    .send_response(channel, CoreResponse(CoreResponseEvent::Payload(payload)))
                    .expect("Connection to peer to still be open.");
                debug!(target: "outbound response", "Sent Payload response");
            }
            Command::ErrorResponse { error, channel } => {
                self.swarm
                    .behaviour_mut()
                    .core
                    .send_response(channel, CoreResponse(CoreResponseEvent::RPCError(error)))
                    .expect("Connection to peer to still be open.");
                debug!(target: "outbound response", "Sent Error response");
            }

            Command::StreamRequest {
                id,
                namespace,
                method,
                peer_id,
                params,
                sender,
            } => {
                let request_id = self.swarm.behaviour_mut().core.send_request(
                    &peer_id,
                    CoreRequest(CoreRequestEvent::Request {
                        stream_id: Some(id),
                        namespace,
                        method,
                        params,
                    }),
                );
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound streaming", "Sent StreamRequest {} to peer {}", request_id, peer_id);
            }
            Command::HeaderResponse { header, channel } => {
                self.swarm
                    .behaviour_mut()
                    .core
                    .send_response(
                        channel,
                        CoreResponse(CoreResponseEvent::Header(header.clone())),
                    )
                    .expect("Connection to peer to still be open.");
                debug!(target: "outbound streaming", "Sent HeaderResponse {:?}", header);
            }
            Command::SendPacket {
                peer_id,
                packet,
                sender,
            } => {
                let index = packet.index;
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .core
                    .send_request(&peer_id, CoreRequest(CoreRequestEvent::Packet(packet)));
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound streaming", "Sent packet {} with request_id {}", index, request_id);
            }
            Command::CloseStream { id } => match self.active_streams.remove(&id) {
                Some(_) => debug!(target: "inbound streaming", "Closing Stream {}", id),
                None => {
                    error!(target: "inbound streaming", "Expected stream {} to still exist, has already been removed", id)
                }
            },
            Command::ShutDown => {
                self.command_rec.close();
            }
        }
    }

    pub async fn handle_request(
        &mut self,
        name: String,
        method: String,
        streaming_id: Option<u64>,
        params: Vec<u8>,
    ) -> Result<Vec<u8>, RPCError> {
        let namespace = match self.handlers.get_mut(&name) {
            Some(n) => n,
            None => return Err(RPCError::NamespaceNotFound),
        };
        namespace
            .handle(method, &mut self.state, streaming_id, params)
            .await
    }
}

pub struct ServerConfig<T> {
    swarm: Option<Swarm<Behaviour>>,
    commands_receiver: Option<mpsc::Receiver<Command>>,
    state: Option<State<T>>,
    namespaces: HashMap<String, Namespace<T>>,
}

impl<T> ServerConfig<T> {
    pub fn new() -> Self {
        ServerConfig {
            swarm: None,
            commands_receiver: None,
            state: None,
            namespaces: Default::default(),
        }
    }

    pub fn with_swarm<I: Into<Swarm<Behaviour>>>(mut self, swarm: I) -> Self {
        self.swarm = Some(swarm.into());
        self
    }

    pub fn with_commands_receiver<I: Into<mpsc::Receiver<Command>>>(mut self, rec: I) -> Self {
        self.commands_receiver = Some(rec.into());
        self
    }

    pub fn with_state<I: Into<State<T>>>(mut self, state: I) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn with_namespace<F>(mut self, name: String, with_methods: F) -> Self
    where
        F: FnOnce(Namespace<T>) -> Namespace<T>,
    {
        let n = Namespace::new(name.clone());
        let n = with_methods(n);
        self.namespaces.insert(name, n);
        self
    }
}

pub struct Namespace<T> {
    name: String,
    handlers: HashMap<String, BoxedHandler<T>>,
}

impl<T> Namespace<T> {
    pub fn new(name: String) -> Self {
        Self {
            name,
            handlers: Default::default(),
        }
    }

    pub fn with_method(mut self, method: String, handler: BoxedHandler<T>) -> Self {
        self.handlers.insert(method, handler);
        self
    }

    pub async fn handle(
        &mut self,
        method: String,
        state: &mut State<T>,
        stream_id: Option<u64>,
        params: Vec<u8>,
    ) -> Result<Vec<u8>, RPCError> {
        let handler = match self.handlers.get(&method) {
            Some(h) => &h.0,
            None => return Err(RPCError::MethodNotFound),
        };
        handler(state, stream_id, params).await
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }
}

pub struct State<T>(T);

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Params<T>(pub T);

pub struct BoxedHandler<T>(
    Box<
        dyn Fn(
                &mut State<T>,
                Option<u64>,
                Vec<u8>,
            )
                -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<u8>, RPCError>> + Send>>
            + Send
            + Sync,
    >,
);
