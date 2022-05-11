use std::collections::HashMap;
use std::sync::Arc;

use futures::channel::mpsc;
use futures::prelude::*;
use futures::select;
pub use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::RequestResponseMessage;
use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmEvent};
use libp2p::Swarm;
use rkyv::Deserialize;
use tracing::{debug, error, trace};

use crate::behaviour::rpc::{RpcEvent, RpcRequest, RpcRequestEvent, RpcResponse, RpcResponseEvent};
use crate::behaviour::{Behaviour, Event};
use crate::builder::ServerConfig;
use crate::commands::{Command, PendingId, PendingMap, SenderType};
use crate::error::RpcError;
use crate::handler::{Namespace, State};
use crate::stream::{ActiveStreams, Header, StreamConfig};

/// The Server manages the swarm, gets commands from the client & translates
/// those into events to send over rpc to the correct recepient. It listens for
/// events from the network to give to the client. It also tracks any pending
/// requests we are still waiting on a response for and any active streams
/// that we are still currently listening for.
pub struct Server<T> {
    pub(crate) swarm: Swarm<Behaviour>,
    pub(crate) command_sender: mpsc::Sender<Command>,
    pub(crate) command_rec: mpsc::Receiver<Command>,
    pub(crate) pending_requests: PendingMap,
    pub(crate) active_streams: ActiveStreams,
    pub(crate) state: State<T>,
    pub(crate) handlers: HashMap<String, Namespace<T>>,
    pub(crate) stream_capacity: usize,
}

impl<T> Server<T> {
    pub fn server_from_config(
        command_sender: mpsc::Sender<Command>,
        command_receiver: mpsc::Receiver<Command>,
        config: ServerConfig<T>,
    ) -> Result<Self, RpcError> {
        let swarm = config
            .swarm
            .ok_or_else(|| RpcError::BadConfig("no swarm given".into()))?;
        let state = config
            .state
            .ok_or_else(|| RpcError::BadConfig("no server state specified".into()))?;
        Ok(Server {
            swarm,
            command_sender,
            command_rec: command_receiver,
            state,
            handlers: config.namespaces,
            pending_requests: Default::default(),
            active_streams: Default::default(),
            stream_capacity: config.stream_capacity,
        })
    }

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
                        debug!("{} shutting down", self.swarm.local_peer_id());
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
                    .remove(&PendingId::Listener(listener_id))
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
                debug!("Connection with {:?} established", peer_id);
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::Peer(peer_id)) {
                        let _ = sender.send(SenderType::Ack);
                    }
                }
            }
            SwarmEvent::ConnectionClosed { .. } => {}
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::Peer(peer_id)) {
                        let _ =
                            sender.send(SenderType::Error(RpcError::DialError(error.to_string())));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(peer_id) => {
                debug!("{} - Dialing {}", self.swarm.local_peer_id(), peer_id)
            }
            SwarmEvent::Behaviour(Event::Rpc(e)) => match e {
                RpcEvent::Message { message, peer, .. } => match message {
                    RequestResponseMessage::Request {
                        request, channel, ..
                    } => match request.0 {
                        RpcRequestEvent::Request {
                            namespace,
                            method,
                            params,
                            stream_id,
                        } => {
                            let cfg = match stream_id {
                                None => None,
                                Some(id) => Some(StreamConfig {
                                    id,
                                    peer_id: peer,
                                    channel: self.command_sender.clone(),
                                }),
                            };
                            match self.handle_request(namespace, method, cfg, params).await {
                                Ok(res) => {
                                    let event = match stream_id {
                                        None => RpcResponseEvent::Payload(res),
                                        Some(_) => RpcResponseEvent::Header(res),
                                    };
                                    self.swarm
                                        .behaviour_mut()
                                        .rpc
                                        .send_response(channel, RpcResponse(event))
                                        .expect("Connection to peer to still be open.");
                                }
                                Err(e) => {
                                    self.swarm
                                        .behaviour_mut()
                                        .rpc
                                        .send_response(
                                            channel,
                                            RpcResponse(RpcResponseEvent::RpcError(e)),
                                        )
                                        .expect("Connection to peer to still be open.");
                                }
                            };
                        }
                        RpcRequestEvent::Packet(packet) => {
                            let stream_id = packet.id;
                            let index = packet.index;
                            debug!("Received Packet {} for stream {}", index, stream_id);
                            if let Err(e) = self.active_streams.update_stream(packet) {
                                error!("Packet {} could not be delievered because stream {} no longer in active stream list", index, stream_id);
                                self.swarm
                                    .behaviour_mut()
                                    .rpc
                                    .send_response(
                                        channel,
                                        RpcResponse(RpcResponseEvent::RpcError(e)),
                                    )
                                    .expect("Connection to peer to still be open.");
                                return;
                            };

                            // only ack for now, send back error if we cannot send to stream
                            debug!("Acknowledging Packet {} from stream {}", index, stream_id);
                            self.swarm
                                .behaviour_mut()
                                .rpc
                                .send_response(channel, RpcResponse(RpcResponseEvent::Ack))
                                .expect("Connection to peer to still be open.");
                        }
                        RpcRequestEvent::StreamError { stream_id, error } => {
                            debug!("Received StreamError for stream {}", stream_id);
                            if let Err(e) = self.active_streams.send_error(stream_id, error) {
                                error!("StreamError could not be delievered because stream {} no longer in active stream list", stream_id);
                                self.swarm
                                    .behaviour_mut()
                                    .rpc
                                    .send_response(
                                        channel,
                                        RpcResponse(RpcResponseEvent::RpcError(e)),
                                    )
                                    .expect("Connection to peer to still be open.");
                                return;
                            }
                            // TODO: this is odd, but we need to send back a response
                            // only ack for now, send back error if we cannot send to stream
                            debug!("Acknowledging StreamError from stream {}", stream_id);
                            self.swarm
                                .behaviour_mut()
                                .rpc
                                .send_response(channel, RpcResponse(RpcResponseEvent::Ack))
                                .expect("Connection to peer to still be open.");
                        }
                    },
                    RequestResponseMessage::Response {
                        request_id,
                        response,
                    } => {
                        let sender = self
                            .pending_requests
                            .remove(&PendingId::Request(request_id))
                            .expect("Request to still be pending.");
                        match response.0 {
                            RpcResponseEvent::Payload(payload) => {
                                let _ = sender.send(SenderType::Res(payload));
                            }
                            RpcResponseEvent::RpcError(error) => {
                                let _ = sender.send(SenderType::Error(error));
                            }
                            RpcResponseEvent::Header(header) => {
                                let header = match rkyv::check_archived_root::<Header>(&header) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        let _ = sender.send(SenderType::Error(
                                            RpcError::SerializeError(e.to_string()),
                                        ));
                                        return;
                                    }
                                };
                                let header: Header = match header.deserialize(&mut rkyv::Infallible)
                                {
                                    Ok(h) => h,
                                    Err(e) => {
                                        let _ = sender.send(SenderType::Error(
                                            RpcError::SerializeError(e.to_string()),
                                        ));
                                        return;
                                    }
                                };

                                let (s, r) = mpsc::channel(self.stream_capacity);
                                debug!("Received header: Adding active stream {}", header.id);
                                self.active_streams.insert(header.clone(), s);
                                debug!("Sending stream receiver to client");
                                let _ = sender.send(SenderType::Stream { header, stream: r });
                            }
                            RpcResponseEvent::Ack => {
                                debug!("Received Ack for request {}", request_id);
                                let _ = sender.send(SenderType::Ack);
                            }
                        }
                    }
                },
                RpcEvent::OutboundFailure {
                    request_id, error, ..
                } => {
                    let _ = self
                        .pending_requests
                        .remove(&PendingId::Request(request_id))
                        .expect("Request to still be pending.")
                        .send(SenderType::Error(RpcError::OutboundFailure(
                            error.to_string(),
                        )));
                }
                RpcEvent::InboundFailure {
                    peer,
                    request_id,
                    error,
                } => {
                    debug!(
                        "RpcEvent::InboundFailure:\npeer_id: {}\nrequest_id: {}\nerror: {}",
                        peer, request_id, error
                    );
                }
                RpcEvent::ResponseSent { peer, request_id } => {
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
                        .insert(PendingId::Listener(listener_id), sender);
                }
                Err(e) => {
                    let _ = sender.send(SenderType::Error(RpcError::TransportError(e.to_string())));
                }
            },
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(_e) =
                    self.pending_requests.entry(PendingId::Peer(peer_id))
                {
                    self.swarm
                        .behaviour_mut()
                        .rpc
                        .add_address(&peer_id, peer_addr.clone());

                    match self
                        .swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                    {
                        Ok(()) => {
                            self.pending_requests
                                .insert(PendingId::Peer(peer_id), sender);
                        }
                        Err(e) => {
                            let _ =
                                sender.send(SenderType::Error(RpcError::DialError(e.to_string())));
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
                let request_id = self.swarm.behaviour_mut().rpc.send_request(
                    &peer_id,
                    RpcRequest(RpcRequestEvent::Request {
                        stream_id: None,
                        namespace,
                        method,
                        params,
                    }),
                );
                self.pending_requests
                    .insert(PendingId::Request(request_id), sender);
                debug!("Sent SendRequest {} to peer {}", request_id, peer_id);
            }
            Command::SendResponse { payload, channel } => {
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(channel, RpcResponse(RpcResponseEvent::Payload(payload)))
                    .expect("Connection to peer to still be open.");
                debug!("Sent Payload response");
            }
            Command::ErrorResponse { error, channel } => {
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(channel, RpcResponse(RpcResponseEvent::RpcError(error)))
                    .expect("Connection to peer to still be open.");
                debug!("Sent Error response");
            }

            Command::StreamRequest {
                id,
                namespace,
                method,
                peer_id,
                params,
                sender,
            } => {
                let request_id = self.swarm.behaviour_mut().rpc.send_request(
                    &peer_id,
                    RpcRequest(RpcRequestEvent::Request {
                        stream_id: Some(id),
                        namespace,
                        method,
                        params,
                    }),
                );
                self.pending_requests
                    .insert(PendingId::Request(request_id), sender);
                debug!("Sent StreamRequest {} to peer {}", request_id, peer_id);
            }
            Command::HeaderResponse { header, channel } => {
                let header = rkyv::to_bytes::<_, 1024>(&header).expect("header to serialize");
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(
                        channel,
                        RpcResponse(RpcResponseEvent::Header(header.to_vec())),
                    )
                    .expect("Connection to peer to still be open.");
                debug!("Sent HeaderResponse {:?}", header);
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
                    .rpc
                    .send_request(&peer_id, RpcRequest(RpcRequestEvent::Packet(packet)));
                self.pending_requests
                    .insert(PendingId::Request(request_id), sender);
                debug!("Sent packet {} with request_id {}", index, request_id);
            }
            Command::CloseStream { id } => self.active_streams.remove(id),
            Command::ShutDown => {
                self.command_rec.close();
            }
        }
    }

    pub async fn handle_request(
        &mut self,
        name: String,
        method: String,
        stream_cfg: Option<StreamConfig>,
        params: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        let namespace = match self.handlers.get_mut(&name) {
            Some(n) => n,
            None => return Err(RpcError::NamespaceNotFound(name)),
        };
        namespace
            .handle(method, State(Arc::clone(&self.state.0)), stream_cfg, params)
            .await
    }
}
