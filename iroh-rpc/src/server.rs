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
use tracing::{debug, error, trace};

use crate::behaviour::rpc::{RpcEvent, RpcRequest, RpcRequestEvent, RpcResponse, RpcResponseEvent};
use crate::behaviour::{Behaviour, Event};
use crate::commands::{ActiveStreams, Command, PendingId, PendingMap, SenderType};
use crate::config::ServerConfig;
use crate::error::RpcError;
use crate::handler::{Namespace, State};
use crate::stream::StreamType;

/// The Server manages the swarm, gets commands from the client & translates
/// those into events to send over rpc to the correct recepient. It listens for
/// events from the network to give to the client. It also tracks any pending
/// requests we are still waiting on a response for and any active streams
/// that we are still currently listening for.
pub struct Server<T> {
    pub(crate) swarm: Swarm<Behaviour>,
    pub(crate) command_rec: mpsc::Receiver<Command>,
    pub(crate) pending_requests: PendingMap,
    pub(crate) active_streams: ActiveStreams,
    pub(crate) state: State<T>,
    pub(crate) handlers: HashMap<String, Namespace<T>>,
}

impl<T> Server<T> {
    pub fn server_from_config(
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
            command_rec: command_receiver,
            state,
            handlers: config.namespaces,
            pending_requests: Default::default(),
            active_streams: Default::default(),
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
                debug!("Connection with {:?} established", peer_id);
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
                        let _ = sender.send(SenderType::Error(RpcError::TODO));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(peer_id) => {
                debug!("{} - Dialing {}", self.swarm.local_peer_id(), peer_id)
            }
            SwarmEvent::Behaviour(Event::Rpc(e)) => match e {
                RpcEvent::Message { message, .. } => match message {
                    RequestResponseMessage::Request {
                        request, channel, ..
                    } => match request.0 {
                        RpcRequestEvent::Request {
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
                                        .rpc
                                        .send_response(
                                            channel,
                                            RpcResponse(RpcResponseEvent::Payload(res)),
                                        )
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
                                    return;
                                }
                            };
                        }
                        RpcRequestEvent::Packet(packet) => {
                            let stream_id = packet.id;
                            let index = packet.index;
                            debug!(target: "inbound streaming", "Received Packet {} for stream {}", index, stream_id);
                            let sender = match self.active_streams.get_mut(&stream_id) {
                                Some(s) => s,
                                None => {
                                    error!(target: "inbound streaming", "Packet {} could not be delievered because stream {} no longer in active stream list", index, stream_id);
                                    self.swarm
                                        .behaviour_mut()
                                        .rpc
                                        .send_response(
                                            channel,
                                            RpcResponse(RpcResponseEvent::RpcError(
                                                RpcError::StreamClosed,
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
                            .remove(&PendingId::RequestId(request_id))
                            .expect("Request to still be pending.");
                        match response.0 {
                            RpcResponseEvent::Payload(payload) => {
                                let _ = sender.send(SenderType::Res(payload));
                            }
                            RpcResponseEvent::RpcError(error) => {
                                let _ = sender.send(SenderType::Error(error));
                            }
                            RpcResponseEvent::Header(header) => {
                                let (s, r) = mpsc::channel(1000);
                                debug!(target: "inbound streaming", "Received header: Adding active stream {}", header.id);
                                self.active_streams.insert(header.id, s);
                                debug!(target: "inbound streaming", "Sending stream receiver to client");
                                let _ = sender.send(SenderType::Stream { header, stream: r });
                            }
                            RpcResponseEvent::Ack => {
                                debug!(target: "inbound streaming", "Received Ack for request {}", request_id);
                                let _ = sender.send(SenderType::Ack);
                            }
                        }
                    }
                },
                RpcEvent::OutboundFailure { request_id, .. } => {
                    let _ = self
                        .pending_requests
                        .remove(&PendingId::RequestId(request_id))
                        .expect("Request to still be pending.")
                        // TODO: add error for outbound failure containing the outbound failure
                        // error
                        .send(SenderType::Error(RpcError::TODO));
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
                        .insert(PendingId::ListenerId(listener_id), sender);
                }
                Err(_e) => {
                    // TODO: add listening error
                    let _ = sender.send(SenderType::Error(RpcError::TODO));
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
                        .rpc
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
                            let _ = sender.send(SenderType::Error(RpcError::TODO));
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
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound request", "Sent SendRequest {} to peer {}", request_id, peer_id);
            }
            Command::SendResponse { payload, channel } => {
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(channel, RpcResponse(RpcResponseEvent::Payload(payload)))
                    .expect("Connection to peer to still be open.");
                debug!(target: "outbound response", "Sent Payload response");
            }
            Command::ErrorResponse { error, channel } => {
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(channel, RpcResponse(RpcResponseEvent::RpcError(error)))
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
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound streaming", "Sent StreamRequest {} to peer {}", request_id, peer_id);
            }
            Command::HeaderResponse { header, channel } => {
                self.swarm
                    .behaviour_mut()
                    .rpc
                    .send_response(
                        channel,
                        RpcResponse(RpcResponseEvent::Header(header.clone())),
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
                    .rpc
                    .send_request(&peer_id, RpcRequest(RpcRequestEvent::Packet(packet)));
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
    ) -> Result<Vec<u8>, RpcError> {
        let namespace = match self.handlers.get_mut(&name) {
            Some(n) => n,
            None => return Err(RpcError::NamespaceNotFound(name)),
        };
        namespace
            .handle(
                method,
                State(Arc::clone(&self.state.0)),
                streaming_id,
                params,
            )
            .await
    }
}
