use crate::behaviour::{CoreBehaviour, CoreEvent};
use crate::commands::{ActiveStreams, InCommand, OutCommand, PendingId, PendingMap, SenderType};
use crate::request_response::{
    Request, RequestEvent, RequestResponseEvent, Response, ResponseEvent,
};
use crate::stream::{InStream, StreamError, StreamType};
use crate::streaming::{
    StreamingEvent, StreamingRequest, StreamingRequestEvent, StreamingResponse,
    StreamingResponseChannel, StreamingResponseEvent,
};

use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::select;
use libp2p::core::either::EitherError;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::RequestResponseMessage;
use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmBuilder, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm};
use log::{debug, error};
use rand::Rng;
use std::error::Error;

pub use libp2p::identity::Keypair;

pub struct Server {
    swarm: Swarm<CoreBehaviour>,
    // commands received from the client aka user
    out_receiver: mpsc::Receiver<OutCommand>,
    // commands sent to the client from the network
    in_sender: mpsc::Sender<InboundEvent>,
    pending_requests: PendingMap,
    active_streams: ActiveStreams,
}

impl Server {
    pub fn new(
        swarm: Swarm<CoreBehaviour>,
        out_receiver: mpsc::Receiver<OutCommand>,
        in_sender: mpsc::Sender<InboundEvent>,
    ) -> Self {
        Server {
            swarm,
            out_receiver,
            in_sender,
            pending_requests: Default::default(),
            active_streams: Default::default(),
        }
    }

    pub async fn run(mut self) {
        loop {
            select! {
                event = self.swarm.next() => {
                    let event = event.expect("Swarm stream to be infinite.");
                    self.handle_event(event).await
                }
                command = self.out_receiver.next() => match command {
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

    async fn handle_client_command(&mut self, command: OutCommand) {
        match command {
            OutCommand::StartListening { addr, sender } => match self.swarm.listen_on(addr) {
                Ok(listener_id) => {
                    self.pending_requests
                        .insert(PendingId::ListenerId(listener_id), sender);
                }
                Err(e) => {
                    let _ = sender.send(SenderType::Error(Box::new(e)));
                }
            },
            OutCommand::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(_e) =
                    self.pending_requests.entry(PendingId::PeerId(peer_id))
                {
                    self.swarm
                        .behaviour_mut()
                        .request_response
                        .add_address(&peer_id, peer_addr.clone());

                    match self
                        .swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                    {
                        Ok(()) => {
                            self.pending_requests
                                .insert(PendingId::PeerId(peer_id), sender);
                        }
                        Err(e) => {
                            let _ = sender.send(SenderType::Error(Box::new(e)));
                        }
                    }
                }
            }
            OutCommand::Ping { peer_id, sender } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, Request(RequestEvent::Ping));
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
            }
            OutCommand::DataRequest {
                path,
                id,
                peer_id,
                sender,
            } => {
                let request_id = self.swarm.behaviour_mut().streaming.send_request(
                    &peer_id,
                    StreamingRequest(StreamingRequestEvent::DataRequest { id, path }),
                );
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound streaming", "Sent DataRequest {} to peer {}", request_id, peer_id);
            }
            OutCommand::HeaderResponse { header, channel } => {
                self.swarm
                    .behaviour_mut()
                    .streaming
                    .send_response(
                        channel,
                        StreamingResponse(StreamingResponseEvent::Header(header.clone())),
                    )
                    .expect("Connection to peer to still be open.");
                debug!(target: "outbound streaming", "Sent HeaderResponse {:?}", header);
            }
            OutCommand::SendPacket {
                peer_id,
                packet,
                sender,
            } => {
                let index = packet.index;
                let request_id = self.swarm.behaviour_mut().streaming.send_request(
                    &peer_id,
                    StreamingRequest(StreamingRequestEvent::Packet(packet)),
                );
                self.pending_requests
                    .insert(PendingId::RequestId(request_id), sender);
                debug!(target: "outbound streaming", "Sent packet {} with request_id {}", index, request_id);
            }
            OutCommand::CloseStream { id } => match self.active_streams.remove(&id) {
                Some(_) => debug!(target: "inbound streaming", "Closing Stream {}", id),
                None => {
                    error!(target: "inbound streaming", "Expected stream {} to still exist, has already been removed", id)
                }
            },
            OutCommand::PeerId { sender } => {
                let _ = sender.send(SenderType::PeerId(*self.swarm.local_peer_id()));
            }
        }
    }

    async fn handle_event(
        &mut self,
        event: SwarmEvent<
            CoreEvent,
            EitherError<
                ConnectionHandlerUpgrErr<std::io::Error>,
                ConnectionHandlerUpgrErr<std::io::Error>,
            >,
        >,
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
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::PeerId(peer_id))
                    {
                        let _ = sender.send(SenderType::Error(Box::new(error)));
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {}
            SwarmEvent::Dialing(peer_id) => {
                println!("{} - Dialing {}", self.swarm.local_peer_id(), peer_id)
            }
            SwarmEvent::Behaviour(CoreEvent::Streaming(e)) => self.handle_streaming_events(e).await,
            SwarmEvent::Behaviour(CoreEvent::RequestResponse(e)) => {
                self.handle_request_response_events(e).await
            }
            e => panic!("{:?}", e),
        }
    }

    async fn handle_request_response_events(&mut self, event: RequestResponseEvent) {
        match event {
            RequestResponseEvent::Message { message, .. } => match message {
                RequestResponseMessage::Request {
                    request, channel, ..
                } => match request.0 {
                    RequestEvent::Ping => {
                        println!("{:?} received ping", self.swarm.local_peer_id());
                        // under different circumstances, we may want to send this down another
                        // channel that is listening for network commands, to deal with responding
                        // somewhere else.
                        self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, Response(ResponseEvent::Pong))
                            .expect("Connection to peer to still be open.");
                    }
                },
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => match response.0 {
                    ResponseEvent::Pong => {
                        println!("{:?} received pong", self.swarm.local_peer_id());
                        let _ = self
                            .pending_requests
                            .remove(&PendingId::RequestId(request_id))
                            .expect("Request to still be pending.")
                            .send(SenderType::Ack);
                    }
                },
            },
            RequestResponseEvent::OutboundFailure {
                request_id, error, ..
            } => {
                let _ = self
                    .pending_requests
                    .remove(&PendingId::RequestId(request_id))
                    .expect("Request to still be pending.")
                    .send(SenderType::Error(Box::new(error)));
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                print!("\n\nThis peer_id: {}\n", self.swarm.local_peer_id());
                println!(
                    "RequestResponseEvent::InboundFailure:\npeer_id: {}\nrequest_id: {}\nerror: {}",
                    peer, request_id, error
                );
            }
            RequestResponseEvent::ResponseSent { .. } => {}
        }
    }

    async fn handle_streaming_events(&mut self, event: StreamingEvent) {
        match event {
            StreamingEvent::Message { message, peer } => match message {
                RequestResponseMessage::Request {
                    request, channel, ..
                } => match request.0 {
                    StreamingRequestEvent::DataRequest { id, path } => {
                        debug!(target: "inbound streaming", "Inbound data request for {} with id {}", path, id);
                        self.in_sender
                            .send(InboundEvent {
                                command: InCommand::DataRequest {
                                    id,
                                    path,
                                    peer_id: peer,
                                },
                                channel,
                            })
                            .await
                            .expect("Inbound Sender to still be open.");
                    }
                    StreamingRequestEvent::Packet(packet) => {
                        let stream_id = packet.id;
                        let index = packet.index;
                        debug!(target: "inbound streaming", "Received Packet {} for stream {}", index, stream_id);
                        let sender = match self.active_streams.get_mut(&stream_id) {
                            Some(s) => s,
                            None => {
                                error!(target: "inbound streaming", "Packet {} could not be delievered because stream {} no longer in active stream list", index, stream_id);
                                self.swarm
                                    .behaviour_mut()
                                    .streaming
                                    .send_response(
                                        channel,
                                        StreamingResponse(StreamingResponseEvent::StreamError(
                                            StreamError::NoLongerActive,
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
                            .streaming
                            .send_response(channel, StreamingResponse(StreamingResponseEvent::Ack))
                            .expect("Connection to peer to still be open.");
                    }
                },
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => match response.0 {
                    StreamingResponseEvent::Header(header) => {
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
                    StreamingResponseEvent::Ack => {
                        debug!(target: "inbound streaming", "Received Ack for request {}", request_id);
                        let _ = self
                            .pending_requests
                            .remove(&PendingId::RequestId(request_id))
                            .expect("Request to still be pending.")
                            .send(SenderType::Ack);
                    }
                    StreamingResponseEvent::StreamError(e) => {
                        debug!(target: "inbound streaming", "Received Ack for request {}", request_id);
                        let _ = self
                            .pending_requests
                            .remove(&PendingId::RequestId(request_id))
                            .expect("Request to still be pending.")
                            .send(SenderType::Error(e.into()));
                    }
                },
            },
            StreamingEvent::OutboundFailure {
                request_id, error, ..
            } => {
                let _ = self
                    .pending_requests
                    .remove(&PendingId::RequestId(request_id))
                    .expect("Request to still be pending.")
                    .send(SenderType::Error(Box::new(error)));
            }
            StreamingEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                print!("\n\nThis peer_id: {}\n", self.swarm.local_peer_id());
                println!(
                    "RequestResponseEvent::InboundFailure:\npeer_id: {}\nrequest_id: {}\nerror: {}",
                    peer, request_id, error
                );
            }
            StreamingEvent::ResponseSent { .. } => {}
        }
    }
}

pub struct InboundEvent {
    pub command: InCommand,
    pub channel: StreamingResponseChannel,
}

// eventually generalize, pass in config etc
pub fn new_mem_swarm(id_keys: Keypair) -> Swarm<CoreBehaviour> {
    let peer_id = id_keys.public().to_peer_id();
    SwarmBuilder::new(mem_transport(id_keys), CoreBehaviour::new(), peer_id).build()
}

pub async fn new_swarm(id_keys: Keypair) -> Result<Swarm<CoreBehaviour>, Box<dyn Error>> {
    let peer_id = id_keys.public().to_peer_id();
    Ok(SwarmBuilder::new(
        libp2p::development_transport(id_keys).await?,
        CoreBehaviour::new(),
        peer_id,
    )
    .build())
}

use libp2p::core::transport::{MemoryTransport, Transport};
use libp2p::core::{muxing, transport, upgrade};
use libp2p::mplex;
use libp2p::noise;
use libp2p::yamux;

pub fn mem_transport(keypair: Keypair) -> transport::Boxed<(PeerId, muxing::StreamMuxerBox)> {
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .unwrap();
    MemoryTransport::default()
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(upgrade::SelectUpgrade::new(
            yamux::YamuxConfig::default(),
            mplex::MplexConfig::default(),
        ))
        .timeout(std::time::Duration::from_secs(20))
        .boxed()
}

pub struct Client {
    out_sender: mpsc::Sender<OutCommand>,
}

impl Client {
    pub fn new(out_sender: mpsc::Sender<OutCommand>) -> Self {
        Self { out_sender }
    }

    pub fn sender(&self) -> mpsc::Sender<OutCommand> {
        self.out_sender.clone()
    }

    pub async fn start_listening(
        &mut self,
        addr: Multiaddr,
    ) -> Result<Multiaddr, Box<dyn Error + Send + Sync>> {
        let (sender, rec) = oneshot::channel();
        self.out_sender
            .send(OutCommand::StartListening { addr, sender })
            .await
            .expect("Command receiver not to be dropped.");
        match rec.await.expect("Sender not to be dropped.") {
            SenderType::Multiaddr(m) => Ok(m),
            SenderType::Error(e) => Err(e),
            s => Err(format!("Incorrect SenderType: {:?}", s).into()),
        }
    }

    pub async fn dial(
        &mut self,
        peer_id: PeerId,
        peer_addr: Multiaddr,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (sender, rec) = oneshot::channel();
        self.out_sender
            .send(OutCommand::Dial {
                peer_id,
                peer_addr,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped.");
        match rec.await.expect("Sender not to be dropped.") {
            SenderType::Ack => Ok(()),
            SenderType::Error(e) => Err(e),
            s => Err(format!("Incorrect SenderType: {:?}", s).into()),
        }
    }

    pub async fn ping(&mut self, peer_id: PeerId) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (sender, rec) = oneshot::channel();
        self.out_sender
            .send(OutCommand::Ping { peer_id, sender })
            .await
            .expect("Command receiver not to be dropped");
        match rec.await.expect("Sender not to be dropped.") {
            SenderType::Ack => Ok(()),
            SenderType::Error(e) => Err(e),
            s => Err(format!("Incorrect SenderType: {:?}", s).into()),
        }
    }

    pub async fn peer_id(&mut self) -> PeerId {
        let (sender, rec) = oneshot::channel();
        self.out_sender
            .send(OutCommand::PeerId { sender })
            .await
            .expect("Command receiver not to be dropped");
        match rec.await.expect("Sender not to be dropped") {
            SenderType::PeerId(p) => p,
            s => panic!("Unexpected SenderType: {:?}", s),
        }
    }

    pub async fn get_file(
        &mut self,
        peer_id: PeerId,
        path: String,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let (sender, rec) = oneshot::channel();
        debug!(target: "client streaming", "Sending OutCommand::DataRequest for {}", path);
        // come up with better solution for generating an id
        let id: u64 = {
            let mut rng = rand::thread_rng();
            rng.gen()
        };

        self.out_sender
            .send(OutCommand::DataRequest {
                peer_id,
                id,
                path,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        let (header, stream) = match rec.await.expect("Sender not to be dropped.") {
            SenderType::Stream { header, stream } => (header, stream),
            s => {
                return Err(format!("Incorrect SenderType: {:?}", s).into());
            }
        };

        // can examine heade_ here and determine if we even want to
        // accept this file
        // need some way of rejecting if we don't want it
        // ignoring this for now

        debug!(target: "client streaming", "Received Header: {:?}", header);
        let mut f = Vec::new();

        let mut s = InStream::new(header, stream, self.out_sender.clone());

        while let Some(res) = s.next().await {
            match res {
                Ok(mut d) => f.append(&mut d),
                Err(e) => {
                    debug!(target: "client streaming", "Unexpected error: {:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(f)
    }
}
