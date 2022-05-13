use std::collections::HashMap;
use std::sync::Arc;

use bytecheck::CheckBytes;
use futures::channel::oneshot;
use futures::prelude::*;
pub use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{RequestResponseMessage, ResponseChannel};
use libp2p::swarm::{ConnectionHandlerUpgrErr, SwarmEvent};
use libp2p::{Multiaddr, PeerId, Swarm};
use rkyv::{Archive, Deserialize, Serialize};
use tokio::{select, sync::mpsc};
use tracing::{debug, error, info, trace, warn};

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
    pub(crate) my_namespace: String,
    pub(crate) addresses: AddressBook,
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
            my_namespace: config.my_namespace,
            command_sender,
            command_rec: command_receiver,
            state,
            handlers: config.namespaces,
            pending_requests: Default::default(),
            active_streams: Default::default(),
            stream_capacity: config.stream_capacity,
            addresses: config.addresses,
        })
    }

    pub async fn run(mut self) {
        loop {
            select! {
                event = self.swarm.next() => {
                    let event = event.expect("Swarm stream to be infinite.");
                    self.handle_event(event).await
                }
                command = self.command_rec.recv() => match command {
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

    fn send_response(&mut self, channel: ResponseChannel<RpcResponse>, msg: RpcResponseEvent) {
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .rpc
            .send_response(channel, RpcResponse(msg))
        {
            warn!("Connection to peer is already closed {:?}", e);
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
                info!("listening on {} - {}", address, local_peer_id);
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
                info!("Connection with {:?} established", peer_id);
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::Peer(peer_id)) {
                        let _ = sender.send(SenderType::Ack);
                    }
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                info!("Connection with {:?} closed ({})", peer_id, num_established);
                if num_established < 1 {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::Peer(peer_id)) {
                        let _ = self.addresses.remove_by_peer_id(peer_id);
                        let _ = sender.send(SenderType::Error(RpcError::StreamClosed));
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    if let Some(sender) = self.pending_requests.remove(&PendingId::Peer(peer_id)) {
                        let _ = self.addresses.remove_by_peer_id(peer_id);
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
                            let msg =
                                match self.handle_request(namespace, method, cfg, params).await {
                                    Ok(res) => match stream_id {
                                        None => RpcResponseEvent::Payload(res),
                                        Some(_) => RpcResponseEvent::Header(res),
                                    },
                                    Err(e) => RpcResponseEvent::RpcError(e),
                                };

                            self.send_response(channel, msg);
                        }
                        RpcRequestEvent::Packet(packet) => {
                            let stream_id = packet.id;
                            let index = packet.index;
                            debug!("Received Packet {} for stream {}", index, stream_id);
                            if let Err(e) = self.active_streams.update_stream(packet) {
                                error!("Packet {} could not be delievered because stream {} no longer in active stream list", index, stream_id);
                                self.send_response(channel, RpcResponseEvent::RpcError(e));

                                return;
                            };

                            // only ack for now, send back error if we cannot send to stream
                            debug!("Acknowledging Packet {} from stream {}", index, stream_id);
                            self.send_response(channel, RpcResponseEvent::Ack);
                        }
                        RpcRequestEvent::StreamError { stream_id, error } => {
                            debug!("Received StreamError for stream {}", stream_id);
                            if let Err(e) = self.active_streams.send_error(stream_id, error) {
                                error!("StreamError could not be delivered because stream {} no longer in active stream list", stream_id);
                                self.send_response(channel, RpcResponseEvent::RpcError(e));
                                return;
                            }

                            // TODO: this is odd, but we need to send back a response
                            // only ack for now, send back error if we cannot send to stream
                            debug!("Acknowledging StreamError from stream {}", stream_id);
                            self.send_response(channel, RpcResponseEvent::Ack);
                        }
                        RpcRequestEvent::AddressBook(address_book) => {
                            let sender = self.command_sender.clone();
                            for addrs in address_book.0 {
                                if addrs.namespace == self.my_namespace {
                                    continue;
                                };
                                let namespace = addrs.namespace;
                                let address: Multiaddr = addrs.addrs[0].parse().unwrap();
                                let peer_id: PeerId = addrs.peer_id.parse().unwrap();
                                if !self.addresses.exists(namespace.clone()) {
                                    let sender = sender.clone();
                                    tokio::spawn(async move {
                                        let (s, r) = oneshot::channel();
                                        if let Err(e) = sender
                                            .send(Command::Dial {
                                                namespace,
                                                address,
                                                peer_id,
                                                sender: s,
                                            })
                                            .await
                                        {
                                            warn!("receiver dropped {:?}", e);
                                        }

                                        match r.await {
                                            Ok(SenderType::Ack) => (),
                                            Ok(SenderType::Error(e)) => error!("Error connecting to namespaces in address book: {}", e),
                                            Ok(s) => {
                                                error!("Error, unexpected response type when trying to connect to namespaces is address book: {}", s) ;
                                            },
                                            Err(e) => {
                                                warn!("sender dropped {:?}", e);
                                            },
                                        };
                                    });
                                }
                            }
                            self.send_response(channel, RpcResponseEvent::Ack);
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
                    if let Some(sender) = self
                        .pending_requests
                        .remove(&PendingId::Request(request_id))
                    {
                        if let Err(e) = sender.send(SenderType::Error(RpcError::OutboundFailure(
                            error.to_string(),
                        ))) {
                            warn!("failed to send error {}: {:?}", error, e);
                        }
                    } else {
                        warn!("missing sender for request {}", request_id);
                    }
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
                namespace,
                peer_id,
                address,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(_e) =
                    self.pending_requests.entry(PendingId::Peer(peer_id))
                {
                    self.swarm
                        .behaviour_mut()
                        .rpc
                        .add_address(&peer_id, address.clone());

                    self.addresses
                        .insert(namespace, vec![address.clone()], peer_id);

                    match self.swarm.dial(address.with(Protocol::P2p(peer_id.into()))) {
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
            Command::SendAddressBook { sender, namespace } => {
                let (_, peer_id) = match self.addresses.get(&namespace) {
                    None => {
                        let _ =
                            sender.send(SenderType::Error(RpcError::NoNamespacePeerId(namespace)));
                        return;
                    }
                    Some(val) => val,
                };
                let mut address_book: ArchivableAddressBook = self.addresses.clone().into();
                address_book.0.push(ArchivableAddress::new(
                    self.my_namespace.clone(),
                    self.swarm.listeners().cloned().collect(),
                    self.swarm.local_peer_id(),
                ));
                let request_id = self.swarm.behaviour_mut().rpc.send_request(
                    peer_id,
                    RpcRequest(RpcRequestEvent::AddressBook(address_book)),
                );
                self.pending_requests
                    .insert(PendingId::Request(request_id), sender);
                debug!("Sent SendRequest {} to peer {}", request_id, peer_id);
            }
            Command::PeerId { sender } => {
                let _ = sender.send(SenderType::PeerId(*self.swarm.local_peer_id()));
            }
            Command::SendRequest {
                namespace,
                method,
                params,
                sender,
            } => {
                let (_, peer_id) = match self.addresses.get(&namespace) {
                    None => {
                        let _ =
                            sender.send(SenderType::Error(RpcError::NoNamespacePeerId(namespace)));
                        return;
                    }
                    Some(val) => val,
                };
                let request_id = self.swarm.behaviour_mut().rpc.send_request(
                    peer_id,
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
                self.send_response(channel, RpcResponseEvent::Payload(payload));
                debug!("Sent Payload response");
            }
            Command::ErrorResponse { error, channel } => {
                self.send_response(channel, RpcResponseEvent::RpcError(error));
                debug!("Sent Error response");
            }

            Command::StreamRequest {
                id,
                namespace,
                method,
                params,
                sender,
            } => {
                let (_, peer_id) = match self.addresses.get(&namespace) {
                    None => {
                        let _ =
                            sender.send(SenderType::Error(RpcError::NoNamespacePeerId(namespace)));
                        return;
                    }
                    Some(val) => val,
                };
                let request_id = self.swarm.behaviour_mut().rpc.send_request(
                    peer_id,
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
                self.send_response(channel, RpcResponseEvent::Header(header.to_vec()));
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

#[derive(Clone, Debug)]
pub struct AddressBook(HashMap<String, (Vec<Multiaddr>, PeerId)>);

impl AddressBook {
    pub fn new() -> Self {
        AddressBook(Default::default())
    }

    pub fn insert(&mut self, namespace: String, addrs: Vec<Multiaddr>, peer_id: PeerId) {
        self.0.insert(namespace, (addrs, peer_id));
    }

    pub fn remove(&mut self, namespace: &str) {
        self.0.remove(namespace);
    }

    pub fn remove_by_peer_id(&mut self, peer_id: PeerId) {
        let mut namespace = String::new();
        for (n, (_, pid)) in self.0.iter() {
            if peer_id == *pid {
                namespace = n.clone();
                break;
            }
        }
        self.0.remove(&namespace);
    }

    pub fn get(&self, namespace: &str) -> Option<&(Vec<Multiaddr>, PeerId)> {
        self.0.get(namespace)
    }

    pub fn exists(&mut self, namespace: String) -> bool {
        if let std::collections::hash_map::Entry::Vacant(_e) = self.0.entry(namespace) {
            return false;
        }
        true
    }
}

impl From<ArchivableAddressBook> for AddressBook {
    fn from(arc: ArchivableAddressBook) -> Self {
        let mut addresses = AddressBook(Default::default());
        for a in arc.0 {
            addresses.insert(
                a.namespace,
                a.addrs.iter().map(|a| a.parse().unwrap()).collect(),
                a.peer_id.parse().unwrap(),
            );
        }
        addresses
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        AddressBook::new()
    }
}

// TODO: more serialization bs
#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub struct ArchivableAddressBook(Vec<ArchivableAddress>);

impl From<AddressBook> for ArchivableAddressBook {
    fn from(a: AddressBook) -> Self {
        let mut s = ArchivableAddressBook(Default::default());
        for (namespace, (addrs, peer_id)) in a.0.iter() {
            s.0.push(ArchivableAddress::new(
                namespace.to_string(),
                addrs.to_owned(),
                peer_id,
            ));
        }
        s
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub struct ArchivableAddress {
    namespace: String,
    addrs: Vec<String>,
    peer_id: String,
}

impl ArchivableAddress {
    fn new(namespace: String, addrs: Vec<Multiaddr>, peer_id: &PeerId) -> Self {
        Self {
            namespace,
            addrs: addrs.iter().map(|a| a.to_string()).collect(),
            peer_id: peer_id.to_string(),
        }
    }
}
