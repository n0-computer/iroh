use futures::channel::{mpsc, oneshot};
use libp2p::core::connection::ListenerId;
use libp2p::request_response::RequestId;
use libp2p::Multiaddr;
use libp2p::PeerId;
use std::collections::HashMap;

use crate::behaviour::core::CoreResponseChannel;
use crate::error::RPCError;
use crate::stream::{Header, Packet, StreamType};

// Commands are commands from the Client going out to the server or network
// They should include a sender on which the server will send the response from
// the network to the client
#[derive(Debug)]
pub enum Command {
    // Commands handled by CoreProtocol
    StartListening {
        addr: Multiaddr,
        sender: OneshotSender,
    },
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: OneshotSender,
    },
    PeerId {
        sender: OneshotSender,
    },
    SendRequest {
        namespace: String,
        method: String,
        peer_id: PeerId,
        params: Vec<u8>,
        sender: OneshotSender,
    },
    SendResponse {
        payload: Vec<u8>,
        channel: CoreResponseChannel,
    },
    ErrorResponse {
        error: RPCError,
        channel: CoreResponseChannel,
    },

    StreamRequest {
        id: u64,
        namespace: String,
        method: String,
        peer_id: PeerId,
        params: Vec<u8>,
        sender: OneshotSender,
    },
    HeaderResponse {
        header: Header,
        channel: CoreResponseChannel,
    },
    SendPacket {
        peer_id: PeerId,
        packet: Packet,
        sender: OneshotSender,
    },
    CloseStream {
        id: u64,
    },
    ShutDown,
}

pub type OneshotSender = oneshot::Sender<SenderType>;

#[derive(Debug)]
pub enum SenderType {
    Ack,
    File(Vec<u8>),
    PeerId(PeerId),
    Multiaddr(Multiaddr),
    Stream {
        header: Header,
        stream: mpsc::Receiver<StreamType>,
    },
    Error(RPCError),
    Res(Vec<u8>),
}

pub type PendingMap = HashMap<PendingId, OneshotSender>;

#[derive(PartialEq, Eq, Hash)]
pub enum PendingId {
    PeerId(PeerId),
    RequestId(RequestId),
    ListenerId(ListenerId),
}

pub type ActiveStreams = HashMap<u64, mpsc::Sender<StreamType>>;
