use futures::channel::{mpsc, oneshot};
use libp2p::core::connection::ListenerId;
use libp2p::request_response::RequestId;
use libp2p::Multiaddr;
use libp2p::PeerId;
use std::collections::HashMap;
use std::error::Error;

use crate::stream::{Header, Packet, StreamType};
use crate::streaming::StreamingResponseChannel;

// OutCommands are commands from the Client going out to the server or network
// They should include a sender on which the server will send the response from
// the network to the client
pub enum OutCommand {
    StartListening {
        addr: Multiaddr,
        sender: OneshotSender,
    },
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: OneshotSender,
    },
    Ping {
        peer_id: PeerId,
        sender: OneshotSender,
    },
    DataRequest {
        id: u64,
        resource_id: String,
        peer_id: PeerId,
        sender: OneshotSender,
    },
    HeaderResponse {
        header: Header,
        channel: StreamingResponseChannel,
    },
    SendPacket {
        peer_id: PeerId,
        packet: Packet,
        sender: OneshotSender,
    },
    CloseStream {
        id: u64,
    },
    PeerId {
        sender: OneshotSender,
    },
}

// InCommands are commands from the Network to the client, passed by the Server
pub enum InCommand {
    DataRequest {
        id: u64,
        peer_id: PeerId,
        resource_id: String,
    },
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
    Error(Box<dyn Error + Send + Sync>),
}

pub type PendingMap = HashMap<PendingId, OneshotSender>;

#[derive(PartialEq, Eq, Hash)]
pub enum PendingId {
    PeerId(PeerId),
    RequestId(RequestId),
    ListenerId(ListenerId),
}

pub type ActiveStreams = HashMap<u64, mpsc::Sender<StreamType>>;
