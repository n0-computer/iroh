use crate::commands::OutCommand;
use bytecheck::CheckBytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use libp2p::PeerId;
use log::{debug, error};
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use std::collections::HashMap;
use std::io::BufRead;

/// InStream coordinates a stream of packet data, allowing the user
/// to receive the chunks of bytes in the correct order.
// TODO: better name, add timeout, early cancel, and handle errors
pub struct InStream {
    packet_receiver: StreamReceiver,
    out_sender: mpsc::Sender<OutCommand>,
    chunks: HashMap<u64, Vec<u8>>,
    id: u64,
    next_chunk: u64,
    num_chunks: u64,
}

impl InStream {
    pub fn new(
        header: Header,
        packet_receiver: StreamReceiver,
        out_sender: mpsc::Sender<OutCommand>,
    ) -> Self {
        InStream {
            packet_receiver,
            out_sender,
            next_chunk: 0,
            id: header.id,
            num_chunks: header.num_chunks,
            chunks: HashMap::new(),
        }
    }

    // TODO: this should implement `poll_next` & satisfy the `Stream` trait
    // rather than directly implementing an async `next` method
    pub async fn next(
        &mut self,
    ) -> Option<Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>> {
        // check if the stream has finished its task successfully
        if self.next_chunk == self.num_chunks {
            debug!(target: "InStream", "No more items in stream.");
            return None;
        }
        // check if the chunk we are looking for is a chunk we already have
        if let Some(c) = self.chunks.remove(&self.next_chunk) {
            debug!(target: "InStream", "Returning already received chunk");
            self.next_chunk += 1;
            return Some(Ok(c));
        }
        // otherwise, check the channel to see if we can get the next chunk
        while let Some(p) = self.packet_receiver.next().await {
            match p {
                StreamType::Packet(p) => {
                    if self.next_chunk == p.index {
                        self.next_chunk += 1;
                        debug!(target: "InStream", "Returning just received chunk {}", p.index);
                        return Some(Ok(p.data));
                    }
                    debug!(target: "InStream", "Storing out of order chunk {}", p.index);
                    self.chunks.insert(p.index, p.data);
                }
                StreamType::Error(e) => {
                    error!(target: "InStream", "Received error off of the stream: {:?}", e);
                    return Some(Err(e.into()));
                }
            }
        }
        // We would only get here if the stream is no longer active, but we
        // haven't received an error saying why the stream was cut off
        // prematurely
        error!(target: "InStream", "TODO: HANDLE THIS ERROR");
        Some(Err("TODO: stream is no longer active, has not received an error, but we have not received all the expected data".into()))
    }
}

impl Drop for InStream {
    fn drop(&mut self) {
        self.out_sender
            .try_send(OutCommand::CloseStream { id: self.id })
            .expect("Out sender to still be active.");
    }
}

/// OutStream coordinates sending chunks of data over a stream
// TODO: handle ack & errors, timeouts, & early cancel
pub struct OutStream {
    header: Header,
    packet_sender: mpsc::Sender<OutCommand>,
    // early_close_receiver: oneshot::Sender<Box<dyn Error + Send + Sync>>,
    reader: Box<dyn BufRead + Send + Sync>,
    peer_id: PeerId,
}

impl OutStream {
    pub fn new(
        header: Header,
        peer_id: PeerId,
        packet_sender: mpsc::Sender<OutCommand>,
        reader: Box<dyn BufRead + Send + Sync>,
    ) -> Self {
        OutStream {
            peer_id,
            header,
            packet_sender,
            reader,
        }
    }

    pub async fn send_packets(&mut self) {
        debug!(target: "db streaming", "Iterating over file");
        for index in 0..self.header.num_chunks {
            let mut chunk_size = self.header.chunk_size as usize;
            if index == self.header.num_chunks - 1 {
                chunk_size = self.header.size as usize % chunk_size;
            }
            // TODO: should this be allocated once and then reused & cleared?
            // or is it better to just allocate each time & not worry about clearing it?
            let mut buf = vec![0u8; chunk_size];
            debug!(target: "db streaming", "Reading file chunk {}", index);
            self.reader.read_exact(&mut buf)
            .expect("TODO: handle reading error, and send an Error type letting the other end know there has been an error.");
            let packet = Packet {
                id: self.header.id,
                index,
                data: buf,
                last: index == self.header.num_chunks - 1,
            };
            // TODO: ignoring errors and ack for now. If we get a "channel full" error
            // should trigger a slowdown, if we get some other error indicating a termination
            // we should stop sending packets
            let (sender, _) = oneshot::channel();
            debug!(target: "db streaming", "Sending Packet {:?}", packet.index);
            self.packet_sender
                .send(OutCommand::SendPacket {
                    sender,
                    packet,
                    peer_id: self.peer_id,
                })
                .await
                .expect("Sender to not be closed.");
        }
    }
}

pub type StreamReceiver = mpsc::Receiver<StreamType>;
pub type StreamSender = mpsc::Sender<StreamType>;

#[derive(Debug)]
pub enum StreamType {
    Packet(Packet),
    Error(StreamError),
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub enum StreamError {
    NoLongerActive,
    TODO,
}

impl std::error::Error for StreamError {}
impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::NoLongerActive => write!(f, "Stream is not longer active"),
            StreamError::TODO => write!(f, "TODO: split into more specific errors"),
        }
    }
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub struct Packet {
    pub id: u64,
    pub index: u64,
    pub data: Vec<u8>,
    pub last: bool,
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
pub struct Header {
    pub id: u64,
    pub size: u64,
    pub chunk_size: u64,
    pub num_chunks: u64,
}
