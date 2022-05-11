use std::collections::HashMap;
use std::io::BufRead;

use async_stream::stream;
use bytecheck::CheckBytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::Stream;
use libp2p::PeerId;
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use tracing::{debug, error};

use crate::commands::Command;
use crate::error::RpcError;

pub fn make_order(
    packet_receiver: StreamReceiver,
) -> impl Stream<Item = Result<Vec<u8>, RpcError>> {
    let max = 1024;
    let mut chunks = HashMap::with_capacity(max);
    let mut next_chunk = 0;

    stream! {
        for await packet in packet_receiver {
            match packet {
                StreamType::Packet(p) => {
                    if next_chunk == p.index {
                        next_chunk += 1;
                        yield Ok(p.data);
                        while let Some(chunk) = chunks.remove(&next_chunk) {
                            next_chunk += 1;
                            yield Ok(chunk);
                        }
                    } else {
                        while let Some(chunk) = chunks.remove(&next_chunk) {
                            next_chunk += 1;
                            yield Ok(chunk);
                        }
                        if chunks.len() > max {
                            yield Err(RpcError::BufferMax);
                        } else {
                            chunks.insert(p.index, p.data);
                        }
                    }
                },
                StreamType::RpcError(e) => {
                   yield Err(e);
                },
            }
        }
    }
}

/// OutStream coordinates sending chunks of data over a stream
// TODO: handle ack & errors, timeouts, & early cancel
pub struct OutStream {
    header: Header,
    packet_sender: mpsc::Sender<Command>,
    // early_close_receiver: oneshot::Sender<Box<dyn RpcError + Send + Sync>>,
    reader: Box<dyn BufRead + Send + Sync>,
    peer_id: PeerId,
}

impl OutStream {
    pub fn new(cfg: StreamConfig, header: Header, reader: Box<dyn BufRead + Send + Sync>) -> Self {
        OutStream {
            peer_id: cfg.peer_id,
            header,
            packet_sender: cfg.channel,
            reader,
        }
    }

    pub async fn send_packets(&mut self) {
        debug!("Iterating over file");
        let mut chunk_size = self.header.chunk_size as usize;

        let mut buf = vec![0u8; chunk_size];
        for index in 0..self.header.num_chunks {
            if index == self.header.num_chunks - 1 {
                chunk_size = self.header.size as usize % chunk_size;
                buf = vec![0u8; chunk_size];
                println!("sending new chunk_size {}", chunk_size);
            }
            debug!("Reading file chunk {}", index);
            self.reader.read_exact(&mut buf)
            .expect("TODO: handle reading error, and send an RpcError type letting the other end know there has been an error.");
            let packet = Packet {
                id: self.header.id,
                index,
                data: buf[..].to_vec(),
                last: index == self.header.num_chunks - 1,
            };
            // TODO: ignoring errors and ack for now. If we get a "channel full" error
            // should trigger a slowdown, if we get some other error indicating a termination
            // we should stop sending packets
            let (sender, _) = oneshot::channel();
            debug!("Sending Packet {:?}", packet.index);
            self.packet_sender
                .send(Command::SendPacket {
                    sender,
                    packet,
                    peer_id: self.peer_id,
                })
                .await
                .expect("Sender to not be closed.");
            buf.clear();
            buf.resize(chunk_size, 0u8);
        }
    }
}

pub type StreamReceiver = mpsc::Receiver<StreamType>;
pub type StreamSender = mpsc::Sender<StreamType>;

#[derive(Debug)]
pub enum StreamType {
    Packet(Packet),
    RpcError(RpcError),
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

impl Header {
    pub fn new(id: u64, size: u64, chunk_size: u64) -> Self {
        Header {
            id,
            size,
            chunk_size,
            num_chunks: (size as f64 / chunk_size as f64).ceil() as u64,
        }
    }
}

pub struct StreamConfig {
    pub id: u64,
    pub peer_id: PeerId,
    pub channel: mpsc::Sender<Command>,
}

pub struct ActiveStreams(HashMap<u64, ActiveStream>);

impl ActiveStreams {
    pub fn new() -> Self {
        ActiveStreams(Default::default())
    }

    pub fn insert(&mut self, header: Header, sender: mpsc::Sender<StreamType>) {
        self.0.insert(header.id, ActiveStream::new(header, sender));
    }

    pub fn update_stream(&mut self, packet: Packet) -> Result<(), RpcError> {
        let id = packet.id;
        let in_stream = match self.0.get_mut(&id) {
            Some(s) => s,
            None => {
                return Err(RpcError::StreamClosed);
            }
        };
        in_stream.received_chunks += 1;
        // send the packet to the stream
        if let Err(e) = in_stream.sender.try_send(StreamType::Packet(packet)) {
            error!("Error sending packet from network to stream {}: {}", id, e);
            // TODO: recover from error rather than just closing the stream
            // this is most likely an error indicating that the channel is full
            // and so the sender should back off
            let _ = self.0.remove(&id);
            return Err(RpcError::TODO);
        }
        // we've received all the packet for this stream
        if in_stream.received_chunks == in_stream.size {
            let _ = self.0.remove(&id);
        }
        Ok(())
    }

    pub fn send_error(&mut self, id: u64, error: RpcError) -> Result<(), RpcError> {
        match self.0.get_mut(&id) {
            Some(s) => {
                if let Err(e) = s.sender.try_send(StreamType::RpcError(error)) {
                    error!("Error sending message from network to stream {}: {}", id, e);
                    // TODO: recover from error rather than just closing the stream
                    // this is most likely an error indicating that the channel is full
                    // and so the sender should back off
                    let _ = self.0.remove(&id);
                    return Err(RpcError::TODO);
                }
            }
            None => {
                return Err(RpcError::StreamClosed);
            }
        };
        Ok(())
    }

    pub fn remove(&mut self, id: u64) {
        let _ = self.0.remove(&id);
    }
}

impl Default for ActiveStreams {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ActiveStream {
    size: u64,
    received_chunks: u64,
    sender: mpsc::Sender<StreamType>,
}

impl ActiveStream {
    pub fn new(header: Header, sender: mpsc::Sender<StreamType>) -> Self {
        ActiveStream {
            size: header.num_chunks,
            received_chunks: 0,
            sender,
        }
    }
}
