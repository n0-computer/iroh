use std::collections::HashMap;
use std::io::BufRead;
use std::pin::Pin;

use bytecheck::CheckBytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::stream::StreamExt;
use futures::task::{Context, Poll};
use libp2p::PeerId;
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use tracing::{debug, error};

use crate::commands::Command;
use crate::error::RpcError;

/// InStream coordinates a stream of packet data, allowing the user
/// to receive the chunks of bytes in the correct order.
// TODO: better name, add timeout, early cancel, and handle errors
pub struct InStream {
    packet_receiver: StreamReceiver,
    out_sender: mpsc::Sender<Command>,
    chunks: HashMap<u64, Vec<u8>>,
    id: u64,
    next_chunk: u64,
    num_chunks: u64,
}

impl InStream {
    pub fn new(
        header: Header,
        packet_receiver: StreamReceiver,
        out_sender: mpsc::Sender<Command>,
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
}

impl Stream for InStream {
    type Item = Result<Vec<u8>, RpcError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // check if the stream has finished its task successfully
        let num_chunks = self.num_chunks;
        let next_chunk = self.next_chunk;
        if next_chunk == num_chunks {
            debug!(target: "InStream", "No more items in stream.");
            return Poll::Ready(None);
        }
        // check if the chunk we are looking for is a chunk we already have
        if let Some(c) = self.chunks.remove(&next_chunk) {
            debug!(target: "InStream", "Returning already received chunk");
            self.next_chunk += 1;
            return Poll::Ready(Some(Ok(c)));
        }
        // otherwise, check the channel to see if we can get the next chunk
        match self.packet_receiver.poll_next_unpin(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(res) => match res {
                None => Poll::Ready(Some(Err(RpcError::StreamClosed.into()))),
                Some(p) => match p {
                    StreamType::Packet(p) => {
                        if next_chunk == p.index {
                            self.next_chunk += 1;
                            debug!(target: "InStream", "Returning just received chunk {}", p.index);
                            return Poll::Ready(Some(Ok(p.data)));
                        }
                        debug!(target: "InStream", "Storing out of order chunk {}", p.index);
                        self.chunks.insert(p.index, p.data);
                        Poll::Pending
                    }
                    StreamType::RpcError(e) => {
                        error!(target: "InStream", "Received error off of the stream: {:?}", e);
                        Poll::Ready(Some(Err(e.into())))
                    }
                },
            },
        }
    }
}

impl Drop for InStream {
    fn drop(&mut self) {
        self.out_sender
            .try_send(Command::CloseStream { id: self.id })
            .expect("Out sender to still be active.");
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
    pub fn new(
        header: Header,
        peer_id: PeerId,
        packet_sender: mpsc::Sender<Command>,
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
            .expect("TODO: handle reading error, and send an RpcError type letting the other end know there has been an error.");
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
                .send(Command::SendPacket {
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
    RpcError(RpcError),
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
// #[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
pub struct Packet {
    pub id: u64,
    pub index: u64,
    pub data: Vec<u8>,
    pub last: bool,
}

#[derive(Archive, Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
#[archive(compare(PartialEq))]
#[archive_attr(derive(Debug, CheckBytes))]
// #[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Eq)]
pub struct Header {
    pub id: u64,
    pub size: u64,
    pub chunk_size: u64,
    pub num_chunks: u64,
}
