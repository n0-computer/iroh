use std::collections::HashMap;
use std::io::BufRead;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytecheck::CheckBytes;
use futures::channel::{mpsc, oneshot};
use futures::prelude::*;
use futures::select;
use futures::stream::StreamExt;
use futures::task::{AtomicWaker, Context, Poll};
use libp2p::PeerId;
use rkyv;
use rkyv::{Archive, Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, error};

use crate::commands::Command;
use crate::error::RpcError;

/// to receive the chunks of bytes in the correct order.
// TODO: better name, add timeout, early cancel, and handle errors
pub struct OrderedStream {
    out_sender: mpsc::Sender<Command>,
    error_receiver: mpsc::Receiver<RpcError>,
    chunks: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
    id: u64,
    next_chunk: u64,
    num_chunks: u64,
    // Handle to the stream's task
    task: Arc<Mutex<AtomicWaker>>,
    // Handle to the poll receiver task
    handle: JoinHandle<()>,
    // shutdown receiver loop
    early_shutdown: Option<oneshot::Sender<()>>,
}

impl OrderedStream {
    pub fn new(
        header: Header,
        packet_receiver: StreamReceiver,
        out_sender: mpsc::Sender<Command>,
    ) -> Self {
        let (error_sender, error_receiver) = mpsc::channel(8);

        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let chunks = Arc::new(Mutex::new(HashMap::new()));
        let task = Arc::new(Mutex::new(AtomicWaker::new()));
        OrderedStream {
            out_sender,
            error_receiver,
            next_chunk: 0,
            id: header.id,
            num_chunks: header.num_chunks,
            chunks: Arc::clone(&chunks),
            task: Arc::clone(&task),
            handle: {
                tokio::spawn(async move {
                    OrderedStream::gather_packets(
                        packet_receiver,
                        chunks,
                        task,
                        error_sender,
                        shutdown_receiver,
                    )
                    .await
                })
            },
            early_shutdown: Some(shutdown_sender),
        }
    }

    // we have loop that is taking in packets and ordering them. If there is an
    // error, send the error to the main stream
    async fn gather_packets(
        mut packet_receiver: StreamReceiver,
        chunks: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
        task: Arc<Mutex<AtomicWaker>>,
        mut error_sender: mpsc::Sender<RpcError>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        loop {
            select! {
              res = packet_receiver.next() => {
                if let Some(r) = res {
                  match r {
                    StreamType::Packet(p) => {
                      {
                        let mut chunks = chunks.lock().expect("failed to lock stream chunk mutex");
                        chunks.insert(p.index, p.data);
                      }
                      debug!(target="OrderedStream", "Stream received chunk {}", p.index);
                  },
                    StreamType::RpcError(e) => {
                      error!(target="OrderedStream", "stream received error {}", e);
                      error_sender
                          .send(e)
                          .await
                          .expect("failed to send on error sender");
                    },
                  }
                  // notify poll_next that we have a message we want them to
                  // process
                  {
                    let task = task.lock().expect("failed to lock task");
                    task.wake();
                  }
                  continue;
                }
                // if res == None, then the packet_receiver stream has closed
                    debug!(target="OrderedStream", "Packet receiver closed, done gathering packets");
                      return;
                                },
              _ = shutdown => {
                debug!(target="OrderedStream", "Shutdown triggered, no longer gathering packets");
                return;
              }
            }
        }
    }

    /// close cleans up the stream. MUST BE CALLED AFTER YOU ARE FINISHED WITH THE STREAM.
    pub async fn close(mut self) {
        self.out_sender
            .try_send(Command::CloseStream { id: self.id })
            .expect("Out sender to still be active.");
        if let Some(sender) = self.early_shutdown.take() {
            debug!(target = "OrderedStream", "closing stream");
            let _ = sender
                .send(())
                .expect("shutdown receiver should still be open");
            return;
        } else {
            debug!(target = "OrderedStream", "stream already closed");
        }
        match self.handle.await {
            Ok(()) => {
                debug!("stream closed gracefully");
            }
            Err(e) => {
                error!(
                    target = "OrderedStream",
                    "error in `gather_packets` handle {}", e
                );
            }
        };
    }
}

impl Stream for OrderedStream {
    type Item = Result<Vec<u8>, RpcError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // check if the stream has already finished its task successfully
        let num_chunks = self.num_chunks;
        let next_chunk = self.next_chunk;
        if next_chunk == num_chunks {
            debug!(target: "OrderedStream", "No more items in stream.");

            return Poll::Ready(None);
        }

        // check if there are errors we should be returning
        if let Ok(Some(e)) = self.error_receiver.try_next() {
            error!(target = "OrderedStream", "stream error {}", e);
            return Poll::Ready(Some(Err(e)));
        }

        {
            // check if the chunk we are looking for is a chunk we already have
            let chunks = Arc::clone(&self.chunks);
            let mut chunks = chunks.lock().unwrap();
            if let Some(c) = chunks.remove(&next_chunk) {
                debug!(target: "OrderedStream", "Returning an already received chunk");
                self.next_chunk += 1;
                return Poll::Ready(Some(Ok(c)));
            }
        }
        // otherwise, we don't have the chunk, so let's wait until the next
        // message
        debug!(
            target = "OrderedStream",
            "Pausing task until next packet comes in"
        );
        {
            let task = self.task.lock().expect("failed to lock task mutex");
            task.register(cx.waker());
        }
        Poll::Pending
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
        debug!(target: "OrderedStream", "Iterating over file");
        for index in 0..self.header.num_chunks {
            let mut chunk_size = self.header.chunk_size as usize;
            if index == self.header.num_chunks - 1 {
                chunk_size = self.header.size as usize % chunk_size;
            }
            // TODO: should this be allocated once and then reused & cleared?
            // or is it better to just allocate each time & not worry about clearing it?
            let mut buf = vec![0u8; chunk_size];
            debug!(target: "OrderedStream", "Reading file chunk {}", index);
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
            debug!(target: "OrderedStream", "Sending Packet {:?}", packet.index);
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
