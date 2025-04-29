use anyhow::{anyhow, Result};
use atomic_waker::AtomicWaker;
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use smallvec::SmallVec;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
use tokio::sync::mpsc;
use tracing::{error, trace, warn};

use crate::magicsock::{RelayContents, RelayRecvDatagram, RelaySendItem};

use super::{RecvMeta, Transmit, Transport};

#[derive(Debug, Clone)]
pub struct RelayTransport {
    /// Queue to receive datagrams from relays for [`AsyncUdpSocket::poll_recv`].
    ///
    /// Relay datagrams received by relays are put into this queue and consumed by
    /// [`AsyncUdpSocket`].  This queue takes care of the wakers needed by
    /// [`AsyncUdpSocket::poll_recv`].
    pub(crate) relay_datagram_recv_queue: Arc<RelayDatagramRecvQueue>,
    /// Channel on which to send datagrams via a relay server.
    pub(crate) relay_datagram_send_channel: RelayDatagramSendChannelSender,
}

impl RelayTransport {
    pub fn new() -> (Self, RelayDatagramSendChannelReceiver) {
        let (relay_datagram_send_tx, relay_datagram_send_rx) = relay_datagram_send_channel();
        let relay_datagram_recv_queue = Arc::new(RelayDatagramRecvQueue::new());

        (
            Self {
                relay_datagram_recv_queue,
                relay_datagram_send_channel: relay_datagram_send_tx,
            },
            relay_datagram_send_rx,
        )
    }
}

impl Transport for RelayTransport {
    fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        todo!()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let contents = split_packets(transmit);
        let (dest_url, dest_node) = transmit.destination.try_into().expect("invalid src");

        let msg = RelaySendItem {
            remote_node: dest_node,
            url: dest_url.clone(),
            datagrams: contents,
        };

        match self.relay_datagram_send_channel.try_send(msg) {
            Ok(_) => {
                trace!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                       "send relay: message queued");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is closed");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                ))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is full");
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "channel to actor is full",
                ))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;
        'outer: for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
            loop {
                let dm = match self.relay_datagram_recv_queue.poll_recv(cx) {
                    Poll::Ready(Ok(recv)) => recv,
                    Poll::Ready(Err(err)) => {
                        error!("relay_recv_channel closed: {err:#}");
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "connection closed",
                        )));
                    }
                    Poll::Pending => {
                        break 'outer;
                    }
                };

                buf_out[..dm.buf.len()].copy_from_slice(&dm.buf);
                *meta_out = RecvMeta {
                    len: dm.buf.len(),
                    stride: dm.buf.len(),
                    addr: (dm.url, dm.src).into(),
                    ecn: None,
                    dst_ip: None, // TODO: insert the relay url for this relay
                };
                num_msgs += 1;
            }
        }

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs > 0 {
            Poll::Ready(Ok(num_msgs))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        todo!()
    }

    fn max_transmit_segments(&self) -> usize {
        todo!()
    }

    fn max_receive_segments(&self) -> usize {
        todo!()
    }

    fn may_fragment(&self) -> bool {
        todo!()
    }

    fn is_valid_send_addr(&self, addr: SocketAddr) -> bool {
        todo!()
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        todo!()
    }

    fn bind_addr(&self) -> Option<SocketAddr> {
        todo!()
    }

    fn rebind(&self) -> io::Result<()> {
        todo!()
    }
}

/// A queue holding [`RelayRecvDatagram`]s that can be polled in async
/// contexts, and wakes up tasks when something adds items using [`try_send`].
///
/// This is used to transfer relay datagrams between the [`RelayActor`]
/// and [`MagicSock`].
///
/// [`try_send`]: Self::try_send
/// [`RelayActor`]: crate::magicsock::RelayActor
/// [`MagicSock`]: crate::magicsock::MagicSock
#[derive(Debug)]
pub(crate) struct RelayDatagramRecvQueue {
    queue: ConcurrentQueue<RelayRecvDatagram>,
    waker: AtomicWaker,
}

impl RelayDatagramRecvQueue {
    /// Creates a new, empty queue with a fixed size bound of 512 items.
    fn new() -> Self {
        Self {
            queue: ConcurrentQueue::bounded(512),
            waker: AtomicWaker::new(),
        }
    }

    /// Sends an item into this queue and wakes a potential task
    /// that's registered its waker with a [`poll_recv`] call.
    ///
    /// [`poll_recv`]: Self::poll_recv
    pub(crate) fn try_send(
        &self,
        item: RelayRecvDatagram,
    ) -> Result<(), concurrent_queue::PushError<RelayRecvDatagram>> {
        self.queue.push(item).inspect(|_| {
            self.waker.wake();
        })
    }

    /// Polls for new items in the queue.
    ///
    /// Although this method is available from `&self`, it must not be
    /// polled concurrently between tasks.
    ///
    /// Calling this will replace the current waker used. So if another task
    /// waits for this, that task's waker will be replaced and it won't be
    /// woken up for new items.
    ///
    /// The reason this method is made available as `&self` is because
    /// the interface for quinn's [`AsyncUdpSocket::poll_recv`] requires us
    /// to be able to poll from `&self`.
    pub(crate) fn poll_recv(&self, cx: &mut Context) -> Poll<Result<RelayRecvDatagram>> {
        match self.queue.pop() {
            Ok(value) => Poll::Ready(Ok(value)),
            Err(concurrent_queue::PopError::Empty) => {
                self.waker.register(cx.waker());

                match self.queue.pop() {
                    Ok(value) => {
                        self.waker.take();
                        Poll::Ready(Ok(value))
                    }
                    Err(concurrent_queue::PopError::Empty) => Poll::Pending,
                    Err(concurrent_queue::PopError::Closed) => {
                        self.waker.take();
                        Poll::Ready(Err(anyhow!("Queue closed")))
                    }
                }
            }
            Err(concurrent_queue::PopError::Closed) => Poll::Ready(Err(anyhow!("Queue closed"))),
        }
    }
}

/// Creates a sender and receiver pair for sending datagrams to the [`RelayActor`].
///
/// These includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
fn relay_datagram_send_channel() -> (
    RelayDatagramSendChannelSender,
    RelayDatagramSendChannelReceiver,
) {
    let (sender, receiver) = mpsc::channel(256);
    let wakers = Arc::new(std::sync::Mutex::new(Vec::new()));
    let tx = RelayDatagramSendChannelSender {
        sender,
        wakers: wakers.clone(),
    };
    let rx = RelayDatagramSendChannelReceiver { receiver, wakers };
    (tx, rx)
}

/// Sender to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
#[derive(Debug, Clone)]
struct RelayDatagramSendChannelSender {
    sender: mpsc::Sender<RelaySendItem>,
    wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
}

impl RelayDatagramSendChannelSender {
    fn try_send(
        &self,
        item: RelaySendItem,
    ) -> Result<(), mpsc::error::TrySendError<RelaySendItem>> {
        self.sender.try_send(item)
    }

    fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        match self.sender.capacity() {
            0 => {
                let mut wakers = self.wakers.lock().expect("poisoned");
                if !wakers.iter().any(|waker| waker.will_wake(cx.waker())) {
                    wakers.push(cx.waker().clone());
                }
                drop(wakers);
                if self.sender.capacity() != 0 {
                    // We "risk" a spurious wake-up in this case, but rather that
                    // than potentially skipping a receive.
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
            _ => Poll::Ready(Ok(())),
        }
    }
}

/// Receiver to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`AsyncUdpSocket::try_send`]
/// and [`quinn::UdpPoller::poll_writable`].
#[derive(Debug)]
pub(crate) struct RelayDatagramSendChannelReceiver {
    receiver: mpsc::Receiver<RelaySendItem>,
    wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
}

impl RelayDatagramSendChannelReceiver {
    pub(crate) async fn recv(&mut self) -> Option<RelaySendItem> {
        let item = self.receiver.recv().await;
        let mut wakers = self.wakers.lock().expect("poisoned");
        wakers.drain(..).for_each(Waker::wake);
        item
    }
}

/// Split a transmit containing a GSO payload into individual packets.
///
/// This allocates the data.
///
/// If the transmit has a segment size it contains multiple GSO packets.  It will be split
/// into multiple packets according to that segment size.  If it does not have a segment
/// size, the contents will be sent as a single packet.
// TODO: If quinn stayed on bytes this would probably be much cheaper, probably.  Need to
// figure out where they allocate the Vec.
fn split_packets(transmit: &Transmit<'_>) -> RelayContents {
    let mut res = SmallVec::with_capacity(1);
    let contents = transmit.contents;
    if let Some(segment_size) = transmit.segment_size {
        for chunk in contents.chunks(segment_size) {
            res.push(Bytes::from(chunk.to_vec()));
        }
    } else {
        res.push(Bytes::from(contents.to_vec()));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_packets() {
        fn mk_transmit(contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
            let src_ip = "127.0.0.1:12".parse::<SocketAddr>().unwrap().into();
            let destination = "127.0.0.1:0".parse::<SocketAddr>().unwrap().into();
            Transmit {
                destination,
                ecn: None,
                contents,
                segment_size,
                src_ip,
            }
        }
        fn mk_expected(parts: impl IntoIterator<Item = &'static str>) -> RelayContents {
            parts
                .into_iter()
                .map(|p| p.as_bytes().to_vec().into())
                .collect()
        }
        // no split
        assert_eq!(
            split_packets(&mk_transmit(b"hello", None)),
            mk_expected(["hello"])
        );
        // split without rest
        assert_eq!(
            split_packets(&mk_transmit(b"helloworld", Some(5))),
            mk_expected(["hello", "world"])
        );
        // split with rest and second transmit
        assert_eq!(
            split_packets(&mk_transmit(b"hello world", Some(5))),
            mk_expected(["hello", " worl", "d"]) // spellchecker:disable-line
        );
        // split that results in 1 packet
        assert_eq!(
            split_packets(&mk_transmit(b"hello world", Some(1000))),
            mk_expected(["hello world"])
        );
    }
}
