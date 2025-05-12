use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use anyhow::{anyhow, Result};
use atomic_waker::AtomicWaker;
use bytes::Bytes;
use concurrent_queue::ConcurrentQueue;
use iroh_base::{NodeId, RelayUrl};
use n0_future::task::{self, AbortOnDropHandle};
use smallvec::SmallVec;
use tokio::sync::mpsc;
use tracing::{error, info_span, trace, warn, Instrument};

use super::{RecvMeta, Transmit};
use crate::{
    magicsock::RelayContents,
    watchable::{Watchable, Watcher as _},
};

mod actor;

pub use self::actor::Config as RelayActorConfig;
use self::actor::{RelayActor, RelayActorMessage, RelayRecvDatagram, RelaySendItem};

#[derive(Debug)]
pub struct RelayTransport {
    /// Queue to receive datagrams from relays for [`AsyncUdpSocket::poll_recv`].
    ///
    /// Relay datagrams received by relays are put into this queue and consumed by
    /// [`AsyncUdpSocket`].  This queue takes care of the wakers needed by
    /// [`AsyncUdpSocket::poll_recv`].
    pub(crate) relay_datagram_recv_queue: Arc<RelayDatagramRecvQueue>,
    /// Channel on which to send datagrams via a relay server.
    pub(super) relay_datagram_send_channel: RelayDatagramSendChannelSender,
    actor_sender: mpsc::Sender<RelayActorMessage>,
    _actor_handle: AbortOnDropHandle<()>,
    my_relay: Watchable<Option<RelayUrl>>,
    my_node_id: NodeId,
}

impl RelayTransport {
    pub fn new(config: RelayActorConfig) -> Self {
        let (relay_datagram_send_tx, relay_datagram_send_rx) = relay_datagram_send_channel();
        let relay_datagram_recv_queue = Arc::new(RelayDatagramRecvQueue::new());

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        let my_node_id = config.secret_key.public();
        let my_relay = config.my_relay.clone();

        let relay_actor = RelayActor::new(config, relay_datagram_recv_queue.clone());

        // TODO: track task
        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move {
                relay_actor
                    .run(actor_receiver, relay_datagram_send_rx)
                    .await;
            }
            .instrument(info_span!("relay-actor")),
        ));

        Self {
            relay_datagram_recv_queue,
            relay_datagram_send_channel: relay_datagram_send_tx,
            actor_sender,
            _actor_handle: actor_handle,
            my_relay,
            my_node_id,
        }
    }

    fn send_relay_actor(&self, msg: RelayActorMessage) {
        match self.actor_sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to relay actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for relay actor, channel is full");
            }
        }
    }

    pub fn create_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(self.relay_datagram_send_channel.clone())
    }

    pub fn poll_send(
        &self,
        dest_url: RelayUrl,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let contents = split_packets(transmit);

        let msg = RelaySendItem {
            remote_node: dest_node,
            url: dest_url.clone(),
            datagrams: contents,
        };

        match self.relay_datagram_send_channel.try_send(msg) {
            Ok(_) => {
                trace!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                       "send relay: message queued");
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is closed");
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                )))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is full");
                Poll::Pending
            }
        }
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;
        'outer: for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
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

        // If we have any msgs to report, they are in the first `num_msgs_total` slots
        if num_msgs > 0 {
            debug_assert!(num_msgs <= metas.len());
            Poll::Ready(Ok(num_msgs))
        } else {
            Poll::Pending
        }
    }

    pub fn local_addr(&self) -> Option<(RelayUrl, NodeId)> {
        self.my_relay.get().map(|url| (url, self.my_node_id))
    }

    pub fn local_addr_watch(
        &self,
    ) -> impl crate::watchable::Watcher<Value = Option<(RelayUrl, NodeId)>> {
        let my_node_id = self.my_node_id;
        let watcher = self
            .my_relay
            .watch()
            .map(move |url| url.map(|url| (url, my_node_id)))
            .expect("disconnected");
        watcher
    }

    pub fn max_transmit_segments(&self) -> usize {
        1
    }

    pub fn max_receive_segments(&self) -> usize {
        1
    }

    pub fn may_fragment(&self) -> bool {
        false
    }

    pub fn is_valid_send_addr(&self, _url: &RelayUrl, _node_id: &NodeId) -> bool {
        true
    }

    pub fn poll_writable(&self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.relay_datagram_send_channel.poll_writable(cx)
    }

    pub fn bind_addr(&self) -> Option<SocketAddr> {
        None
    }

    pub fn rebind(&self) -> io::Result<()> {
        self.send_relay_actor(RelayActorMessage::MaybeCloseRelaysOnRebind);

        Ok(())
    }

    pub fn on_network_change(&self, info: &crate::magicsock::NetInfo) {
        self.send_relay_actor(RelayActorMessage::NetworkChange { info: info.clone() });
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
    pub(crate) fn new() -> Self {
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
pub(super) struct RelayDatagramSendChannelSender {
    sender: mpsc::Sender<RelaySendItem>,
    wakers: Arc<std::sync::Mutex<Vec<Waker>>>,
}

impl quinn::UdpPoller for RelayDatagramSendChannelSender {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.as_ref().poll_writable(cx)
    }
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
    use std::{collections::BTreeSet, time::Duration};

    use iroh_base::NodeId;
    use tokio::task::JoinSet;
    use tracing::debug;

    use super::*;
    use crate::defaults::staging;

    #[test]
    fn test_split_packets() {
        fn mk_transmit(contents: &[u8], segment_size: Option<usize>) -> Transmit<'_> {
            let src_ip = "127.0.0.1:12".parse::<SocketAddr>().unwrap().into();
            Transmit {
                ecn: None,
                contents,
                segment_size,
                src_ip: Some(src_ip),
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

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relay_datagram_queue() {
        let queue = Arc::new(RelayDatagramRecvQueue::new());
        let url = staging::default_na_relay_node().url;
        let capacity = queue.queue.capacity().unwrap();

        let mut tasks = JoinSet::new();

        tasks.spawn({
            let queue = queue.clone();
            async move {
                let mut expected_msgs: BTreeSet<usize> = (0..capacity).collect();
                while !expected_msgs.is_empty() {
                    let datagram = n0_future::future::poll_fn(|cx| {
                        queue.poll_recv(cx).map(|result| result.unwrap())
                    })
                    .await;

                    let msg_num = usize::from_le_bytes(datagram.buf.as_ref().try_into().unwrap());
                    debug!("Received {msg_num}");

                    if !expected_msgs.remove(&msg_num) {
                        panic!("Received message number {msg_num} twice or more, but expected it only exactly once.");
                    }
                }
            }
        });

        for i in 0..capacity {
            tasks.spawn({
                let queue = queue.clone();
                let url = url.clone();
                async move {
                    debug!("Sending {i}");
                    queue
                        .try_send(RelayRecvDatagram {
                            url,
                            src: NodeId::from_bytes(&[0u8; 32]).unwrap(),
                            buf: Bytes::copy_from_slice(&i.to_le_bytes()),
                        })
                        .unwrap();
                }
            });
        }

        // We expect all of this work to be done in 10 seconds max.
        if tokio::time::timeout(Duration::from_secs(10), tasks.join_all())
            .await
            .is_err()
        {
            panic!("Timeout - not all messages between 0 and {capacity} received.");
        }
    }
}
