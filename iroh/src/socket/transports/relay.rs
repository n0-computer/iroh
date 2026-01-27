use std::{
    io,
    num::NonZeroU16,
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{EndpointId, RelayUrl};
use iroh_relay::protos::relay::Datagrams;
use n0_future::{
    ready,
    task::{self, AbortOnDropHandle},
};
use n0_watcher::{Watchable, Watcher as _};
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{Instrument, error, info_span, warn};

use super::{Addr, Transmit};

mod actor;

pub(crate) use self::actor::Config as RelayActorConfig;
use self::actor::{RelayActor, RelayActorMessage, RelayRecvDatagram, RelaySendItem};

#[derive(Debug)]
pub(crate) struct RelayTransport {
    /// Queue to receive datagrams from relays for [`quinn::AsyncUdpSocket::poll_recv`].
    relay_datagram_recv_queue: mpsc::Receiver<RelayRecvDatagram>,
    /// Channel on which to send datagrams via a relay server.
    relay_datagram_send_channel: mpsc::Sender<RelaySendItem>,
    /// A datagram from the last poll_recv that didn't quite fit our buffers.
    pending_item: Option<RelayRecvDatagram>,
    actor_sender: mpsc::Sender<RelayActorMessage>,
    _actor_handle: AbortOnDropHandle<()>,
    my_relay: Watchable<Option<RelayUrl>>,
    my_endpoint_id: EndpointId,
}

impl RelayTransport {
    pub(crate) fn new(config: RelayActorConfig, cancel_token: CancellationToken) -> Self {
        let (relay_datagram_send_tx, relay_datagram_send_rx) = mpsc::channel(256);

        let (relay_datagram_recv_tx, relay_datagram_recv_rx) = mpsc::channel(512);

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        let my_endpoint_id = config.secret_key.public();
        let my_relay = config.my_relay.clone();

        let relay_actor = RelayActor::new(config, relay_datagram_recv_tx, cancel_token);

        let actor_handle = AbortOnDropHandle::new(task::spawn(
            async move {
                relay_actor
                    .run(actor_receiver, relay_datagram_send_rx)
                    .await;
            }
            .instrument(info_span!("relay-actor")),
        ));

        Self {
            relay_datagram_recv_queue: relay_datagram_recv_rx,
            relay_datagram_send_channel: relay_datagram_send_tx,
            pending_item: None,
            actor_sender,
            _actor_handle: actor_handle,
            my_relay,
            my_endpoint_id,
        }
    }

    pub(crate) fn create_sender(&self) -> RelaySender {
        RelaySender {
            sender: PollSender::new(self.relay_datagram_send_channel.clone()),
        }
    }

    pub(super) fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>> {
        let mut num_msgs = 0;
        for ((buf_out, meta_out), addr) in bufs
            .iter_mut()
            .zip(metas.iter_mut())
            .zip(source_addrs.iter_mut())
        {
            let dm = match self.poll_recv_queue(cx) {
                Poll::Ready(Some(recv)) => recv,
                Poll::Ready(None) => {
                    error!("relay_recv_channel closed");
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "connection closed",
                    )));
                }
                Poll::Pending => {
                    break;
                }
            };

            // This *tries* to make the datagrams fit into our buffer by re-batching them.
            let num_segments = dm
                .datagrams
                .segment_size
                .map_or(1, |ss| buf_out.len() / u16::from(ss) as usize);
            let datagrams = dm.datagrams.take_segments(num_segments);
            let empty_after = dm.datagrams.contents.is_empty();
            let dm = RelayRecvDatagram {
                datagrams,
                src: dm.src,
                url: dm.url.clone(),
            };
            // take_segments can leave `self.pending_item` empty, in that case we clear it
            if empty_after {
                self.pending_item = None;
            }

            if buf_out.len() < dm.datagrams.contents.len() {
                // Our receive buffer isn't big enough to process this datagram.
                // Continuing would cause a panic.
                warn!(
                    quinn_buf_len = buf_out.len(),
                    datagram_len = dm.datagrams.contents.len(),
                    segment_size = ?dm.datagrams.segment_size,
                    "dropping received datagram: quinn buffer too small"
                );
                break;
                // In theory we could put some logic in here to fragment the datagram in case
                // we still have enough room in our `buf_out` left to fit a couple of
                // `dm.datagrams.segment_size`es, but we *should* have cut those datagrams
                // to appropriate sizes earlier in the pipeline (just before we put them
                // into the `relay_datagram_recv_queue` in the `ActiveRelayActor`).
                // So the only case in which this happens is we receive a datagram via the relay
                // that's essentially bigger than our configured `max_udp_payload_size`.
                // In that case we drop it and let MTU discovery take over.
            }

            buf_out[..dm.datagrams.contents.len()].copy_from_slice(&dm.datagrams.contents);
            meta_out.len = dm.datagrams.contents.len();
            meta_out.stride = dm
                .datagrams
                .segment_size
                .map_or(dm.datagrams.contents.len(), |s| u16::from(s) as usize);
            meta_out.ecn = None;
            meta_out.dst_ip = None;

            *addr = (dm.url, dm.src).into();
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

    pub(super) fn local_addr_watch(
        &self,
    ) -> n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, EndpointId)>> {
        let my_endpoint_id = self.my_endpoint_id;
        self.my_relay
            .watch()
            .map(move |url| url.map(|url| (url, my_endpoint_id)))
    }

    pub(super) fn create_network_change_sender(&self) -> RelayNetworkChangeSender {
        RelayNetworkChangeSender {
            sender: self.actor_sender.clone(),
        }
    }

    /// Makes sure we have a pending item stored, if not, it'll poll a new one from the queue.
    ///
    /// Returns a mutable reference to the stored pending item.
    #[inline]
    fn poll_recv_queue<'a>(
        &'a mut self,
        cx: &mut Context,
    ) -> Poll<Option<&'a mut RelayRecvDatagram>> {
        // Borrow checker doesn't quite understand an if let Some(_)... here
        if self.pending_item.is_some() {
            return Poll::Ready(self.pending_item.as_mut());
        }

        let item = match self.relay_datagram_recv_queue.poll_recv(cx) {
            Poll::Ready(Some(item)) => item,
            Poll::Ready(None) => return Poll::Ready(None),
            Poll::Pending => return Poll::Pending,
        };

        Poll::Ready(Some(self.pending_item.insert(item)))
    }
}

#[derive(Debug)]
pub(super) struct RelayNetworkChangeSender {
    sender: mpsc::Sender<RelayActorMessage>,
}

impl RelayNetworkChangeSender {
    pub(super) fn on_network_change(&self, report: &crate::socket::Report) {
        self.send_relay_actor(RelayActorMessage::NetworkChange {
            report: report.clone(),
        });
    }

    pub(super) fn rebind(&self) -> io::Result<()> {
        self.send_relay_actor(RelayActorMessage::MaybeCloseRelaysOnRebind);

        Ok(())
    }

    fn send_relay_actor(&self, msg: RelayActorMessage) {
        match self.sender.try_send(msg) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("unable to send to relay actor, already closed");
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("dropping message for relay actor, channel is full");
            }
        }
    }
}

/// Sender to send datagrams to the [`RelayActor`].
///
/// This includes the waker coordination required to support [`quinn::UdpSender::poll_send`].
#[derive(Debug, Clone)]
pub(crate) struct RelaySender {
    sender: PollSender<RelaySendItem>,
}

impl RelaySender {
    pub(super) fn is_valid_send_addr(&self, _url: &RelayUrl, _endpoint_id: &EndpointId) -> bool {
        true
    }

    pub(super) fn poll_send(
        &mut self,
        cx: &mut Context,
        dest_url: RelayUrl,
        dest_endpoint: EndpointId,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        match ready!(self.sender.poll_reserve(cx)) {
            Ok(()) => {
                let contents = datagrams_from_transmit(transmit);
                let item = RelaySendItem {
                    remote_endpoint: dest_endpoint,
                    url: dest_url.clone(),
                    datagrams: contents,
                };
                match self.sender.send_item(item) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_err) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "channel to actor is closed",
                    ))),
                }
            }
            Err(_err) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "channel to actor is closed",
            ))),
        }
    }
}

/// Translate a UDP transmit to the `Datagrams` type for sending over the relay.
fn datagrams_from_transmit(transmit: &Transmit<'_>) -> Datagrams {
    Datagrams {
        ecn: transmit.ecn.map(|ecn| match ecn {
            quinn_udp::EcnCodepoint::Ect0 => quinn_proto::EcnCodepoint::Ect0,
            quinn_udp::EcnCodepoint::Ect1 => quinn_proto::EcnCodepoint::Ect1,
            quinn_udp::EcnCodepoint::Ce => quinn_proto::EcnCodepoint::Ce,
        }),
        segment_size: transmit
            .segment_size
            .map(|ss| ss as u16)
            .and_then(NonZeroU16::new),
        contents: Bytes::copy_from_slice(transmit.contents),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use iroh_base::EndpointId;
    use tokio::task::JoinSet;
    use tracing::debug;

    use super::*;
    use crate::defaults::staging;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relay_datagram_queue() {
        let capacity = 16;
        let (sender, mut receiver) = mpsc::channel(capacity);
        let url = staging::default_na_east_relay().url;

        let mut tasks = JoinSet::new();

        tasks.spawn({
            async move {
                let mut expected_msgs: BTreeSet<usize> = (0..capacity).collect();
                while !expected_msgs.is_empty() {
                    let datagram: RelayRecvDatagram = receiver.recv().await.unwrap();
                    let msg_num = usize::from_le_bytes(datagram.datagrams.contents.as_ref().try_into().unwrap());
                    debug!("Received {msg_num}");

                    if !expected_msgs.remove(&msg_num) {
                        panic!("Received message number {msg_num} twice or more, but expected it only exactly once.");
                    }
                }
            }
        });

        for i in 0..capacity {
            tasks.spawn({
                let sender = sender.clone();
                let url = url.clone();
                async move {
                    debug!("Sending {i}");
                    sender
                        .try_send(RelayRecvDatagram {
                            url,
                            src: EndpointId::from_bytes(&[0u8; 32]).unwrap(),
                            datagrams: Datagrams::from(&i.to_le_bytes()),
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
