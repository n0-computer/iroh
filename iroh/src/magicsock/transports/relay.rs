use std::{
    io,
    task::{Context, Poll},
};

use bytes::Bytes;
use iroh_base::{NodeId, RelayUrl};
use iroh_relay::protos::relay::Datagrams;
use n0_future::{
    ready,
    task::{self, AbortOnDropHandle},
};
use n0_watcher::{Watchable, Watcher as _};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tracing::{error, info_span, trace, warn, Instrument};

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
    actor_sender: mpsc::Sender<RelayActorMessage>,
    _actor_handle: AbortOnDropHandle<()>,
    my_relay: Watchable<Option<RelayUrl>>,
    my_node_id: NodeId,
}

impl RelayTransport {
    pub(crate) fn new(config: RelayActorConfig) -> Self {
        let (relay_datagram_send_tx, relay_datagram_send_rx) = mpsc::channel(256);

        let (relay_datagram_recv_tx, relay_datagram_recv_rx) = mpsc::channel(512);

        let (actor_sender, actor_receiver) = mpsc::channel(256);

        let my_node_id = config.secret_key.public();
        let my_relay = config.my_relay.clone();

        let relay_actor = RelayActor::new(config, relay_datagram_recv_tx);

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
            actor_sender,
            _actor_handle: actor_handle,
            my_relay,
            my_node_id,
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
            let dm = match self.relay_datagram_recv_queue.poll_recv(cx) {
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

            buf_out[..dm.datagrams.contents.len()].copy_from_slice(&dm.datagrams.contents);
            meta_out.len = dm.datagrams.contents.len();
            meta_out.stride = dm
                .datagrams
                .segment_size
                .map_or(dm.datagrams.contents.len(), |s| s as usize);
            meta_out.ecn = None;
            meta_out.dst_ip = None; // TODO: insert the relay url for this relay

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
    ) -> n0_watcher::Map<n0_watcher::Direct<Option<RelayUrl>>, Option<(RelayUrl, NodeId)>> {
        let my_node_id = self.my_node_id;
        self.my_relay
            .watch()
            .map(move |url| url.map(|url| (url, my_node_id)))
            .expect("disconnected")
    }

    pub(super) fn create_network_change_sender(&self) -> RelayNetworkChangeSender {
        RelayNetworkChangeSender {
            sender: self.actor_sender.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct RelayNetworkChangeSender {
    sender: mpsc::Sender<RelayActorMessage>,
}

impl RelayNetworkChangeSender {
    pub(super) fn on_network_change(&self, report: &crate::magicsock::Report) {
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
    pub(super) fn is_valid_send_addr(&self, _url: &RelayUrl, _node_id: &NodeId) -> bool {
        true
    }

    pub(super) async fn send(
        &self,
        dest_url: RelayUrl,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let contents = datagrams_from_transmit(transmit);

        let item = RelaySendItem {
            remote_node: dest_node,
            url: dest_url.clone(),
            datagrams: contents,
        };

        let dest_node = item.remote_node;
        let dest_url = item.url.clone();
        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::other("channel closed"));
        };
        match sender.send(item).await {
            Ok(_) => {
                trace!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                        "send relay: message queued");
                Ok(())
            }
            Err(mpsc::error::SendError(_)) => {
                error!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                        "send relay: message dropped, channel to actor is closed");
                Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                ))
            }
        }
    }

    pub(super) fn poll_send(
        &mut self,
        cx: &mut Context,
        dest_url: RelayUrl,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        match ready!(self.sender.poll_reserve(cx)) {
            Ok(()) => {
                trace!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                    "send relay: message queued");

                let contents = datagrams_from_transmit(transmit);
                let item = RelaySendItem {
                    remote_node: dest_node,
                    url: dest_url.clone(),
                    datagrams: contents,
                };
                let dest_node = item.remote_node;
                let dest_url = item.url.clone();

                match self.sender.send_item(item) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(_err) => {
                        error!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is closed");
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionReset,
                            "channel to actor is closed",
                        )))
                    }
                }
            }
            Err(_err) => {
                error!(node = %dest_node.fmt_short(), relay_url = %dest_url,
                      "send relay: message dropped, channel to actor is closed");
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "channel to actor is closed",
                )))
            }
        }
    }

    pub(super) fn try_send(
        &self,
        dest_url: RelayUrl,
        dest_node: NodeId,
        transmit: &Transmit<'_>,
    ) -> io::Result<()> {
        let contents = datagrams_from_transmit(transmit);

        let item = RelaySendItem {
            remote_node: dest_node,
            url: dest_url.clone(),
            datagrams: contents,
        };

        let dest_node = item.remote_node;
        let dest_url = item.url.clone();

        let Some(sender) = self.sender.get_ref() else {
            return Err(io::Error::other("channel closed"));
        };

        match sender.try_send(item) {
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
                Err(io::Error::new(io::ErrorKind::WouldBlock, "channel full"))
            }
        }
    }
}

/// Translate a UDP transmit to the `Datagrams` type for sending over the relay.
// TODO: If quinn stayed on bytes this would probably be much cheaper, probably.  Need to
// figure out where they allocate the Vec.
fn datagrams_from_transmit(transmit: &Transmit<'_>) -> Datagrams {
    Datagrams {
        ecn: transmit.ecn.map(|ecn| match ecn {
            quinn_udp::EcnCodepoint::Ect0 => quinn_proto::EcnCodepoint::Ect0,
            quinn_udp::EcnCodepoint::Ect1 => quinn_proto::EcnCodepoint::Ect1,
            quinn_udp::EcnCodepoint::Ce => quinn_proto::EcnCodepoint::Ce,
        }),
        segment_size: transmit.segment_size.map(|ss| ss as u16),
        contents: Bytes::copy_from_slice(transmit.contents),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use iroh_base::NodeId;
    use tokio::task::JoinSet;
    use tracing::debug;

    use super::*;
    use crate::defaults::staging;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_relay_datagram_queue() {
        let capacity = 16;
        let (sender, mut receiver) = mpsc::channel(capacity);
        let url = staging::default_na_relay_node().url;

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
                            src: NodeId::from_bytes(&[0u8; 32]).unwrap(),
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
