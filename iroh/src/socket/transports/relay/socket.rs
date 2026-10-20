//! The noq socket of a relay server.

use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};

use iroh_base::EndpointId;
use iroh_relay::protos::relay::Datagrams;
use tracing::{debug, error, trace, warn};

use super::{RelayConnection, RelayDatagramSender};
use crate::socket::{
    Socket,
    mapped_addrs::{DEFAULT_FAKE_ADDR, MultipathMappedAddr, relay_mapped_net},
    transports::{RecvInfo, Transmit},
};

/// How many datagrams noq may batch into one transmit over a relay.
///
/// The relay client splits batches into relay frames, so this only bounds the work per
/// `poll_send`. It matches a typical GSO limit.
const RELAY_TRANSMIT_SEGMENTS: NonZeroUsize = NonZeroUsize::new(64).expect("non zero");

/// A relay server as a noq socket.
///
/// noq routes the relay mapped addresses of the server to it, see [`Self::route`].
#[derive(Debug)]
pub(super) struct RelaySocket {
    sock: Arc<Socket>,
    connection: Arc<RelayConnection>,
    /// Whether noq created the one receiver yet.
    has_receiver: AtomicBool,
}

impl RelaySocket {
    pub(super) fn new(sock: Arc<Socket>, connection: Arc<RelayConnection>) -> Self {
        Self {
            sock,
            connection,
            has_receiver: AtomicBool::new(false),
        }
    }

    /// Returns the route of the relay mapped addresses of this server.
    pub(super) fn route(&self) -> noq::SocketRoute {
        noq::SocketRoute::new(relay_mapped_net(self.connection.index()).into())
    }
}

impl noq::AsyncUdpSocketNext for RelaySocket {
    fn create_sender(&self) -> Pin<Box<dyn noq::UdpSender>> {
        Box::pin(RelaySocketSender {
            sock: self.sock.clone(),
            sender: RelayDatagramSender::new(self.connection.clone()),
        })
    }

    fn create_receiver(&self) -> Option<Box<dyn noq::UdpReceiver>> {
        if self.has_receiver.swap(true, Ordering::Relaxed) {
            return None;
        }
        Some(Box::new(RelaySocketReceiver {
            sock: self.sock.clone(),
            datagrams: RelayDatagrams {
                connection: self.connection.clone(),
                pending: None,
            },
            recv_infos: Default::default(),
        }))
    }

    /// Returns a fake IPv6 address, as a relay server has no local IP address.
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(DEFAULT_FAKE_ADDR.into())
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

/// Sends noq's transmits to the endpoints their relay mapped addresses stand for.
#[derive(Debug)]
struct RelaySocketSender {
    sock: Arc<Socket>,
    sender: RelayDatagramSender,
}

impl noq::UdpSender for RelaySocketSender {
    fn poll_send(
        self: Pin<&mut Self>,
        noq_transmit: &noq_udp::Transmit,
        cx: &mut Context,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.sock.is_closed() {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        }
        let MultipathMappedAddr::Relay(mapped_addr) = noq_transmit.destination.into() else {
            error!(dst = %noq_transmit.destination, "not a relay address, dropped transmit");
            return Poll::Ready(Ok(()));
        };
        let Some((url, dst)) = this.sock.mapped_addrs.relay_addrs.lookup(&mapped_addr) else {
            error!(dst = ?mapped_addr, "unknown RelayMappedAddr, dropped transmit");
            return Poll::Ready(Ok(()));
        };
        debug_assert_eq!(&url, this.sender.url(), "transmit routed to another relay");
        let transmit = Transmit {
            ecn: noq_transmit.ecn,
            contents: noq_transmit.contents,
            segment_size: noq_transmit.segment_size,
        };
        // A send error is not permanent: like a lost datagram, QUIC recovers from it.
        match std::task::ready!(this.sender.poll_send(cx, dst, &transmit)) {
            Ok(()) => trace!(%url, len = transmit.contents.len(), "sent transmit"),
            Err(err) => debug!(%url, "dropped transmit: {err:#}"),
        }
        Poll::Ready(Ok(()))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        RELAY_TRANSMIT_SEGMENTS
    }
}

/// Receives the datagrams of a relay server for noq.
#[derive(Debug)]
struct RelaySocketReceiver {
    sock: Arc<Socket>,
    datagrams: RelayDatagrams,
    /// Cache for per-packet recv info, to speed up access
    recv_infos: Box<[RecvInfo; noq_udp::BATCH_SIZE]>,
}

impl noq::UdpReceiver for RelaySocketReceiver {
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        assert_eq!(bufs.len(), metas.len(), "non matching bufs & metas");
        assert!(bufs.len() <= noq_udp::BATCH_SIZE, "too many buffers");
        if self.sock.is_closed() {
            return Poll::Pending;
        }
        let count = self
            .datagrams
            .fill(cx, bufs, metas, &mut self.recv_infos[..]);
        if count == 0 {
            return Poll::Pending;
        }
        self.sock.process_datagrams(
            &mut bufs[..count],
            &mut metas[..count],
            &self.recv_infos[..count],
        );
        Poll::Ready(Ok(count))
    }
}

/// The datagrams received on a relay connection, re-batched to fit noq's buffers.
#[derive(Debug)]
struct RelayDatagrams {
    connection: Arc<RelayConnection>,
    /// The rest of a datagram batch that did not fit into the last buffers.
    pending: Option<(EndpointId, Datagrams)>,
}

impl RelayDatagrams {
    /// Fills `bufs` with received datagrams, and returns how many it filled.
    fn fill(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> usize {
        let url = self.connection.url();
        let mut count = 0;
        for (buf_out, meta_out) in bufs.iter_mut().zip(metas.iter_mut()) {
            let (src, batch) = match &mut self.pending {
                Some(pending) => pending,
                None => match self.connection.poll_recv(cx) {
                    Poll::Ready(received) => self.pending.insert(received),
                    Poll::Pending => break,
                },
            };
            let src = *src;

            // This *tries* to make the datagrams fit into our buffer by re-batching them.
            let num_segments = batch
                .segment_size
                .map_or(1, |ss| buf_out.len() / u16::from(ss) as usize);
            let datagrams = batch.take_segments(num_segments);
            // If `take_segments` took the whole batch, the rest is empty and can be dropped.
            // If it took nothing, a single segment does not fit into the buffer, and later
            // calls would not change this, so drop the batch with the oversized segments.
            if batch.contents.is_empty() || datagrams.contents.is_empty() {
                self.pending = None;
            }
            if datagrams.contents.is_empty() {
                warn!(
                    noq_buf_len = buf_out.len(),
                    segment_size = ?datagrams.segment_size,
                    "dropping received datagram: segment_size too large");
                continue;
            }
            if buf_out.len() < datagrams.contents.len() {
                // The datagram is bigger than our configured `max_udp_payload_size`, which
                // the relay should not deliver. Drop it and let MTU discovery take over.
                warn!(
                    noq_buf_len = buf_out.len(),
                    datagram_len = datagrams.contents.len(),
                    segment_size = ?datagrams.segment_size,
                    "dropping received datagram: noq buffer too small"
                );
                break;
            }

            buf_out[..datagrams.contents.len()].copy_from_slice(&datagrams.contents);
            meta_out.len = datagrams.contents.len();
            meta_out.stride = datagrams
                .segment_size
                .map_or(datagrams.contents.len(), |s| u16::from(s) as usize);
            meta_out.ecn = None;
            meta_out.dst_ip = None;
            recv_infos[count] = RecvInfo::from_addr((url.clone(), src).into());
            count += 1;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroU16, task::Waker};

    use bytes::Bytes;

    use super::*;
    use crate::{defaults::staging, socket::transports::relay::RelayConnections};

    #[test]
    fn progress_is_made_for_large_segment_size_datagram_batch() {
        let url = staging::default_na_east_relay().url;
        let src = EndpointId::from_bytes(&[3u8; 32]).unwrap();
        // Fat datagram batch with segment size larger than the buffer
        let batch = Datagrams {
            ecn: None,
            segment_size: NonZeroU16::new(2000),
            contents: Bytes::from(vec![0u8; 4000]),
        };
        let mut datagrams = RelayDatagrams {
            connection: RelayConnections::default().get(&url),
            pending: Some((src, batch)),
        };
        let mut cx = Context::from_waker(Waker::noop());
        // Deliberately smaller than the 2000-byte segment size above
        let mut storage = [0u8; 1500];
        let mut metas = [noq_udp::RecvMeta::default()];
        let mut recv_infos = [RecvInfo::default()];

        // Progress does not need to be immediate but within a reasonable number of rounds.
        for _ in 0..10 {
            let mut bufs = [IoSliceMut::new(&mut storage)];
            datagrams.fill(&mut cx, &mut bufs, &mut metas, &mut recv_infos);
            if datagrams.pending.is_none() {
                return;
            }
        }
        panic!("poll_recv made no progress on batch too large");
    }
}
