use std::{
    io,
    num::NonZeroUsize,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_base::CustomAddr;

use super::{Addr, Transmit};

/// Custom transport.
///
/// Usually a transport will only deal with a single custom address type, but
/// the signature allows for dealing with multiple custom address types.
///
/// A transport is a factory for custom endpoints. Whenever an iroh endpoint is
/// created using [crate::endpoint::Builder::bind], a new custom endpoint will
/// be created using [CustomTransport::bind].
pub trait CustomTransport: std::fmt::Debug + Send + Sync + 'static {
    /// Create a custom endpoint
    ///
    /// Analogously to [std::net::UdpSocket::bind], this is where the actual
    /// underlying hardware resource is created.
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>>;
}

/// Custom endpoint created by a [CustomTransport].
///
/// An endpoint has a local address (or multiple local addresses), can receive
/// packets, and can create senders to send packets.
pub trait CustomEndpoint: std::fmt::Debug + Send + Sync + 'static {
    /// A watcher for local addresses for this custom endpoint.
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>>;
    /// Create a custom sender for this custom endpoint.
    fn create_sender(&self) -> Arc<dyn CustomSender>;
    /// poll receiving a packet on this custom endpoint.
    ///
    /// This will be called with `bufs`, `metas` and `source_addrs` of the same length.
    /// It is acceptable to panic if this is not the case.
    ///
    /// The maximum length of the slices is [`noq_udp::BATCH_SIZE`].
    /// It is acceptable to panic if this is exceeded.
    ///
    /// On success, all three slices must be filled up to the returned length,
    /// and the returned length must be less than or equal to the length of the slices.
    ///
    /// It does not make much sense to return addresses unrelated to this transport.
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>>;

    /// Maximum number of segments to transmit (GSO).
    ///
    /// This controls how many datagrams Noq will batch into a single transmit.
    /// The default is 1 (no batching). Custom transports that support batching
    /// can override this to allow more efficient transmission.
    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

/// Custom sender
///
/// A sender provides a poll based interface to send packets to custom addresses.
/// It can decide whether it wants to send to a given custom address type.
///
/// This is not enforced at type level, but [CustomSender::poll_send] should
/// only be called with addresses for which [CustomSender::is_valid_send_addr]
/// returns true.
pub trait CustomSender: std::fmt::Debug + Send + Sync + 'static {
    /// True if this sender can send to the given address.
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool;
    /// poll sending a packet on this sender.
    ///
    /// This will only be called from iroh with addresses for which [CustomSender::is_valid_send_addr] returns true.
    ///
    /// You should handle invalid addresses by returning an error.
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: &CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>>;
}
