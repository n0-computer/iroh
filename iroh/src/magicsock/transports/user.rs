use std::{
    io,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_base::CustomAddr;

use super::{Addr, Transmit};

/// User defined transport.
///
/// Usually a transport will only deal with a single user address type, but
/// the signature allows for dealing with multiple user address types.
///
/// A transport is a factory for user endpoints. Whenever an iroh endpoint is
/// create using [crate::endpoint::Builder::bind], a new user endpoint will
/// be created using [CustomTransport::bind].
pub trait CustomTransport: std::fmt::Debug + Send + Sync + 'static {
    /// Create a custom endpoint
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>>;
}

/// User endpoint created by a [CustomTransport].
///
/// An endpoint has a local address (or multiple local addresses), can receive
/// packets, and can create senders to send packets.
pub trait CustomEndpoint: std::fmt::Debug + Send + Sync + 'static {
    /// Watch local addrs
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>>;
    /// Create a sender
    fn create_sender(&self) -> Arc<dyn CustomSender>;
    /// Poll recv
    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [quinn_udp::RecvMeta],
        source_addrs: &mut [Addr],
    ) -> Poll<io::Result<usize>>;
}

/// User sender
///
/// A sender provides a poll based interface to send packets to user addresses.
/// It can decide whether it wants to send to a given user address type.
///
/// This is not enforced at type level, but [CustomSender::poll_send] should
/// only be called with addresses for which [CustomSender::is_valid_send_addr]
/// returns true.
pub trait CustomSender: std::fmt::Debug + Send + Sync + 'static {
    /// is addr valid for this transport?
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool;
    /// poll_send
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: CustomAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>>;
}
