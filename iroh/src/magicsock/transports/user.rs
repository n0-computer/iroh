use std::{
    io,
    sync::Arc,
    task::{Context, Poll},
};

use iroh_base::UserAddr;

use super::{Addr, Transmit};

/// User transport factory
pub trait UserTransportFactory: std::fmt::Debug + Send + Sync + 'static {
    /// Create an actual user transport
    fn bind(&self) -> io::Result<Box<dyn UserTransport>>;
}

/// An user transport
pub trait UserTransport: std::fmt::Debug + Send + Sync + 'static {
    /// Watch local addrs
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<UserAddr>>;
    /// Create a sender
    fn create_sender(&self) -> Arc<dyn UserSender>;
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
pub trait UserSender: std::fmt::Debug + Send + Sync + 'static {
    /// is addr valid for this transport?
    fn is_valid_send_addr(&self, addr: &UserAddr) -> bool;
    /// poll_send
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        dst: UserAddr,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>>;
}
