use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use quinn::AsyncUdpSocket;

mod ip;

pub trait Transport: AsyncUdpSocket {
    fn is_valid_send_addr(&self, addr: SocketAddr) -> bool;
    fn poll_writable(&self, cx: &mut Context) -> Poll<std::io::Result<()>>;
    fn create_self_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>>;

    /// If this transport is IP based, returns the bound address.
    fn bind_addr(&self) -> Option<SocketAddr>;
    fn rebind(&self) -> std::io::Result<()>;
}

pub use self::ip::IpTransport;
