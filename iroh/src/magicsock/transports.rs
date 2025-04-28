use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use quinn::AsyncUdpSocket;

mod ip;

pub trait Transport: AsyncUdpSocket {
    fn is_valid_send_addr(&self, addr: SocketAddr) -> bool;
    fn poll_writable(&self, cx: &mut Context) -> Poll<std::io::Result<()>>;

    fn create_self_io_poller(&self) -> Pin<Box<dyn quinn::UdpPoller>>;
}

pub use self::ip::IpTransport;
