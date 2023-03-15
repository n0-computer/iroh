use std::net::SocketAddr;

use anyhow::Result;

pub trait Conn: Send + 'static {
    fn close(&self) -> Result<()>;
    fn local_addr(&self) -> SocketAddr;
}
