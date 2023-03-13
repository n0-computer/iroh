use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Result;

pub trait Conn {
    fn close(&self) -> Result<()>;
    fn local_addr(&self) -> SocketAddr;
    fn set_deadline(&mut self, duration: Duration) -> Result<()>;
    fn set_read_deadline(&mut self, duration: Duration) -> Result<()>;
    fn set_write_deadline(&mut self, duration: Duration) -> Result<()>;
}
