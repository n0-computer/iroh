use std::net::SocketAddr;

use tokio::{net::UdpSocket, sync::RwLock};

use super::conn::Network;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no connection set")]
    NoConn,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// Reports whether err is an error from a UDP send
    /// operation that should be treated as a UDP packet that just got lost.
    ///
    /// Notably, on Linux this reports true for EPERM errors (from outbound
    /// firewall blocks) which aren't really send errors; they're just
    /// sends that are never going to make it because the local OS blocked it.
    pub fn treat_as_lost_udp(&self) -> bool {
        if let Error::Io(io_err) = self {
            // Linux, while not documented in the man page,
            // returns EPERM when there's an OUTPUT rule with -j
            // DROP or -j REJECT.  We use this very specific
            // Linux+EPERM check rather than something super broad
            // like net.Error.Temporary which could be anything.
            //
            // For now we only do this on Linux, as such outgoing
            // firewall violations mapping to syscall errors
            // hasn't yet been observed on other OSes.
            if let Some(raw_os_err) = io_err.raw_os_error() {
                if raw_os_err == libc::EPERM {
                    return true;
                }
            }
        }
        false
    }
}

/// A UDP socket that can be re-bound. Unix has no notion of re-binding a socket, so we swap it out for a new one.
#[derive(Default)]
pub struct RebindingUdpConn(pub(super) RwLock<Inner>);

#[derive(Default)]
pub(super) struct Inner {
    // TODO: evaluate which locking strategy to use
    // pconnAtomic is a pointer to the value stored in pconn, but doesn't
    // require acquiring mu. It's used for reads/writes and only upon failure
    // do the reads/writes then check pconn (after acquiring mu) to see if
    // there's been a rebind meanwhile.
    // pconn isn't really needed, but makes some of the code simpler
    // to keep it distinct.
    // Neither is expected to be nil, sockets are bound on creation.
    // pconn_atomic: atomic.Pointer[nettype.PacketConn],
    pub(super) pconn: Option<UdpSocket>,
    pub(super) port: u16,
}

impl RebindingUdpConn {
    /// Reads a packet from the connection into b.
    /// It returns the number of bytes copied and the source address.
    pub async fn read_from(&self, b: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let state = self.0.read().await; // TODO: atomic access?
        let pconn = state.pconn.as_ref().ok_or_else(|| Error::NoConn)?;

        let res = pconn.recv_from(b).await?;
        Ok(res)
    }

    pub async fn port(&self) -> u16 {
        self.0.read().await.port
    }

    pub async fn local_addr(&self) -> Option<SocketAddr> {
        self.0.read().await.local_addr()
    }

    pub async fn close(&self) -> Result<(), Error> {
        let mut state = self.0.write().await;
        state.close()
    }

    pub async fn write_to(&self, addr: SocketAddr, b: &[u8]) -> Result<usize, Error> {
        let state = self.0.read().await; // TODO: atomic access?
        let pconn = state.pconn.as_ref().ok_or_else(|| Error::NoConn)?;

        let written = pconn.send_to(b, addr).await?;
        Ok(written)
    }
}

impl Inner {
    /// Sets the provided nettype.PacketConn. It should be called only
    /// after acquiring RebindingUDPConn.mu. It upgrades the provided
    /// nettype.PacketConn to a udpConnWithBatchOps when appropriate. This upgrade
    /// is intentionally pushed closest to where read/write ops occur in order to
    /// avoid disrupting surrounding code that assumes nettype.PacketConn is a *net.UDPConn.
    pub fn set_conn(&mut self, p: UdpSocket, network: Network) {
        // upc := upgradePacketConn(p, network)
        let port = p.local_addr().expect("missing addr").port();
        self.pconn = Some(p);
        self.port = port;
    }

    pub fn close(&mut self) -> Result<(), Error> {
        match self.pconn.take() {
            Some(pconn) => {
                self.port = 0;
                // pconn.close() is not available, so we just drop for now
                // TODO: make sure the recv loops get shutdown
                Ok(())
            }
            None => Err(Error::NoConn),
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.pconn
            .as_ref()
            .and_then(|pconn| pconn.local_addr().ok())
    }
}
