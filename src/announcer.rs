//! experimental local net announcement

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

use crate::PeerId;

const PORT: u16 = 5566;
const MAX_MSG_SIZE: usize = 511;
const MAGIC: &[u8; 12] = b"n0/x/ann/0.1";

/// Announce a provider on IPv4.
#[derive(Debug)]
pub struct Announcer {
    peer: PeerId,
    port: u16,
}

impl Announcer {
    /// new
    pub fn new(peer: PeerId, port: u16) -> Self {
        Announcer { peer, port }
    }

    /// run
    pub async fn run(&self) -> Result<()> {
        let msg = postcard::to_stdvec(&Message {
            magic: *MAGIC,
            peer: self.peer,
            port: self.port,
        })?;
        ensure!(msg.len() <= MAX_MSG_SIZE, "message too large");
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        sock.set_broadcast(true)?;
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, PORT));
        loop {
            let n = sock.send_to(&msg, dst).await?;
            if n != msg.len() {
                bail!("did not send full packet");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    magic: [u8; 12],
    peer: PeerId,
    port: u16,
}

/// Listen for an announced provider
#[derive(Debug)]
pub struct Listener {
    /// We want this peer specifically.
    peer: PeerId,
}

impl Listener {
    /// new
    pub fn new(peer: PeerId) -> Self {
        Listener { peer }
    }

    /// listen
    pub async fn listen(&self) -> Result<SocketAddr> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PORT)).await?;
        let mut buf = [0u8; MAX_MSG_SIZE + 1];
        loop {
            let (n, addr) = sock.recv_from(&mut buf).await?;
            if n > MAX_MSG_SIZE {
                continue; // not a datagram for us
            }
            let msg: Message = postcard::from_bytes(&buf[..n])?;
            if msg.magic != *MAGIC {
                continue; // not  a datagram for us
            }
            if msg.peer != self.peer {
                continue; // wrong peer
            }
            let peer_ip = match addr.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => continue, // unreachable
            };
            return Ok(SocketAddr::from((peer_ip, msg.port)));
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::timeout;

    use crate::Keypair;

    use super::*;

    #[tokio::test]
    async fn test_announc_listen() {
        let key = Keypair::generate();
        let peer_id = PeerId::from(key.public());

        let ann = Announcer::new(peer_id, 1234);
        let ann_handle = tokio::spawn(async move { ann.run().await });

        let lis = Listener::new(peer_id);
        let addr = timeout(Duration::from_secs(10), lis.listen())
            .await
            .expect("listen timeout")
            .expect("listen err");
        println!("{addr:?}");

        ann_handle.abort();
    }
}
