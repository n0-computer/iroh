use anyhow::Result;
use async_trait::async_trait;
use iroh_rpc_client::{Lookup, P2pClient};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
#[cfg(feature = "testing")]
use mockall::automock;

pub struct ClientP2p {
    client: P2pClient,
}

#[derive(Debug, Clone)]
pub enum PeerIdOrAddr {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

impl ClientP2p {
    pub fn new(client: P2pClient) -> Self {
        Self { client }
    }
}

#[cfg_attr(feature = "testing", automock)]
#[async_trait]
pub trait P2p: Sync {
    async fn lookup_local(&self) -> Result<Lookup>;
    async fn lookup(&self, addr: &PeerIdOrAddr) -> Result<Lookup>;
    async fn connect(&self, addr: &PeerIdOrAddr) -> Result<()>;
}

#[async_trait]
impl P2p for ClientP2p {
    async fn lookup_local(&self) -> Result<Lookup> {
        let (_, listen_addrs) = self.client.get_listening_addrs().await?;
        Ok(Lookup {
            peer_id: self.client.local_peer_id().await?,
            listen_addrs,
            observed_addrs: self.client.external_addresses().await?,
            protocol_version: String::new(),
            agent_version: String::new(),
            protocols: Default::default(),
        })
    }

    async fn lookup(&self, addr: &PeerIdOrAddr) -> Result<Lookup> {
        match addr {
            PeerIdOrAddr::PeerId(peer_id) => self.client.lookup(*peer_id, None).await,
            PeerIdOrAddr::Multiaddr(addr) => {
                let peer_id = peer_id_from_multiaddr(addr)?;
                self.client.lookup(peer_id, Some(addr.clone())).await
            }
        }
    }

    async fn connect(&self, addr: &PeerIdOrAddr) -> Result<()> {
        match addr {
            PeerIdOrAddr::PeerId(peer_id) => self.client.connect(*peer_id, vec![]).await,
            PeerIdOrAddr::Multiaddr(addr) => {
                let peer_id = peer_id_from_multiaddr(addr)?;
                self.client.connect(peer_id, vec![addr.clone()]).await
            }
        }
    }
}

fn peer_id_from_multiaddr(addr: &Multiaddr) -> Result<PeerId> {
    match addr.iter().find(|p| matches!(*p, Protocol::P2p(_))) {
        Some(Protocol::P2p(peer_id)) => {
            PeerId::from_multihash(peer_id).map_err(|m| anyhow::anyhow!("Multiaddress contains invalid p2p multihash {:?}. Cannot derive a PeerId from this address.", m ))
        }
        ,
        _ => anyhow::bail!("Mulitaddress must include the peer id"),
    }
}
