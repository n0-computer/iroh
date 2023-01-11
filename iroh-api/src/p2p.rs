use std::collections::HashMap;

use anyhow::Result;
use bytes::Bytes;
use futures::stream::Stream;
use iroh_rpc_client::{GossipsubEvent, Lookup, P2pClient};
use libp2p::{
    gossipsub::{MessageId, TopicHash},
    multiaddr::Protocol,
    Multiaddr, PeerId,
};

use crate::error::map_service_error;

#[derive(Debug, Clone)]
pub struct P2p {
    client: P2pClient,
}

#[derive(Debug, Clone)]
pub enum PeerIdOrAddr {
    PeerId(PeerId),
    Multiaddr(Multiaddr),
}

impl P2p {
    pub fn new(client: P2pClient) -> Self {
        Self { client }
    }

    pub async fn lookup_local(&self) -> Result<Lookup> {
        self.client
            .lookup_local()
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// The [`PeerId`] for this Iroh p2p nod
    pub async fn peer_id(&self) -> Result<PeerId> {
        self.client
            .local_peer_id()
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// The list of [`Multiaddr`] that the Iroh p2p node is listening on
    pub async fn addrs(&self) -> Result<Vec<Multiaddr>> {
        self.client
            .get_listening_addrs()
            .await
            .map(|(_, addrs)| addrs)
            .map_err(|e| map_service_error("p2p", e))
    }

    pub async fn lookup(&self, addr: &PeerIdOrAddr) -> Result<Lookup> {
        match addr {
            PeerIdOrAddr::PeerId(peer_id) => self.client.lookup(*peer_id, None).await,
            PeerIdOrAddr::Multiaddr(addr) => {
                let peer_id = peer_id_from_multiaddr(addr)?;
                self.client.lookup(peer_id, Some(addr.clone())).await
            }
        }
        .map_err(|e| map_service_error("p2p", e))
    }

    /// Connect to a peer using a [`PeerId`] and `Vec` of [`Multiaddr`]
    ///
    /// If there is an empty `Vec` of `Multiaddr`s, Iroh will attempt to find
    /// the peer on the DHT using the `PeerId`.
    pub async fn connect(&self, peer_id: PeerId, addrs: Vec<Multiaddr>) -> Result<()> {
        self.client
            .connect(peer_id, addrs)
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    pub async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        self.client
            .get_peers()
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// Subscribe to a pub/sub Topic
    ///
    /// We use Gossipsub as the pub/sub protocol. This method will subscribe you
    /// to a Gossipsub topic and return a stream of [`GossipsubEvent`]s relevant
    /// to that topic.
    ///
    /// Learn more about the Gossipsub protocol in the `libp2p-gossipsub`
    /// [documentation](https://docs.rs/libp2p-gossipsub/latest/libp2p_gossipsub/).
    pub async fn subscribe(
        &self,
        topic: String,
    ) -> Result<impl Stream<Item = Result<GossipsubEvent>>> {
        let topic = TopicHash::from_raw(topic);
        self.client
            .gossipsub_subscribe(topic)
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// Publish a message on a pub/sub Topic.
    ///
    /// We use Gossipsub as the pub/sub protocol. This method allows you to publish
    /// a message on a given topic to anyone in your network that is subscribed to
    /// that topic.
    ///
    /// Read the [`P2p::subscribe`] documentation for how to subscribe and receive
    /// Gossipsub messages.
    pub async fn publish(&self, topic: String, data: Bytes) -> Result<MessageId> {
        let topic = TopicHash::from_raw(topic);
        self.client
            .gossipsub_publish(topic, data)
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// Explicitly add a peer to our pub/sub network.
    ///
    /// We use Gossipsub as our pub/sub protocol.
    ///
    /// We will attempt to stay connected and forward all relevant Gossipsub messages
    /// to this peer. Read the [`P2p::subscribe`] and [`P2p::publish`] documentation
    /// for how to subscribe, read, and publish messages.
    pub async fn add_pubsub_peer(&self, peer_id: PeerId) -> Result<()> {
        self.client
            .gossipsub_add_explicit_peer(peer_id)
            .await
            .map_err(|e| map_service_error("p2p", e))
    }
}

pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Result<PeerId> {
    match addr.iter().find(|p| matches!(*p, Protocol::P2p(_))) {
        Some(Protocol::P2p(peer_id)) => {
            PeerId::from_multihash(peer_id).map_err(|m| anyhow::anyhow!("Multiaddress contains invalid p2p multihash {:?}. Cannot derive a PeerId from this address.", m ))
        }
        ,
        _ => anyhow::bail!("Mulitaddress must include the peer id"),
    }
}
