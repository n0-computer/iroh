use std::collections::HashMap;

use anyhow::Result;
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use iroh_p2p::NetworkEvent;
use iroh_rpc_client::{Lookup, P2pClient};
use libp2p::{
    gossipsub::{MessageId, TopicHash},
    multiaddr::Protocol,
    Multiaddr, PeerId,
};

use crate::error::map_service_error;

#[derive(Debug)]
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
        self.client.lookup_local().await
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

    pub async fn connect(&self, addr: &PeerIdOrAddr) -> Result<()> {
        match addr {
            PeerIdOrAddr::PeerId(peer_id) => self.client.connect(*peer_id, vec![]).await,
            PeerIdOrAddr::Multiaddr(addr) => {
                let peer_id = peer_id_from_multiaddr(addr)?;
                self.client.connect(peer_id, vec![addr.clone()]).await
            }
        }
        .map_err(|e| map_service_error("p2p", e))
    }

    pub async fn peers(&self) -> Result<HashMap<PeerId, Vec<Multiaddr>>> {
        self.client
            .get_peers()
            .await
            .map_err(|e| map_service_error("p2p", e))
    }

    /// Get a stream of [`NetworkEvent`].
    pub async fn network_events(&self) -> Result<BoxStream<'static, Result<NetworkEvent>>> {
        let stream = self
            .client
            .network_events()
            .await
            .map_err(|e| map_service_error("p2p", e))?;
        Ok(stream.boxed())
    }

    /// Subscribe to a Gossipsub Topic
    ///
    /// Gossipsub is a pub/sub protocol. This will subscribe you to a Gossipsub
    /// topic. All Gossipsub messages for topics that you are subscribed to can
    /// be read off the the `NetworkEvent` stream, as
    /// `NetworkEvent::Gossipsub(GossipsubEvent::Message)`. You can access this
    /// stream using `P2p::network_events`.
    ///
    /// There is currently no `gossipsub_unsubscribe` exposed to `iroh-api` crate
    /// yet.
    ///
    /// Learn more about the Gossipsub protocol in the `libp2p-gossipsub`
    /// [documentation](https://docs.rs/libp2p-gossipsub/latest/libp2p_gossipsub/).
    //
    // TODO(ramfox): write `gossipsub_messages(topic: String)` method that returns
    // a stream of only the gossipsub messages on that topic
    pub async fn gossipsub_subscribe(&self, topic: String) -> Result<bool> {
        let topic = TopicHash::from_raw(topic);
        self.client.gossipsub_subscribe(topic).await
    }

    /// Publish a message on a Gossipsub Topic.
    ///
    /// This allows you to publish a message on a given topic to anyone in your
    /// network that is subscribed to that topic.
    ///
    /// Read the [`P2p::gossipsub_subscribe`] documentation for how to subscribe
    /// and receive Gossipsub messages.
    pub async fn gossipsub_publish(&self, topic: String, data: Bytes) -> Result<MessageId> {
        let topic = TopicHash::from_raw(topic);
        self.client.gossipsub_publish(topic, data).await
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
