use iroh_bitswap::BitswapEvent;
use libp2p::{
    autonat, dcutr, gossipsub::GossipsubEvent, identify::IdentifyEvent, kad::KademliaEvent,
    mdns::MdnsEvent, ping::PingEvent, relay,
};

use super::peer_manager::PeerManagerEvent;

/// Event type which is emitted from the [`NodeBehaviour`].
#[derive(Debug)]
pub enum Event {
    Ping(PingEvent),
    Identify(Box<IdentifyEvent>),
    Kademlia(KademliaEvent),
    Mdns(MdnsEvent),
    Bitswap(BitswapEvent),
    Autonat(autonat::Event),
    Relay(relay::v2::relay::Event),
    RelayClient(relay::v2::client::Event),
    Dcutr(dcutr::behaviour::Event),
    Gossipsub(GossipsubEvent),
    PeerManager(PeerManagerEvent),
}

impl From<PingEvent> for Event {
    fn from(event: PingEvent) -> Self {
        Event::Ping(event)
    }
}

impl From<IdentifyEvent> for Event {
    fn from(event: IdentifyEvent) -> Self {
        Event::Identify(Box::new(event))
    }
}

impl From<KademliaEvent> for Event {
    fn from(event: KademliaEvent) -> Self {
        Event::Kademlia(event)
    }
}

impl From<MdnsEvent> for Event {
    fn from(event: MdnsEvent) -> Self {
        Event::Mdns(event)
    }
}

impl From<BitswapEvent> for Event {
    fn from(event: BitswapEvent) -> Self {
        Event::Bitswap(event)
    }
}

impl From<GossipsubEvent> for Event {
    fn from(event: GossipsubEvent) -> Self {
        Event::Gossipsub(event)
    }
}

impl From<autonat::Event> for Event {
    fn from(event: autonat::Event) -> Self {
        Event::Autonat(event)
    }
}

impl From<relay::v2::relay::Event> for Event {
    fn from(event: relay::v2::relay::Event) -> Self {
        Event::Relay(event)
    }
}

impl From<relay::v2::client::Event> for Event {
    fn from(event: relay::v2::client::Event) -> Self {
        Event::RelayClient(event)
    }
}

impl From<dcutr::behaviour::Event> for Event {
    fn from(event: dcutr::behaviour::Event) -> Self {
        Event::Dcutr(event)
    }
}

impl From<PeerManagerEvent> for Event {
    fn from(event: PeerManagerEvent) -> Self {
        Event::PeerManager(event)
    }
}
