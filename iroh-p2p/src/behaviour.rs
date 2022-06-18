use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;

use crate::config::Libp2pConfig;
use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use iroh_bitswap::{Bitswap, BitswapConfig, BitswapEvent, Priority, QueryId};
use libp2p::autonat;
use libp2p::core::identity::Keypair;
use libp2p::core::PeerId;
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaConfig, KademliaEvent};
use libp2p::mdns::{Mdns, MdnsEvent};
use libp2p::multiaddr::Protocol;
use libp2p::ping::{Ping, PingEvent};
use libp2p::request_response::RequestResponseConfig;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{Multiaddr, NetworkBehaviour};
use prometheus_client::registry::Registry;
use tracing::warn;

lazy_static::lazy_static! {
    static ref VERSION: &'static str = env!("CARGO_PKG_VERSION");
}

/// Libp2p behaviour for the node.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = false)]
pub(crate) struct NodeBehaviour {
    ping: Ping,
    identify: Identify,
    bitswap: Bitswap,
    pub(crate) kad: Toggle<Kademlia<MemoryStore>>,
    mdns: Toggle<Mdns>,
    pub(crate) autonat: Toggle<autonat::Behaviour>,
}

/// Event type which is emitted from the [NodeBehaviour] into the libp2p service.
#[derive(Debug)]
pub(crate) enum Event {
    Ping(PingEvent),
    Identify(Box<IdentifyEvent>),
    Kademlia(KademliaEvent),
    Mdns(MdnsEvent),
    Bitswap(BitswapEvent),
    Autonat(autonat::Event),
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

impl From<autonat::Event> for Event {
    fn from(event: autonat::Event) -> Self {
        Event::Autonat(event)
    }
}

impl NodeBehaviour {
    pub async fn new(
        local_key: &Keypair,
        config: &Libp2pConfig,
        registry: &mut Registry,
    ) -> Result<Self> {
        let bs_config = BitswapConfig::default();
        let bitswap = Bitswap::new(bs_config, registry);

        let mdns = if config.mdns {
            Some(Mdns::new(Default::default()).await?)
        } else {
            None
        }
        .into();

        let kad = if config.kademlia {
            let pub_key = local_key.public();

            // TODO: persist to store
            let store = MemoryStore::new(pub_key.to_peer_id());

            // TODO: make user configurable
            let mut kad_config = KademliaConfig::default();
            kad_config.set_parallelism(16usize.try_into().unwrap());
            // TODO: potentially lower (this is per query)
            kad_config.set_query_timeout(Duration::from_secs(60));

            let mut kademlia = Kademlia::with_config(pub_key.to_peer_id(), store, kad_config);
            for multiaddr in &config.bootstrap_peers {
                // TODO: move parsing into config
                let mut addr = multiaddr.to_owned();
                if let Some(Protocol::P2p(mh)) = addr.pop() {
                    let peer_id = PeerId::from_multihash(mh).unwrap();
                    kademlia.add_address(&peer_id, addr);
                } else {
                    warn!("Could not parse bootstrap addr {}", multiaddr);
                }
            }

            // Trigger initial bootstrap
            if let Err(e) = kademlia.bootstrap() {
                warn!("Kademlia bootstrap failed: {}", e);
            }

            Some(kademlia)
        } else {
            None
        }
        .into();

        let autonat = if config.autonat {
            let pub_key = local_key.public();
            let config = autonat::Config {
                use_connected: true,
                ..Default::default()
            }; // TODO: configurable
            let autonat = autonat::Behaviour::new(pub_key.to_peer_id(), config);
            Some(autonat)
        } else {
            None
        }
        .into();

        let mut req_res_config = RequestResponseConfig::default();
        req_res_config.set_request_timeout(Duration::from_secs(20));
        req_res_config.set_connection_keep_alive(Duration::from_secs(20));

        Ok(NodeBehaviour {
            ping: Ping::default(),
            identify: Identify::new(IdentifyConfig::new("ipfs/0.1.0".into(), local_key.public())),
            bitswap,
            mdns,
            kad,
            autonat,
        })
    }

    /// Send a block to a peer over bitswap
    #[allow(dead_code)]
    pub fn send_block(
        &mut self,
        peer_id: &PeerId,
        cid: Cid,
        data: Bytes,
    ) -> Result<(), Box<dyn Error>> {
        self.bitswap.send_block(peer_id, cid, data);
        Ok(())
    }

    /// Send a request for data over bitswap
    pub fn want_block(
        &mut self,
        cid: Cid,
        priority: Priority,
        providers: HashSet<PeerId>,
    ) -> Result<QueryId, Box<dyn Error>> {
        let id = self.bitswap.want_block(cid, priority, providers);
        Ok(id)
    }

    pub fn add_address(&mut self, peer: &PeerId, addr: Multiaddr) {
        if let Some(kad) = self.kad.as_mut() {
            kad.add_address(peer, addr);
        }
    }

    pub fn finish_query(&mut self, id: &libp2p::kad::QueryId) {
        if let Some(kad) = self.kad.as_mut() {
            if let Some(mut query) = kad.query_mut(id) {
                query.finish();
            }
        }
    }
}
