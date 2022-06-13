use std::collections::HashSet;
use std::error::Error;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use cid::Cid;
use iroh_bitswap::{Bitswap, BitswapConfig, Priority, QueryId};
use libp2p::core::identity::Keypair;
use libp2p::core::PeerId;
use libp2p::gossipsub::{Gossipsub, GossipsubConfig, GossipsubEvent, MessageAuthenticity};
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{Kademlia, KademliaConfig};
use libp2p::mdns::Mdns;
use libp2p::multiaddr::Protocol;
use libp2p::ping::Ping;
use libp2p::relay;
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{autonat, dcutr};
use libp2p::{Multiaddr, NetworkBehaviour};
use prometheus_client::registry::Registry;
use tracing::warn;

pub(crate) use self::event::Event;
use crate::config::Libp2pConfig;

mod event;

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
    relay: Toggle<relay::v2::relay::Relay>,
    relay_client: Toggle<relay::v2::client::Client>,
    dcutr: Toggle<dcutr::behaviour::Behaviour>,
    gossipsub: Gossipsub,
}

impl NodeBehaviour {
    pub async fn new(
        local_key: &Keypair,
        config: &Libp2pConfig,
        registry: &mut Registry,
        relay_client: Option<relay::v2::client::Client>,
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

        let relay = if config.relay_server {
            let config = relay::v2::relay::Config::default();
            let r = relay::v2::relay::Relay::new(local_key.public().to_peer_id(), config);
            Some(r)
        } else {
            None
        }
        .into();

        let (dcutr, relay_client) = if config.relay_client {
            let relay_client =
                relay_client.expect("missing relay client even though it was enabled");
            let dcutr = dcutr::behaviour::Behaviour::new();
            (Some(dcutr), Some(relay_client))
        } else {
            (None, None)
        };

        let identify = {
            let config = IdentifyConfig::new("ipfs/0.1.0".into(), local_key.public())
                .with_agent_version(format!("iroh/{}", env!("CARGO_PKG_VERSION")));
            Identify::new(config)
        };

        let gossipsub_config = GossipsubConfig::default();
        let message_authenticity = MessageAuthenticity::Signed(local_key.clone());
        let gossipsub = Gossipsub::new(message_authenticity, gossipsub_config)
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        Ok(NodeBehaviour {
            ping: Ping::default(),
            identify,
            bitswap,
            mdns,
            kad,
            autonat,
            relay,
            dcutr: dcutr.into(),
            relay_client: relay_client.into(),
            gossipsub,
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
