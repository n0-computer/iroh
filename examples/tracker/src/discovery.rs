// copied and adapted from https://github.com/dvc94ch/p2p/blob/master/src/discovery.rs
use anyhow::Result;
use futures::future::BoxFuture;
use futures::{future, FutureExt};
use iroh_net::key::PublicKey as NodeId;
use iroh_net::{AddrInfo, PeerAddr};
use pkarr::dns::rdata::{RData, A, AAAA, TXT};
use pkarr::dns::{Name, Packet, ResourceRecord, CLASS};
use pkarr::url::Url;
use pkarr::{Keypair, PkarrClient, SignedPacket};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use tracing::info;

const DERP_REGION_KEY: &str = "_derp_region.iroh.";

#[allow(unused)]
fn filter_ipaddr(rr: &ResourceRecord) -> Option<IpAddr> {
    if rr.class != CLASS::IN {
        return None;
    }
    let addr: IpAddr = match rr.rdata {
        RData::A(A { address }) => IpAddr::V4(address.into()),
        RData::AAAA(AAAA { address }) => IpAddr::V6(address.into()),
        _ => return None,
    };
    Some(addr)
}

fn filter_txt(rr: &ResourceRecord) -> Option<String> {
    if rr.class != CLASS::IN {
        return None;
    }
    if let RData::TXT(txt) = &rr.rdata {
        String::try_from(txt.clone()).ok()
    } else {
        None
    }
}

fn filter_u16(rr: &ResourceRecord) -> Option<u16> {
    if rr.class != CLASS::IN {
        return None;
    }
    if let RData::A(A { address }) = rr.rdata {
        Some(address as _)
    } else {
        None
    }
}

fn packet_to_node_addr(peer_id: &NodeId, packet: &SignedPacket) -> PeerAddr {
    let direct_addresses = packet
        .resource_records("@")
        .filter_map(filter_txt)
        .filter_map(|addr| addr.parse().ok())
        .collect::<BTreeSet<SocketAddr>>();
    let derp_region = packet
        .resource_records(DERP_REGION_KEY)
        .find_map(filter_u16);
    PeerAddr {
        peer_id: *peer_id,
        info: AddrInfo {
            derp_region,
            direct_addresses,
        },
    }
}

fn node_addr_to_packet(keypair: &Keypair, info: &AddrInfo, ttl: u32) -> Result<SignedPacket> {
    let mut packet = Packet::new_reply(0);
    for addr in &info.direct_addresses {
        let addr = addr.to_string();
        packet.answers.push(ResourceRecord::new(
            Name::new("@").unwrap(),
            CLASS::IN,
            ttl,
            RData::TXT(TXT::try_from(addr.as_str())?.into_owned()),
        ));
    }
    if let Some(derp_region) = info.derp_region {
        packet.answers.push(ResourceRecord::new(
            Name::new(DERP_REGION_KEY).unwrap(),
            CLASS::IN,
            ttl,
            RData::A(A {
                address: derp_region as _,
            }),
        ));
    }
    Ok(SignedPacket::from_packet(keypair, &packet)?)
}

/// A discovery method that uses the pkarr DNS protocol. See pkarr.org for more
/// information.
///
/// This is using pkarr via a simple http relay or self-contained server.
#[derive(Debug)]
pub struct PkarrRelayDiscovery {
    keypair: pkarr::Keypair,
    relay: Url,
    client: PkarrClient,
}

impl PkarrRelayDiscovery {
    #[allow(dead_code)]
    pub fn new(secret_key: iroh_net::key::SecretKey, relay: Url) -> Self {
        let keypair = pkarr::Keypair::from_secret_key(&secret_key.to_bytes());
        Self {
            keypair,
            relay,
            client: PkarrClient::new(),
        }
    }
}

impl iroh_net::magicsock::Discovery for PkarrRelayDiscovery {
    fn publish(&self, info: &AddrInfo) {
        info!("publishing {:?} via {}", info, self.relay);
        let signed_packet = node_addr_to_packet(&self.keypair, info, 0).unwrap();
        let client = self.client.clone();
        let relay = self.relay.clone();
        tokio::spawn(async move {
            let res = client.relay_put(&relay, signed_packet).await;
            info!("done publishing, ok:{}", res.is_ok());
        });
    }

    fn resolve<'a>(
        &'a self,
        node_id: &'a NodeId,
    ) -> futures::future::BoxFuture<'a, Result<AddrInfo>> {
        async move {
            info!("resolving {} via {}", node_id, self.relay);
            let pkarr_public_key = pkarr::PublicKey::try_from(*node_id.as_bytes()).unwrap();
            let packet = self.client.relay_get(&self.relay, pkarr_public_key).await?;
            let addr = packet_to_node_addr(node_id, &packet);
            info!("resolved: {} to {:?}", node_id, addr);
            Ok(addr.info)
        }
        .boxed()
    }
}

/// A discovery method that just uses a hardcoded region.
#[derive(Debug)]
pub struct HardcodedRegionDiscovery {
    region: u16,
}

impl HardcodedRegionDiscovery {
    /// Create a new discovery method that always returns the given region.
    pub fn new(region: u16) -> Self {
        Self { region }
    }
}

impl iroh_net::magicsock::Discovery for HardcodedRegionDiscovery {
    fn publish(&self, _info: &AddrInfo) {}

    fn resolve<'a>(&'a self, _node_id: &'a NodeId) -> BoxFuture<'a, Result<AddrInfo>> {
        future::ok(AddrInfo {
            derp_region: Some(self.region),
            direct_addresses: Default::default(),
        })
        .boxed()
    }
}
