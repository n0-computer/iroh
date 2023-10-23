// copied from https://github.com/dvc94ch/p2p/blob/master/src/discovery.rs
use anyhow::Result;
use futures::FutureExt;
use iroh_net::key::PublicKey as PeerId;
use iroh_net::{AddrInfo, PeerAddr};
use pkarr::dns::rdata::{RData, A, AAAA, TXT};
use pkarr::dns::{Name, Packet, ResourceRecord, CLASS};
use pkarr::url::Url;
use pkarr::{Keypair, PkarrClient, SignedPacket};
use simple_mdns::async_discovery::ServiceDiscovery;
use simple_mdns::{InstanceInformation, NetworkScope};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use ttl_cache::TtlCache;

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

fn filter_txt<'a>(rr: &'a ResourceRecord) -> Option<String> {
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

fn packet_to_peer_addr(peer_id: &PeerId, packet: &SignedPacket) -> PeerAddr {
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

fn peer_addr_to_packet(keypair: &Keypair, info: &AddrInfo, ttl: u32) -> Result<SignedPacket> {
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
    Ok(SignedPacket::from_packet(&keypair, &packet)?)
}

fn peer_addr_to_instance_info(addr: &PeerAddr) -> InstanceInformation {
    let mut instance_info = InstanceInformation::new();
    for addr in &addr.info.direct_addresses {
        instance_info.ip_addresses.push(addr.ip());
        instance_info.ports.push(addr.port());
    }
    instance_info
}

fn instance_info_to_peer_addr(peer_id: &PeerId, instance_info: &InstanceInformation) -> PeerAddr {
    PeerAddr {
        peer_id: *peer_id,
        info: AddrInfo {
            derp_region: None,
            direct_addresses: instance_info.get_socket_addresses().collect(),
        },
    }
}

#[derive(Debug)]
pub struct PkarrRelayDiscovery {
    keypair: pkarr::Keypair,
    relay: Url,
    client: PkarrClient,
}

impl PkarrRelayDiscovery {
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
        println!("publishing {:?} via {}", info, self.relay);
        let signed_packet = peer_addr_to_packet(&self.keypair, info, 0).unwrap();
        let client = self.client.clone();
        let relay = self.relay.clone();
        tokio::spawn(async move {
            let res = client.relay_put(&relay, signed_packet).await;
            println!("done publishing, ok:{}", res.is_ok());
        });
    }

    fn resolve<'a>(
        &'a self,
        peer_id: &'a PeerId,
    ) -> futures::future::BoxFuture<'a, Result<AddrInfo>> {
        async move {
            println!("resolving {} via {}", peer_id, self.relay);
            let pkarr_public_key = pkarr::PublicKey::try_from(*peer_id.as_bytes()).unwrap();
            let packet = self.client.relay_get(&self.relay, pkarr_public_key).await?;
            let addr = packet_to_peer_addr(&peer_id, &packet);
            println!("resolved: {} to {:?}", peer_id, addr);
            Ok(addr.info)
        }
        .boxed()
    }
}

#[derive(Debug)]
pub struct HardcodedRegionDiscovery {
    region: u16,
}

impl HardcodedRegionDiscovery {
    pub fn new(region: u16) -> Self {
        Self { region }
    }
}

impl iroh_net::magicsock::Discovery for HardcodedRegionDiscovery {
    fn publish(&self, info: &AddrInfo) {}

    fn resolve<'a>(
        &'a self,
        peer_id: &'a PeerId,
    ) -> futures::future::BoxFuture<'a, Result<AddrInfo>> {
        futures::future::ok(AddrInfo {
            derp_region: Some(self.region),
            direct_addresses: Default::default(),
        })
        .boxed()
    }
}

pub struct Discovery {
    cache: TtlCache<PeerId, PeerAddr>,
    keypair: Keypair,
    relay: Option<Url>,
    pkarr: Option<PkarrClient>,
    mdns: Option<ServiceDiscovery>,
    ttl: u32,
}

impl Discovery {
    pub fn new(secret: [u8; 32], relay: Option<Url>, mdns: bool, ttl: u32) -> Result<Self> {
        let keypair = Keypair::from_secret_key(&secret);
        let origin = keypair.public_key().to_z32();
        let mdns = if mdns {
            Some(ServiceDiscovery::new_with_scope(
                &origin,
                "_pkarr.local",
                ttl,
                None,
                NetworkScope::V4,
            )?)
        } else {
            None
        };
        let pkarr = if relay.is_some() {
            Some(PkarrClient::new())
        } else {
            None
        };
        Ok(Self {
            cache: TtlCache::new(100),
            keypair,
            relay,
            pkarr,
            mdns,
            ttl,
        })
    }

    pub fn add_address(&mut self, addr: PeerAddr) {
        self.cache
            .insert(addr.peer_id, addr, Duration::from_secs(self.ttl as _));
    }

    pub async fn resolve(&mut self, peer_id: &PeerId) -> Result<PeerAddr> {
        if let Some(addr) = self.cache.get(peer_id) {
            return Ok(addr.clone());
        }
        let origin = pkarr::PublicKey::try_from(*peer_id.as_bytes()).unwrap();
        let origin_z32 = origin.to_z32();
        if let Some(mdns) = self.mdns.as_ref() {
            if let Some(addr) = mdns
                .get_known_services()
                .await
                .into_iter()
                .find(|(peer, _)| peer == &origin_z32)
                .map(|(_, instance_info)| instance_info_to_peer_addr(peer_id, &instance_info))
            {
                self.add_address(addr.clone());
                return Ok(addr);
            }
        }
        if let (Some(pkarr), Some(url)) = (self.pkarr.as_ref(), self.relay.as_ref()) {
            let msg = pkarr.relay_get(url, origin).await?;
            let addr = packet_to_peer_addr(peer_id, &msg);
            self.add_address(addr.clone());
            return Ok(addr);
        }
        anyhow::bail!("peer not found");
    }

    pub async fn publish(&mut self, addr: &PeerAddr) -> Result<()> {
        if let Some(mdns) = self.mdns.as_mut() {
            let instance_info = peer_addr_to_instance_info(addr);
            mdns.add_service_info(instance_info).await?;
        }
        if let (Some(pkarr), Some(url)) = (self.pkarr.as_ref(), self.relay.as_ref()) {
            let packet = peer_addr_to_packet(&self.keypair, &addr.info, self.ttl)?;
            pkarr.relay_put(url, packet).await?;
        }
        Ok(())
    }
}
