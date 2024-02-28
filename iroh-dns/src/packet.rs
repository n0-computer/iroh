use std::{collections::HashMap, fmt::Display, str::FromStr};

// use hickory_proto::rr::Name;
use anyhow::{anyhow, bail, Result};
use hickory_proto::error::ProtoError;
use iroh_net::{AddrInfo, NodeAddr, NodeId};
use url::Url;

use crate::from_z32;

pub const IROH_ROOT_ZONE: &str = "iroh";
pub const IROH_NODE_TXT_LABEL: &str = "_iroh_node";
pub const DEFAULT_TTL: u32 = 30;

pub const ATTR_DERP: &str = "derp";
pub const ATTR_NODE_ID: &str = "node";
pub const ATTR_DNS: &str = "dns";

#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct NodeAnnounce {
    pub node_id: NodeId,
    #[debug("{:?}", self.home_derp.as_ref().map(|s| s.to_string()))]
    pub home_derp: Option<Url>,
    pub home_dns: Vec<String>,
}

impl From<NodeAnnounce> for NodeAddr {
    fn from(value: NodeAnnounce) -> Self {
        NodeAddr {
            node_id: value.node_id,
            info: value.into(),
        }
    }
}

impl From<NodeAnnounce> for AddrInfo {
    fn from(value: NodeAnnounce) -> Self {
        AddrInfo {
            derp_url: value.home_derp.map(|u| u.into()),
            direct_addresses: Default::default(),
        }
    }
}

impl NodeAnnounce {
    pub fn new(node_id: NodeId, derp: Option<Url>, dns: Vec<String>) -> Self {
        Self {
            node_id,
            home_derp: derp,
            home_dns: dns,
        }
    }

    pub fn to_attr_string(&self) -> String {
        let mut attrs = vec![];
        attrs.push(fmt_attr(ATTR_NODE_ID, self.node_id));
        if let Some(derp) = &self.home_derp {
            attrs.push(fmt_attr(ATTR_DERP, derp));
        }
        for dns in &self.home_dns {
            attrs.push(fmt_attr(ATTR_DNS, dns));
        }
        attrs.join(" ")
    }

    pub fn zone(&self, absolute: bool) -> String {
        match absolute {
            true => format!("{}.{}.", self.node_id, IROH_ROOT_ZONE),
            false => format!("{}.{}", self.node_id, IROH_ROOT_ZONE),
        }
    }

    pub fn hickory_zone(&self, absolute: bool) -> Result<hickory_proto::rr::Name, ProtoError> {
        hickory_proto::rr::Name::from_str(&self.zone(absolute))
    }

    pub fn into_hickory_answers_message(&self) -> Result<hickory_proto::op::Message> {
        use hickory_proto::op;
        let record = self.into_hickory_dns_record()?;
        let mut packet = op::Message::new();
        packet.answers_mut().push(record);
        Ok(packet)
    }

    pub fn into_hickory_update_message(&self) -> Result<hickory_proto::op::Message> {
        use hickory_proto::{op, rr};
        let record = self.into_hickory_dns_record()?;
        let zone = rr::Name::from_str(&self.zone(true))?;
        let message = op::update_message::create(record.into(), zone, false);
        Ok(message)
    }

    pub fn into_hickory_dns_record(&self) -> Result<hickory_proto::rr::Record> {
        use hickory_proto::rr;
        let origin = rr::Name::from_str(IROH_ROOT_ZONE)?;
        self.into_hickory_dns_record_with_origin(&origin)
    }

    pub fn into_hickory_dns_record_with_origin(
        &self,
        origin: &hickory_proto::rr::Name,
    ) -> Result<hickory_proto::rr::Record> {
        use hickory_proto::rr;
        let zone = rr::Name::from_str(&self.node_id.to_string())?;
        let zone = zone.append_domain(origin)?;
        let name = rr::Name::parse(IROH_NODE_TXT_LABEL, Some(&zone))?;
        let txt_value = self.to_attr_string();
        let txt_data = rr::rdata::TXT::new(vec![txt_value]);
        let rdata = rr::RData::TXT(txt_data);
        let record = rr::Record::from_rdata(name, DEFAULT_TTL, rdata);
        Ok(record)
    }

    pub fn into_pkarr_dns_packet(&self) -> Result<pkarr::dns::Packet<'static>> {
        use pkarr::dns::{self, rdata};
        let mut packet = dns::Packet::new_reply(0);
        // let name = format!("{}.{}", IROH_NODE_TXT_NAME, self.zone());
        let name = IROH_NODE_TXT_LABEL;
        let name = dns::Name::new(name)?.into_owned();
        let txt_value = self.to_attr_string();
        let txt_data = rdata::TXT::new().with_string(&txt_value)?.into_owned();
        let rdata = rdata::RData::TXT(txt_data);
        packet.answers.push(dns::ResourceRecord::new(
            name,
            dns::CLASS::IN,
            DEFAULT_TTL,
            rdata,
        ));
        Ok(packet)
    }

    pub fn into_pkarr_signed_packet(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<pkarr::SignedPacket> {
        // TODO: PR to pkarr for impl From<ed25519_dalek::SigningKey> for pkarr::Keypair
        let keypair = pkarr::Keypair::from_secret_key(&signing_key.to_bytes());
        let packet = self.into_pkarr_dns_packet()?;
        let signed_packet = pkarr::SignedPacket::from_packet(&keypair, &packet)?;
        Ok(signed_packet)
    }

    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        use pkarr::dns::{self, rdata::RData};
        let pubkey = packet.public_key();
        let pubkey_z32 = pubkey.to_z32();
        let node_id = NodeId::from(*pubkey.verifying_key());
        let zone = dns::Name::new(&pubkey_z32)?;
        let inner = packet.packet();
        let txt_record = inner
            .answers
            .iter()
            .find_map(|rr| match &rr.rdata {
                RData::TXT(txt) => match rr.name.without(&zone) {
                    Some(name) if name.to_string() == IROH_NODE_TXT_LABEL => Some(txt),
                    Some(_) | None => None,
                },
                _ => None,
            })
            .ok_or_else(|| anyhow!("missing _iroh_node txt record"))?;

        let txt_record = txt_record.to_owned();
        let txt = String::try_from(txt_record)?;
        let an = Self::parse_from_attributes(&txt)?;
        if an.node_id != node_id {
            bail!("node id mismatch between record name and TXT value");
        }
        Ok(an)
    }

    pub fn from_hickory_answers_message(message: &hickory_proto::op::Message) -> Result<Self> {
        Self::from_hickory_records(message.answers())
    }

    pub fn from_hickory_lookup(lookup: &hickory_resolver::lookup::Lookup) -> Result<Self> {
        Self::from_hickory_records(lookup.records())
    }

    pub fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        use hickory_proto::rr;
        let (node_id, txt) = records
            .iter()
            .find_map(|rr| match rr.data() {
                Some(rr::RData::TXT(txt)) => {
                    is_hickory_node_info_name(rr.name()).map(|node_id| (node_id, txt))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("no TXT record with name _iroh_node.b32encodedpubkey found"))?;
        let attr_str = txt.to_string();
        let an = Self::parse_from_attributes(&attr_str)?;
        if an.node_id != node_id {
            bail!("node id mismatch between record name and TXT value");
        }
        Ok(an)
    }

    pub fn parse_from_attributes(attrs: &str) -> Result<Self> {
        let attrs = parse_attrs(attrs);
        let Some(node) = attrs.get(ATTR_NODE_ID) else {
            bail!("missing required node attr");
        };
        if node.len() != 1 {
            bail!("more than one node attr is not allowed");
        }
        let node_id = NodeId::from_str(node[0])?;
        let home_derp: Option<Url> = attrs
            .get(ATTR_DERP)
            .into_iter()
            .flatten()
            .find_map(|x| Url::parse(x).ok());
        let home_dns: Vec<String> = attrs
            .get(ATTR_DNS)
            .into_iter()
            .flat_map(|x| x.iter())
            .map(|s| s.to_string())
            .collect();
        Ok(Self {
            node_id,
            home_derp,
            home_dns,
        })
    }
}

fn is_hickory_node_info_name(name: &hickory_proto::rr::Name) -> Option<NodeId> {
    if name.num_labels() < 2 {
        return None;
    }
    let mut labels = name.iter();
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    if label != IROH_NODE_TXT_LABEL {
        return None;
    }
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    let node_id = from_z32(label).ok()?;
    Some(node_id)
}

fn parse_attrs<'a>(s: &'a str) -> HashMap<&'a str, Vec<&'a str>> {
    let mut map: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
    let parts = s.split(' ');
    for part in parts {
        if let Some((name, value)) = part.split_once('=') {
            map.entry(name).or_default().push(value);
        }
    }
    map
}

fn fmt_attr(label: &str, value: impl Display) -> String {
    format!("{label}={value}")
}

// fn simple_dns_to_hickory(
//     signed_packet: &pkarr::SignedPacket,
// ) -> anyhow::Result<hickory_proto::op::Message> {
//     let encoded = signed_packet.encoded_packet();
//     let parsed1 = pkarr::dns::Packet::parse(&encoded)?;
//     println!("simple_dns {parsed1:#?}");
//     let parsed2 = hickory_proto::op::Message::from_bytes(&encoded)?;
//     println!("hickory {parsed2:#?}");
//     Ok(parsed2)
// }

#[cfg(test)]
mod tests {
    // TODO: The tests are not comprehensive in any way, more like examples while getting things to
    // work

    use std::str::FromStr;

    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use url::Url;

    use super::*;

    #[test]
    fn create_signed_packet() -> Result<()> {
        let signing_key = iroh_net::key::SecretKey::generate();
        let node_id = signing_key.public();
        let home_derp: Url = "https://derp.example/".parse()?;
        let an = NodeAnnounce {
            node_id,
            home_derp: Some(home_derp),
            home_dns: vec![],
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key.to_bytes());
        let sp = an.into_pkarr_signed_packet(&signing_key)?;
        println!("sp {sp:#?}");
        println!("packet {:#?}", sp.packet());
        let an2 = NodeAnnounce::from_pkarr_signed_packet(&sp)?;
        assert_eq!(an, an2);
        let _p = an.into_hickory_answers_message()?;
        Ok(())
    }

    #[test]
    fn convert2() -> anyhow::Result<()> {
        let key = iroh_net::key::SecretKey::generate();
        let node_id = key.public();
        let home_derp: Url = "https://derp.example".parse()?;
        let a = NodeAnnounce {
            node_id,
            home_derp: Some(home_derp),
            home_dns: Default::default(),
        };
        let packet_simpdns = a.into_hickory_answers_message()?;
        let packet_hickory = a.into_hickory_answers_message()?;
        let buf_simpdns = packet_simpdns.to_bytes()?;
        let buf_hickory = packet_hickory.to_bytes()?;
        println!(
            "simple_dns {} {}",
            buf_simpdns.len(),
            hex::encode(&buf_simpdns)
        );
        println!(
            "hickory    {} {}",
            buf_hickory.len(),
            hex::encode(&buf_hickory)
        );
        let _simpdns_from_hickory = pkarr::dns::Packet::parse(&buf_hickory)?;
        let _hickory_form_simpdns = hickory_proto::op::Message::from_bytes(&buf_simpdns)?;

        Ok(())
    }

    #[test]
    fn convert3() -> anyhow::Result<()> {
        use hickory_proto as proto;
        use pkarr::dns;
        let ttl = 300;
        let (packet1, bytes1) = {
            use dns::rdata;
            let mut packet = dns::Packet::new_reply(0);
            let name = dns::Name::new("foo")?;
            let rdata = rdata::RData::TXT(rdata::TXT::new().with_string("bar")?);
            let record = dns::ResourceRecord::new(name, dns::CLASS::IN, ttl, rdata);
            packet.answers.push(record);
            let bytes = packet.build_bytes_vec()?;
            (packet, bytes)
        };
        let (packet2, bytes2) = {
            use proto::rr;
            use proto::serialize::binary::BinEncodable;
            let mut packet = proto::op::Message::new();
            let name = rr::Name::from_str("foo")?;
            let rdata = rr::RData::TXT(rr::rdata::TXT::new(vec!["bar".to_string()]));
            let mut record = rr::Record::with(name, rr::RecordType::TXT, ttl);
            record.set_data(Some(rdata));
            packet.answers_mut().push(record);
            let bytes = packet.to_bytes()?;
            (packet, bytes)
        };
        println!("simple_dns deb {:#?}", packet1);
        println!("hickory    deb {:#?}", packet2);
        println!("simple_dns len {}", bytes1.len());
        println!("hickory    len {}", bytes2.len());
        println!("simple_dns hex {}", hex::encode(&bytes1));
        println!("hickory    hex {}", hex::encode(&bytes2));

        Ok(())
    }
}
