//! This module contains functions and structs to lookup node information from DNS
//! and to encode node information in Pkarr signed packets.

use std::{collections::HashMap, fmt, str::FromStr};

use anyhow::{anyhow, bail, Result};
use hickory_proto::error::ProtoError;
use hickory_resolver::Name;
use url::Url;

use crate::{key::SecretKey, AddrInfo, NodeAddr, NodeId};

const ATTR_DERP: &str = "derp";
const ATTR_NODE_ID: &str = "node";

/// The label for the node info TXT record
pub const IROH_NODE_TXT_LABEL: &str = "_iroh_node";

/// Lookup node info by domain name
///
/// The domain name must either contain an _iroh_node TXT record or be a CNAME record that leads to
/// an _iroh_node TXT record.
pub async fn lookup_by_domain(domain: &str) -> Result<NodeAddr> {
    let name = Name::from_str(domain)?;
    let info = lookup_node_info(name).await?;
    Ok(info.into())
}

/// Lookup node info by node id and origin domain name.
pub async fn lookup_by_id(node_id: &NodeId, origin: &str) -> Result<NodeAddr> {
    let domain = format!("{}.{}", to_z32(node_id), origin);
    lookup_by_domain(&domain).await
}

async fn lookup_node_info(name: Name) -> Result<NodeInfo> {
    let name = ensure_iroh_node_txt_label(name)?;
    let lookup = super::resolver().txt_lookup(name).await?;
    NodeInfo::from_hickory_lookup(lookup.as_lookup())
}

fn ensure_iroh_node_txt_label(name: Name) -> Result<Name, ProtoError> {
    if name.iter().next() == Some(IROH_NODE_TXT_LABEL.as_bytes()) {
        Ok(name)
    } else {
        Name::parse(IROH_NODE_TXT_LABEL, Some(&name))
    }
}

/// Encode a [`NodeId`] in [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn to_z32(node_id: &NodeId) -> String {
    z32::encode(node_id.as_bytes())
}

/// Parse a [`NodeId`] from [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn from_z32(s: &str) -> Result<NodeId> {
    let bytes = z32::decode(s.as_bytes()).map_err(|_| anyhow!("invalid z32"))?;
    let bytes: &[u8; 32] = &bytes.try_into().map_err(|_| anyhow!("not 32 bytes long"))?;
    let node_id = NodeId::from_bytes(bytes)?;
    Ok(node_id)
}

/// Node info contained in a DNS _iroh_node TXT record.
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct NodeInfo {
    /// The node id
    pub node_id: NodeId,
    /// Home Derp server for this node
    #[debug("{:?}", self.derp_url.as_ref().map(|s| s.to_string()))]
    pub derp_url: Option<Url>,
}

impl From<NodeInfo> for NodeAddr {
    fn from(value: NodeInfo) -> Self {
        NodeAddr {
            node_id: value.node_id,
            info: value.into(),
        }
    }
}

impl From<NodeInfo> for AddrInfo {
    fn from(value: NodeInfo) -> Self {
        AddrInfo {
            derp_url: value.derp_url.map(|u| u.into()),
            direct_addresses: Default::default(),
        }
    }
}

impl NodeInfo {
    /// Create a new [`NodeInfo`] from its parts.
    pub fn new(node_id: NodeId, derp_url: Option<Url>) -> Self {
        Self { node_id, derp_url }
    }

    /// Convert this node info into a DNS attribute string.
    ///
    /// It will look like this:
    /// `node=b32encodednodeid derp=https://myderp.example`
    pub fn to_attribute_string(&self) -> String {
        let mut attrs = vec![];
        attrs.push(fmt_attr(ATTR_NODE_ID, self.node_id));
        if let Some(derp) = &self.derp_url {
            attrs.push(fmt_attr(ATTR_DERP, derp));
        }
        attrs.join(" ")
    }

    /// Try to parse a [`NodeInfo`] from the lookup result of our DNS resolver.
    pub fn from_hickory_lookup(lookup: &hickory_resolver::lookup::Lookup) -> Result<Self> {
        Self::from_hickory_records(lookup.records())
    }

    /// Try to parse a [`NodeInfo`] from a set of DNS records.
    pub fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        use hickory_proto::rr;
        let (node_id, txt) = records
            .iter()
            .find_map(|rr| match rr.data() {
                Some(rr::RData::TXT(txt)) => {
                    parse_hickory_node_info_name(rr.name()).map(|node_id| (node_id, txt))
                }
                _ => None,
            })
            .ok_or_else(|| anyhow!("no TXT record with name _iroh_node.b32encodedpubkey found"))?;
        let node_info = Self::parse_from_attributes(&txt.to_string())?;
        if node_info.node_id != node_id {
            bail!("node id mismatch between record name and TXT value");
        }
        Ok(node_info)
    }

    /// Parse the [`NodeInfo`] from an attribute string.
    ///
    /// See [Self::to_attribute_string] for the expected format.
    pub fn parse_from_attributes(attrs: &str) -> Result<Self> {
        let attrs = parse_attrs(attrs);
        let Some(node) = attrs.get(ATTR_NODE_ID) else {
            bail!("missing required node attribute");
        };
        if node.len() != 1 {
            bail!("more than one node attribute is not allowed");
        }
        let node_id = NodeId::from_str(node[0])?;
        let home_derp: Option<Url> = attrs
            .get(ATTR_DERP)
            .into_iter()
            .flatten()
            .find_map(|x| Url::parse(x).ok());
        Ok(Self {
            node_id,
            derp_url: home_derp,
        })
    }

    /// Create a [`pkarr::SignedPacket`] by constructing a DNS packet and
    /// signing it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket> {
        let packet = self.to_pkarr_dns_packet(ttl)?;
        let keypair = pkarr::Keypair::from_secret_key(&secret_key.to_bytes());
        let signed_packet = pkarr::SignedPacket::from_packet(&keypair, &packet)?;
        Ok(signed_packet)
    }

    fn to_pkarr_dns_packet(&self, ttl: u32) -> Result<pkarr::dns::Packet<'static>> {
        use pkarr::dns::{self, rdata};
        let name = dns::Name::new(IROH_NODE_TXT_LABEL)?.into_owned();
        let rdata = {
            let value = self.to_attribute_string();
            let txt = rdata::TXT::new().with_string(&value)?.into_owned();
            rdata::RData::TXT(txt)
        };

        let mut packet = dns::Packet::new_reply(0);
        packet
            .answers
            .push(dns::ResourceRecord::new(name, dns::CLASS::IN, ttl, rdata));
        Ok(packet)
    }

    /// Try to parse a [`NodeInfo`] from a [`pkarr::SignedPacket`].
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
        let info = Self::parse_from_attributes(&txt)?;
        if info.node_id != node_id {
            bail!("node id mismatch between record name and TXT value");
        }
        Ok(info)
    }
}

fn parse_hickory_node_info_name(name: &hickory_proto::rr::Name) -> Option<NodeId> {
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

fn fmt_attr(label: &str, value: impl fmt::Display) -> String {
    format!("{label}={value}")
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
