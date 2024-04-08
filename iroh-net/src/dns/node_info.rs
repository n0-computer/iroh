//! This module contains functions and structs to lookup node information from DNS
//! and to encode node information in Pkarr signed packets.

use std::{collections::BTreeMap, str::FromStr};

use anyhow::{anyhow, ensure, Result};
use hickory_proto::error::ProtoError;
use hickory_resolver::{Name, TokioAsyncResolver};
use url::Url;

use crate::{key::SecretKey, AddrInfo, NodeAddr, NodeId};

/// The DNS name for the iroh TXT record
pub const IROH_TXT_NAME: &str = "_iroh";

/// The attributes supported for `_iroh` DNS records
#[derive(
    Debug, strum::Display, strum::AsRefStr, strum::EnumString, Hash, Eq, PartialEq, Ord, PartialOrd,
)]
#[strum(serialize_all = "kebab-case")]
pub enum IrohAttr {
    /// `relay`: URL of home relay
    Relay,
}

/// Lookup node info by domain name
///
/// The domain name must either contain an _iroh TXT record or be a CNAME record that leads to
/// an _iroh TXT record.
pub async fn lookup_by_domain(resolver: &TokioAsyncResolver, domain: &str) -> Result<NodeAddr> {
    let name = Name::from_str(domain)?;
    let info = lookup_node_info(resolver, name).await?;
    Ok(info.into())
}

/// Lookup node info by node id and origin domain name.
pub async fn lookup_by_id(
    resolver: &TokioAsyncResolver,
    node_id: &NodeId,
    origin: &str,
) -> Result<NodeAddr> {
    let domain = format!("{}.{}", to_z32(node_id), origin);
    lookup_by_domain(resolver, &domain).await
}

async fn lookup_node_info(resolver: &TokioAsyncResolver, name: Name) -> Result<NodeInfo> {
    let name = ensure_iroh_node_txt_label(name)?;
    let lookup = resolver.txt_lookup(name).await?;
    NodeInfo::from_hickory_records(lookup.as_lookup().records())
}

fn ensure_iroh_node_txt_label(name: Name) -> Result<Name, ProtoError> {
    if name.iter().next() == Some(IROH_TXT_NAME.as_bytes()) {
        Ok(name)
    } else {
        Name::parse(IROH_TXT_NAME, Some(&name))
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
    /// Home relay server for this node
    #[debug("{:?}", self.relay_url.as_ref().map(|s| s.to_string()))]
    pub relay_url: Option<Url>,
}

impl From<NodeAttrs> for NodeInfo {
    fn from(attrs: NodeAttrs) -> Self {
        (&attrs).into()
    }
}

impl From<&NodeAttrs> for NodeInfo {
    fn from(attrs: &NodeAttrs) -> Self {
        let node_id = attrs.node_id();
        let attrs = attrs.attrs();
        let relay_url = attrs
            .get(&IrohAttr::Relay)
            .into_iter()
            .flatten()
            .next()
            .and_then(|s| Url::parse(s).ok());
        Self { node_id, relay_url }
    }
}

impl From<&NodeInfo> for NodeAttrs {
    fn from(info: &NodeInfo) -> Self {
        let mut attrs = vec![];
        if let Some(relay_url) = &info.relay_url {
            attrs.push((IrohAttr::Relay, relay_url.to_string()));
        }
        Self::from_parts(info.node_id, attrs.into_iter())
    }
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
            relay_url: value.relay_url.map(|u| u.into()),
            direct_addresses: Default::default(),
        }
    }
}

impl NodeInfo {
    /// Create a new [`NodeInfo`] from its parts.
    pub fn new(node_id: NodeId, relay_url: Option<Url>) -> Self {
        Self { node_id, relay_url }
    }

    fn to_attrs(&self) -> NodeAttrs {
        self.into()
    }

    /// Try to parse a [`NodeInfo`] from a set of DNS records.
    pub fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        let attrs = NodeAttrs::from_hickory_records(records)?;
        Ok(attrs.into())
    }

    /// Try to parse a [`NodeInfo`] from a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        let attrs = NodeAttrs::from_pkarr_signed_packet(packet)?;
        Ok(attrs.into())
    }

    /// Create a [`pkarr::SignedPacket`] by constructing a DNS packet and
    /// signing it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket> {
        self.to_attrs().to_pkarr_signed_packet(secret_key, ttl)
    }

    /// Convert into a [`hickory_proto::rr::Record`] DNS record.
    pub fn to_hickory_records(
        &self,
        origin: &str,
        ttl: u32,
    ) -> Result<impl Iterator<Item = hickory_proto::rr::Record> + 'static> {
        let attrs = self.to_attrs();
        let records = attrs.to_hickory_records(origin, ttl)?;
        Ok(records.collect::<Vec<_>>().into_iter())
    }
}

pub(crate) fn parse_hickory_node_info_name(name: &hickory_proto::rr::Name) -> Option<NodeId> {
    if name.num_labels() < 2 {
        return None;
    }
    let mut labels = name.iter();
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    if label != IROH_TXT_NAME {
        return None;
    }
    let label = std::str::from_utf8(labels.next().expect("num_labels checked")).ok()?;
    let node_id = from_z32(label).ok()?;
    Some(node_id)
}

struct NodeAttrs {
    node_id: NodeId,
    attrs: BTreeMap<IrohAttr, Vec<String>>,
}

impl NodeAttrs {
    fn from_parts(node_id: NodeId, pairs: impl Iterator<Item = (IrohAttr, String)>) -> Self {
        let mut attrs: BTreeMap<IrohAttr, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, node_id }
    }

    fn from_strings(node_id: NodeId, strings: impl Iterator<Item = String>) -> Result<Self> {
        let mut attrs: BTreeMap<IrohAttr, Vec<String>> = BTreeMap::new();
        for s in strings {
            let mut parts = s.split('=');
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(attr) = IrohAttr::from_str(key) else {
                continue;
            };
            attrs.entry(attr).or_default().push(value.to_string());
        }
        Ok(Self { attrs, node_id })
    }

    fn attrs(&self) -> &BTreeMap<IrohAttr, Vec<String>> {
        &self.attrs
    }

    fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Try to parse a [`NodeInfo`] from a [`pkarr::SignedPacket`].
    fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        use pkarr::dns::{self, rdata::RData};
        let pubkey = packet.public_key();
        let pubkey_z32 = pubkey.to_z32();
        let node_id = NodeId::from(*pubkey.verifying_key());
        let zone = dns::Name::new(&pubkey_z32)?;
        let inner = packet.packet();
        let txt_data = inner.answers.iter().filter_map(|rr| match &rr.rdata {
            RData::TXT(txt) => match rr.name.without(&zone) {
                Some(name) if name.to_string() == IROH_TXT_NAME => Some(txt),
                Some(_) | None => None,
            },
            _ => None,
        });

        let txt_strs = txt_data.filter_map(|s| String::try_from(s.clone()).ok());
        Self::from_strings(node_id, txt_strs)
    }

    /// Try to parse a [`NodeInfo`] from a set of DNS records.
    fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        use hickory_proto::rr;
        let mut records = records.iter().filter_map(|rr| match rr.data() {
            Some(rr::RData::TXT(txt)) => {
                parse_hickory_node_info_name(rr.name()).map(|node_id| (node_id, txt))
            }
            _ => None,
        });
        let (node_id, first) = records.next().ok_or_else(|| {
            anyhow!("invalid DNS answer: no TXT record with name _iroh.z32encodedpubkey found")
        })?;
        ensure!(
            &records.all(|(n, _)| n == node_id),
            "invalid DNS answer: all _iroh txt records must belong to the same node domain"
        );
        let records = records.map(|(_, txt)| txt).chain(Some(first));
        let strings = records.map(ToString::to_string);
        Self::from_strings(node_id, strings)
    }

    fn to_txt_strings(&self) -> impl Iterator<Item = String> + '_ {
        self.attrs
            .iter()
            .flat_map(move |(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
    }

    /// Convert into list of [`hickory_proto::rr::Record`].
    fn to_hickory_records(
        &self,
        origin: &str,
        ttl: u32,
    ) -> Result<impl Iterator<Item = hickory_proto::rr::Record> + '_> {
        use hickory_proto::rr;
        let name = format!("{}.{}.{}", IROH_TXT_NAME, to_z32(&self.node_id), origin);
        let name = rr::Name::from_utf8(name)?;
        let records = self.to_txt_strings().map(move |s| {
            let txt = rr::rdata::TXT::new(vec![s]);
            let rdata = rr::RData::TXT(txt);
            rr::Record::from_rdata(name.clone(), ttl, rdata)
        });
        Ok(records)
    }

    /// Create a [`pkarr::SignedPacket`] by constructing a DNS packet and
    /// signing it with a [`SecretKey`].
    fn to_pkarr_signed_packet(
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
        let name = dns::Name::new(IROH_TXT_NAME)?.into_owned();

        let mut packet = dns::Packet::new_reply(0);
        for s in self.to_txt_strings() {
            let mut txt = rdata::TXT::new();
            txt.add_string(&s)?;
            let rdata = rdata::RData::TXT(txt.into_owned());
            packet.answers.push(dns::ResourceRecord::new(
                name.clone(),
                dns::CLASS::IN,
                ttl,
                rdata,
            ));
        }
        Ok(packet)
    }
}
