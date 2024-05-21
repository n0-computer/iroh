//! Support for handling DNS resource records for dialing by [`NodeId`].
//!
//! Dialing by [`NodeId`] is supported by iroh nodes publishing [Pkarr] records to DNS
//! servers or the Mainline DHT.  This module supports creating and parsing these records.
//!
//! DNS records are published under the following names:
//!
//! `_iroh.<z32-node-id>.<origin-domain> TXT`
//!
//! - `_iroh` is the record name as defined by [`IROH_TXT_NAME`].
//!
//! - `<z32-node-id>` is the [z-base-32] encoding of the [`NodeId`].
//!
//! - `<origin-domain>` is the domain name of the publishing DNS server,
//!   [`N0_DNS_NODE_ORIGIN`] is the server operated by number0.
//!
//! - `TXT` is the DNS record type.
//!
//! The returned TXT records must contain a string value of the form `key=value` as defined
//! in [RFC1464].  The following attributes are defined:
//!
//! - `relay=<url>`: The home [`RelayUrl`] of this node.
//!
//! - `addr=<addr> <addr>`: A space-separated list of sockets addresses for this iroh node.
//!   Each address is an IPv4 or IPv6 address with a port.
//!
//! [Pkarr]: https://app.pkarr.org
//! [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
//! [RFC1464]: https://www.rfc-editor.org/rfc/rfc1464
//! [`RelayUrl`]: iroh_base::node_addr::RelayUrl
//! [`N0_DNS_NODE_ORIGIN`]: crate::discovery::dns::N0_DNS_NODE_ORIGIN

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    hash::Hash,
    net::SocketAddr,
    str::FromStr,
};

use anyhow::{anyhow, ensure, Result};
use hickory_proto::error::ProtoError;
use hickory_resolver::{Name, TokioAsyncResolver};
use url::Url;

use crate::{key::SecretKey, AddrInfo, NodeAddr, NodeId};

/// The DNS name for the iroh TXT record.
pub const IROH_TXT_NAME: &str = "_iroh";

/// The attributes supported by iroh for [`IROH_TXT_NAME`] DNS resource records.
///
/// The resource record uses the lower-case names.
#[derive(
    Debug, strum::Display, strum::AsRefStr, strum::EnumString, Hash, Eq, PartialEq, Ord, PartialOrd,
)]
#[strum(serialize_all = "kebab-case")]
pub enum IrohAttr {
    /// URL of home relay.
    Relay,
    /// Direct address.
    Addr,
}

/// Encodes a [`NodeId`] in [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn to_z32(node_id: &NodeId) -> String {
    z32::encode(node_id.as_bytes())
}

/// Parses a [`NodeId`] from [`z-base-32`] encoding.
///
/// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
pub fn from_z32(s: &str) -> Result<NodeId> {
    let bytes = z32::decode(s.as_bytes()).map_err(|_| anyhow!("invalid z32"))?;
    let bytes: &[u8; 32] = &bytes.try_into().map_err(|_| anyhow!("not 32 bytes long"))?;
    let node_id = NodeId::from_bytes(bytes)?;
    Ok(node_id)
}

/// Information about the iroh node contained in an [`IROH_TXT_NAME`] TXT resource record.
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct NodeInfo {
    /// The [`NodeId`].
    pub node_id: NodeId,
    /// The advertised home relay server.
    #[debug("{:?}", self.relay_url.as_ref().map(|s| s.to_string()))]
    pub relay_url: Option<Url>,
    /// Any direct addresses.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl From<TxtAttrs<IrohAttr>> for NodeInfo {
    fn from(attrs: TxtAttrs<IrohAttr>) -> Self {
        (&attrs).into()
    }
}

impl From<&TxtAttrs<IrohAttr>> for NodeInfo {
    fn from(attrs: &TxtAttrs<IrohAttr>) -> Self {
        let node_id = attrs.node_id();
        let attrs = attrs.attrs();
        let relay_url = attrs
            .get(&IrohAttr::Relay)
            .into_iter()
            .flatten()
            .next()
            .and_then(|s| Url::parse(s).ok());
        let direct_addresses = attrs
            .get(&IrohAttr::Addr)
            .into_iter()
            .flatten()
            .filter_map(|s| SocketAddr::from_str(s).ok())
            .collect();
        Self {
            node_id,
            relay_url,
            direct_addresses,
        }
    }
}

impl From<&NodeInfo> for TxtAttrs<IrohAttr> {
    fn from(info: &NodeInfo) -> Self {
        let mut attrs = vec![];
        if let Some(relay_url) = &info.relay_url {
            attrs.push((IrohAttr::Relay, relay_url.to_string()));
        }
        for addr in &info.direct_addresses {
            attrs.push((IrohAttr::Addr, addr.to_string()));
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
            direct_addresses: value.direct_addresses,
        }
    }
}

impl NodeInfo {
    /// Creates a new [`NodeInfo`] from its parts.
    pub fn new(
        node_id: NodeId,
        relay_url: Option<Url>,
        direct_addresses: BTreeSet<SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            relay_url,
            direct_addresses,
        }
    }

    fn to_attrs(&self) -> TxtAttrs<IrohAttr> {
        self.into()
    }

    /// Parses a [`NodeInfo`] from a set of DNS records.
    pub fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        let attrs = TxtAttrs::from_hickory_records(records)?;
        Ok(attrs.into())
    }

    /// Parses a [`NodeInfo`] from a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
        let attrs = TxtAttrs::from_pkarr_signed_packet(packet)?;
        Ok(attrs.into())
    }

    /// Creates a [`pkarr::SignedPacket`].
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket> {
        self.to_attrs().to_pkarr_signed_packet(secret_key, ttl)
    }

    /// Converts into a [`hickory_proto::rr::Record`] DNS record.
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

/// Parses a [`NodeId`] from iroh DNS name.
///
/// Takes a [`hickory_proto::rr::Name`] DNS name and expects the first label to be
/// [`IROH_TXT_NAME`] and the second label to be a z32 encoded [`NodeId`]. Ignores
/// subsequent labels.
pub(crate) fn node_id_from_hickory_name(name: &hickory_proto::rr::Name) -> Option<NodeId> {
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

/// Attributes parsed from [`IROH_TXT_NAME`] TXT records.
///
/// This struct is generic over the key type. When using with [`String`], this will parse
/// all attributes. Can also be used with an enum, if it implements [`FromStr`] and
/// [`Display`].
#[derive(Debug)]
pub struct TxtAttrs<T> {
    node_id: NodeId,
    attrs: BTreeMap<T, Vec<String>>,
}

impl<T: FromStr + Display + Hash + Ord> TxtAttrs<T> {
    /// Creates [`TxtAttrs`] from a node id and an iterator of key-value pairs.
    pub fn from_parts(node_id: NodeId, pairs: impl Iterator<Item = (T, String)>) -> Self {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, node_id }
    }

    /// Creates [`TxtAttrs`] from a node id and an iterator of "{key}={value}" strings.
    pub fn from_strings(node_id: NodeId, strings: impl Iterator<Item = String>) -> Result<Self> {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for s in strings {
            let mut parts = s.split('=');
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Ok(attr) = T::from_str(key) else {
                continue;
            };
            attrs.entry(attr).or_default().push(value.to_string());
        }
        Ok(Self { attrs, node_id })
    }

    async fn lookup(resolver: &TokioAsyncResolver, name: Name) -> Result<Self> {
        let name = ensure_iroh_txt_label(name)?;
        let lookup = resolver.txt_lookup(name).await?;
        let attrs = Self::from_hickory_records(lookup.as_lookup().records())?;
        Ok(attrs)
    }

    /// Looks up attributes by [`NodeId`] and origin domain.
    pub async fn lookup_by_id(
        resolver: &TokioAsyncResolver,
        node_id: &NodeId,
        origin: &str,
    ) -> Result<Self> {
        let name = node_domain(node_id, origin)?;
        TxtAttrs::lookup(resolver, name).await
    }

    /// Looks up attributes by DNS name.
    pub async fn lookup_by_name(resolver: &TokioAsyncResolver, name: &str) -> Result<Self> {
        let name = Name::from_str(name)?;
        TxtAttrs::lookup(resolver, name).await
    }

    /// Returns the parsed attributes.
    pub fn attrs(&self) -> &BTreeMap<T, Vec<String>> {
        &self.attrs
    }

    /// Returns the node id.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Parses a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self> {
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

    /// Parses a set of DNS resource records.
    pub fn from_hickory_records(records: &[hickory_proto::rr::Record]) -> Result<Self> {
        use hickory_proto::rr;
        let mut records = records.iter().filter_map(|rr| match rr.data() {
            Some(rr::RData::TXT(txt)) => {
                node_id_from_hickory_name(rr.name()).map(|node_id| (node_id, txt))
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

    /// Converts to a list of [`hickory_proto::rr::Record`] resource records.
    pub fn to_hickory_records(
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

    /// Creates a [`pkarr::SignedPacket`]
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
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

fn ensure_iroh_txt_label(name: Name) -> Result<Name, ProtoError> {
    if name.iter().next() == Some(IROH_TXT_NAME.as_bytes()) {
        Ok(name)
    } else {
        Name::parse(IROH_TXT_NAME, Some(&name))
    }
}

fn node_domain(node_id: &NodeId, origin: &str) -> Result<Name> {
    let domain = format!("{}.{}", to_z32(node_id), origin);
    let domain = Name::from_str(&domain)?;
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use iroh_base::key::SecretKey;
    use std::str::FromStr;

    use super::NodeInfo;

    #[test]
    fn txt_attr_roundtrip() {
        let expected = NodeInfo {
            node_id: "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
                .parse()
                .unwrap(),
            relay_url: Some("https://example.com".parse().unwrap()),
            direct_addresses: ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        };
        let attrs = expected.to_attrs();
        let actual = NodeInfo::from(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip() {
        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();
        let expected = NodeInfo {
            node_id: secret_key.public(),
            relay_url: Some("https://example.com".parse().unwrap()),
            direct_addresses: ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        };
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = NodeInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }
}
