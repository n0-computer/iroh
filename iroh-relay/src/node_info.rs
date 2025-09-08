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
//!   [`N0_DNS_NODE_ORIGIN_PROD`] is the server operated by number0 for production.
//!   [`N0_DNS_NODE_ORIGIN_STAGING`] is the server operated by number0 for testing.
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
//! [`RelayUrl`]: iroh_base::RelayUrl
//! [`N0_DNS_NODE_ORIGIN_PROD`]: crate::dns::N0_DNS_NODE_ORIGIN_PROD
//! [`N0_DNS_NODE_ORIGIN_STAGING`]: crate::dns::N0_DNS_NODE_ORIGIN_STAGING

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    hash::Hash,
    net::SocketAddr,
    str::{FromStr, Utf8Error},
};

#[cfg(not(wasm_browser))]
use hickory_resolver::{Name, proto::ProtoError};
use iroh_base::{NodeAddr, NodeId, RelayUrl, SecretKey, SignatureError};
use nested_enum_utils::common_fields;
use snafu::{Backtrace, ResultExt, Snafu};
#[cfg(not(wasm_browser))]
use tracing::warn;
use url::Url;

#[cfg(not(wasm_browser))]
use crate::{
    defaults::timeouts::DNS_TIMEOUT,
    dns::{DnsError, DnsResolver},
};

/// The DNS name for the iroh TXT record.
pub const IROH_TXT_NAME: &str = "_iroh";

#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum EncodingError {
    #[snafu(transparent)]
    FailedBuildingPacket {
        source: pkarr::errors::SignedPacketBuildError,
    },
    #[snafu(display("invalid TXT entry"))]
    InvalidTxtEntry { source: pkarr::dns::SimpleDnsError },
}

#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum DecodingError {
    #[snafu(display("node id was not encoded in valid z32"))]
    InvalidEncodingZ32 { source: z32::Z32Error },
    #[snafu(display("length must be 32 bytes, but got {len} byte(s)"))]
    InvalidLength { len: usize },
    #[snafu(display("node id is not a valid public key"))]
    InvalidSignature { source: SignatureError },
}

/// Extension methods for [`NodeId`] to encode to and decode from [`z32`],
/// which is the encoding used in [`pkarr`] domain names.
pub trait NodeIdExt {
    /// Encodes a [`NodeId`] in [`z-base-32`] encoding.
    ///
    /// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    fn to_z32(&self) -> String;

    /// Parses a [`NodeId`] from [`z-base-32`] encoding.
    ///
    /// [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    fn from_z32(s: &str) -> Result<NodeId, DecodingError>;
}

impl NodeIdExt for NodeId {
    fn to_z32(&self) -> String {
        z32::encode(self.as_bytes())
    }

    fn from_z32(s: &str) -> Result<NodeId, DecodingError> {
        let bytes = z32::decode(s.as_bytes()).context(InvalidEncodingZ32Snafu)?;
        let bytes: &[u8; 32] = &bytes
            .try_into()
            .map_err(|_| InvalidLengthSnafu { len: s.len() }.build())?;
        let node_id = NodeId::from_bytes(bytes).context(InvalidSignatureSnafu)?;
        Ok(node_id)
    }
}

/// Data about a node that may be published to and resolved from discovery services.
///
/// This includes an optional [`RelayUrl`], a set of direct addresses, and the optional
/// [`UserData`], a string that can be set by applications and is not parsed or used by iroh
/// itself.
///
/// This struct does not include the node's [`NodeId`], only the data *about* a certain
/// node. See [`NodeInfo`] for a struct that contains a [`NodeId`] with associated [`NodeData`].
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct NodeData {
    /// URL of the home relay of this node.
    relay_url: Option<RelayUrl>,
    /// Direct addresses where this node can be reached.
    direct_addresses: BTreeSet<SocketAddr>,
    /// Optional user-defined [`UserData`] for this node.
    user_data: Option<UserData>,
}

impl NodeData {
    /// Creates a new [`NodeData`] with a relay URL and a set of direct addresses.
    pub fn new(relay_url: Option<RelayUrl>, direct_addresses: BTreeSet<SocketAddr>) -> Self {
        Self {
            relay_url,
            direct_addresses,
            user_data: None,
        }
    }

    /// Sets the relay URL and returns the updated node data.
    pub fn with_relay_url(mut self, relay_url: Option<RelayUrl>) -> Self {
        self.relay_url = relay_url;
        self
    }

    /// Sets the direct addresses and returns the updated node data.
    pub fn with_direct_addresses(mut self, direct_addresses: BTreeSet<SocketAddr>) -> Self {
        self.direct_addresses = direct_addresses;
        self
    }

    /// Sets the user-defined data and returns the updated node data.
    pub fn with_user_data(mut self, user_data: Option<UserData>) -> Self {
        self.user_data = user_data;
        self
    }

    /// Returns the relay URL of the node.
    pub fn relay_url(&self) -> Option<&RelayUrl> {
        self.relay_url.as_ref()
    }

    /// Returns the optional user-defined data of the node.
    pub fn user_data(&self) -> Option<&UserData> {
        self.user_data.as_ref()
    }

    /// Returns the direct addresses of the node.
    pub fn direct_addresses(&self) -> &BTreeSet<SocketAddr> {
        &self.direct_addresses
    }

    /// Removes all direct addresses from the node data.
    pub fn clear_direct_addresses(&mut self) {
        self.direct_addresses = Default::default();
    }

    /// Adds direct addresses to the node data.
    pub fn add_direct_addresses(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        self.direct_addresses.extend(addrs)
    }

    /// Sets the relay URL of the node data.
    pub fn set_relay_url(&mut self, relay_url: Option<RelayUrl>) {
        self.relay_url = relay_url
    }

    /// Sets the user-defined data of the node data.
    pub fn set_user_data(&mut self, user_data: Option<UserData>) {
        self.user_data = user_data;
    }
}

impl From<NodeAddr> for NodeData {
    fn from(node_addr: NodeAddr) -> Self {
        Self {
            relay_url: node_addr.relay_url,
            direct_addresses: node_addr.direct_addresses,
            user_data: None,
        }
    }
}

// User-defined data that can be published and resolved through node discovery.
///
/// Under the hood this is a UTF-8 String is no longer than [`UserData::MAX_LENGTH`] bytes.
///
/// Iroh does not keep track of or examine the user-defined data.
///
/// `UserData` implements [`FromStr`] and [`TryFrom<String>`], so you can
/// convert `&str` and `String` into `UserData` easily.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserData(pub String);

impl UserData {
    /// The max byte length allowed for user-defined data.
    ///
    /// In DNS discovery services, the user-defined data is stored in a TXT record character string,
    /// which has a max length of 255 bytes. We need to subtract the `user-data=` prefix,
    /// which leaves 245 bytes for the actual user-defined data.
    pub const MAX_LENGTH: usize = 245;
}

/// Error returned when an input value is too long for [`UserData`].
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
pub struct MaxLengthExceededError {
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
}

impl TryFrom<String> for UserData {
    type Error = MaxLengthExceededError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        snafu::ensure!(value.len() <= Self::MAX_LENGTH, MaxLengthExceededSnafu);
        Ok(Self(value))
    }
}

impl FromStr for UserData {
    type Err = MaxLengthExceededError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        snafu::ensure!(s.len() <= Self::MAX_LENGTH, MaxLengthExceededSnafu);
        Ok(Self(s.to_string()))
    }
}

impl fmt::Display for UserData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for UserData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Information about a node that may be published to and resolved from discovery services.
///
/// This struct couples a [`NodeId`] with its associated [`NodeData`].
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct NodeInfo {
    /// The [`NodeId`] of the node this is about.
    pub node_id: NodeId,
    /// The information published about the node.
    pub data: NodeData,
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
        let user_data = attrs
            .get(&IrohAttr::UserData)
            .into_iter()
            .flatten()
            .next()
            .and_then(|s| UserData::from_str(s).ok());
        let data = NodeData {
            relay_url: relay_url.map(Into::into),
            direct_addresses,
            user_data,
        };
        Self { node_id, data }
    }
}

impl From<NodeInfo> for NodeAddr {
    fn from(value: NodeInfo) -> Self {
        value.into_node_addr()
    }
}

impl From<NodeAddr> for NodeInfo {
    fn from(addr: NodeAddr) -> Self {
        Self::new(addr.node_id)
            .with_relay_url(addr.relay_url)
            .with_direct_addresses(addr.direct_addresses)
    }
}

impl NodeInfo {
    /// Creates a new [`NodeInfo`] with an empty [`NodeData`].
    pub fn new(node_id: NodeId) -> Self {
        Self::from_parts(node_id, Default::default())
    }

    /// Creates a new [`NodeInfo`] from its parts.
    pub fn from_parts(node_id: NodeId, data: NodeData) -> Self {
        Self { node_id, data }
    }

    /// Sets the relay URL and returns the updated node info.
    pub fn with_relay_url(mut self, relay_url: Option<RelayUrl>) -> Self {
        self.data = self.data.with_relay_url(relay_url);
        self
    }

    /// Sets the direct addresses and returns the updated node info.
    pub fn with_direct_addresses(mut self, direct_addresses: BTreeSet<SocketAddr>) -> Self {
        self.data = self.data.with_direct_addresses(direct_addresses);
        self
    }

    /// Sets the user-defined data and returns the updated node info.
    pub fn with_user_data(mut self, user_data: Option<UserData>) -> Self {
        self.data = self.data.with_user_data(user_data);
        self
    }

    /// Converts into a [`NodeAddr`] by cloning the needed fields.
    pub fn to_node_addr(&self) -> NodeAddr {
        NodeAddr {
            node_id: self.node_id,
            relay_url: self.data.relay_url.clone(),
            direct_addresses: self.data.direct_addresses.clone(),
            channel_id: None,
            webrtc_info: None
        }
    }

    /// Converts into a [`NodeAddr`] without cloning.
    pub fn into_node_addr(self) -> NodeAddr {
        NodeAddr {
            node_id: self.node_id,
            relay_url: self.data.relay_url,
            direct_addresses: self.data.direct_addresses,
            channel_id: None,
            webrtc_info: None
        }
    }

    fn to_attrs(&self) -> TxtAttrs<IrohAttr> {
        self.into()
    }

    #[cfg(not(wasm_browser))]
    /// Parses a [`NodeInfo`] from a TXT records lookup.
    pub fn from_txt_lookup(lookup: crate::dns::TxtLookup) -> Result<Self, ParseError> {
        let attrs = TxtAttrs::from_txt_lookup(lookup)?;
        Ok(attrs.into())
    }

    /// Parses a [`NodeInfo`] from a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self, ParseError> {
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
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        self.to_attrs().to_pkarr_signed_packet(secret_key, ttl)
    }

    /// Converts into a list of `{key}={value}` strings.
    pub fn to_txt_strings(&self) -> Vec<String> {
        self.to_attrs().to_txt_strings().collect()
    }
}

#[cfg(not(wasm_browser))]
#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum LookupError {
    #[snafu(display("Malformed txt from lookup"))]
    ParseError {
        #[snafu(source(from(ParseError, Box::new)))]
        source: Box<ParseError>,
    },
    #[snafu(display("Failed to resolve TXT record"))]
    LookupFailed {
        #[snafu(source(from(DnsError, Box::new)))]
        source: Box<DnsError>,
    },
    #[cfg(not(wasm_browser))]
    #[snafu(display("Name is not a valid TXT label"))]
    InvalidLabel { source: ProtoError },
}

#[common_fields({
    backtrace: Option<Backtrace>,
    #[snafu(implicit)]
    span_trace: n0_snafu::SpanTrace,
})]
#[allow(missing_docs)]
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[snafu(visibility(pub(crate)))]
pub enum ParseError {
    #[snafu(display("Expected format `key=value`, received `{s}`"))]
    UnexpectedFormat { s: String },
    #[snafu(display("Could not convert key to Attr"))]
    AttrFromString { key: String },
    #[snafu(display("Expected 2 labels, received {num_labels}"))]
    NumLabels { num_labels: usize },
    #[snafu(display("Could not parse labels"))]
    Utf8 { source: Utf8Error },
    #[snafu(display("Record is not an `iroh` record, expected `_iroh`, got `{label}`"))]
    NotAnIrohRecord { label: String },
    #[snafu(transparent)]
    DecodingError {
        #[snafu(source(from(DecodingError, Box::new)))]
        source: Box<DecodingError>,
    },
}

impl std::ops::Deref for NodeInfo {
    type Target = NodeData;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl std::ops::DerefMut for NodeInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

/// Parses a [`NodeId`] from iroh DNS name.
///
/// Takes a [`hickory_resolver::proto::rr::Name`] DNS name and expects the first label to be
/// [`IROH_TXT_NAME`] and the second label to be a z32 encoded [`NodeId`]. Ignores
/// subsequent labels.
#[cfg(not(wasm_browser))]
fn node_id_from_hickory_name(
    name: &hickory_resolver::proto::rr::Name,
) -> Result<NodeId, ParseError> {
    if name.num_labels() < 2 {
        return Err(NumLabelsSnafu {
            num_labels: name.num_labels(),
        }
        .build());
    }
    let mut labels = name.iter();
    let label =
        std::str::from_utf8(labels.next().expect("num_labels checked")).context(Utf8Snafu)?;
    if label != IROH_TXT_NAME {
        return Err(NotAnIrohRecordSnafu { label }.build());
    }
    let label =
        std::str::from_utf8(labels.next().expect("num_labels checked")).context(Utf8Snafu)?;
    let node_id = NodeId::from_z32(label)?;
    Ok(node_id)
}

/// The attributes supported by iroh for [`IROH_TXT_NAME`] DNS resource records.
///
/// The resource record uses the lower-case names.
#[derive(
    Debug, strum::Display, strum::AsRefStr, strum::EnumString, Hash, Eq, PartialEq, Ord, PartialOrd,
)]
#[strum(serialize_all = "kebab-case")]
pub(crate) enum IrohAttr {
    /// URL of home relay.
    Relay,
    /// Direct address.
    Addr,
    /// User-defined data
    UserData,
}

/// Attributes parsed from [`IROH_TXT_NAME`] TXT records.
///
/// This struct is generic over the key type. When using with [`String`], this will parse
/// all attributes. Can also be used with an enum, if it implements [`FromStr`] and
/// [`Display`].
#[derive(Debug)]
pub(crate) struct TxtAttrs<T> {
    node_id: NodeId,
    attrs: BTreeMap<T, Vec<String>>,
}

impl From<&NodeInfo> for TxtAttrs<IrohAttr> {
    fn from(info: &NodeInfo) -> Self {
        let mut attrs = vec![];
        if let Some(relay_url) = &info.data.relay_url {
            attrs.push((IrohAttr::Relay, relay_url.to_string()));
        }
        for addr in &info.data.direct_addresses {
            attrs.push((IrohAttr::Addr, addr.to_string()));
        }
        if let Some(user_data) = &info.data.user_data {
            attrs.push((IrohAttr::UserData, user_data.to_string()));
        }
        Self::from_parts(info.node_id, attrs.into_iter())
    }
}

impl<T: FromStr + Display + Hash + Ord> TxtAttrs<T> {
    /// Creates [`TxtAttrs`] from a node id and an iterator of key-value pairs.
    pub(crate) fn from_parts(node_id: NodeId, pairs: impl Iterator<Item = (T, String)>) -> Self {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, node_id }
    }

    /// Creates [`TxtAttrs`] from a node id and an iterator of "{key}={value}" strings.
    pub(crate) fn from_strings(
        node_id: NodeId,
        strings: impl Iterator<Item = String>,
    ) -> Result<Self, ParseError> {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for s in strings {
            let mut parts = s.split('=');
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                return Err(UnexpectedFormatSnafu { s }.build());
            };
            let attr = T::from_str(key).map_err(|_| AttrFromStringSnafu { key }.build())?;
            attrs.entry(attr).or_default().push(value.to_string());
        }
        Ok(Self { attrs, node_id })
    }

    #[cfg(not(wasm_browser))]
    async fn lookup(resolver: &DnsResolver, name: Name) -> Result<Self, LookupError> {
        let name = ensure_iroh_txt_label(name)?;
        let lookup = resolver
            .lookup_txt(name, DNS_TIMEOUT)
            .await
            .context(LookupFailedSnafu)?;
        let attrs = Self::from_txt_lookup(lookup).context(ParseSnafu)?;
        Ok(attrs)
    }

    /// Looks up attributes by [`NodeId`] and origin domain.
    #[cfg(not(wasm_browser))]
    pub(crate) async fn lookup_by_id(
        resolver: &DnsResolver,
        node_id: &NodeId,
        origin: &str,
    ) -> Result<Self, LookupError> {
        let name = node_domain(node_id, origin)?;
        TxtAttrs::lookup(resolver, name).await
    }

    /// Looks up attributes by DNS name.
    #[cfg(not(wasm_browser))]
    pub(crate) async fn lookup_by_name(
        resolver: &DnsResolver,
        name: &str,
    ) -> Result<Self, LookupError> {
        let name = Name::from_str(name).context(InvalidLabelSnafu)?;
        TxtAttrs::lookup(resolver, name).await
    }

    /// Returns the parsed attributes.
    pub(crate) fn attrs(&self) -> &BTreeMap<T, Vec<String>> {
        &self.attrs
    }

    /// Returns the node id.
    pub(crate) fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Parses a [`pkarr::SignedPacket`].
    pub(crate) fn from_pkarr_signed_packet(
        packet: &pkarr::SignedPacket,
    ) -> Result<Self, ParseError> {
        use pkarr::dns::{
            rdata::RData,
            {self},
        };
        let pubkey = packet.public_key();
        let pubkey_z32 = pubkey.to_z32();
        let node_id = NodeId::from(*pubkey.verifying_key());
        let zone = dns::Name::new(&pubkey_z32).expect("z32 encoding is valid");
        let txt_data = packet
            .all_resource_records()
            .filter_map(|rr| match &rr.rdata {
                RData::TXT(txt) => match rr.name.without(&zone) {
                    Some(name) if name.to_string() == IROH_TXT_NAME => Some(txt),
                    Some(_) | None => None,
                },
                _ => None,
            });

        let txt_strs = txt_data.filter_map(|s| String::try_from(s.clone()).ok());
        Self::from_strings(node_id, txt_strs)
    }

    /// Parses a TXT records lookup.
    #[cfg(not(wasm_browser))]
    pub(crate) fn from_txt_lookup(lookup: crate::dns::TxtLookup) -> Result<Self, ParseError> {
        let queried_node_id = node_id_from_hickory_name(lookup.0.query().name())?;

        let strings = lookup.0.as_lookup().record_iter().filter_map(|record| {
            match node_id_from_hickory_name(record.name()) {
                // Filter out only TXT record answers that match the node_id we searched for.
                Ok(n) if n == queried_node_id => match record.data().as_txt() {
                    Some(txt) => Some(txt.to_string()),
                    None => {
                        warn!(
                            ?queried_node_id,
                            data = ?record.data(),
                            "unexpected record type for DNS discovery query"
                        );
                        None
                    }
                },
                Ok(answered_node_id) => {
                    warn!(
                        ?queried_node_id,
                        ?answered_node_id,
                        "unexpected node ID answered for DNS query"
                    );
                    None
                }
                Err(e) => {
                    warn!(
                        ?queried_node_id,
                        name = ?record.name(),
                        err = ?e,
                        "unexpected answer record name for DNS query"
                    );
                    None
                }
            }
        });

        Self::from_strings(queried_node_id, strings)
    }

    fn to_txt_strings(&self) -> impl Iterator<Item = String> + '_ {
        self.attrs
            .iter()
            .flat_map(move |(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
    }

    /// Creates a [`pkarr::SignedPacket`]
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub(crate) fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        use pkarr::dns::{self, rdata};
        let keypair = pkarr::Keypair::from_secret_key(&secret_key.to_bytes());
        let name = dns::Name::new(IROH_TXT_NAME).expect("constant");

        let mut builder = pkarr::SignedPacket::builder();
        for s in self.to_txt_strings() {
            let mut txt = rdata::TXT::new();
            txt.add_string(&s).context(InvalidTxtEntrySnafu)?;
            builder = builder.txt(name.clone(), txt.into_owned(), ttl);
        }
        let signed_packet = builder.build(&keypair)?;
        Ok(signed_packet)
    }
}

#[cfg(not(wasm_browser))]
fn ensure_iroh_txt_label(name: Name) -> Result<Name, LookupError> {
    if name.iter().next() == Some(IROH_TXT_NAME.as_bytes()) {
        Ok(name)
    } else {
        Name::parse(IROH_TXT_NAME, Some(&name)).context(InvalidLabelSnafu)
    }
}

#[cfg(not(wasm_browser))]
fn node_domain(node_id: &NodeId, origin: &str) -> Result<Name, LookupError> {
    let domain = format!("{}.{origin}", NodeId::to_z32(node_id));
    let domain = Name::from_str(&domain).context(InvalidLabelSnafu)?;
    Ok(domain)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr, sync::Arc};

    use hickory_resolver::{
        Name,
        lookup::Lookup,
        proto::{
            op::Query,
            rr::{
                RData, Record, RecordType,
                rdata::{A, TXT},
            },
        },
    };
    use iroh_base::{NodeId, SecretKey};
    use n0_snafu::{Result, ResultExt};

    use super::{NodeData, NodeIdExt, NodeInfo};

    #[test]
    fn txt_attr_roundtrip() {
        let node_data = NodeData::new(
            Some("https://example.com".parse().unwrap()),
            ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        )
        .with_user_data(Some("foobar".parse().unwrap()));
        let node_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = NodeInfo::from_parts(node_id, node_data);
        let attrs = expected.to_attrs();
        let actual = NodeInfo::from(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip() {
        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();
        let node_data = NodeData::new(
            Some("https://example.com".parse().unwrap()),
            ["127.0.0.1:1234".parse().unwrap()].into_iter().collect(),
        )
        .with_user_data(Some("foobar".parse().unwrap()));
        let expected = NodeInfo::from_parts(secret_key.public(), node_data);
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = NodeInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }

    /// There used to be a bug where uploading a NodeAddr with more than only exactly
    /// one relay URL or one publicly reachable IP addr would prevent connection
    /// establishment.
    ///
    /// The reason was that only the first address was parsed (e.g. 192.168.96.145 in
    /// this example), which could be a local, unreachable address.
    #[test]
    fn test_from_hickory_lookup() -> Result {
        let name = Name::from_utf8(
            "_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.",
        )
        .context("dns name")?;
        let query = Query::query(name.clone(), RecordType::TXT);
        let records = [
            Record::from_rdata(
                name.clone(),
                30,
                RData::TXT(TXT::new(vec!["addr=192.168.96.145:60165".to_string()])),
            ),
            Record::from_rdata(
                name.clone(),
                30,
                RData::TXT(TXT::new(vec!["addr=213.208.157.87:60165".to_string()])),
            ),
            // Test a record with mismatching record type (A instead of TXT). It should be filtered out.
            Record::from_rdata(name.clone(), 30, RData::A(A::new(127, 0, 0, 1))),
            // Test a record with a mismatching name
            Record::from_rdata(
                Name::from_utf8(format!(
                    "_iroh.{}.dns.iroh.link.",
                    NodeId::from_str(
                        // Another NodeId
                        "a55f26132e5e43de834d534332f66a20d480c3e50a13a312a071adea6569981e"
                    )?
                    .to_z32()
                ))
                .context("name")?,
                30,
                RData::TXT(TXT::new(vec![
                    "relay=https://euw1-1.relay.iroh.network./".to_string(),
                ])),
            ),
            // Test a record with a completely different name
            Record::from_rdata(
                Name::from_utf8("dns.iroh.link.").context("name")?,
                30,
                RData::TXT(TXT::new(vec![
                    "relay=https://euw1-1.relay.iroh.network./".to_string(),
                ])),
            ),
            Record::from_rdata(
                name.clone(),
                30,
                RData::TXT(TXT::new(vec![
                    "relay=https://euw1-1.relay.iroh.network./".to_string(),
                ])),
            ),
        ];
        let lookup = Lookup::new_with_max_ttl(query, Arc::new(records));
        let lookup = hickory_resolver::lookup::TxtLookup::from(lookup);

        let node_info = NodeInfo::from_txt_lookup(lookup.into())?;

        let expected_node_info = NodeInfo::new(NodeId::from_str(
            "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18",
        )?)
        .with_relay_url(Some("https://euw1-1.relay.iroh.network./".parse()?))
        .with_direct_addresses(BTreeSet::from([
            "192.168.96.145:60165".parse().unwrap(),
            "213.208.157.87:60165".parse().unwrap(),
        ]));

        assert_eq!(node_info, expected_node_info);

        Ok(())
    }
}
