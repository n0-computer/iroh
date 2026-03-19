//! Support for handling DNS resource records for dialing by [`EndpointId`].
//!
//! Dialing by [`EndpointId`] is supported by iroh endpoints publishing [Pkarr] records to DNS
//! servers or the Mainline DHT.  This module supports creating and parsing these records.
//!
//! DNS records are published under the following names:
//!
//! `_iroh.<z32-endpoint-id>.<origin-domain> TXT`
//!
//! - `_iroh` is the record name as defined by [`IROH_TXT_NAME`].
//!
//! - `<z32-endpoint-id>` is the [z-base-32] encoding of the [`EndpointId`].
//!
//! - `<origin-domain>` is the domain name of the publishing DNS server,
//!   [`N0_DNS_ENDPOINT_ORIGIN_PROD`] is the server operated by number0 for production.
//!   [`N0_DNS_ENDPOINT_ORIGIN_STAGING`] is the server operated by number0 for testing.
//!
//! - `TXT` is the DNS record type.
//!
//! The returned TXT records must contain a string value of the form `key=value` as defined
//! in [RFC1464].  The following attributes are defined:
//!
//! - `relay=<url>`: The home [`RelayUrl`] of this endpoint.
//!
//! - `addr=<addr> <addr>`: A space-separated list of sockets addresses for this iroh endpoint.
//!   Each address is an IPv4 or IPv6 address with a port.
//!
//! [Pkarr]: https://app.pkarr.org
//! [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
//! [RFC1464]: https://www.rfc-editor.org/rfc/rfc1464
//! [`RelayUrl`]: iroh_base::RelayUrl
//! [`N0_DNS_ENDPOINT_ORIGIN_PROD`]: crate::dns::N0_DNS_ENDPOINT_ORIGIN_PROD
//! [`N0_DNS_ENDPOINT_ORIGIN_STAGING`]: crate::dns::N0_DNS_ENDPOINT_ORIGIN_STAGING

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    hash::Hash,
    net::SocketAddr,
    str::{FromStr, Utf8Error},
    sync::Arc,
};

use ahash::AHashSet;
use iroh_base::{EndpointAddr, EndpointId, KeyParsingError, RelayUrl, SecretKey, TransportAddr};
use n0_error::{e, ensure, stack_error};
use url::Url;

/// The DNS name for the iroh TXT record.
pub const IROH_TXT_NAME: &str = "_iroh";

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum EncodingError {
    #[error(transparent)]
    FailedBuildingPacket {
        #[error(std_err)]
        source: pkarr::errors::SignedPacketBuildError,
    },
    #[error("invalid TXT entry")]
    InvalidTxtEntry {
        #[error(std_err)]
        source: pkarr::dns::SimpleDnsError,
    },
}

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum DecodingError {
    #[error("endpoint id was not encoded in valid z32")]
    InvalidEncodingZ32 {
        #[error(std_err)]
        source: z32::Z32Error,
    },
    #[error("length must be 32 bytes, but got {len} byte(s)")]
    InvalidLength { len: usize },
    #[error("endpoint id is not a valid public key")]
    InvalidKey { source: KeyParsingError },
}

/// Extension methods for [`EndpointId`] to encode to and decode from [`z32`],
/// which is the encoding used in [`pkarr`] domain names.
pub trait EndpointIdExt {
    /// Encodes a [`EndpointId`] in [`z-base-32`] encoding.
    ///
    /// [`z-base-32`]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    fn to_z32(&self) -> String;

    /// Parses a [`EndpointId`] from [`z-base-32`] encoding.
    ///
    /// [`z-base-32`]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt
    fn from_z32(s: &str) -> Result<EndpointId, DecodingError>;
}

impl EndpointIdExt for EndpointId {
    fn to_z32(&self) -> String {
        z32::encode(self.as_bytes())
    }

    fn from_z32(s: &str) -> Result<EndpointId, DecodingError> {
        let bytes =
            z32::decode(s.as_bytes()).map_err(|err| e!(DecodingError::InvalidEncodingZ32, err))?;
        let bytes: &[u8; 32] = &bytes
            .try_into()
            .map_err(|_| e!(DecodingError::InvalidLength { len: s.len() }))?;
        let endpoint_id =
            EndpointId::from_bytes(bytes).map_err(|err| e!(DecodingError::InvalidKey, err))?;
        Ok(endpoint_id)
    }
}

/// Data about an endpoint that may be published to and resolved from discovery services.
///
/// This includes an optional [`RelayUrl`], a set of direct addresses, and the optional
/// [`UserData`], a string that can be set by applications and is not parsed or used by iroh
/// itself.
///
/// This struct does not include the endpoint's [`EndpointId`], only the data *about* a certain
/// endpoint. See [`EndpointInfo`] for a struct that contains a [`EndpointId`] with associated [`EndpointData`].
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct EndpointData {
    /// addresses where this endpoint can be reached.
    addrs: Vec<TransportAddr>,
    /// Optional user-defined [`UserData`] for this endpoint.
    user_data: Option<UserData>,
}

fn dedup<T: Eq + Hash + Clone>(items: &mut Vec<T>) -> AHashSet<T> {
    // Remove all duplicate entries, but keep the array order.
    let mut seen = AHashSet::new();
    items.retain(|item| seen.insert(item.clone()));
    seen
}

impl EndpointData {
    /// Creates a new [`EndpointData`] with given list of transport addresses.
    ///
    /// The address order is preserved, so it can encode priority for address lookup
    /// services, should they not fit into e.g. a single DNS packet otherwise.
    ///
    /// If the addresses contain duplicate entries, those entries are removed.
    pub fn new(mut addrs: Vec<TransportAddr>) -> Self {
        dedup(&mut addrs);
        Self {
            addrs,
            user_data: None,
        }
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    ///
    /// Useful for calling on construction after [`EndpointData::new`] or [`EndpointData::from_iter`].
    ///
    /// See also [`Self::set_user_data`].
    pub fn with_user_data(mut self, user_data: UserData) -> Self {
        self.user_data = Some(user_data);
        self
    }

    /// Adds the relay URL to the end of the endpoint data, unless it already existed.
    pub fn add_relay_url(&mut self, relay_url: RelayUrl) {
        let addr = TransportAddr::Relay(relay_url);
        if !self.addrs.contains(&addr) {
            self.addrs.push(addr);
        }
    }

    /// Adds addresses in order with duplicates or already existing addresses filtered out.
    pub fn add_ip_addrs(&mut self, addresses: Vec<SocketAddr>) {
        self.add_addrs(addresses.into_iter().map(TransportAddr::Ip))
    }

    /// Adds addresses to the endpoint data in the given ordered, but with duplicates filtered.
    pub fn add_addrs(&mut self, addrs: impl IntoIterator<Item = TransportAddr>) {
        let mut addr_set = dedup(&mut self.addrs);
        for addr in addrs.into_iter() {
            if !addr_set.contains(&addr) {
                self.addrs.push(addr.clone());
                addr_set.insert(addr);
            }
        }
    }

    /// Sets the user-defined data and returns the updated endpoint data.
    pub fn set_user_data(&mut self, user_data: Option<UserData>) {
        self.user_data = user_data;
    }

    /// Removes all direct addresses from the endpoint data.
    pub fn clear_ip_addrs(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Ip(_)));
    }

    /// Removes all direct addresses from the endpoint data.
    pub fn clear_relay_urls(&mut self) {
        self.addrs
            .retain(|addr| !matches!(addr, TransportAddr::Relay(_)));
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Relay(url) => Some(url),
            _ => None,
        })
    }

    /// Returns the optional user-defined data of the endpoint.
    pub fn user_data(&self) -> Option<&UserData> {
        self.user_data.as_ref()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.addrs.iter().filter_map(|addr| match addr {
            TransportAddr::Ip(addr) => Some(addr),
            _ => None,
        })
    }

    /// Returns the full list of all known addresses
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.addrs.iter()
    }

    /// Does this have any addresses?
    pub fn has_addrs(&self) -> bool {
        !self.addrs.is_empty()
    }

    /// Apply the given filter to the current addresses.
    ///
    /// Returns a vec to allow re-ordering of addresses.
    pub fn filtered_addrs(&self, filter: &AddrFilter) -> Cow<'_, Vec<TransportAddr>> {
        filter.apply(&self.addrs)
    }

    /// Returns the `EndpointData` with given filter applied.
    pub fn apply_filter(&self, filter: &AddrFilter) -> Cow<'_, Self> {
        match self.filtered_addrs(filter) {
            Cow::Borrowed(_) => Cow::Borrowed(self),
            Cow::Owned(addrs) => {
                let mut data = EndpointData::new(addrs);
                data.set_user_data(self.user_data.clone());
                Cow::Owned(data)
            }
        }
    }
}

// These From instances are faster than `EndpointData::new`, as they don't require deduplication.

impl From<BTreeSet<TransportAddr>> for EndpointData {
    fn from(addrs: BTreeSet<TransportAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

impl From<BTreeSet<SocketAddr>> for EndpointData {
    fn from(addrs: BTreeSet<SocketAddr>) -> Self {
        Self {
            addrs: addrs.into_iter().map(TransportAddr::Ip).collect(),
            user_data: None,
        }
    }
}

impl FromIterator<TransportAddr> for EndpointData {
    fn from_iter<T: IntoIterator<Item = TransportAddr>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect())
    }
}

/// The function type inside [`AddrFilter`].
type AddrFilterFn =
    dyn Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static;

/// A filter and/or reordering function applied to transport addresses,
/// typically used by AddressLookup services in iroh before publishing.
///
/// Takes the full set of transport addresses and returns them as an ordered `Vec`,
/// allowing both filtering (by omitting addresses) and reordering (by controlling
/// the output order). A `BTreeSet` cannot preserve a custom order, so the return
/// type is `Vec` to make reordering possible.
///
/// See the documentation for each address lookup implementation for details on
/// what additional filtering the implementation may perform on top.
#[derive(Clone, Default)]
pub struct AddrFilter(Option<Arc<AddrFilterFn>>);

impl std::fmt::Debug for AddrFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_some() {
            f.debug_struct("AddrFilter").finish_non_exhaustive()
        } else {
            write!(f, "identity")
        }
    }
}

impl AddrFilter {
    /// Create a new [`AddrFilter`]
    pub fn new(
        f: impl Fn(&Vec<TransportAddr>) -> Cow<'_, Vec<TransportAddr>> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(f)))
    }

    /// Constructs a filter that doesn't filter addresses and passes all through.
    pub fn unfiltered() -> Self {
        Self::new(|addrs| Cow::Borrowed(addrs))
    }

    /// Only keep relay addresses.
    pub fn relay_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| a.is_relay()).cloned().collect()))
    }

    /// Only keep direct IP addresses.
    pub fn ip_only() -> Self {
        Self::new(|addrs| Cow::Owned(addrs.iter().filter(|a| !a.is_relay()).cloned().collect()))
    }

    /// Apply the address filter function to a set of addresses.
    pub fn apply<'a>(&self, addrs: &'a Vec<TransportAddr>) -> Cow<'a, Vec<TransportAddr>> {
        match &self.0 {
            Some(f) => f(addrs),
            None => Cow::Borrowed(addrs),
        }
    }
}

impl From<EndpointAddr> for EndpointData {
    fn from(endpoint_addr: EndpointAddr) -> Self {
        Self {
            // No need to check for duplicates - we already know they can't have duplicates
            addrs: endpoint_addr.addrs.into_iter().collect(),
            user_data: None,
        }
    }
}

// User-defined data that can be published and resolved through endpoint discovery.
///
/// Under the hood this is a UTF-8 String is no longer than [`UserData::MAX_LENGTH`] bytes.
///
/// Iroh does not keep track of or examine the user-defined data.
///
/// `UserData` implements [`FromStr`] and [`TryFrom<String>`], so you can
/// convert `&str` and `String` into `UserData` easily.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserData(String);

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
#[stack_error(derive, add_meta)]
#[error("max length exceeded")]
pub struct MaxLengthExceededError {}

impl TryFrom<String> for UserData {
    type Error = MaxLengthExceededError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ensure!(value.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
        Ok(Self(value))
    }
}

impl FromStr for UserData {
    type Err = MaxLengthExceededError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        ensure!(s.len() <= Self::MAX_LENGTH, MaxLengthExceededError);
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

/// Information about an endpoint that may be published to and resolved from discovery services.
///
/// This struct couples a [`EndpointId`] with its associated [`EndpointData`].
#[derive(derive_more::Debug, Clone, Eq, PartialEq)]
pub struct EndpointInfo {
    /// The [`EndpointId`] of the endpoint this is about.
    pub endpoint_id: EndpointId,
    /// The information published about the endpoint.
    pub data: EndpointData,
}

impl From<TxtAttrs<IrohAttr>> for EndpointInfo {
    fn from(attrs: TxtAttrs<IrohAttr>) -> Self {
        (&attrs).into()
    }
}

impl From<&TxtAttrs<IrohAttr>> for EndpointInfo {
    fn from(attrs: &TxtAttrs<IrohAttr>) -> Self {
        use iroh_base::CustomAddr;

        let endpoint_id = attrs.endpoint_id();
        let attrs = attrs.attrs();
        let relay_urls = attrs
            .get(&IrohAttr::Relay)
            .into_iter()
            .flatten()
            .filter_map(|s| Url::parse(s).ok())
            .map(|url| TransportAddr::Relay(url.into()));
        // Parse addresses: try IP first, then CustomAddr
        let addrs = attrs
            .get(&IrohAttr::Addr)
            .into_iter()
            .flatten()
            .filter_map(|s| {
                if let Ok(addr) = SocketAddr::from_str(s) {
                    Some(TransportAddr::Ip(addr))
                } else if let Ok(addr) = CustomAddr::from_str(s) {
                    Some(TransportAddr::Custom(addr))
                } else {
                    None
                }
            });

        let user_data = attrs
            .get(&IrohAttr::UserData)
            .into_iter()
            .flatten()
            .next()
            .and_then(|s| UserData::from_str(s).ok());
        let mut data = EndpointData::default();
        data.set_user_data(user_data);
        data.add_addrs(relay_urls.chain(addrs));

        Self { endpoint_id, data }
    }
}

impl From<EndpointInfo> for EndpointAddr {
    fn from(value: EndpointInfo) -> Self {
        value.into_endpoint_addr()
    }
}

impl From<EndpointAddr> for EndpointInfo {
    fn from(addr: EndpointAddr) -> Self {
        Self {
            endpoint_id: addr.id,
            data: EndpointData::from(addr.addrs),
        }
    }
}

impl EndpointInfo {
    /// Creates a new [`EndpointInfo`] with an empty [`EndpointData`].
    pub fn new(endpoint_id: EndpointId) -> Self {
        Self::from_parts(endpoint_id, Default::default())
    }

    /// Creates a new [`EndpointInfo`] from its parts.
    pub fn from_parts(endpoint_id: EndpointId, data: EndpointData) -> Self {
        Self { endpoint_id, data }
    }

    /// Adds the relay URL and returns the updated endpoint info.
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.data.add_relay_url(relay_url);
        self
    }

    /// Sets the IP based addresses and returns the updated endpoint info.
    pub fn with_ip_addrs(mut self, addrs: Vec<SocketAddr>) -> Self {
        self.data.add_ip_addrs(addrs);
        self
    }

    /// Sets the user-defined data and returns the updated endpoint info.
    pub fn with_user_data(mut self, user_data: Option<UserData>) -> Self {
        self.data.set_user_data(user_data);
        self
    }

    /// Converts into a [`EndpointAddr`] by cloning the needed fields.
    pub fn to_endpoint_addr(&self) -> EndpointAddr {
        EndpointAddr {
            id: self.endpoint_id,
            addrs: self.data.addrs.iter().cloned().collect(),
        }
    }

    /// Converts into a [`EndpointAddr`].
    pub fn into_endpoint_addr(self) -> EndpointAddr {
        let Self { endpoint_id, data } = self;
        EndpointAddr {
            id: endpoint_id,
            addrs: data.addrs.into_iter().collect(),
        }
    }

    /// Returns the transport addr information.
    pub fn addrs(&self) -> impl Iterator<Item = &TransportAddr> {
        self.data.addrs()
    }

    /// Returns the relay URL of the endpoint.
    pub fn relay_urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.data.relay_urls()
    }

    /// Returns user data information, if set.
    pub fn user_data(&self) -> Option<&UserData> {
        self.data.user_data()
    }

    /// Returns the direct addresses of the endpoint.
    pub fn ip_addrs(&self) -> impl Iterator<Item = &SocketAddr> {
        self.data.ip_addrs()
    }

    fn to_attrs(&self) -> TxtAttrs<IrohAttr> {
        self.into()
    }

    #[cfg(not(wasm_browser))]
    /// Parses a [`EndpointInfo`] from DNS TXT lookup.
    pub fn from_txt_lookup(
        domain_name: String,
        lookup: impl Iterator<Item = crate::dns::TxtRecordData>,
    ) -> Result<Self, ParseError> {
        let attrs = TxtAttrs::from_txt_lookup(domain_name, lookup)?;
        Ok(Self::from(attrs))
    }

    /// Parses a [`EndpointInfo`] from a [`pkarr::SignedPacket`].
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

#[allow(missing_docs)]
#[stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum ParseError {
    #[error("Expected format `key=value`, received `{s}`")]
    UnexpectedFormat { s: String },
    #[error("Could not convert key to Attr")]
    AttrFromString { key: String },
    #[error("Expected 2 labels, received {num_labels}")]
    NumLabels { num_labels: usize },
    #[error("Could not parse labels")]
    Utf8 {
        #[error(std_err)]
        source: Utf8Error,
    },
    #[error("Record is not an `iroh` record, expected `_iroh`, got `{label}`")]
    NotAnIrohRecord { label: String },
    #[error(transparent)]
    DecodingError { source: DecodingError },
}

/// Parses a [`EndpointId`] from iroh DNS name.
///
/// Takes a [`hickory_resolver::proto::rr::Name`] DNS name and expects the first label to be
/// [`IROH_TXT_NAME`] and the second label to be a z32 encoded [`EndpointId`]. Ignores
/// subsequent labels.
#[cfg(not(wasm_browser))]
fn endpoint_id_from_txt_name(name: &str) -> Result<EndpointId, ParseError> {
    let num_labels = name.split(".").count();
    if num_labels < 2 {
        return Err(e!(ParseError::NumLabels { num_labels }));
    }
    let mut labels = name.split(".");
    let label = labels.next().expect("checked above");
    if label != IROH_TXT_NAME {
        return Err(e!(ParseError::NotAnIrohRecord {
            label: label.to_string()
        }));
    }
    let label = labels.next().expect("checked above");
    let endpoint_id = EndpointId::from_z32(label)?;
    Ok(endpoint_id)
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
    /// Address (IP or custom transport).
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
    endpoint_id: EndpointId,
    attrs: BTreeMap<T, Vec<String>>,
}

impl From<&EndpointInfo> for TxtAttrs<IrohAttr> {
    fn from(info: &EndpointInfo) -> Self {
        let mut attrs = vec![];
        for addr in &info.data.addrs {
            match addr {
                TransportAddr::Relay(url) => attrs.push((IrohAttr::Relay, url.to_string())),
                TransportAddr::Ip(addr) => attrs.push((IrohAttr::Addr, addr.to_string())),
                TransportAddr::Custom(addr) => attrs.push((IrohAttr::Addr, addr.to_string())),
                _ => {}
            }
        }

        if let Some(user_data) = &info.data.user_data {
            attrs.push((IrohAttr::UserData, user_data.to_string()));
        }
        Self::from_parts(info.endpoint_id, attrs.into_iter())
    }
}

impl<T: FromStr + Display + Hash + Ord> TxtAttrs<T> {
    /// Creates [`TxtAttrs`] from an endpoint id and an iterator of key-value pairs.
    pub(crate) fn from_parts(
        endpoint_id: EndpointId,
        pairs: impl Iterator<Item = (T, String)>,
    ) -> Self {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, endpoint_id }
    }

    /// Creates [`TxtAttrs`] from an endpoint id and an iterator of "{key}={value}" strings.
    pub(crate) fn from_strings(
        endpoint_id: EndpointId,
        strings: impl Iterator<Item = String>,
    ) -> Result<Self, ParseError> {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for s in strings {
            let mut parts = s.split('=');
            let (Some(key), Some(value)) = (parts.next(), parts.next()) else {
                return Err(e!(ParseError::UnexpectedFormat { s }));
            };
            let attr = T::from_str(key).map_err(|_| {
                e!(ParseError::AttrFromString {
                    key: key.to_string()
                })
            })?;
            attrs.entry(attr).or_default().push(value.to_string());
        }
        Ok(Self { attrs, endpoint_id })
    }

    /// Returns the parsed attributes.
    pub(crate) fn attrs(&self) -> &BTreeMap<T, Vec<String>> {
        &self.attrs
    }

    /// Returns the endpoint id.
    pub(crate) fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
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
        let endpoint_id =
            EndpointId::from_bytes(&pubkey.verifying_key().to_bytes()).expect("valid key");
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
        Self::from_strings(endpoint_id, txt_strs)
    }

    /// Parses a TXT records lookup.
    #[cfg(not(wasm_browser))]
    pub(crate) fn from_txt_lookup(
        name: String,
        lookup: impl Iterator<Item = crate::dns::TxtRecordData>,
    ) -> Result<Self, ParseError> {
        let queried_endpoint_id = endpoint_id_from_txt_name(&name)?;

        let strings = lookup.map(|record| record.to_string());
        Self::from_strings(queried_endpoint_id, strings)
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
            txt.add_string(&s)
                .map_err(|err| e!(EncodingError::InvalidTxtEntry, err))?;
            builder = builder.txt(name.clone(), txt.into_owned(), ttl);
        }
        let signed_packet = builder
            .build(&keypair)
            .map_err(|err| e!(EncodingError::FailedBuildingPacket, err))?;
        Ok(signed_packet)
    }
}

#[cfg(not(wasm_browser))]
pub(crate) fn ensure_iroh_txt_label(name: String) -> String {
    let mut parts = name.split(".");
    if parts.next() == Some(IROH_TXT_NAME) {
        name
    } else {
        format!("{IROH_TXT_NAME}.{name}")
    }
}

#[cfg(not(wasm_browser))]
pub(crate) fn endpoint_domain(endpoint_id: &EndpointId, origin: &str) -> String {
    format!("{}.{}", EndpointId::to_z32(endpoint_id), origin)
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Arc};

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
    use iroh_base::{EndpointId, SecretKey, TransportAddr};
    use n0_error::{Result, StdResultExt};

    use super::{EndpointData, EndpointIdExt, EndpointInfo};
    use crate::dns::TxtRecordData;

    #[test]
    fn txt_attr_roundtrip() {
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = EndpointInfo::from(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip() {
        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();
        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
        ])
        .with_user_data("foobar".parse().unwrap());
        let expected = EndpointInfo::from_parts(secret_key.public(), endpoint_data);
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = EndpointInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }

    #[test]
    fn txt_attr_roundtrip_with_custom_addr() {
        use iroh_base::CustomAddr;

        // Bluetooth-like address (small id, 6 byte MAC)
        let bt_addr = CustomAddr::from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        // Tor-like address (larger id, 32 byte pubkey)
        let tor_addr = CustomAddr::from_parts(42, &[0xab; 32]);

        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(bt_addr),
            TransportAddr::Custom(tor_addr),
        ]);
        let endpoint_id = "vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia"
            .parse()
            .unwrap();
        let expected = EndpointInfo::from_parts(endpoint_id, endpoint_data);
        let attrs = expected.to_attrs();
        let actual = EndpointInfo::from(&attrs);
        assert_eq!(expected, actual);
    }

    #[test]
    fn signed_packet_roundtrip_with_custom_addr() {
        use iroh_base::CustomAddr;

        let secret_key =
            SecretKey::from_str("vpnk377obfvzlipnsfbqba7ywkkenc4xlpmovt5tsfujoa75zqia").unwrap();

        // Bluetooth-like address (small id, 6 byte MAC)
        let bt_addr = CustomAddr::from_parts(1, &[0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]);
        // Tor-like address (larger id, 32 byte pubkey)
        let tor_addr = CustomAddr::from_parts(42, &[0xab; 32]);

        let endpoint_data = EndpointData::from_iter([
            TransportAddr::Relay("https://example.com".parse().unwrap()),
            TransportAddr::Ip("127.0.0.1:1234".parse().unwrap()),
            TransportAddr::Custom(bt_addr),
            TransportAddr::Custom(tor_addr),
        ])
        .with_user_data("foobar".parse().unwrap());

        let expected = EndpointInfo::from_parts(secret_key.public(), endpoint_data);
        let packet = expected.to_pkarr_signed_packet(&secret_key, 30).unwrap();
        let actual = EndpointInfo::from_pkarr_signed_packet(&packet).unwrap();
        assert_eq!(expected, actual);
    }

    /// There used to be a bug where uploading an EndpointAddr with more than only exactly
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
        .std_context("dns name")?;
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
                    EndpointId::from_str(
                        // Another EndpointId
                        "a55f26132e5e43de834d534332f66a20d480c3e50a13a312a071adea6569981e"
                    )?
                    .to_z32()
                ))
                .std_context("name")?,
                30,
                RData::TXT(TXT::new(vec![
                    "relay=https://euw1-1.relay.iroh.network./".to_string(),
                ])),
            ),
            // Test a record with a completely different name
            Record::from_rdata(
                Name::from_utf8("dns.iroh.link.").std_context("name")?,
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
        let lookup = lookup
            .into_iter()
            .map(|txt| TxtRecordData::from_iter(txt.iter().cloned()));

        let endpoint_info = EndpointInfo::from_txt_lookup(name.to_string(), lookup)?;

        let expected_endpoint_info = EndpointInfo::new(EndpointId::from_str(
            "1992d53c02cdc04566e5c0edb1ce83305cd550297953a047a445ea3264b54b18",
        )?)
        .with_relay_url("https://euw1-1.relay.iroh.network./".parse()?)
        .with_ip_addrs(vec![
            "192.168.96.145:60165".parse().unwrap(),
            "213.208.157.87:60165".parse().unwrap(),
        ]);

        assert_eq!(endpoint_info, expected_endpoint_info);

        Ok(())
    }
}
