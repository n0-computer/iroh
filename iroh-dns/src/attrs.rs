//! Support for handling DNS resource records for dialing by [`EndpointId`].
//!
//! DNS records are published under the following names:
//!
//! `_iroh.<z32-endpoint-id>.<origin-domain> TXT`
//!
//! The returned TXT records must contain a string value of the form `key=value` as defined
//! in [RFC1464].
//!
//! [RFC1464]: https://www.rfc-editor.org/rfc/rfc1464

use std::{collections::BTreeMap, fmt::Display, hash::Hash, str::FromStr};

use iroh_base::{EndpointId, SecretKey};
use n0_error::{e, stack_error};

use crate::{EndpointIdExt, pkarr};

/// The DNS name for the iroh TXT record.
pub const IROH_TXT_NAME: &str = "_iroh";

#[allow(missing_docs)]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub enum EncodingError {
    #[error(transparent)]
    FailedBuildingPacket {
        #[error(std_err)]
        source: pkarr::SignedPacketBuildError,
    },
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
        source: std::str::Utf8Error,
    },
    #[error("Record is not an `iroh` record, expected `_iroh`, got `{label}`")]
    NotAnIrohRecord { label: String },
    #[error(transparent)]
    DecodingError { source: crate::DecodingError },
}

/// Parses a [`EndpointId`] from iroh DNS name.
///
/// Takes a DNS name and expects the first label to be [`IROH_TXT_NAME`] and the second
/// label to be a z32 encoded [`EndpointId`]. Ignores subsequent labels.
pub(crate) fn endpoint_id_from_txt_name(name: &str) -> Result<EndpointId, ParseError> {
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
    let endpoint_id = <EndpointId as EndpointIdExt>::from_z32(label)?;
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

impl<T: FromStr + Display + Hash + Ord> TxtAttrs<T> {
    /// Creates [`TxtAttrs`] from an endpoint id and an iterator of key-value pairs.
    pub fn from_parts(endpoint_id: EndpointId, pairs: impl Iterator<Item = (T, String)>) -> Self {
        let mut attrs: BTreeMap<T, Vec<String>> = BTreeMap::new();
        for (k, v) in pairs {
            attrs.entry(k).or_default().push(v);
        }
        Self { attrs, endpoint_id }
    }

    /// Creates [`TxtAttrs`] from an endpoint id and an iterator of "{key}={value}" strings.
    pub fn from_strings(
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
    pub fn attrs(&self) -> &BTreeMap<T, Vec<String>> {
        &self.attrs
    }

    /// Returns the endpoint id.
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Parses TXT record lookup results.
    ///
    /// The `name` is the queried DNS name. The `lookup` iterator yields TXT record
    /// values that implement [`Display`].
    pub fn from_txt_lookup(
        name: String,
        lookup: impl Iterator<Item = impl Display>,
    ) -> Result<Self, ParseError> {
        let queried_endpoint_id = endpoint_id_from_txt_name(&name)?;
        let strings = lookup.map(|record| record.to_string());
        Self::from_strings(queried_endpoint_id, strings)
    }

    /// Parses a [`pkarr::SignedPacket`].
    pub fn from_pkarr_signed_packet(packet: &pkarr::SignedPacket) -> Result<Self, ParseError> {
        let pubkey = packet.public_key();
        let endpoint_id = EndpointId::from_bytes(pubkey.as_bytes()).expect("valid key");
        let txt_strs = packet.txt_records(IROH_TXT_NAME);
        Self::from_strings(endpoint_id, txt_strs.into_iter())
    }

    /// Converts to `{key}={value}` strings.
    pub fn to_txt_strings(&self) -> impl Iterator<Item = String> + '_ {
        self.attrs
            .iter()
            .flat_map(move |(k, vs)| vs.iter().map(move |v| format!("{k}={v}")))
    }

    /// Creates a [`pkarr::SignedPacket`]
    ///
    /// This constructs a DNS packet and signs it with a [`SecretKey`].
    pub fn to_pkarr_signed_packet(
        &self,
        secret_key: &SecretKey,
        ttl: u32,
    ) -> Result<pkarr::SignedPacket, EncodingError> {
        let signed_packet = pkarr::SignedPacket::from_txt_strings(
            secret_key,
            IROH_TXT_NAME,
            self.to_txt_strings(),
            ttl,
        )
        .map_err(|err| e!(EncodingError::FailedBuildingPacket, err))?;
        Ok(signed_packet)
    }
}
