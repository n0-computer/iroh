//! HTTP-specific constants for the relay server and client.

use http::{HeaderName, HeaderValue};
use n0_error::stack_error;
use strum::VariantArray;

#[cfg(feature = "server")]
pub(crate) const WEBSOCKET_UPGRADE_PROTOCOL: &str = "websocket";
#[cfg(feature = "server")] // only used in the server for now
pub(crate) const SUPPORTED_WEBSOCKET_VERSION: &str = "13";

/// The HTTP path under which the relay accepts relaying connections
/// (over websockets and a custom upgrade protocol).
pub const RELAY_PATH: &str = "/relay";
/// The HTTP path under which the relay allows doing latency queries for testing.
pub const RELAY_PROBE_PATH: &str = "/ping";

/// The HTTP header name for relay client authentication
pub const CLIENT_AUTH_HEADER: HeaderName = HeaderName::from_static("x-iroh-relay-client-auth-v1");

///
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default, VariantArray)]
pub enum ProtocolVersion {
    /// Added in iroh 0.97.0.
    /// - Deprecated `Health` frame (id 11)
    /// - Added new `Health` frame (id 13)
    /// - Changed behavior such that unknown frames are allowed
    #[default]
    V2,
    /// Deprecated version 1 (before iroh 0.97.0)
    V1,
}

impl ProtocolVersion {
    /// TODO
    pub fn all() -> String {
        Self::VARIANTS
            .iter()
            .map(ProtocolVersion::to_str)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// TODO
    pub fn all_as_header_value() -> HeaderValue {
        HeaderValue::from_bytes(Self::all().as_bytes()).expect("valid header name")
    }

    /// TODO
    pub fn to_str(&self) -> &'static str {
        match self {
            ProtocolVersion::V1 => "iroh-relay-v1",
            ProtocolVersion::V2 => "iroh-relay-v2",
        }
    }

    /// TODO
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_static(self.to_str())
    }
}

impl TryFrom<&str> for ProtocolVersion {
    type Error = UnsupportedRelayProtocolVersion;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "iroh-relay-v1" => Ok(Self::V1),
            "iroh-relay-v2" => Ok(Self::V2),
            _ => Err(UnsupportedRelayProtocolVersion),
        }
    }
}

/// TODO
#[stack_error(derive)]
#[error("Relay protocol version is not supported")]
pub struct UnsupportedRelayProtocolVersion;
