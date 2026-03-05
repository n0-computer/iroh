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

/// The relay protocol version negotiated between client and server.
///
/// Sent as the websocket sub-protocol header `Sec-Websocket-Protocol` from
/// the client. The server picks the best supported version and replies with it.
///
/// Variants are ordered by preference (highest first), so the [`Ord`] impl
/// can be used during negotiation to pick the best version.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    strum::VariantArray,
    strum::EnumString,
    strum::Display,
    strum::IntoStaticStr,
)]
#[strum(parse_err_ty = UnsupportedRelayProtocolVersion, parse_err_fn = strum_err_fn)]
// Needs to be ordered with latest version last, so that the `Ord` impl orders by latest version as max.
pub enum ProtocolVersion {
    /// Version 1 (before iroh 0.97.0)
    #[strum(serialize = "iroh-relay-v1")]
    V1,
    /// Version 2 (added in iroh 0.97.0)
    /// - Removed `Health` frame (id 11)
    /// - Added new `Status` frame (id 13)
    /// - Changed behavior such that unknown frames are allowed
    #[default]
    #[strum(serialize = "iroh-relay-v2")]
    V2,
}

impl ProtocolVersion {
    /// Returns an iterator of all supported protocol version identifiers, in order of preference.
    pub fn all() -> impl Iterator<Item = &'static str> {
        Self::VARIANTS
            .iter()
            .map(ProtocolVersion::to_str)
            // Need to reverse order so that the latest version comes last.
            .rev()
    }

    /// Returns a comma-separated string of all supported protocol version identifiers.
    pub fn all_joined() -> String {
        Self::all().collect::<Vec<_>>().join(", ")
    }

    /// Returns all supported protocol versions in a comma-seperated string as an HTTP header value.
    pub fn all_as_header_value() -> HeaderValue {
        HeaderValue::from_bytes(Self::all_joined().as_bytes()).expect("valid header name")
    }

    /// Returns the protocol version identifier string.
    pub fn to_str(&self) -> &'static str {
        self.into()
    }

    /// Tries to parse a [`ProtocolVersion`] from `s`.
    ///
    /// Returns `None` if `s` is not a valid protocol version string.
    pub fn match_from_str(s: &str) -> Option<Self> {
        Self::try_from(s).ok()
    }

    /// Returns this protocol version as an HTTP header value.
    pub fn to_header_value(&self) -> HeaderValue {
        HeaderValue::from_static(self.to_str())
    }
}

/// Error returned when the relay protocol version is not recognized.
#[stack_error(derive)]
#[error("Relay protocol version is not supported")]
pub struct UnsupportedRelayProtocolVersion;

fn strum_err_fn(_item: &str) -> UnsupportedRelayProtocolVersion {
    UnsupportedRelayProtocolVersion::new()
}
