//! HTTP-specific constants for the relay server and client.

use http::HeaderName;

#[cfg(feature = "server")]
pub(crate) const WEBSOCKET_UPGRADE_PROTOCOL: &str = "websocket";
#[cfg(feature = "server")] // only used in the server for now
pub(crate) const SUPPORTED_WEBSOCKET_VERSION: &str = "13";

/// The HTTP path under which the relay accepts relaying connections
/// (over websockets and a custom upgrade protocol).
pub const RELAY_PATH: &str = "/relay";
/// The HTTP path under which the relay allows doing latency queries for testing.
pub const RELAY_PROBE_PATH: &str = "/ping";

/// The websocket sub-protocol version that we currently support.
///
/// This is sent as the websocket sub-protocol header `Sec-Websocket-Protocol` from
/// the client and answered from the server.
pub const RELAY_PROTOCOL_VERSION: &str = "iroh-relay-v1";
/// The HTTP header name for relay client authentication
pub const CLIENT_AUTH_HEADER: HeaderName = HeaderName::from_static("x-iroh-relay-client-auth-v1");

/// ALPN protocol identifier for H3 relay connections.
///
/// Uses the standard HTTP/3 ALPN. The relay protocol is negotiated via
/// RFC 9220 extended CONNECT with `:protocol = websocket` and the
/// `Sec-WebSocket-Protocol` subprotocol header, mirroring the HTTP/1.1
/// WebSocket upgrade flow.
#[cfg(feature = "h3-transport")]
pub const ALPN_RELAY_H3: &[u8] = b"h3";
