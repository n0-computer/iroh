//! HTTP-specific constants for the relay server and client.

pub(crate) const HTTP_UPGRADE_PROTOCOL: &str = "iroh derp http";
pub(crate) const WEBSOCKET_UPGRADE_PROTOCOL: &str = "websocket";
#[cfg(feature = "server")] // only used in the server for now
pub(crate) const SUPPORTED_WEBSOCKET_VERSION: &str = "13";

/// The HTTP path under which the relay accepts relaying connections
/// (over websockets and a custom upgrade protocol).
pub const RELAY_PATH: &str = "/relay";
/// The HTTP path under which the relay allows doing latency queries for testing.
pub const RELAY_PROBE_PATH: &str = "/ping";
/// The legacy HTTP path under which the relay used to accept relaying connections.
/// We keep this for backwards compatibility.
#[cfg(feature = "server")] // legacy paths only used on server-side for backwards compat
pub(crate) const LEGACY_RELAY_PATH: &str = "/derp";

/// The HTTP upgrade protocol used for relaying.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protocol {
    /// Relays over the custom relaying protocol with a custom HTTP upgrade header.
    Relay,
    /// Relays over websockets.
    ///
    /// Originally introduced to support browser connections.
    Websocket,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Websocket
    }
}

impl Protocol {
    /// The HTTP upgrade header used or expected.
    pub const fn upgrade_header(&self) -> &'static str {
        match self {
            Protocol::Relay => HTTP_UPGRADE_PROTOCOL,
            Protocol::Websocket => WEBSOCKET_UPGRADE_PROTOCOL,
        }
    }

    /// Tries to match the value of an HTTP upgrade header to figure out which protocol should be initiated.
    pub fn parse_header(header: &http::HeaderValue) -> Option<Self> {
        let header_bytes = header.as_bytes();
        if header_bytes == Protocol::Relay.upgrade_header().as_bytes() {
            Some(Protocol::Relay)
        } else if header_bytes == Protocol::Websocket.upgrade_header().as_bytes() {
            Some(Protocol::Websocket)
        } else {
            None
        }
    }
}
