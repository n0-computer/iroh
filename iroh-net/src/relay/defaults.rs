//! Default values used in [`iroh-net`][`crate`]

use url::Url;

use crate::relay::{RelayMap, RelayNode};

/// The default STUN port used by the Relay server.
///
/// The STUN port as defined by [RFC
/// 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// Production configuration.
pub mod prod {
    use super::*;

    /// Hostname of the default NA relay.
    pub const NA_RELAY_HOSTNAME: &str = "use1-1.relay.iroh.network.";
    /// Hostname of the default EU relay.
    pub const EU_RELAY_HOSTNAME: &str = "euw1-1.relay.iroh.network.";
    /// Hostname of the default Asia-Pacific relay.
    pub const AP_RELAY_HOSTNAME: &str = "aps1-1.relay.iroh.network.";

    /// Get the default [`RelayMap`].
    pub fn default_relay_map() -> RelayMap {
        RelayMap::from_nodes([
            default_na_relay_node(),
            default_eu_relay_node(),
            default_ap_relay_node(),
        ])
        .expect("default nodes invalid")
    }

    /// Get the default [`RelayNode`] for NA.
    pub fn default_na_relay_node() -> RelayNode {
        // The default NA relay server run by number0.
        let url: Url = format!("https://{NA_RELAY_HOSTNAME}")
            .parse()
            .expect("default url");
        RelayNode {
            url: url.into(),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        }
    }

    /// Get the default [`RelayNode`] for EU.
    pub fn default_eu_relay_node() -> RelayNode {
        // The default EU relay server run by number0.
        let url: Url = format!("https://{EU_RELAY_HOSTNAME}")
            .parse()
            .expect("default_url");
        RelayNode {
            url: url.into(),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        }
    }

    /// Get the default [`RelayNode`] for Asia-Pacific
    pub fn default_ap_relay_node() -> RelayNode {
        // The default Asia-Pacific relay server run by number0.
        let url: Url = format!("https://{AP_RELAY_HOSTNAME}")
            .parse()
            .expect("default_url");
        RelayNode {
            url: url.into(),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        }
    }
}

/// Staging configuration.
///
/// Used by tests and might have incompatible changes deployed
///
/// Note: we have staging servers in EU and NA, but no corresponding staging server for AP at this time.
pub mod staging {
    use super::*;

    /// Hostname of the default NA relay.
    pub const NA_RELAY_HOSTNAME: &str = "staging-use1-1.relay.iroh.network.";
    /// Hostname of the default EU relay.
    pub const EU_RELAY_HOSTNAME: &str = "staging-euw1-1.relay.iroh.network.";

    /// Get the default [`RelayMap`].
    pub fn default_relay_map() -> RelayMap {
        RelayMap::from_nodes([default_na_relay_node(), default_eu_relay_node()])
            .expect("default nodes invalid")
    }

    /// Get the default [`RelayNode`] for NA.
    pub fn default_na_relay_node() -> RelayNode {
        // The default NA relay server run by number0.
        let url: Url = format!("https://{NA_RELAY_HOSTNAME}")
            .parse()
            .expect("default url");
        RelayNode {
            url: url.into(),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        }
    }

    /// Get the default [`RelayNode`] for EU.
    pub fn default_eu_relay_node() -> RelayNode {
        // The default EU relay server run by number0.
        let url: Url = format!("https://{EU_RELAY_HOSTNAME}")
            .parse()
            .expect("default_url");
        RelayNode {
            url: url.into(),
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
        }
    }
}

/// Contains all timeouts that we use in `iroh-net`.
pub(super) mod timeouts {
    use std::time::Duration;

    /// Timeout used by the relay client while connecting to the relay server,
    /// using `TcpStream::connect`
    pub(crate) const DIAL_NODE_TIMEOUT: Duration = Duration::from_millis(1500);
    /// Timeout for expecting a pong from the relay server
    pub(crate) const PING_TIMEOUT: Duration = Duration::from_secs(5);
    /// Timeout for the entire relay connection, which includes dns, dialing
    /// the server, upgrading the connection, and completing the handshake
    pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    /// Timeout for our async dns resolver
    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(1);

    /// Maximum time the client will wait to receive on the connection, since
    /// the last message. Longer than this time and the client will consider
    /// the connection dead.
    pub(crate) const CLIENT_RECV_TIMEOUT: Duration = Duration::from_secs(120);

    /// Maximum time the server will attempt to get a successful write to the connection.
    #[cfg(feature = "iroh-relay")]
    #[cfg_attr(iroh_docsrs, doc(cfg(feature = "iroh-relay")))]
    pub(crate) const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
}
