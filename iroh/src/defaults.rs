//! Default values used in [`iroh`][`crate`]

use iroh_base::relay_map::QuicConfig;
/// The default QUIC port used by the Relay server to accept QUIC connections
/// for QUIC address discovery
///
/// The port is "QUIC" typed on a phone keypad.
pub use iroh_base::relay_map::DEFAULT_RELAY_QUIC_PORT;
/// The default STUN port used by the Relay server.
///
/// The STUN port as defined by [RFC
/// 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub use iroh_base::relay_map::DEFAULT_STUN_PORT;
use url::Url;

/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Production configuration.
pub mod prod {
    use iroh_base::relay_map::{QuicConfig, RelayMap, RelayNode};

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
            quic: Some(QuicConfig::default()),
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
            quic: Some(QuicConfig::default()),
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
            quic: Some(QuicConfig::default()),
        }
    }
}

/// Staging configuration.
///
/// Used by tests and might have incompatible changes deployed
///
/// Note: we have staging servers in EU and NA, but no corresponding staging server for AP at this time.
pub mod staging {
    use iroh_base::relay_map::{RelayMap, RelayNode};

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
            quic: Some(QuicConfig::default()),
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
            quic: Some(QuicConfig::default()),
        }
    }
}

/// Contains all timeouts that we use in `iroh`.
pub(crate) mod timeouts {
    use std::time::Duration;

    // Timeouts for net_report

    /// Maximum duration to wait for a net_report.
    pub(crate) const NET_REPORT_TIMEOUT: Duration = Duration::from_secs(10);
}
