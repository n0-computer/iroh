//! Default values used in [`iroh`][`crate`]

/// The default QUIC port used by the Relay server to accept QUIC connections
/// for QUIC address discovery
///
/// The port is "QUIC" typed on a phone keypad.
pub use iroh_relay::defaults::DEFAULT_RELAY_QUIC_PORT;
use url::Url;

/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Production configuration.
pub mod prod {
    use iroh_relay::{RelayMap, RelayNode, RelayQuicConfig};

    use super::*;

    /// Hostname of the default NA relay.
    pub const NA_RELAY_HOSTNAME: &str = "use1-1.relay.n0.iroh-canary.iroh.link.";
    /// Hostname of the default EU relay.
    pub const EU_RELAY_HOSTNAME: &str = "euc1-1.relay.n0.iroh-canary.iroh.link.";
    /// Hostname of the default Asia-Pacific relay.
    pub const AP_RELAY_HOSTNAME: &str = "aps1-1.relay.n0.iroh-canary.iroh.link.";

    /// Get the default [`RelayMap`].
    pub fn default_relay_map() -> RelayMap {
        RelayMap::from_iter([
            default_na_relay_node(),
            default_eu_relay_node(),
            default_ap_relay_node(),
        ])
    }

    /// Get the default [`RelayNode`] for NA.
    pub fn default_na_relay_node() -> RelayNode {
        // The default NA relay server run by number0.
        let url: Url = format!("https://{NA_RELAY_HOSTNAME}")
            .parse()
            .expect("default url");
        RelayNode {
            url: url.into(),
            quic: Some(RelayQuicConfig::default()),
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
            quic: Some(RelayQuicConfig::default()),
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
            quic: Some(RelayQuicConfig::default()),
        }
    }
}

/// Staging configuration.
///
/// Used by tests and might have incompatible changes deployed
///
/// Note: we have staging servers in EU and NA, but no corresponding staging server for AP at this time.
pub mod staging {
    use iroh_relay::{RelayMap, RelayNode, RelayQuicConfig};

    use super::*;

    /// Hostname of the default NA relay.
    pub const NA_RELAY_HOSTNAME: &str = "staging-use1-1.relay.iroh.network.";
    /// Hostname of the default EU relay.
    pub const EU_RELAY_HOSTNAME: &str = "staging-euw1-1.relay.iroh.network.";

    /// Get the default [`RelayMap`].
    pub fn default_relay_map() -> RelayMap {
        RelayMap::from_iter([default_na_relay_node(), default_eu_relay_node()])
    }

    /// Get the default [`RelayNode`] for NA.
    pub fn default_na_relay_node() -> RelayNode {
        // The default NA relay server run by number0.
        let url: Url = format!("https://{NA_RELAY_HOSTNAME}")
            .parse()
            .expect("default url");
        RelayNode {
            url: url.into(),
            quic: Some(RelayQuicConfig::default()),
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
            quic: Some(RelayQuicConfig::default()),
        }
    }
}

/// Contains all timeouts that we use in `iroh`.
pub(crate) mod timeouts {
    use n0_future::time::Duration;

    // Timeouts for net_report

    /// Maximum duration to wait for a net_report.
    pub(crate) const NET_REPORT_TIMEOUT: Duration = Duration::from_secs(10);
}
