//! Default values used in [`iroh-net`][`crate`]

use url::Url;

use crate::relay::{RelayMap, RelayNode};

/// The default STUN port used by the Relay server.
///
/// The STUN port as defined by [RFC
/// 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

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
pub(crate) mod timeouts {
    use std::time::Duration;

    // Timeouts for netcheck

    /// Maximum duration to wait for a netcheck report.
    pub(crate) const NETCHECK_REPORT_TIMEOUT: Duration = Duration::from_secs(10);

    /// The maximum amount of time netcheck will spend gathering a single report.
    pub(crate) const OVERALL_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

    /// The total time we wait for all the probes.
    ///
    /// This includes the STUN, ICMP and HTTPS probes, which will all
    /// start at different times based on the ProbePlan.
    pub(crate) const PROBES_TIMEOUT: Duration = Duration::from_secs(3);

    /// How long to await for a captive-portal result.
    ///
    /// This delay is chosen so it starts after good-working STUN probes
    /// would have finished, but not too long so the delay is bearable if
    /// STUN is blocked.
    pub(crate) const CAPTIVE_PORTAL_DELAY: Duration = Duration::from_millis(200);

    /// Timeout for captive portal checks
    ///
    /// Must be lower than [`OVERALL_REPORT_TIMEOUT`] minus
    /// [`CAPTIVE_PORTAL_DELAY`].
    pub(crate) const CAPTIVE_PORTAL_TIMEOUT: Duration = Duration::from_secs(2);

    pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(3);

    /// The amount of time we wait for a hairpinned packet to come back.
    pub(crate) const HAIRPIN_CHECK_TIMEOUT: Duration = Duration::from_millis(100);

    /// Maximum duration a UPnP search can take before timing out.
    pub(crate) const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(1);

    /// Timeout to receive a response from a PCP server.
    pub(crate) const PCP_RECV_TIMEOUT: Duration = Duration::from_millis(500);

    /// Default Pinger timeout
    pub(crate) const DEFAULT_PINGER_TIMEOUT: Duration = Duration::from_secs(5);

    /// Timeout to receive a response from a NAT-PMP server.
    pub(crate) const NAT_PMP_RECV_TIMEOUT: Duration = Duration::from_millis(500);

    /// Timeouts specifically used in the iroh-relay
    pub(crate) mod relay {
        use super::*;

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
        pub(crate) const SERVER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
    }
}
