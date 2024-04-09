//! Default values used in [`iroh-net`][`crate`]

use url::Url;

use crate::relay::{RelayMap, RelayNode};

/// Hostname of the default NA relay.
pub const NA_RELAY_HOSTNAME: &str = "use1-1.derp.iroh.network.";
/// Hostname of the default EU relay.
pub const EU_RELAY_HOSTNAME: &str = "euw1-1.derp.iroh.network.";
/// Hostname of the default test relay.
pub const TEST_RELAY_HOSTNAME: &str = "test-2.derp.iroh.network.";

/// STUN port as defined by [RFC 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_RELAY_STUN_PORT: u16 = 3478;

/// Get the default [`RelayMap`].
pub fn default_relay_map() -> RelayMap {
    RelayMap::from_nodes([
        default_na_relay_node(),
        default_eu_relay_node(),
        default_test_relay_node(),
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
        stun_port: DEFAULT_RELAY_STUN_PORT,
    }
}

/// Get the default [`RelayNode`] for NA.
pub fn default_test_relay_node() -> RelayNode {
    // The default NA relay server run by number0.
    let url: Url = format!("https://{TEST_RELAY_HOSTNAME}")
        .parse()
        .expect("default url");
    RelayNode {
        url: url.into(),
        stun_only: false,
        stun_port: DEFAULT_RELAY_STUN_PORT,
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
        stun_port: DEFAULT_RELAY_STUN_PORT,
    }
}
