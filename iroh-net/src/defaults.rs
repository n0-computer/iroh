//! Default values used in [`iroh-net`][`crate`]

use url::Url;

use crate::derp::{DerpMap, DerpNode};

/// Hostname of the default NA relay.
pub const NA_RELAY_HOSTNAME: &str = "use1-1.relay.iroh.network.";
/// Hostname of the default EU relay.
pub const EU_RELAY_HOSTNAME: &str = "euw1-1.relay.iroh.network.";

/// STUN port as defined by [RFC 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_RELAY_STUN_PORT: u16 = 3478;

/// Get the default [`DerpMap`].
pub fn default_relay_map() -> DerpMap {
    DerpMap::from_nodes([default_na_relay_node(), default_eu_relay_node()])
        .expect("default nodes invalid")
}

/// Get the default [`DerpNode`] for NA.
pub fn default_na_relay_node() -> DerpNode {
    // The default NA relay server run by number0.
    let url: Url = format!("https://{NA_RELAY_HOSTNAME}")
        .parse()
        .expect("default url");
    DerpNode {
        url: url.into(),
        stun_only: false,
        stun_port: DEFAULT_RELAY_STUN_PORT,
    }
}

/// Get the default [`DerpNode`] for EU.
pub fn default_eu_relay_node() -> DerpNode {
    // The default EU relay server run by number0.
    let url: Url = format!("https://{EU_RELAY_HOSTNAME}")
        .parse()
        .expect("default_url");
    DerpNode {
        url: url.into(),
        stun_only: false,
        stun_port: DEFAULT_RELAY_STUN_PORT,
    }
}
