//! Default values used in [`iroh-net`][`crate`]

use url::Url;

use crate::derp::{DerpMap, DerpNode};

/// Hostname of the default NA Derp.
pub const NA_DERP_HOSTNAME: &str = "use1-1.derp.iroh.network.";
/// Hostname of the default EU Derp.
pub const EU_DERP_HOSTNAME: &str = "euw1-1.derp.iroh.network.";

/// STUN port as defined by [RFC 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_DERP_STUN_PORT: u16 = 3478;

/// Get the default [`DerpMap`].
pub fn default_derp_map() -> DerpMap {
    DerpMap::from_nodes([default_na_derp_node(), default_eu_derp_node()])
        .expect("default regions invalid")
}

/// Get the default [`DerpRegion`] for NA.
pub fn default_na_derp_node() -> (Url, DerpNode) {
    // The default NA derper run by number0.
    let url: Url = format!("https://{NA_DERP_HOSTNAME}").parse().unwrap();
    let default_n0_derp = DerpNode {
        url: url.clone(),
        stun_only: false,
        stun_port: DEFAULT_DERP_STUN_PORT,
    };
    (url, default_n0_derp)
}

/// Get the default [`DerpNode`] for EU.
pub fn default_eu_derp_node() -> (Url, DerpNode) {
    // The default EU derper run by number0.
    let url: Url = format!("https://{EU_DERP_HOSTNAME}").parse().unwrap();
    let default_n0_derp = DerpNode {
        url: url.clone(),
        stun_only: false,
        stun_port: DEFAULT_DERP_STUN_PORT,
    };
    (url, default_n0_derp)
}
