//! Default values used in [`iroh-net`][`crate`]
use std::collections::HashMap;

use crate::hp::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

/// Hostname of the default Derp.
pub const DEFAULT_DERP_HOSTNAME: &str = "derp.iroh.network.";
/// STUN port as defined by [RFC 8489](<https://www.rfc-editor.org/rfc/rfc8489#section-18.6>)
pub const DEFAULT_DERP_STUN_PORT: u16 = 3478;
/// IPv4 of the default Derp.
pub const DEFAULT_DERP_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(35, 175, 99, 113);

/// Get the default [`DerpMap`].
pub fn default_derp_map() -> DerpMap {
    DerpMap {
        regions: HashMap::from_iter([(1, default_derp_region())].into_iter()),
    }
}

/// Get the default [`DerpRegion`].
pub fn default_derp_region() -> DerpRegion {
    // The default derper run by number0.
    let default_n0_derp = DerpNode {
        name: "default-1".into(),
        region_id: 1,
        url: format!("https://{DEFAULT_DERP_HOSTNAME}").parse().unwrap(),
        stun_only: false,
        stun_port: DEFAULT_DERP_STUN_PORT,
        ipv4: UseIpv4::Some(DEFAULT_DERP_IPV4),
        ipv6: UseIpv6::None,
        stun_test_ip: None,
    };
    DerpRegion {
        region_id: 1,
        nodes: vec![default_n0_derp],
        avoid: false,
        region_code: "default-1".into(),
    }
}
