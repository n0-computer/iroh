//! Default values used in [`iroh-net`][`crate`]

use crate::hp::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

/// Get the default [`DerpMap`].
pub fn default_derp_map() -> DerpMap {
    DerpMap {
        regions: [(1, default_derp_region())].into(),
    }
}

/// Get the default [`DerpRegion`].
pub fn default_derp_region() -> DerpRegion {
    // The default derper run by number0.
    let default_n0_derp = DerpNode {
        name: "default-1".into(),
        region_id: 1,
        url: "https://derp.iroh.network".parse().unwrap(),
        stun_only: false,
        stun_port: 3478,
        ipv4: UseIpv4::Some([35, 175, 99, 113].into()),
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
