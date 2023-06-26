use std::collections::HashMap;

use crate::hp::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

pub fn default_derp_map() -> DerpMap {
    DerpMap {
        regions: HashMap::from_iter([(1, default_derp_region())].into_iter()),
    }
}

pub fn default_derp_region() -> DerpRegion {
    // The default derper run by number0.
    let default_n0_derp = DerpNode {
        name: "default-1".into(),
        region_id: 1,
        host_name: "derp.iroh.network".into(),
        stun_only: false,
        stun_port: 3478,
        ipv4: UseIpv4::Some("35.175.99.113".parse().unwrap()),
        ipv6: UseIpv6::None,
        derp_port: 443,
        stun_test_ip: None,
    };
    DerpRegion {
        region_id: 1,
        nodes: vec![default_n0_derp],
        avoid: false,
        region_code: "default-1".into(),
    }
}
