//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use url::Url;

/// Configuration of all the Derp servers that can be used.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DerpMap {
    pub regions: HashMap<u16, DerpRegion>,
}

impl DerpMap {
    /// Returns the sorted region IDs.
    pub fn region_ids(&self) -> Vec<u16> {
        let mut ids: Vec<_> = self.regions.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Creates a new [`DerpMap`] with a single Derp server configured.
    pub fn default_from_node(
        url: Url,
        stun_port: u16,
        derp_ipv4: UseIpv4,
        derp_ipv6: UseIpv6,
    ) -> Self {
        let mut dm = DerpMap {
            regions: HashMap::new(),
        };

        dm.regions.insert(
            1,
            DerpRegion {
                region_id: 1,
                nodes: vec![DerpNode {
                    name: "default-1".into(),
                    region_id: 1,
                    url: url,
                    stun_only: !derp_ipv4.is_enabled() && !derp_ipv6.is_enabled(),
                    stun_port,
                    ipv4: derp_ipv4,
                    ipv6: derp_ipv6,
                    stun_test_ip: None,
                }],
                avoid: false,
                region_code: "default".into(),
            },
        );

        dm
    }
}

impl fmt::Display for DerpMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// A geographic region running DERP relay node(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerpRegion {
    /// A unique integer for a geographic region.
    pub region_id: u16,
    pub nodes: Vec<DerpNode>,
    pub avoid: bool,
    pub region_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerpNode {
    pub name: String,
    pub region_id: u16,
    pub url: Url,
    pub stun_only: bool,
    pub stun_port: u16,
    pub stun_test_ip: Option<IpAddr>,
    /// Optionally forces an IPv4 address to use, instead of using DNS.
    /// If `None`, A record(s) from DNS lookups of HostName are used.
    /// If `Disabled`, IPv4 is not used;
    pub ipv4: UseIpv4,
    /// Optionally forces an IPv6 address to use, instead of using DNS.
    /// If `None`, A record(s) from DNS lookups of HostName are used.
    /// If `Disabled`, IPv6 is not used;
    pub ipv6: UseIpv6,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UseIpv4 {
    None,
    Disabled,
    Some(Ipv4Addr),
}

impl UseIpv4 {
    /// Is this enabled?
    pub fn is_enabled(&self) -> bool {
        !matches!(self, &UseIpv4::Disabled)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UseIpv6 {
    None,
    Disabled,
    Some(Ipv6Addr),
}

impl UseIpv6 {
    /// Is this enabled?
    pub fn is_enabled(&self) -> bool {
        !matches!(self, &UseIpv6::Disabled)
    }
}
