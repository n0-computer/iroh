//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::defaults::DEFAULT_DERP_STUN_PORT;

/// Configuration of all the Derp servers that can be used.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DerpMap {
    /// A map of the different region IDs to the [`DerpRegion`] information
    regions: Arc<HashMap<u16, DerpRegion>>,
}

impl DerpMap {
    /// Returns the sorted region IDs.
    pub fn region_ids(&self) -> Vec<u16> {
        let mut ids: Vec<_> = self.regions.keys().copied().collect();
        ids.sort();
        ids
    }

    /// Returns an `Iterator` over all known regions.
    pub fn regions(&self) -> impl Iterator<Item = &DerpRegion> {
        self.regions.values()
    }

    /// Is this a known region?
    pub fn contains_region(&self, region_id: u16) -> bool {
        self.regions.contains_key(&region_id)
    }

    /// Get the given region.
    pub fn get_region(&self, region_id: u16) -> Option<&DerpRegion> {
        self.regions.get(&region_id)
    }

    /// Get the given region mutable.
    #[cfg(test)]
    pub fn get_region_mut(&mut self, region_id: u16) -> Option<&mut DerpRegion> {
        Arc::get_mut(&mut self.regions).and_then(|r| r.get_mut(&region_id))
    }

    /// How many regions are known?
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Are there any regions in this map?
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Creates a new [`DerpMap`] with a single Derp server configured.
    ///
    /// Allows to set a custom STUN port and different IP addresses for IPv4 and IPv6.
    /// If IP addresses are provided, no DNS lookup will be performed.
    pub fn default_from_node(
        url: Url,
        stun_port: u16,
        derp_ipv4: UseIpv4,
        derp_ipv6: UseIpv6,
        region_id: u16,
    ) -> Self {
        let mut regions = HashMap::with_capacity(1);
        regions.insert(
            region_id,
            DerpRegion {
                region_id,
                nodes: vec![DerpNode {
                    name: "default-1".into(),
                    region_id,
                    url,
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

        DerpMap {
            regions: Arc::new(regions),
        }
    }

    /// Returns the [`DerpNode`] by name.
    pub fn find_by_name(&self, node_name: &str) -> Option<&DerpNode> {
        self.regions
            .values()
            .flat_map(|r| r.nodes.iter())
            .find(|n| n.name == node_name)
    }

    /// Returns a [`DerpMap`] from a [`Url`] and a `region_id`
    ///
    /// This will use the default STUN port and IP addresses resolved from the URL's host name via DNS.
    /// Region IDs are specified at <../../../docs/derp_regions.md>
    pub fn from_url(url: Url, region_id: u16) -> Self {
        Self::default_from_node(
            url,
            DEFAULT_DERP_STUN_PORT,
            UseIpv4::TryDns,
            UseIpv6::TryDns,
            region_id,
        )
    }

    /// Constructs the [`DerpMap`] from an iterator of [`DerpRegion`]s.
    pub fn from_regions(value: impl IntoIterator<Item = DerpRegion>) -> Result<Self> {
        let mut map = HashMap::new();
        for region in value.into_iter() {
            ensure!(!map.contains_key(&region.region_id), "Duplicate region id");
            ensure!(!region.nodes.is_empty(), "A DerpRegion must have DerpNodes");
            for node in region.nodes.iter() {
                ensure!(
                    node.region_id == region.region_id,
                    "DerpNode region_id does not match DerpRegion region_id"
                );
            }
            map.insert(region.region_id, region);
        }
        Ok(DerpMap {
            regions: map.into(),
        })
    }
}

impl fmt::Display for DerpMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// A geographic region running DERP relay node(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct DerpRegion {
    /// A unique integer for a geographic region
    pub region_id: u16,
    /// A list of [`DerpNode`]s in this region
    pub nodes: Vec<DerpNode>,
    /// Whether or not to avoid this region
    pub avoid: bool,
    /// The region-specific string identifier
    pub region_code: String,
}

impl DerpRegion {
    /// Whether this region has a full DERP node configured.
    ///
    /// It is possible for a region to only have STUN servers configured and no full blown
    /// DERP server.  In this case this will return false.
    pub fn has_derp_node(&self) -> bool {
        for node in self.nodes.iter() {
            if !node.stun_only {
                return true;
            }
        }
        false
    }
}

/// Information on a specific derp server.
///
/// Includes the region in which it can be found, as well as how to dial the server.
#[derive(derive_more::Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct DerpNode {
    /// The name of this derp server.
    ///
    /// This name MUST be unique among all configured DERP servers.
    pub name: String,
    /// The numeric region ID
    pub region_id: u16,
    /// The [`Url`] where this derp server can be dialed
    #[debug("{}", url)]
    pub url: Url,
    /// Whether this derp server should only be used for STUN requests
    pub stun_only: bool,
    /// The stun port of the derp server
    pub stun_port: u16,
    /// Optional stun-specific IP address
    pub stun_test_ip: Option<IpAddr>,
    /// Whether to dial this server on IPv4.
    pub ipv4: UseIpv4,
    /// Whether to dial this server on IPv6.
    pub ipv6: UseIpv6,
}

impl fmt::Display for DerpNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Whether we should use IPv4 when communicating with this derp server
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum UseIpv4 {
    /// Indicates we do not have an IPv4 address, but the server may still
    /// be able to communicate over IPv4 by resolving the hostname over DNS
    TryDns,
    /// Do not attempt to contact the derp server using IPv4
    Disabled,
    /// The IPv4 address of the derp server
    Some(Ipv4Addr),
}

impl UseIpv4 {
    /// Is this enabled?
    pub fn is_enabled(&self) -> bool {
        !matches!(self, &UseIpv4::Disabled)
    }
}

/// Whether we should use IPv6 when communicating with this derp server
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum UseIpv6 {
    /// Indicates we do not have an IPv6 address, but the server may still
    /// be able to communicate over IPv6 by resolving the hostname over DNS
    TryDns,
    /// Do not attempt to contact the derp server using IPv6
    Disabled,
    /// The IPv6 address of the derp server
    Some(Ipv6Addr),
}

impl UseIpv6 {
    /// Is this enabled?
    pub fn is_enabled(&self) -> bool {
        !matches!(self, &UseIpv6::Disabled)
    }
}
