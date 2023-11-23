//! based on tailscale/tailcfg/derpmap.go

use std::{collections::BTreeMap, fmt, sync::Arc};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::defaults::DEFAULT_DERP_STUN_PORT;

/// Configuration options for the Derp servers of the magic endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerpMode {
    /// Disable Derp servers completely.
    Disabled,
    /// Use the default Derp map, with Derp servers from n0.
    Default,
    /// Use a custom Derp map.
    Custom(DerpMap),
}

/// Configuration of all the Derp servers that can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpMap {
    /// A map of the different region IDs to the [`DerpRegion`] information
    regions: Arc<BTreeMap<Url, DerpRegion>>,
}

impl DerpMap {
    /// Returns the sorted region URLs.
    pub fn region_urls(&self) -> impl Iterator<Item = &Url> {
        self.regions.keys()
    }

    /// Create an empty Derp map.
    pub fn empty() -> Self {
        Self {
            regions: Default::default(),
        }
    }

    /// Returns an `Iterator` over all known regions.
    pub fn regions(&self) -> impl Iterator<Item = (&Url, &DerpRegion)> {
        self.regions.iter()
    }

    /// Is this a known region?
    pub fn contains_region(&self, url: &Url) -> bool {
        self.regions.contains_key(&url)
    }

    /// Get the given region.
    pub fn get_region(&self, url: &Url) -> Option<&DerpRegion> {
        self.regions.get(&url)
    }

    /// Get the given region mutable.
    #[cfg(test)]
    pub fn get_region_mut(&mut self, url: &Url) -> Option<&mut DerpRegion> {
        Arc::get_mut(&mut self.regions).and_then(|r| r.get_mut(&url))
    }

    #[cfg(test)]
    pub fn get_node_mut(&mut self, url: &Url, node_idx: usize) -> Option<&mut DerpNode> {
        Arc::get_mut(&mut self.regions)
            .and_then(|regions| regions.get_mut(&url))
            .map(|region| region.nodes.as_mut_slice())
            .and_then(|slice| slice.get_mut(node_idx))
            .map(Arc::make_mut)
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
    pub fn default_from_node(url: Url, stun_port: u16) -> Self {
        let mut regions = BTreeMap::new();
        regions.insert(
            url.clone(),
            DerpRegion {
                nodes: vec![DerpNode {
                    url,
                    stun_only: false,
                    stun_port,
                }
                .into()],
                avoid: false,
                region_code: "default".into(),
            },
        );

        DerpMap {
            regions: Arc::new(regions),
        }
    }

    /// Returns a [`DerpMap`] from a [`Url`] and a `region_id`
    ///
    /// This will use the default STUN port and IP addresses resolved from the URL's host name via DNS.
    /// Region IDs are specified at <../../../docs/derp_regions.md>
    pub fn from_url(url: Url) -> Self {
        Self::default_from_node(url, DEFAULT_DERP_STUN_PORT)
    }

    /// Constructs the [`DerpMap`] from an iterator of [`DerpRegion`]s.
    pub fn from_regions(value: impl IntoIterator<Item = (Url, DerpRegion)>) -> Result<Self> {
        let mut map = BTreeMap::new();
        for (url, region) in value.into_iter() {
            ensure!(!map.contains_key(&url), "Duplicate region id");
            ensure!(!region.nodes.is_empty(), "A DerpRegion must have DerpNodes");
            for node in region.nodes.iter() {
                ensure!(
                    node.url == url,
                    "DerpNode region_id does not match DerpRegion region_id"
                );
            }
            map.insert(url, region);
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
    /// A list of [`DerpNode`]s in this region
    pub nodes: Vec<Arc<DerpNode>>,
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
    /// The [`Url`] where this derp server can be dialed.
    #[debug("{}", url)]
    pub url: Url,
    /// Whether this derp server should only be used for STUN requests.
    ///
    /// This essentially allows you to use a normal STUN server as a DERP node, no DERP
    /// functionality is used.
    pub stun_only: bool,
    /// The stun port of the derp server.
    ///
    /// Setting this to `0` means the default STUN port is used.
    pub stun_port: u16,
}

impl fmt::Display for DerpNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
