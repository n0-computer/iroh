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
    /// A map of the different derp IDs to the [`DerpNode`] information
    nodes: Arc<BTreeMap<Url, Arc<DerpNode>>>,
}

impl DerpMap {
    /// Returns the sorted DERP URLs.
    pub fn urls(&self) -> impl Iterator<Item = &Url> {
        self.nodes.keys()
    }

    /// Create an empty Derp map.
    pub fn empty() -> Self {
        Self {
            nodes: Default::default(),
        }
    }

    /// Returns an `Iterator` over all known nodes.
    pub fn nodes(&self) -> impl Iterator<Item = (&Url, &Arc<DerpNode>)> {
        self.nodes.iter()
    }

    /// Is this a known node?
    pub fn contains_node(&self, url: &Url) -> bool {
        self.nodes.contains_key(url)
    }

    /// Get the given node.
    pub fn get_node(&self, url: &Url) -> Option<&Arc<DerpNode>> {
        self.nodes.get(url)
    }

    /// How many nodes are known?
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Are there any nodes in this map?
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Creates a new [`DerpMap`] with a single Derp server configured.
    ///
    /// Allows to set a custom STUN port and different IP addresses for IPv4 and IPv6.
    /// If IP addresses are provided, no DNS lookup will be performed.
    pub fn default_from_node(url: Url, stun_port: u16) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            url.clone(),
            DerpNode {
                url,
                stun_only: false,
                stun_port,
            }
            .into(),
        );

        DerpMap {
            nodes: Arc::new(nodes),
        }
    }

    /// Returns a [`DerpMap`] from a [`Url`].
    ///
    /// This will use the default STUN port and IP addresses resolved from the URL's host name via DNS.
    /// Derp nodes are specified at <../../../docs/derp_nodes.md>
    pub fn from_url(url: Url) -> Self {
        Self::default_from_node(url, DEFAULT_DERP_STUN_PORT)
    }

    /// Constructs the [`DerpMap`] from an iterator of [`DerpNode`]s.
    pub fn from_nodes(value: impl IntoIterator<Item = DerpNode>) -> Result<Self> {
        let mut map = BTreeMap::new();
        for node in value.into_iter() {
            ensure!(!map.contains_key(&node.url), "Duplicate node url");
            map.insert(node.url.clone(), node.into());
        }
        Ok(DerpMap { nodes: map.into() })
    }
}

impl fmt::Display for DerpMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Information on a specific derp server.
///
/// Includes the Url where it can be dialed.
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
