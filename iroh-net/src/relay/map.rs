//! based on tailscale/tailcfg/derpmap.go

use std::{collections::BTreeMap, fmt, sync::Arc};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::defaults::DEFAULT_RELAY_STUN_PORT;

use super::RelayUrl;

/// Configuration options for the relay servers of the magic endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMode {
    /// Disable relay servers completely.
    Disabled,
    /// Use the default relay map, with relay servers from n0.
    Default,
    /// Use a custom relay map.
    Custom(RelayMap),
}

/// Configuration of all the relay servers that can be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMap {
    /// A map of the different relay IDs to the [`RelayNode`] information
    nodes: Arc<BTreeMap<RelayUrl, Arc<RelayNode>>>,
}

impl RelayMap {
    /// Returns the sorted relay URLs.
    pub fn urls(&self) -> impl Iterator<Item = &RelayUrl> {
        self.nodes.keys()
    }

    /// Create an empty relay map.
    pub fn empty() -> Self {
        Self {
            nodes: Default::default(),
        }
    }

    /// Returns an `Iterator` over all known nodes.
    pub fn nodes(&self) -> impl Iterator<Item = &Arc<RelayNode>> {
        self.nodes.values()
    }

    /// Is this a known node?
    pub fn contains_node(&self, url: &RelayUrl) -> bool {
        self.nodes.contains_key(url)
    }

    /// Get the given node.
    pub fn get_node(&self, url: &RelayUrl) -> Option<&Arc<RelayNode>> {
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

    /// Creates a new [`RelayMap] with a single relay server configured.
    ///
    /// Allows to set a custom STUN port and different IP addresses for IPv4 and IPv6.
    /// If IP addresses are provided, no DNS lookup will be performed.
    pub fn default_from_node(url: RelayUrl, stun_port: u16) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            url.clone(),
            RelayNode {
                url,
                stun_only: false,
                stun_port,
            }
            .into(),
        );

        RelayMap {
            nodes: Arc::new(nodes),
        }
    }

    /// Returns a [`RelayMap] from a [`RelayUrl`].
    ///
    /// This will use the default STUN port and IP addresses resolved from the URL's host name via DNS.
    /// relay nodes are specified at <../../../docs/relay_nodes.md>
    pub fn from_url(url: RelayUrl) -> Self {
        Self::default_from_node(url, DEFAULT_RELAY_STUN_PORT)
    }

    /// Constructs the [`RelayMap] from an iterator of [`RelayNode`]s.
    pub fn from_nodes(value: impl IntoIterator<Item = RelayNode>) -> Result<Self> {
        let mut map = BTreeMap::new();
        for node in value.into_iter() {
            ensure!(!map.contains_key(&node.url), "Duplicate node url");
            map.insert(node.url.clone(), node.into());
        }
        Ok(RelayMap { nodes: map.into() })
    }
}

impl fmt::Display for RelayMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self, f)
    }
}

/// Information on a specific relay server.
///
/// Includes the Url where it can be dialed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct RelayNode {
    /// The [`RelayUrl`] where this relay server can be dialed.
    pub url: RelayUrl,
    /// Whether this relay server should only be used for STUN requests.
    ///
    /// This essentially allows you to use a normal STUN server as a relay node, no relay
    /// functionality is used.
    pub stun_only: bool,
    /// The stun port of the relay server.
    ///
    /// Setting this to `0` means the default STUN port is used.
    pub stun_port: u16,
}

impl fmt::Display for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
