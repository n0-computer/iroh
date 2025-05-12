//! based on tailscale/tailcfg/derpmap.go

use std::{collections::BTreeMap, fmt, sync::Arc};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};

use crate::defaults::{DEFAULT_RELAY_QUIC_PORT, DEFAULT_STUN_PORT};

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
}

impl FromIterator<RelayNode> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayNode>>(iter: T) -> Self {
        Self {
            nodes: Arc::new(
                iter.into_iter()
                    .map(|node| (node.url.clone(), Arc::new(node)))
                    .collect(),
            ),
        }
    }
}

impl From<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from a [`RelayUrl`].
    ///
    /// The [`RelayNode`]s in the [`RelayMap`] will have the default STUN and QUIC address
    /// discovery ports.
    fn from(value: RelayUrl) -> Self {
        Self {
            nodes: Arc::new([(value.clone(), Arc::new(value.into()))].into()),
        }
    }
}

impl From<RelayNode> for RelayMap {
    fn from(value: RelayNode) -> Self {
        Self {
            nodes: Arc::new([(value.url.clone(), Arc::new(value))].into()),
        }
    }
}

impl FromIterator<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from an iterator of [`RelayUrl`].
    ///
    /// The [`RelayNode`]s in the [`RelayMap`] will have the default STUN and QUIC address
    /// discovery ports.
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self {
            nodes: Arc::new(
                iter.into_iter()
                    .map(|url| (url.clone(), Arc::new(url.into())))
                    .collect(),
            ),
        }
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
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
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
    /// Configuration to speak to the QUIC endpoint on the relay server.
    ///
    /// When `None`, we will not attempt to do QUIC address discovery
    /// with this relay server.
    #[serde(default = "quic_config")]
    pub quic: Option<RelayQuicConfig>,
}

impl From<RelayUrl> for RelayNode {
    fn from(value: RelayUrl) -> Self {
        Self {
            url: value,
            stun_only: false,
            stun_port: DEFAULT_STUN_PORT,
            quic: quic_config(),
        }
    }
}

fn quic_config() -> Option<RelayQuicConfig> {
    Some(RelayQuicConfig::default())
}

/// Configuration for speaking to the QUIC endpoint on the relay
/// server to do QUIC address discovery.
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct RelayQuicConfig {
    /// The port on which the connection should be bound to.
    pub port: u16,
}

impl Default for RelayQuicConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_RELAY_QUIC_PORT,
        }
    }
}

impl fmt::Display for RelayNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
