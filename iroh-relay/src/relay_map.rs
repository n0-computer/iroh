//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};

use crate::defaults::DEFAULT_RELAY_QUIC_PORT;

/// Configuration of all the relay servers that can be used.
#[derive(Debug, Clone)]
pub struct RelayMap {
    /// A map of the different relay IDs to the [`RelayNode`] information
    nodes: Arc<RwLock<BTreeMap<RelayUrl, Arc<RelayNode>>>>,
}

impl PartialEq for RelayMap {
    fn eq(&self, other: &Self) -> bool {
        let this = self.nodes.read().expect("poisoned");
        let that = other.nodes.read().expect("poisoned");
        this.eq(&*that)
    }
}

impl Eq for RelayMap {}

impl RelayMap {
    /// Returns the sorted relay URLs.
    pub fn urls<T>(&self) -> T
    where
        T: FromIterator<RelayUrl>,
    {
        self.nodes
            .read()
            .expect("poisoned")
            .keys()
            .cloned()
            .collect::<T>()
    }

    /// Create an empty relay map.
    pub fn empty() -> Self {
        Self {
            nodes: Default::default(),
        }
    }

    /// Returns an `Iterator` over all known nodes.
    pub fn nodes<T>(&self) -> T
    where
        T: FromIterator<Arc<RelayNode>>,
    {
        self.nodes
            .read()
            .expect("poisoned")
            .values()
            .cloned()
            .collect::<T>()
    }

    /// Is this a known node?
    pub fn contains_node(&self, url: &RelayUrl) -> bool {
        self.nodes.read().expect("poisoned").contains_key(url)
    }

    /// Get the given node.
    pub fn get_node(&self, url: &RelayUrl) -> Option<Arc<RelayNode>> {
        self.nodes.read().expect("poisoned").get(url).cloned()
    }

    /// How many nodes are known?
    pub fn len(&self) -> usize {
        self.nodes.read().expect("poisoned").len()
    }

    /// Are there any nodes in this map?
    pub fn is_empty(&self) -> bool {
        self.nodes.read().expect("poisoned").is_empty()
    }

    /// Insert a new relay.
    pub fn insert(&self, url: RelayUrl, node: Arc<RelayNode>) -> Option<Arc<RelayNode>> {
        self.nodes.write().expect("poisoned").insert(url, node)
    }

    /// Removes an existing relay by `RelayUrl`.
    pub fn remove(&self, url: &RelayUrl) -> Option<Arc<RelayNode>> {
        self.nodes.write().expect("poisoned").remove(url)
    }
}

impl FromIterator<RelayNode> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayNode>>(iter: T) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(
                iter.into_iter()
                    .map(|node| (node.url.clone(), Arc::new(node)))
                    .collect(),
            )),
        }
    }
}

impl From<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from a [`RelayUrl`].
    ///
    /// The [`RelayNode`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from(value: RelayUrl) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(
                [(value.clone(), Arc::new(value.into()))].into(),
            )),
        }
    }
}

impl From<RelayNode> for RelayMap {
    fn from(value: RelayNode) -> Self {
        Self {
            nodes: Arc::new(RwLock::new([(value.url.clone(), Arc::new(value))].into())),
        }
    }
}

impl FromIterator<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from an iterator of [`RelayUrl`].
    ///
    /// The [`RelayNode`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(
                iter.into_iter()
                    .map(|url| (url.clone(), Arc::new(url.into())))
                    .collect(),
            )),
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
