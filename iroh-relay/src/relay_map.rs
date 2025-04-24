//! based on tailscale/tailcfg/derpmap.go

use std::{collections::BTreeMap, fmt, sync::Arc};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};
use tracing::warn;

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

    /// Creates a new [`RelayMap`] with a single relay server configured.
    ///
    /// Allows to set a custom STUN port and different IP addresses for IPv4 and IPv6.
    /// If IP addresses are provided, no DNS lookup will be performed.
    ///
    /// Sets the port to the default [`DEFAULT_RELAY_QUIC_PORT`].
    pub fn default_from_node(url: RelayUrl, stun_port: u16) -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(
            url.clone(),
            RelayNode {
                url,
                stun_only: false,
                stun_port,
                quic: Some(RelayQuicConfig::default()),
            }
            .into(),
        );

        RelayMap {
            nodes: Arc::new(nodes),
        }
    }

    /// Returns a [`RelayMap`] from a [`RelayUrl`].
    ///
    /// This will use the default STUN port, the default QUIC port
    /// (as defined by the `iroh-relay` crate) and IP addresses
    /// resolved from the URL's host name via DNS.
    /// relay nodes are specified at <../../docs/relay_nodes.md>
    pub fn from_url(url: RelayUrl) -> Self {
        Self::default_from_node(url, DEFAULT_STUN_PORT)
    }

    /// Constructs the [`RelayMap`] from an iterator of [`RelayNode`]s.
    pub fn from_nodes<I: Into<Arc<RelayNode>>>(value: impl IntoIterator<Item = I>) -> Self {
        let mut map = BTreeMap::new();
        for node in value.into_iter() {
            let node = node.into();
            if map.contains_key(&node.url) {
                warn!("Duplicate node url: {}, skipping", node.url);
                continue;
            }
            map.insert(node.url.clone(), node);
        }
        RelayMap { nodes: map.into() }
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
