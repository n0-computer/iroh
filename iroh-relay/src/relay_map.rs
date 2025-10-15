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
    /// A map of the different relay IDs to the [`RelayEndpoint`] information
    endpoints: Arc<RwLock<BTreeMap<RelayUrl, Arc<RelayEndpoint>>>>,
}

impl PartialEq for RelayMap {
    fn eq(&self, other: &Self) -> bool {
        let this = self.endpoints.read().expect("poisoned");
        let that = other.endpoints.read().expect("poisoned");
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
        self.endpoints
            .read()
            .expect("poisoned")
            .keys()
            .cloned()
            .collect::<T>()
    }

    /// Create an empty relay map.
    pub fn empty() -> Self {
        Self {
            endpoints: Default::default(),
        }
    }

    /// Returns an `Iterator` over all known endpoints.
    pub fn endpoints<T>(&self) -> T
    where
        T: FromIterator<Arc<RelayEndpoint>>,
    {
        self.endpoints
            .read()
            .expect("poisoned")
            .values()
            .cloned()
            .collect::<T>()
    }

    /// Is this a known endpoint?
    pub fn contains_endpoint(&self, url: &RelayUrl) -> bool {
        self.endpoints.read().expect("poisoned").contains_key(url)
    }

    /// Get the given endpoint.
    pub fn get_endpoint(&self, url: &RelayUrl) -> Option<Arc<RelayEndpoint>> {
        self.endpoints.read().expect("poisoned").get(url).cloned()
    }

    /// How many endpoints are known?
    pub fn len(&self) -> usize {
        self.endpoints.read().expect("poisoned").len()
    }

    /// Are there any endpoints in this map?
    pub fn is_empty(&self) -> bool {
        self.endpoints.read().expect("poisoned").is_empty()
    }

    /// Insert a new relay.
    pub fn insert(
        &self,
        url: RelayUrl,
        endpoint: Arc<RelayEndpoint>,
    ) -> Option<Arc<RelayEndpoint>> {
        self.endpoints
            .write()
            .expect("poisoned")
            .insert(url, endpoint)
    }

    /// Removes an existing relay by `RelayUrl`.
    pub fn remove(&self, url: &RelayUrl) -> Option<Arc<RelayEndpoint>> {
        self.endpoints.write().expect("poisoned").remove(url)
    }
}

impl FromIterator<RelayEndpoint> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayEndpoint>>(iter: T) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(
                iter.into_iter()
                    .map(|endpoint| (endpoint.url.clone(), Arc::new(endpoint)))
                    .collect(),
            )),
        }
    }
}

impl From<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from a [`RelayUrl`].
    ///
    /// The [`RelayEndpoint`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from(value: RelayUrl) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(
                [(value.clone(), Arc::new(value.into()))].into(),
            )),
        }
    }
}

impl From<RelayEndpoint> for RelayMap {
    fn from(value: RelayEndpoint) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new([(value.url.clone(), Arc::new(value))].into())),
        }
    }
}

impl FromIterator<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from an iterator of [`RelayUrl`].
    ///
    /// The [`RelayEndpoint`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self {
            endpoints: Arc::new(RwLock::new(
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
pub struct RelayEndpoint {
    /// The [`RelayUrl`] where this relay server can be dialed.
    pub url: RelayUrl,
    /// Configuration to speak to the QUIC endpoint on the relay server.
    ///
    /// When `None`, we will not attempt to do QUIC address discovery
    /// with this relay server.
    #[serde(default = "quic_config")]
    pub quic: Option<RelayQuicConfig>,
}

impl From<RelayUrl> for RelayEndpoint {
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

impl fmt::Display for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
