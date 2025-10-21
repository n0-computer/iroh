//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

use iroh_base::RelayUrl;
use serde::{Deserialize, Serialize};

use crate::defaults::DEFAULT_RELAY_QUIC_PORT;

/// List of relay server configurations to be used in an iroh endpoint.
///
/// A [`RelayMap`] can be constructed from an iterator of [`RelayConfig`] or [`RelayUrl]`,
/// or by creating an empty relay map with [`RelayMap::new`] and then adding entries with
/// [`RelayMap::insert`].
///
/// Example:
/// ```
/// # use std::str::FromStr;
/// # use iroh_base::RelayUrl;
/// # use iroh_relay::RelayMap;
/// let relay1 = RelayUrl::from_str("https://relay1.example.org").unwrap();
/// let relay2 = RelayUrl::from_str("https://relay2.example.org").unwrap();
/// let map = RelayMap::from_iter(vec![relay1, relay2]);
/// ```
#[derive(Debug, Clone)]
pub struct RelayMap {
    /// A map of the different relay IDs to the [`RelayConfig`] information
    relays: Arc<RwLock<BTreeMap<RelayUrl, Arc<RelayConfig>>>>,
}

impl PartialEq for RelayMap {
    fn eq(&self, other: &Self) -> bool {
        let this = self.relays.read().expect("poisoned");
        let that = other.relays.read().expect("poisoned");
        this.eq(&*that)
    }
}

impl Eq for RelayMap {}

impl RelayMap {
    /// Returns the URLs of all servers in this relay map.
    ///
    /// This function is generic over the container to collect into. If you simply want a list
    /// of URLs, call this with `map.urls::<Vec<_>>()` to get a `Vec<RelayUrl>`.
    pub fn urls<T>(&self) -> T
    where
        T: FromIterator<RelayUrl>,
    {
        self.relays
            .read()
            .expect("poisoned")
            .keys()
            .cloned()
            .collect::<T>()
    }

    /// Creates an empty relay map.
    pub fn empty() -> Self {
        Self {
            relays: Default::default(),
        }
    }

    /// Returns a list with the [`RelayConfig`] for each relay in this relay map.
    ///
    /// This function is generic over the container to collect into. If you simply want a list
    /// of URLs, call this with `map.relays::<Vec<_>>()` to get a `Vec<RelayConfig>`.
    pub fn relays<T>(&self) -> T
    where
        T: FromIterator<Arc<RelayConfig>>,
    {
        self.relays
            .read()
            .expect("poisoned")
            .values()
            .cloned()
            .collect::<T>()
    }

    /// Returns `true` if a relay with `url` is contained in this this relay map.
    pub fn contains(&self, url: &RelayUrl) -> bool {
        self.relays.read().expect("poisoned").contains_key(url)
    }

    /// Returns the config for a relay.
    pub fn get(&self, url: &RelayUrl) -> Option<Arc<RelayConfig>> {
        self.relays.read().expect("poisoned").get(url).cloned()
    }

    /// Returns the number of relays in this relay map.
    pub fn len(&self) -> usize {
        self.relays.read().expect("poisoned").len()
    }

    /// Returns `true` if this relay map is empty.
    pub fn is_empty(&self) -> bool {
        self.relays.read().expect("poisoned").is_empty()
    }

    /// Inserts a new relay into the relay map.
    pub fn insert(&self, url: RelayUrl, endpoint: Arc<RelayConfig>) -> Option<Arc<RelayConfig>> {
        self.relays.write().expect("poisoned").insert(url, endpoint)
    }

    /// Removes an existing relay by its URL.
    pub fn remove(&self, url: &RelayUrl) -> Option<Arc<RelayConfig>> {
        self.relays.write().expect("poisoned").remove(url)
    }
}

impl FromIterator<RelayConfig> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayConfig>>(iter: T) -> Self {
        Self {
            relays: Arc::new(RwLock::new(
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
    /// The [`RelayConfig`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from(value: RelayUrl) -> Self {
        Self {
            relays: Arc::new(RwLock::new(
                [(value.clone(), Arc::new(value.into()))].into(),
            )),
        }
    }
}

impl From<RelayConfig> for RelayMap {
    fn from(value: RelayConfig) -> Self {
        Self {
            relays: Arc::new(RwLock::new([(value.url.clone(), Arc::new(value))].into())),
        }
    }
}

impl FromIterator<RelayUrl> for RelayMap {
    /// Creates a [`RelayMap`] from an iterator of [`RelayUrl`].
    ///
    /// The [`RelayConfig`]s in the [`RelayMap`] will have the default QUIC address
    /// discovery ports.
    fn from_iter<T: IntoIterator<Item = RelayUrl>>(iter: T) -> Self {
        Self {
            relays: Arc::new(RwLock::new(
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
pub struct RelayConfig {
    /// The [`RelayUrl`] where this relay server can be dialed.
    pub url: RelayUrl,
    /// Configuration to speak to the QUIC endpoint on the relay server.
    ///
    /// When `None`, we will not attempt to do QUIC address discovery
    /// with this relay server.
    #[serde(default = "quic_config")]
    pub quic: Option<RelayQuicConfig>,
}

impl From<RelayUrl> for RelayConfig {
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

impl fmt::Display for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
