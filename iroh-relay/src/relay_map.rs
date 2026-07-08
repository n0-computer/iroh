//! based on tailscale/tailcfg/derpmap.go

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

use iroh_base::{RelayUrl, RelayUrlParseError};
use serde::{Deserialize, Serialize};

use crate::defaults::DEFAULT_RELAY_QUIC_PORT;

/// List of relay server configurations to be used in an iroh endpoint.
///
/// A [`RelayMap`] can be constructed from an iterator of [`RelayConfig`] or [`RelayUrl]`,
/// or by creating an empty relay map with [`RelayMap::empty`] and then adding entries with
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
    /// Creates an empty relay map.
    pub fn empty() -> Self {
        Self {
            relays: Default::default(),
        }
    }

    /// Creates a [`RelayMap`] from an iterator.
    ///
    /// The conversion from a URL to a [`RelayConfig`] is done the same as when parsing it directly,
    /// which means it is assumed to run QUIC on default settings as defined in [`RelayQuicConfig::default`].
    ///
    /// # Example
    /// ```rust
    /// # use iroh_relay::RelayMap;
    /// let map =
    ///     RelayMap::try_from_iter(["https://relay_0.cool.com", "https://relay_1.cool.com"]).unwrap();
    /// ```
    pub fn try_from_iter<'a, T: IntoIterator<Item = &'a str>>(
        urls: T,
    ) -> Result<Self, RelayUrlParseError> {
        let relays: BTreeMap<RelayUrl, Arc<RelayConfig>> = urls
            .into_iter()
            .map(|t| {
                t.parse()
                    .map(|url: RelayUrl| (url.clone(), Arc::new(RelayConfig::from(url))))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            relays: Arc::new(RwLock::new(relays)),
        })
    }

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

    /// Extends this `RelayMap` with another one.
    pub fn extend(&self, other: &RelayMap) {
        let mut a = self.relays.write().expect("poisoned");
        let b = other.relays.read().expect("poisoned");
        a.extend(b.iter().map(|(a, b)| (a.clone(), b.clone())));
    }

    /// Sets an authorization token for all relays configured in this relay map.
    ///
    /// This applies [`RelayConfig::with_auth_token`] to all current entries in this relay map.
    /// Any entries added to this relay map *after* calling this will not have the token set.
    ///
    /// See [`RelayConfig::with_auth_token`] for details.
    pub fn with_auth_token(self, auth_token: impl Into<String>) -> Self {
        let auth_token = auth_token.into();
        for config in self.relays.write().expect("poisoned").values_mut() {
            *config = Arc::new(config.as_ref().clone().with_auth_token(auth_token.clone()));
        }
        self
    }
}

impl FromIterator<RelayConfig> for RelayMap {
    fn from_iter<T: IntoIterator<Item = RelayConfig>>(iter: T) -> Self {
        Self::from_iter(iter.into_iter().map(Arc::new))
    }
}

impl FromIterator<Arc<RelayConfig>> for RelayMap {
    fn from_iter<T: IntoIterator<Item = Arc<RelayConfig>>>(iter: T) -> Self {
        Self {
            relays: Arc::new(RwLock::new(
                iter.into_iter()
                    .map(|config| (config.url.clone(), config))
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

/// How the WebTransport relay transport frames relay messages on the wire.
///
/// A relay message is one whole iroh QUIC packet. The framings trade off
/// per-message overhead against head-of-line blocking and reliability.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum WtTransferMode {
    /// One fresh unidirectional stream per relay message (the default).
    ///
    /// Each message is reliable and ordered within itself, but messages are
    /// independent: a retransmission on one stream does not delay later
    /// messages on other streams (no cross-message head-of-line blocking). The
    /// cost is one stream open/finish per message.
    #[default]
    UniPerPacket,
    /// One QUIC DATAGRAM per relay message.
    ///
    /// No per-message stream setup, but datagrams are unreliable and unordered
    /// and capped at the connection's path MTU; iroh's own QUIC running over the
    /// relay recovers any losses. Best on lossy links where head-of-line
    /// blocking hurts most.
    Datagrams,
    /// A single long-lived unidirectional stream per direction, carrying all
    /// messages length-prefixed.
    ///
    /// Reliable and globally ordered -- TCP-like, the same shape as the
    /// WebSocket transport but over WebTransport/QUIC. One lost packet delays
    /// every message behind it (head-of-line blocking), but there is no
    /// per-message stream overhead.
    UniOrdered,
}

impl WtTransferMode {
    /// The URL query-parameter value that selects this mode in the WebTransport
    /// CONNECT (a browser's CONNECT cannot carry custom headers, so the mode is
    /// signalled in the URL). See `RELAY_WT_MODE_QUERY_PARAM`.
    #[cfg(feature = "h3-transport")]
    pub(crate) fn query_value(self) -> &'static str {
        match self {
            WtTransferMode::UniPerPacket => "uni",
            WtTransferMode::Datagrams => "datagram",
            WtTransferMode::UniOrdered => "singleuni",
        }
    }

    /// Parse a mode from its [`query_value`](Self::query_value); unknown values
    /// fall back to the default so an older/newer peer degrades gracefully.
    #[cfg(feature = "server")]
    pub(crate) fn from_query_value(value: &str) -> Self {
        match value {
            "datagram" => WtTransferMode::Datagrams,
            "singleuni" => WtTransferMode::UniOrdered,
            _ => WtTransferMode::UniPerPacket,
        }
    }
}

/// Options for the HTTP/3 (WebTransport) relay transport.
///
/// Construct with [`H3Opts::default`] and set the public fields; the struct is
/// `#[non_exhaustive]`, so it cannot be built with a struct literal.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub struct H3Opts {
    /// SHA-256 hashes of the relay's certificate for browser WebTransport.
    ///
    /// When set, a browser WebTransport client validates the relay certificate
    /// against these hashes (via `serverCertificateHashes`) instead of the
    /// system roots -- for connecting to a relay with a self-signed certificate.
    /// Ignored on native targets, which validate via the TLS config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_hashes: Option<Vec<Vec<u8>>>,
    /// How relay messages are framed on the WebTransport connection.
    ///
    /// Defaults to [`WtTransferMode::UniPerPacket`].
    #[serde(default)]
    pub transfer_mode: WtTransferMode,
}

/// Information on a specific relay server.
///
/// Includes the Url where it can be dialed.
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RelayConfig {
    /// The [`RelayUrl`] where this relay server can be dialed.
    pub url: RelayUrl,
    /// Configuration to speak to the QUIC endpoint on the relay server.
    ///
    /// When `None`, we will not attempt to do QUIC address discovery
    /// with this relay server.
    #[serde(default = "quic_config")]
    pub quic: Option<RelayQuicConfig>,
    /// Optional authorization token sent to the relay.
    ///
    /// Set via [`RelayConfig::with_auth_token`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    /// WebTransport (H3) transport options for this relay.
    ///
    /// `Some` (the default) means the client may prefer WebTransport over
    /// WebSocket when UDP is available; `None` disables WebTransport for this
    /// relay. Set via [`RelayConfig::with_h3`].
    #[serde(default = "h3_default")]
    pub h3: Option<H3Opts>,
}

impl RelayConfig {
    /// Creates a new relay configuration with the given URL and optional QUIC config.
    pub fn new(url: RelayUrl, quic: Option<RelayQuicConfig>) -> Self {
        Self {
            url,
            quic,
            auth_token: None,
            h3: h3_default(),
        }
    }

    /// Sets the WebTransport (H3) transport options for this relay.
    ///
    /// See [`RelayConfig::h3`] and [`H3Opts`].
    pub fn with_h3(mut self, opts: H3Opts) -> Self {
        self.h3 = Some(opts);
        self
    }

    /// Sets an authorization token for this relay.
    ///
    /// On native targets, the token is sent as an `Authorization: Bearer TOKEN`
    /// header on the WebSocket upgrade request.
    ///
    /// When compiled to WebAssembly the token is sent as a `?token=TOKEN`
    /// query parameter on the upgrade URL, since browsers don't allow setting
    /// headers on WebSocket requests.
    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }
}

impl From<RelayUrl> for RelayConfig {
    fn from(value: RelayUrl) -> Self {
        Self {
            url: value,
            quic: quic_config(),
            auth_token: None,
            h3: h3_default(),
        }
    }
}

fn quic_config() -> Option<RelayQuicConfig> {
    Some(RelayQuicConfig::default())
}

fn h3_default() -> Option<H3Opts> {
    Some(H3Opts::default())
}

/// Configuration for speaking to the QUIC endpoint on the relay
/// server to do QUIC address discovery.
///
/// Defaults to using [`DEFAULT_RELAY_QUIC_PORT`].
#[derive(Debug, Deserialize, Serialize, Clone, Eq, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RelayQuicConfig {
    /// The port on which the connection should be bound to.
    pub port: u16,
}

impl RelayQuicConfig {
    /// Creates a new QUIC address discovery configuration with the given port.
    pub fn new(port: u16) -> Self {
        Self { port }
    }
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn relay_map_extend() {
        let urls1 = vec![
            RelayUrl::from_str("https://hello-a-01.com").unwrap(),
            RelayUrl::from_str("https://hello-b-01.com").unwrap(),
            RelayUrl::from_str("https://hello-c-01-.com").unwrap(),
        ];

        let urls2 = vec![
            RelayUrl::from_str("https://hello-a-02.com").unwrap(),
            RelayUrl::from_str("https://hello-b-02.com").unwrap(),
            RelayUrl::from_str("https://hello-c-02-.com").unwrap(),
        ];

        let map1 = RelayMap::from_iter(urls1.clone().into_iter().map(RelayConfig::from));
        let map2 = RelayMap::from_iter(urls2.clone().into_iter().map(RelayConfig::from));

        assert_ne!(map1, map2);

        // combine

        let map3 = RelayMap::from_iter(
            map1.relays::<Vec<_>>()
                .into_iter()
                .chain(map2.relays::<Vec<_>>()),
        );

        assert_eq!(map3.len(), 6);

        map1.extend(&map2);
        assert_eq!(map3, map1);
    }
}
