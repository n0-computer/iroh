use std::{collections::BTreeSet, fmt, net::SocketAddr, ops::Deref, str::FromStr};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::key::PublicKey;

/// A peer and it's addressing information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeAddr {
    /// The node's public key.
    pub node_id: PublicKey,
    /// Addressing information to connect to [`Self::node_id`].
    pub info: AddrInfo,
}

impl NodeAddr {
    /// Create a new [`NodeAddr`] with empty [`AddrInfo`].
    pub fn new(node_id: PublicKey) -> Self {
        NodeAddr {
            node_id,
            info: Default::default(),
        }
    }

    /// Add a relay url to the peer's [`AddrInfo`].
    pub fn with_relay_url(mut self, relay_url: RelayUrl) -> Self {
        self.info.relay_url = Some(relay_url);
        self
    }

    /// Add the given direct addresses to the peer's [`AddrInfo`].
    pub fn with_direct_addresses(
        mut self,
        addresses: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        self.info.direct_addresses = addresses.into_iter().collect();
        self
    }

    /// Get the direct addresses of this peer.
    pub fn direct_addresses(&self) -> impl Iterator<Item = &SocketAddr> {
        self.info.direct_addresses.iter()
    }

    /// Get the relay url of this peer.
    pub fn relay_url(&self) -> Option<&RelayUrl> {
        self.info.relay_url.as_ref()
    }
}

impl From<(PublicKey, Option<RelayUrl>, &[SocketAddr])> for NodeAddr {
    fn from(value: (PublicKey, Option<RelayUrl>, &[SocketAddr])) -> Self {
        let (node_id, relay_url, direct_addresses_iter) = value;
        NodeAddr {
            node_id,
            info: AddrInfo {
                relay_url,
                direct_addresses: direct_addresses_iter.iter().copied().collect(),
            },
        }
    }
}

/// Addressing information to connect to a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AddrInfo {
    /// The peer's home relay url.
    pub relay_url: Option<RelayUrl>,
    /// Socket addresses where the peer might be reached directly.
    pub direct_addresses: BTreeSet<SocketAddr>,
}

impl AddrInfo {
    /// Return whether this addressing information is empty.
    pub fn is_empty(&self) -> bool {
        self.relay_url.is_none() && self.direct_addresses.is_empty()
    }
}

impl NodeAddr {
    /// Create a new [`NodeAddr`] from its parts.
    pub fn from_parts(
        node_id: PublicKey,
        relay_url: Option<RelayUrl>,
        direct_addresses: Vec<SocketAddr>,
    ) -> Self {
        Self {
            node_id,
            info: AddrInfo {
                relay_url,
                direct_addresses: direct_addresses.into_iter().collect(),
            },
        }
    }
}

/// A URL identifying a relay server.
///
/// This is but a wrapper around [`Url`], with a few custom tweaks:
///
/// - A relay URL is never a relative URL, so an implicit `.` is added at the end of the
///   domain name if missing.
///
/// - [`fmt::Debug`] is implemented so it prints the URL rather than the URL struct fields.
///   Useful when logging e.g. `Option<RelayUrl>`.
///
/// To create a [`RelayUrl`] use the `From<Url>` implementation.
#[derive(
    Clone, derive_more::Display, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct RelayUrl(Url);

impl From<Url> for RelayUrl {
    fn from(mut url: Url) -> Self {
        if let Some(domain) = url.domain() {
            if !domain.ends_with('.') {
                let domain = String::from(domain) + ".";

                // This can fail, though it is unlikely the resulting URL is usable as a
                // relay URL, probably it has the wrong scheme or is not a base URL or the
                // like.  We don't do full URL validation however, so just silently leave
                // this bad URL in place.  Something will fail later.
                url.set_host(Some(&domain)).ok();
            }
        }
        Self(url)
    }
}

/// This is a convenience only to directly parse strings.
///
/// If you need more control over the error first create a [`Url`] and use [`RelayUrl::from`]
/// instead.
impl FromStr for RelayUrl {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = Url::from_str(s).context("invalid URL")?;
        Ok(RelayUrl::from(inner))
    }
}

/// Dereference to the wrapped [`Url`].
///
/// Note that [`DerefMut`] is not implemented on purpose, so this type has more flexibility
/// to change the inner later.
///
/// [`DerefMut`]: std::ops::DerefMut
impl Deref for RelayUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelayUrl")
            .field(&DbgStr(self.0.as_str()))
            .finish()
    }
}

/// Helper struct to format a &str without allocating a String.
///
/// Maybe this is entirely unneeded and the compiler would be smart enough to never allocate
/// the String anyway.  Who knows.  Writing this was faster than checking the assembler
/// output.
struct DbgStr<'a>(&'a str);

impl<'a> fmt::Debug for DbgStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#""{}""#, self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_url_debug_display() {
        let url = RelayUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(format!("{url:?}"), r#"RelayUrl("https://example.com./")"#);

        assert_eq!(format!("{url}"), "https://example.com./");
    }

    #[test]
    fn test_relay_url_absolute() {
        let url = RelayUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(url.domain(), Some("example.com."));

        let url1 = RelayUrl::from(Url::parse("https://example.com.").unwrap());
        assert_eq!(url, url1);

        let url2 = RelayUrl::from(Url::parse("https://example.com./").unwrap());
        assert_eq!(url, url2);

        let url3 = RelayUrl::from(Url::parse("https://example.com/").unwrap());
        assert_eq!(url, url3);

        assert_eq!(url1, url2);
    }
}
