//! Package derp implements the Designated Encrypted Relay for Packets (DERP)
//! protocol written by Tailscale.
//
//! DERP routes packets to clients using curve25519 keys as addresses.
//
//! DERP is used by proxy encrypted QUIC packets through the DERP servers when
//! a direct path cannot be found or opened. DERP is a last resort. Both side
//! between very aggressive NATs, firewalls, no IPv6, etc? Well, DERP.
//! Based on tailscale/derp/derp.go

#![deny(missing_docs, rustdoc::broken_intra_doc_links)]

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

pub(crate) mod client;
pub(crate) mod client_conn;
pub(crate) mod clients;
mod codec;
pub mod http;
mod map;
mod metrics;
pub(crate) mod server;
pub(crate) mod types;

pub use self::client::{Client as DerpClient, ReceivedMessage};
pub use self::codec::MAX_PACKET_SIZE;
pub use self::http::Client as HttpClient;
pub use self::map::{DerpMap, DerpMode, DerpNode};
pub use self::metrics::Metrics;
pub use self::server::{
    ClientConnHandler, MaybeTlsStream as MaybeTlsStreamServer, PacketForwarderHandler, Server,
};
pub use self::types::{MeshKey, PacketForwarder};

/// A URL identifying a DERP server.
///
/// This is but a wrapper around [`Url`], with a few custom tweaks:
///
/// - A DERP URL is never a relative URL, so an implicit `.` is added at the end of the
///   domain name if missing.
///
/// - [`fmt::Debug`] is implemented so it prints the URL rather than the URL struct fields.
///   Useful when logging e.g. `Option<DerpUrl>`.
///
/// To create a [`DerpUrl`] use the `From<Url>` implementation.
#[derive(
    Clone, derive_more::Display, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct DerpUrl(Url);

impl From<Url> for DerpUrl {
    fn from(mut url: Url) -> Self {
        if let Some(domain) = url.domain() {
            if !domain.ends_with('.') {
                let domain = String::from(domain) + ".";

                // This can fail, though it is unlikely the resulting URL is usable as a
                // DERP URL, probably it has the wrong scheme or is not a base URL or the
                // like.  We don't do full URL validation however, so just silently leave
                // this bad URL in place.  Something will fail later.
                url.set_host(Some(&domain)).ok();
            }
        }
        Self(url)
    }
}

impl FromStr for DerpUrl {
    // Be aware, we are re-exporting another crate's public type in our API.
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = Url::from_str(s)?;
        Ok(DerpUrl(inner))
    }
}

/// Dereference to the wrapped [`Url`].
///
/// Note that [`DerefMut`] is not implemented on purpose, so this type has more flexibility
/// to change the inner later.
///
/// [`DerefMut`]: std::ops::DerefMut
impl Deref for DerpUrl {
    type Target = Url;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for DerpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DerpUrl")
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
    fn test_derp_url_debug() {
        let url = DerpUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(format!("{url:?}"), r#"DerpUrl("https://example.com./")"#);
    }

    #[test]
    fn test_derp_url_absolute() {
        let url = DerpUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(url.domain(), Some("example.com."));

        let url1 = DerpUrl::from(Url::parse("https://example.com.").unwrap());
        assert_eq!(url, url1);

        let url2 = DerpUrl::from(Url::parse("https://example.com./").unwrap());
        assert_eq!(url, url2);

        let url3 = DerpUrl::from(Url::parse("https://example.com/").unwrap());
        assert_eq!(url, url3);
    }
}
