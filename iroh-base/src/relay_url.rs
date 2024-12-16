use std::{fmt, ops::Deref, str::FromStr};

use serde::{Deserialize, Serialize};
use url::Url;
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

/// Can occur when parsing a string into a [`RelayUrl`].
#[derive(Debug, thiserror::Error)]
#[error("Failed to parse: {0}")]
pub struct RelayUrlParseError(#[from] url::ParseError);

/// Support for parsing strings directly.
///
/// If you need more control over the error first create a [`Url`] and use [`RelayUrl::from`]
/// instead.
impl FromStr for RelayUrl {
    type Err = RelayUrlParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = Url::from_str(s)?;
        Ok(RelayUrl::from(inner))
    }
}

impl From<RelayUrl> for Url {
    fn from(value: RelayUrl) -> Self {
        value.0
    }
}

/// Dereferences to the wrapped [`Url`].
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

impl fmt::Debug for DbgStr<'_> {
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
    }
}
