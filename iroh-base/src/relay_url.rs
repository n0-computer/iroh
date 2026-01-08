use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

use n0_error::stack_error;
use serde::{Deserialize, Serialize};
use url::Url;

/// A URL identifying a relay server.
///
/// It is cheaply clonable, as the underlying type is wrapped into an `Arc`.  The main type
/// under the hood though is [`Url`].
///
/// To create a [`RelayUrl`] use the `From<Url>` implementation.
///
/// It is encouraged to use a fully-qualified DNS domain name in the URL.  Meaning a DNS
/// name which ends in a `.`, e.g, in `relay.example.com.`.  Otherwise the DNS resolution of
/// your local host or network could interpret the DNS name as relative and in some
/// configurations might cause additional delays or even connection problems.
#[derive(
    Clone, derive_more::Display, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct RelayUrl(Arc<Url>);

impl From<Url> for RelayUrl {
    fn from(url: Url) -> Self {
        Self(Arc::new(url))
    }
}

/// Can occur when parsing a string into a [`RelayUrl`].
#[stack_error(derive, add_meta)]
#[error("Failed to parse relay URL")]
pub struct RelayUrlParseError(#[error(std_err)] url::ParseError);

/// Support for parsing strings directly.
///
/// If you need more control over the error first create a [`Url`] and use [`RelayUrl::from`]
/// instead.
impl FromStr for RelayUrl {
    type Err = RelayUrlParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = Url::from_str(s).map_err(RelayUrlParseError::new)?;
        Ok(RelayUrl::from(inner))
    }
}

impl From<RelayUrl> for Url {
    fn from(value: RelayUrl) -> Self {
        Arc::unwrap_or_clone(value.0)
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

        assert_eq!(format!("{url:?}"), r#"RelayUrl("https://example.com/")"#);

        assert_eq!(format!("{url}"), "https://example.com/");
    }

    #[test]
    fn test_relay_url_absolute() {
        let url = RelayUrl::from(Url::parse("https://example.com").unwrap());

        assert_eq!(url.domain(), Some("example.com"));

        let url1 = RelayUrl::from(Url::parse("https://example.com.").unwrap());
        assert_eq!(url1.domain(), Some("example.com."));

        let url2 = RelayUrl::from(Url::parse("https://example.com./").unwrap());
        assert_eq!(url2.domain(), Some("example.com."));

        let url3 = RelayUrl::from(Url::parse("https://example.com/").unwrap());
        assert_eq!(url3.domain(), Some("example.com"));
    }
}
