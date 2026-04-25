//! Reader for the host system's DNS configuration.
//!
//! Wraps [`hickory_resolver::system_conf::read_system_conf`] in a
//! crate-local error type and applies a small set of cross-platform
//! sanitizations (currently: stripping deprecated Windows site-local
//! IPv6 anycast nameservers).

use std::net::{IpAddr, Ipv6Addr};

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use n0_error::{AnyError, anyerr, e, stack_error};

/// Errors returned by [`read_system_conf`].
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(crate) enum SystemConfigError {
    /// The platform reader returned an error.
    #[error("failed to read system DNS configuration")]
    Hickory { source: AnyError },
}

/// Reads the host system's DNS configuration into a hickory [`ResolverConfig`].
///
/// Drops the deprecated `fec0:0:0:ffff::{1,2,3}` site-local IPv6 anycast
/// addresses that Windows still configures as soon as an IPv6 loopback
/// interface exists. They are essentially never reachable, and probing
/// them eats the entire query budget while waiting for them to time out.
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    let (raw, options) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|err| e!(SystemConfigError::Hickory, anyerr!(err)))?;

    let mut config = ResolverConfig::default();
    if let Some(name) = raw.domain() {
        config.set_domain(name.clone());
    }
    for name in raw.search() {
        config.add_search(name.clone());
    }
    for ns in raw.name_servers() {
        if !WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ns.ip) {
            config.add_name_server(ns.clone());
        }
    }
    Ok((config, options))
}

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
///
/// Windows still configures these site-local addresses as soon as an
/// IPv6 loopback interface exists. The chance that they are reachable
/// is close to zero, but the chance that hickory wastes attempts on
/// them is high.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];
