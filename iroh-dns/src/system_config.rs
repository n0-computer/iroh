//! Reader for the host system's DNS configuration.
//!
//! Wraps [`hickory_resolver::system_conf::read_system_conf`] in a
//! crate-local error type and applies platform-specific sanitization.
//!
//! On Android the upstream reader is unsafe to call from a non-JVM
//! context: it dereferences an `ndk_context` that the consumer has not
//! necessarily initialized, panicking on `.expect()`. Even when
//! initialized, the API often hands back link-local IPv6 servers
//! (notably from iPhone Personal Hotspot tethering) that a connected
//! UDP socket cannot reach without scope IDs. We sidestep both
//! problems by returning an error on Android, leaving the caller to
//! fall back to the public DNS defaults; consumers who really want
//! system DNS can opt in via [`crate::dns::install_android_jni_context`].

#[cfg(not(target_os = "android"))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(not(target_os = "android"))]
use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
#[cfg(not(target_os = "android"))]
use n0_error::anyerr;
use n0_error::{AnyError, e, stack_error};

/// Errors returned by [`read_system_conf`].
///
/// Each variant is constructed on a subset of platforms; the
/// `dead_code` allow keeps the cross-platform definition compile-clean
/// without forcing callers into cfg-gated match arms.
#[allow(dead_code, reason = "variants are platform-specific")]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(crate) enum SystemConfigError {
    /// The platform reader returned an error.
    #[error("failed to read system DNS configuration")]
    Hickory { source: AnyError },
    /// System DNS reads are disabled on this platform.
    ///
    /// Currently raised on Android: see the module-level docs.
    #[error("system DNS reads are disabled on this platform")]
    PlatformUnsupported {},
}

/// Reads the host system's DNS configuration into a hickory [`ResolverConfig`].
///
/// Drops nameservers that are known to be unusable from a regular UDP
/// socket: Windows site-local IPv6 anycast (`fec0:0:0:ffff::{1,2,3}`),
/// IPv6 link-local (`fe80::/10`), IPv4 link-local (`169.254.0.0/16`),
/// and the IPv4 and IPv6 unspecified addresses. These either need a
/// scope ID we do not carry or are not routable at all; probing them
/// would burn the per-attempt budget waiting for the timeout.
#[cfg(not(target_os = "android"))]
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    let (raw, options) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|err| e!(SystemConfigError::Hickory, anyerr!(err)))?;
    Ok((sanitize(raw), options))
}

/// Returns [`SystemConfigError::PlatformUnsupported`] on Android.
///
/// See the module-level documentation for why we skip the system DNS
/// path entirely on Android. Callers should treat this as a signal to
/// use a public fallback resolver.
#[cfg(target_os = "android")]
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    Err(e!(SystemConfigError::PlatformUnsupported))
}

/// Copies a [`ResolverConfig`] while filtering out unusable nameservers.
#[cfg(not(target_os = "android"))]
fn sanitize(raw: ResolverConfig) -> ResolverConfig {
    let mut config = ResolverConfig::default();
    if let Some(name) = raw.domain() {
        config.set_domain(name.clone());
    }
    for name in raw.search() {
        config.add_search(name.clone());
    }
    for ns in raw.name_servers() {
        if is_usable_nameserver(ns) {
            config.add_name_server(ns.clone());
        }
    }
    config
}

/// Returns whether a nameserver IP can plausibly be queried from a
/// connected UDP socket.
#[cfg(not(target_os = "android"))]
fn is_usable_nameserver(ns: &NameServerConfig) -> bool {
    if WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ns.ip) {
        return false;
    }
    match ns.ip {
        IpAddr::V4(ip) => ip != Ipv4Addr::UNSPECIFIED && !ip.is_link_local(),
        IpAddr::V6(ip) => ip != Ipv6Addr::UNSPECIFIED && (ip.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
#[cfg(not(target_os = "android"))]
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

#[cfg(all(test, not(target_os = "android")))]
mod tests {
    use hickory_resolver::config::ConnectionConfig;

    use super::*;

    fn ns(ip: IpAddr) -> NameServerConfig {
        NameServerConfig::new(ip, false, vec![ConnectionConfig::udp()])
    }

    #[test]
    fn rejects_link_local_v6() {
        let unusable = "fe80::1".parse().unwrap();
        assert!(!is_usable_nameserver(&ns(unusable)));
    }

    #[test]
    fn rejects_link_local_v4() {
        let unusable = "169.254.1.1".parse().unwrap();
        assert!(!is_usable_nameserver(&ns(unusable)));
    }

    #[test]
    fn rejects_unspecified() {
        assert!(!is_usable_nameserver(&ns("0.0.0.0".parse().unwrap())));
        assert!(!is_usable_nameserver(&ns("::".parse().unwrap())));
    }

    #[test]
    fn rejects_windows_site_local_anycast() {
        for ip in WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS {
            assert!(!is_usable_nameserver(&ns(ip)));
        }
    }

    #[test]
    fn accepts_global_unicast() {
        assert!(is_usable_nameserver(&ns("8.8.8.8".parse().unwrap())));
        assert!(is_usable_nameserver(&ns("2001:4860:4860::8888"
            .parse()
            .unwrap())));
        // ULA, valid for routed networks.
        assert!(is_usable_nameserver(&ns("fd00::1".parse().unwrap())));
    }

    #[test]
    fn sanitize_drops_link_local_servers() {
        let mut raw = ResolverConfig::default();
        raw.add_name_server(ns("fe80::1".parse().unwrap()));
        raw.add_name_server(ns("8.8.8.8".parse().unwrap()));
        let sanitized = sanitize(raw);
        let kept: Vec<_> = sanitized.name_servers().iter().map(|n| n.ip).collect();
        assert_eq!(kept, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }
}
