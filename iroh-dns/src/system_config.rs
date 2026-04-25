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
//! problems by skipping that path entirely. Consumers who want real
//! system DNS on Android can opt into a safe JNI reader by calling
//! [`android::install_android_jni_context`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(not(target_os = "android"))]
use hickory_resolver::config::NameServerConfig;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use n0_error::{AnyError, stack_error};
#[cfg(not(target_os = "android"))]
use n0_error::{anyerr, e};

#[cfg(target_os = "android")]
pub(crate) mod android;

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
    ///
    /// On non-Android platforms the source is hickory's
    /// system-config error. On Android (when a JNI context has been
    /// installed) it wraps the underlying JNI error.
    #[error("failed to read system DNS configuration")]
    Read { source: AnyError },
    /// System DNS reads are disabled on this platform.
    ///
    /// Currently raised on Android when no JNI context has been
    /// installed: see the module-level docs.
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
        .map_err(|err| e!(SystemConfigError::Read, anyerr!(err)))?;
    Ok((sanitize(raw), options))
}

/// Reads system DNS through the consumer-supplied JNI context.
///
/// Returns [`SystemConfigError::PlatformUnsupported`] until the
/// consumer calls [`android::install_android_jni_context`]. After
/// that, the JNI reader inspects `LinkProperties.getDnsServers()` for
/// the active network and returns a [`ResolverConfig`] with the
/// usable entries.
#[cfg(target_os = "android")]
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    android::read_system_conf()
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
        if is_usable_nameserver_config(ns) {
            config.add_name_server(ns.clone());
        }
    }
    config
}

/// Returns whether a configured nameserver can plausibly be queried.
#[cfg(not(target_os = "android"))]
fn is_usable_nameserver_config(ns: &NameServerConfig) -> bool {
    if WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ns.ip) {
        return false;
    }
    is_usable_nameserver(ns.ip)
}

/// Returns whether a nameserver IP can plausibly be queried from a
/// connected UDP socket.
///
/// Drops link-local IPv6 (`fe80::/10`), link-local IPv4
/// (`169.254.0.0/16`), and the unspecified addresses. iPhone Personal
/// Hotspot tethering routinely advertises `fe80::1` as the network's
/// DNS server; without a scope ID a connected UDP socket cannot route
/// to it, so attempts time out instead of returning a useful error.
///
/// This filter is for *reachability* only, not trust. A device-local
/// actor with `ACCESS_NETWORK_STATE` (or a hostile VPN) can still
/// inject an attacker-controlled global IP that survives the filter;
/// callers that need authenticated DNS should add DNS-over-HTTPS or
/// DNSSEC on top.
pub(crate) fn is_usable_nameserver(ip: IpAddr) -> bool {
    match ip {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_link_local_v6() {
        // First (`fe80::`) and last (`febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff`)
        // addresses in `fe80::/10`, the link-local range.
        assert!(!is_usable_nameserver("fe80::1".parse().unwrap()));
        assert!(!is_usable_nameserver(
            "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
    }

    #[test]
    fn accepts_addresses_outside_link_local_v6() {
        // Just below `fe80::/10`: still global.
        assert!(is_usable_nameserver(
            "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
        ));
        // Just above `fe80::/10`: site-local-deprecated, but still routable
        // when explicitly configured.
        assert!(is_usable_nameserver("fec0::1".parse().unwrap()));
    }

    #[test]
    fn rejects_link_local_v4() {
        // First and last addresses in `169.254.0.0/16`.
        assert!(!is_usable_nameserver("169.254.0.0".parse().unwrap()));
        assert!(!is_usable_nameserver("169.254.255.255".parse().unwrap()));
    }

    #[test]
    fn accepts_addresses_outside_link_local_v4() {
        // Just below `169.254.0.0/16`.
        assert!(is_usable_nameserver("169.253.255.255".parse().unwrap()));
        // Just above `169.254.0.0/16`.
        assert!(is_usable_nameserver("169.255.0.0".parse().unwrap()));
    }

    #[test]
    fn rejects_unspecified() {
        assert!(!is_usable_nameserver("0.0.0.0".parse().unwrap()));
        assert!(!is_usable_nameserver("::".parse().unwrap()));
    }

    #[test]
    fn accepts_global_unicast() {
        assert!(is_usable_nameserver("8.8.8.8".parse().unwrap()));
        assert!(is_usable_nameserver("1.1.1.1".parse().unwrap()));
        assert!(is_usable_nameserver(
            "2001:4860:4860::8888".parse().unwrap()
        ));
        // ULA, valid for routed networks.
        assert!(is_usable_nameserver("fd00::1".parse().unwrap()));
    }
}

#[cfg(all(test, not(target_os = "android")))]
mod platform_tests {
    use hickory_resolver::config::ConnectionConfig;

    use super::*;

    fn ns(ip: IpAddr) -> NameServerConfig {
        NameServerConfig::new(ip, false, vec![ConnectionConfig::udp()])
    }

    #[test]
    fn rejects_windows_site_local_anycast() {
        for ip in WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS {
            assert!(!is_usable_nameserver_config(&ns(ip)));
        }
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
