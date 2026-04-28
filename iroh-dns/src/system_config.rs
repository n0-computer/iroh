//! Reader for the host system's DNS configuration.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    net::NetError,
};
use n0_error::stack_error;

#[cfg(target_os = "android")]
pub(crate) mod android;

/// Errors returned by [`read_system_conf`].
#[allow(dead_code, reason = "variants are platform-specific")]
#[stack_error(derive, add_meta)]
#[non_exhaustive]
pub(crate) enum SystemConfigError {
    /// The platform reader returned an error.
    #[error("failed to read system DNS configuration")]
    Read {
        #[error(from, std_err)]
        source: NetError,
    },
    /// No system reader is available on this platform.
    #[error("system DNS reads are disabled on this platform")]
    PlatformUnsupported {},
}

/// Reads the host system's DNS configuration.
///
/// Drops nameservers that cannot plausibly be queried; see
/// [`is_usable_nameserver_config`].
pub(crate) fn read_system_conf() -> Result<(ResolverConfig, ResolverOpts), SystemConfigError> {
    // Hickory returns `NetError` on unix and `ProtoError` on windows and
    // apple, so `NetError::from` is identity on linux only.
    #[cfg(not(target_os = "android"))]
    #[allow(clippy::useless_conversion)]
    let (raw, options) =
        hickory_resolver::system_conf::read_system_conf().map_err(NetError::from)?;
    #[cfg(target_os = "android")]
    let (raw, options) = android::read_system_conf()?;

    let config = sanitize(raw);
    Ok((config, options))
}

/// Copies a [`ResolverConfig`] while filtering out unusable nameservers.
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

/// Returns whether `ns` can plausibly be queried from a connected UDP socket.
///
/// Drops the deprecated Windows IPv6 site-local anycast servers, link-local
/// IPv6 (`fe80::/10`), link-local IPv4 (`169.254.0.0/16`), and the unspecified
/// addresses.
fn is_usable_nameserver_config(ns: &NameServerConfig) -> bool {
    if WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ns.ip) {
        return false;
    }
    match ns.ip {
        IpAddr::V4(ip) => ip != Ipv4Addr::UNSPECIFIED && !ip.is_link_local(),
        IpAddr::V6(ip) => ip != Ipv6Addr::UNSPECIFIED && (ip.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

#[cfg(test)]
mod tests {
    use hickory_resolver::config::ConnectionConfig;

    use super::*;

    fn ns(ip: IpAddr) -> NameServerConfig {
        NameServerConfig::new(ip, false, vec![ConnectionConfig::udp()])
    }

    fn usable(ip: &str) -> bool {
        is_usable_nameserver_config(&ns(ip.parse().unwrap()))
    }

    #[test]
    fn rejects_link_local_v6() {
        // Bounds of `fe80::/10`.
        assert!(!usable("fe80::1"));
        assert!(!usable("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    }

    #[test]
    fn accepts_addresses_outside_link_local_v6() {
        assert!(usable("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
        // `fec0::/10` is site-local-deprecated but still routable.
        assert!(usable("fec0::1"));
    }

    #[test]
    fn rejects_link_local_v4() {
        // Bounds of `169.254.0.0/16`.
        assert!(!usable("169.254.0.0"));
        assert!(!usable("169.254.255.255"));
    }

    #[test]
    fn accepts_addresses_outside_link_local_v4() {
        assert!(usable("169.253.255.255"));
        assert!(usable("169.255.0.0"));
    }

    #[test]
    fn rejects_unspecified() {
        assert!(!usable("0.0.0.0"));
        assert!(!usable("::"));
    }

    #[test]
    fn accepts_global_unicast() {
        assert!(usable("8.8.8.8"));
        assert!(usable("1.1.1.1"));
        assert!(usable("2001:4860:4860::8888"));
        // ULA, valid for routed networks.
        assert!(usable("fd00::1"));
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
