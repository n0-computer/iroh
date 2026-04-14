//! System DNS configuration parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::DnsProtocol;

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
///
/// Windows still configures these site-local addresses as soon as an IPv6 loopback
/// interface is configured. We do not want to use these DNS servers, the chances of them
/// being usable are almost always close to zero, while the chance of DNS configuration
/// **only** relying on these servers and not also being configured normally are also almost
/// zero. The chance of the DNS resolver accidentally trying one of these and taking a
/// bunch of timeouts to figure out they're no good are on the other hand very high.
#[cfg(windows)]
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

/// Standard DNS port.
const DNS_PORT: u16 = 53;

/// Google Public DNS IPv4 primary (8.8.8.8).
const GOOGLE_DNS_IPV4_PRIMARY: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
/// Google Public DNS IPv4 secondary (8.8.4.4).
const GOOGLE_DNS_IPV4_SECONDARY: Ipv4Addr = Ipv4Addr::new(8, 8, 4, 4);
/// Google Public DNS IPv6 primary (2001:4860:4860::8888).
const GOOGLE_DNS_IPV6_PRIMARY: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
/// Google Public DNS IPv6 secondary (2001:4860:4860::8844).
const GOOGLE_DNS_IPV6_SECONDARY: Ipv6Addr =
    Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844);

/// Parsed system DNS configuration.
#[derive(Debug, Clone, Default)]
pub(super) struct SystemDnsConfig {
    pub(super) nameservers: Vec<(SocketAddr, DnsProtocol)>,
    /// Search domains from resolv.conf `search` or `domain` directives.
    ///
    /// When resolving a short hostname (one with fewer dots than `ndots`,
    /// default 1), the resolver should try appending each search domain
    /// before querying the bare name.
    ///
    pub(super) search_domains: Vec<String>,
}

/// Parse system DNS configuration.
///
/// On Unix, reads `/etc/resolv.conf` for `nameserver` and `search`/`domain` lines.
/// On Windows, uses the `ipconfig` crate to enumerate network adapters.
/// Falls back to Google DNS if parsing fails or no servers are found.
pub(super) fn system_config() -> SystemDnsConfig {
    match read_system_dns() {
        Ok(config) if !config.nameservers.is_empty() => config,
        _ => SystemDnsConfig {
            nameservers: fallback_nameservers(),
            search_domains: Vec::new(),
        },
    }
}

/// Read system DNS configuration using platform-specific mechanisms.
#[cfg(windows)]
fn read_system_dns() -> Result<SystemDnsConfig, std::io::Error> {
    read_from_ipconfig()
}

/// Read system DNS configuration using platform-specific mechanisms.
#[cfg(not(windows))]
fn read_system_dns() -> Result<SystemDnsConfig, std::io::Error> {
    read_resolv_conf()
}

/// Google DNS fallback nameservers.
pub(super) fn fallback_nameservers() -> Vec<(SocketAddr, DnsProtocol)> {
    vec![
        (
            SocketAddr::new(IpAddr::V4(GOOGLE_DNS_IPV4_PRIMARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V4(GOOGLE_DNS_IPV4_SECONDARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V6(GOOGLE_DNS_IPV6_PRIMARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
        (
            SocketAddr::new(IpAddr::V6(GOOGLE_DNS_IPV6_SECONDARY), DNS_PORT),
            DnsProtocol::Udp,
        ),
    ]
}

/// Read DNS servers from Windows network adapter configuration.
#[cfg(windows)]
fn read_from_ipconfig() -> Result<SystemDnsConfig, std::io::Error> {
    let adapters =
        ipconfig::get_adapters().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let mut servers = Vec::new();
    for adapter in adapters {
        // Only consider adapters that are up
        if adapter.oper_status() != ipconfig::OperStatus::IfOperStatusUp {
            continue;
        }
        for dns_server in adapter.dns_servers() {
            let ip = IpAddr::from(*dns_server);
            if !WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS.contains(&ip) {
                servers.push((SocketAddr::new(ip, DNS_PORT), DnsProtocol::Udp));
            }
        }
    }

    // Deduplicate -- multiple adapters may report the same DNS server.
    // Use a HashSet since dedup_by_key only removes consecutive duplicates.
    let mut seen = std::collections::HashSet::new();
    servers.retain(|(addr, _)| seen.insert(*addr));

    // Windows does not expose search domains via ipconfig in a
    // straightforward way, so we leave them empty.
    Ok(SystemDnsConfig {
        nameservers: servers,
        search_domains: Vec::new(),
    })
}

/// Read `/etc/resolv.conf` and extract nameserver addresses and search domains.
#[cfg(not(windows))]
fn read_resolv_conf() -> Result<SystemDnsConfig, std::io::Error> {
    let content = std::fs::read_to_string("/etc/resolv.conf")?;
    Ok(parse_resolv_conf(&content))
}

/// Parse resolv.conf content and extract nameserver addresses and search domains.
///
/// Recognized directives:
/// - `nameserver <ip>` -- adds a DNS nameserver
/// - `search <domain> [<domain> ...]` -- sets the search domain list
/// - `domain <domain>` -- equivalent to a single-entry search list
///
/// The `search` and `domain` directives are mutually exclusive per resolv.conf(5);
/// the last one seen wins, matching standard resolver behavior.
#[cfg(any(not(windows), test))]
fn parse_resolv_conf(content: &str) -> SystemDnsConfig {
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("nameserver") => {
                if let Some(addr_str) = parts.next() {
                    // Try parsing as SocketAddr first (supports custom ports like
                    // 8.8.8.8:5353 or [::1]:5353), then fall back to IpAddr with
                    // the default DNS port.
                    let addr = addr_str
                        .parse::<SocketAddr>()
                        .ok()
                        .or_else(|| {
                            addr_str
                                .parse::<IpAddr>()
                                .ok()
                                .map(|ip| SocketAddr::new(ip, DNS_PORT))
                        });
                    if let Some(addr) = addr {
                        servers.push((addr, DnsProtocol::Udp));
                    }
                }
            }
            Some("search") => {
                // `search` replaces any previous search/domain list.
                search_domains = parts.map(|s| s.to_string()).collect();
            }
            Some("domain") => {
                // `domain` is equivalent to a single-entry search list.
                if let Some(domain) = parts.next() {
                    search_domains = vec![domain.to_string()];
                }
            }
            _ => {}
        }
    }

    SystemDnsConfig {
        nameservers: servers,
        search_domains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(config: &SystemDnsConfig) -> Vec<IpAddr> {
        config.nameservers.iter().map(|(a, _)| a.ip()).collect()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_basic() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 8.8.4.4\n");
        assert_eq!(ips(&config), [ipv4(8, 8, 8, 8), ipv4(8, 8, 4, 4)]);
        assert!(config.nameservers.iter().all(|(_, p)| *p == DnsProtocol::Udp));
    }

    #[test]
    fn parse_ipv6() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\n");
        assert_eq!(config.nameservers.len(), 2);
        assert!(config.nameservers[1].0.ip().is_ipv6());
    }

    #[test]
    fn parse_comments_and_directives() {
        let config = parse_resolv_conf(
            "# comment\n; comment\nsearch example.com\nnameserver 1.1.1.1\noptions ndots:5\nnameserver 1.0.0.1\n",
        );
        assert_eq!(ips(&config), [ipv4(1, 1, 1, 1), ipv4(1, 0, 0, 1)]);
        assert_eq!(config.search_domains, ["example.com"]);
    }

    #[test]
    fn parse_skips_invalid_ips() {
        let config = parse_resolv_conf("nameserver not-an-ip\nnameserver 8.8.8.8\n");
        assert_eq!(ips(&config), [ipv4(8, 8, 8, 8)]);
    }

    #[test]
    fn parse_empty() {
        assert!(parse_resolv_conf("").nameservers.is_empty());
    }

    #[test]
    fn parse_no_nameservers() {
        let config = parse_resolv_conf("search example.com\noptions ndots:1\n");
        assert!(config.nameservers.is_empty());
        assert_eq!(config.search_domains, ["example.com"]);
    }

    #[test]
    fn parse_whitespace_variations() {
        let config = parse_resolv_conf("  nameserver   8.8.8.8  \n\tnameserver\t1.1.1.1\t\n");
        assert_eq!(config.nameservers.len(), 2);
    }

    #[test]
    fn parse_inline_comment() {
        let config = parse_resolv_conf("nameserver 8.8.8.8 # primary\nnameserver 1.1.1.1\n");
        assert_eq!(ips(&config), [ipv4(8, 8, 8, 8), ipv4(1, 1, 1, 1)]);
    }

    #[test]
    fn parse_no_space_after_keyword() {
        let config = parse_resolv_conf("nameserver8.8.8.8\nnameserver 1.1.1.1\n");
        assert_eq!(ips(&config), [ipv4(1, 1, 1, 1)]);
    }

    #[test]
    fn parse_scoped_ipv6() {
        let config = parse_resolv_conf("nameserver fe80::1%eth0\nnameserver 8.8.8.8\n");
        assert_eq!(ips(&config), [ipv4(8, 8, 8, 8)]);
    }

    #[test]
    fn parse_search_domains() {
        let config = parse_resolv_conf("search example.com foo.bar\nnameserver 8.8.8.8\n");
        assert_eq!(config.search_domains, ["example.com", "foo.bar"]);
    }

    #[test]
    fn parse_domain_directive() {
        let config = parse_resolv_conf("domain example.com\nnameserver 8.8.8.8\n");
        assert_eq!(config.search_domains, ["example.com"]);
    }

    #[test]
    fn parse_custom_port() {
        let config = parse_resolv_conf("nameserver 8.8.8.8:5353\nnameserver 1.1.1.1\n");
        assert_eq!(config.nameservers.len(), 2);
        assert_eq!(config.nameservers[0].0, "8.8.8.8:5353".parse::<SocketAddr>().unwrap());
        assert_eq!(config.nameservers[1].0.port(), DNS_PORT);
    }

    #[test]
    fn search_overrides_domain() {
        let config = parse_resolv_conf(
            "domain old.com\nsearch new.com other.com\nnameserver 8.8.8.8\n",
        );
        // Last directive wins, per resolv.conf(5).
        assert_eq!(config.search_domains, ["new.com", "other.com"]);
    }

    #[test]
    fn fallback_nameservers_are_google_dns() {
        let servers = fallback_nameservers();
        assert_eq!(servers.len(), 4);
        assert!(servers.iter().all(|(_, p)| *p == DnsProtocol::Udp));
        assert!(servers.iter().all(|(a, _)| a.port() == DNS_PORT));
        assert_eq!(servers.iter().filter(|(a, _)| a.ip().is_ipv4()).count(), 2);
        assert_eq!(servers.iter().filter(|(a, _)| a.ip().is_ipv6()).count(), 2);
    }
}
