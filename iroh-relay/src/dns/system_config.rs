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

/// Parse system DNS configuration.
///
/// On Unix, reads `/etc/resolv.conf` for `nameserver` lines.
/// On Windows, uses the `ipconfig` crate to enumerate network adapters.
/// Falls back to Google DNS if parsing fails or no servers are found.
pub(super) fn system_nameservers() -> Vec<(SocketAddr, DnsProtocol)> {
    match read_system_dns() {
        Ok(servers) if !servers.is_empty() => servers,
        _ => fallback_nameservers(),
    }
}

/// Read system DNS configuration using platform-specific mechanisms.
#[cfg(windows)]
fn read_system_dns() -> Result<Vec<(SocketAddr, DnsProtocol)>, std::io::Error> {
    read_from_ipconfig()
}

/// Read system DNS configuration using platform-specific mechanisms.
#[cfg(not(windows))]
fn read_system_dns() -> Result<Vec<(SocketAddr, DnsProtocol)>, std::io::Error> {
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
fn read_from_ipconfig() -> Result<Vec<(SocketAddr, DnsProtocol)>, std::io::Error> {
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

    // Deduplicate — multiple adapters may report the same DNS server
    servers.dedup_by_key(|(addr, _)| *addr);

    Ok(servers)
}

/// Read `/etc/resolv.conf` and extract nameserver addresses.
#[cfg(not(windows))]
fn read_resolv_conf() -> Result<Vec<(SocketAddr, DnsProtocol)>, std::io::Error> {
    let content = std::fs::read_to_string("/etc/resolv.conf")?;
    Ok(parse_resolv_conf(&content))
}

/// Parse resolv.conf content and extract nameserver addresses.
#[cfg(any(not(windows), test))]
fn parse_resolv_conf(content: &str) -> Vec<(SocketAddr, DnsProtocol)> {
    let mut servers = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip comments
        if line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Split into keyword and rest, handling any whitespace separator
        let mut parts = line.split_whitespace();
        if parts.next() == Some("nameserver")
            && let Some(addr_str) = parts.next()
            && let Ok(ip) = addr_str.parse::<IpAddr>()
        {
            servers.push((SocketAddr::new(ip, DNS_PORT), DnsProtocol::Udp));
        }
    }

    servers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ips(servers: &[(SocketAddr, DnsProtocol)]) -> Vec<IpAddr> {
        servers.iter().map(|(a, _)| a.ip()).collect()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_basic() {
        let servers = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 8.8.4.4\n");
        assert_eq!(ips(&servers), [ipv4(8, 8, 8, 8), ipv4(8, 8, 4, 4)]);
        assert!(servers.iter().all(|(_, p)| *p == DnsProtocol::Udp));
    }

    #[test]
    fn parse_ipv6() {
        let servers = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\n");
        assert_eq!(servers.len(), 2);
        assert!(servers[1].0.ip().is_ipv6());
    }

    #[test]
    fn parse_comments_and_directives() {
        let servers = parse_resolv_conf(
            "# comment\n; comment\nsearch example.com\nnameserver 1.1.1.1\noptions ndots:5\nnameserver 1.0.0.1\n",
        );
        assert_eq!(ips(&servers), [ipv4(1, 1, 1, 1), ipv4(1, 0, 0, 1)]);
    }

    #[test]
    fn parse_skips_invalid_ips() {
        let servers = parse_resolv_conf("nameserver not-an-ip\nnameserver 8.8.8.8\n");
        assert_eq!(ips(&servers), [ipv4(8, 8, 8, 8)]);
    }

    #[test]
    fn parse_empty() {
        assert!(parse_resolv_conf("").is_empty());
    }

    #[test]
    fn parse_no_nameservers() {
        assert!(parse_resolv_conf("search example.com\noptions ndots:1\n").is_empty());
    }

    #[test]
    fn parse_whitespace_variations() {
        let servers = parse_resolv_conf("  nameserver   8.8.8.8  \n\tnameserver\t1.1.1.1\t\n");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn parse_inline_comment() {
        let servers = parse_resolv_conf("nameserver 8.8.8.8 # primary\nnameserver 1.1.1.1\n");
        assert_eq!(ips(&servers), [ipv4(8, 8, 8, 8), ipv4(1, 1, 1, 1)]);
    }

    #[test]
    fn parse_no_space_after_keyword() {
        let servers = parse_resolv_conf("nameserver8.8.8.8\nnameserver 1.1.1.1\n");
        assert_eq!(ips(&servers), [ipv4(1, 1, 1, 1)]);
    }

    #[test]
    fn parse_scoped_ipv6() {
        let servers = parse_resolv_conf("nameserver fe80::1%eth0\nnameserver 8.8.8.8\n");
        assert_eq!(ips(&servers), [ipv4(8, 8, 8, 8)]);
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
