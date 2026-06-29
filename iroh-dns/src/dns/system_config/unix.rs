//! System DNS configuration from `/etc/resolv.conf`.

use std::net::{IpAddr, SocketAddr};

use super::{DNS_PORT, DnsConfig, DnsProtocol, Nameserver};

/// Read `/etc/resolv.conf` and extract nameserver addresses and search domains.
pub(super) fn read_system_dns() -> Result<DnsConfig, std::io::Error> {
    let content = std::fs::read_to_string("/etc/resolv.conf")?;
    Ok(parse_resolv_conf(&content))
}

/// Parse resolv.conf content and extract nameserver addresses and search domains.
///
/// Recognized directives:
/// - `nameserver <ip>` -- adds a DNS nameserver
/// - `search <domain> [<domain> ...]` -- sets the search domain list
/// - `domain <domain>` -- equivalent to a single-entry search list
/// - `options ndots:<n>` -- sets the `ndots` search threshold
///
/// The `search` and `domain` directives are mutually exclusive per resolv.conf(5);
/// the last one seen wins, matching standard resolver behavior.
///
/// `options timeout:`, `options attempts:`, `options rotate`, and `sortlist`
/// are deliberately ignored. iroh wraps every lookup in its own timeout and
/// per-nameserver attempt budget, orders nameservers by measured RTT (which
/// subsumes `rotate`), and selects addresses itself (which subsumes
/// `sortlist`), so honoring these would have no observable effect.
fn parse_resolv_conf(content: &str) -> DnsConfig {
    let mut servers = Vec::new();
    let mut search_domains = Vec::new();
    let mut ndots = None;

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
                    let addr = addr_str.parse::<SocketAddr>().ok().or_else(|| {
                        addr_str
                            .parse::<IpAddr>()
                            .ok()
                            .map(|ip| SocketAddr::new(ip, DNS_PORT))
                    });
                    if let Some(addr) = addr {
                        servers.push(Nameserver::new(addr, DnsProtocol::Udp));
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
            Some("options") => {
                for opt in parts {
                    if let Some(n) = opt.strip_prefix("ndots:").and_then(|v| v.parse().ok()) {
                        ndots = Some(n);
                    }
                }
            }
            _ => {}
        }
    }

    DnsConfig {
        nameservers: servers,
        search_domains,
        ndots,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ips(config: &DnsConfig) -> Vec<IpAddr> {
        config.nameservers.iter().map(|ns| ns.addr.ip()).collect()
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn parse_basic() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 8.8.4.4\n");
        assert_eq!(ips(&config), [ipv4(8, 8, 8, 8), ipv4(8, 8, 4, 4)]);
        assert!(
            config
                .nameservers
                .iter()
                .all(|ns| ns.protocol == DnsProtocol::Udp)
        );
    }

    #[test]
    fn parse_ipv6() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\nnameserver 2001:4860:4860::8888\n");
        assert_eq!(config.nameservers.len(), 2);
        assert!(config.nameservers[1].addr.ip().is_ipv6());
    }

    #[test]
    fn parse_comments_and_directives() {
        let config = parse_resolv_conf(
            "# comment\n; comment\nsearch example.com\nnameserver 1.1.1.1\noptions ndots:5\nnameserver 1.0.0.1\n",
        );
        assert_eq!(ips(&config), [ipv4(1, 1, 1, 1), ipv4(1, 0, 0, 1)]);
        assert_eq!(config.search_domains, ["example.com"]);
        assert_eq!(config.ndots, Some(5));
    }

    #[test]
    fn parse_ndots() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\noptions ndots:3\n");
        assert_eq!(config.ndots, Some(3));
    }

    #[test]
    fn parse_ndots_default() {
        let config = parse_resolv_conf("nameserver 8.8.8.8\n");
        assert_eq!(config.ndots, None);
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
        assert_eq!(
            config.nameservers[0].addr,
            "8.8.8.8:5353".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(config.nameservers[1].addr.port(), DNS_PORT);
    }

    #[test]
    fn search_overrides_domain() {
        let config =
            parse_resolv_conf("domain old.com\nsearch new.com other.com\nnameserver 8.8.8.8\n");
        // Last directive wins, per resolv.conf(5).
        assert_eq!(config.search_domains, ["new.com", "other.com"]);
    }
}
