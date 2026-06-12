//! System DNS configuration from Windows network adapters.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use super::{DNS_PORT, DnsConfig, DnsProtocol};

/// Deprecated IPv6 site-local anycast addresses still configured by Windows.
///
/// Windows still configures these site-local addresses as soon as an IPv6 loopback
/// interface is configured. We do not want to use these DNS servers, the chances of them
/// being usable are almost always close to zero, while the chance of DNS configuration
/// **only** relying on these servers and not also being configured normally are also almost
/// zero. The chance of the DNS resolver accidentally trying one of these and taking a
/// bunch of timeouts to figure out they're no good are on the other hand very high.
const WINDOWS_BAD_SITE_LOCAL_DNS_SERVERS: [IpAddr; 3] = [
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 2)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0xffff, 0, 0, 0, 3)),
];

/// Read DNS servers from Windows network adapter configuration.
pub(super) fn read_system_dns() -> Result<DnsConfig, std::io::Error> {
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

    // Read search domains from the Windows registry (comma-separated SearchList key).
    // Falls back to the primary domain if no search list is configured.
    let search_domains = ipconfig::computer::get_search_list()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    let search_domains = if search_domains.is_empty() {
        ipconfig::computer::get_domain()
            .ok()
            .flatten()
            .filter(|s| !s.is_empty())
            .into_iter()
            .collect()
    } else {
        search_domains
    };

    Ok(DnsConfig {
        nameservers: servers,
        search_domains,
        ndots: None,
    })
}
