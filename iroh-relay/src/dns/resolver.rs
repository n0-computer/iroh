//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use n0_error::e;
use n0_future::time::{self, Duration};
use rustls::ClientConfig;
use simple_dns::TYPE;
use tracing::{debug, trace};

use super::{
    Builder, DnsError, DnsProtocol, TxtRecordData,
    cache::{CachedRecord, DnsCache, QueryType},
    query, system_config, transport,
};

/// Per-nameserver timeout. Ensures we move on to the next nameserver
/// if one is unresponsive, rather than consuming the entire query budget.
/// Matches hickory-resolver's default of 5 seconds.
const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub(super) struct SimpleDnsResolver {
    nameservers: Vec<(SocketAddr, DnsProtocol)>,
    tls_config: Option<Arc<ClientConfig>>,
    /// Lazily initialized, cached reqwest client for DNS-over-HTTPS queries.
    https_client: tokio::sync::Mutex<Option<reqwest::Client>>,
    cache: std::sync::RwLock<DnsCache>,
    builder: Builder,
}

impl SimpleDnsResolver {
    pub(super) fn new(builder: Builder) -> Self {
        let nameservers = Self::build_nameservers(&builder);
        debug!(count = nameservers.len(), "configured DNS nameservers");
        for (addr, proto) in &nameservers {
            trace!(%addr, ?proto, "nameserver");
        }
        let tls_config = builder
            .tls_client_config
            .as_ref()
            .map(|c: &ClientConfig| Arc::new(c.clone()));
        Self {
            nameservers,
            tls_config,
            https_client: tokio::sync::Mutex::new(None),
            cache: std::sync::RwLock::new(DnsCache::new()),
            builder,
        }
    }

    fn build_nameservers(builder: &Builder) -> Vec<(SocketAddr, DnsProtocol)> {
        let mut nameservers = Vec::new();

        if builder.use_system_defaults {
            nameservers.extend(system_config::system_nameservers());
        }

        nameservers.extend(builder.nameservers.iter().copied());

        if nameservers.is_empty() {
            nameservers.extend(system_config::fallback_nameservers());
        }

        nameservers
    }

    /// Returns a clone of the cached reqwest client, creating it on first use.
    ///
    /// `reqwest::Client` uses an inner `Arc`, so cloning is cheap.
    async fn get_or_init_https_client(&self) -> Result<reqwest::Client, DnsError> {
        let mut guard = self.https_client.lock().await;
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        let client = transport::build_https_client(self.tls_config.as_ref())?;
        *guard = Some(client.clone());
        Ok(client)
    }

    /// Send a query to the first responding nameserver.
    async fn send_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, DnsError> {
        let mut last_err = None;
        for (addr, proto) in &self.nameservers {
            trace!(%addr, ?proto, "sending DNS query");
            let result = time::timeout(NAMESERVER_TIMEOUT, async {
                match proto {
                    DnsProtocol::Udp => {
                        let resp = transport::udp_query(*addr, query_bytes).await?;
                        // Check for truncation, fallback to TCP
                        if query::is_truncated(&resp) {
                            debug!(%addr, "UDP response truncated, retrying over TCP");
                            transport::tcp_query(*addr, query_bytes).await
                        } else {
                            Ok(resp)
                        }
                    }
                    DnsProtocol::Tcp => transport::tcp_query(*addr, query_bytes).await,
                    DnsProtocol::Tls => {
                        let tls_config = self.tls_config.as_ref().ok_or_else(|| {
                            e!(DnsError::Transport {
                                source: std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "TLS config required for DNS-over-TLS",
                                ),
                            })
                        })?;
                        transport::tls_query(*addr, query_bytes, tls_config).await
                    }
                    DnsProtocol::Https => {
                        let client = self.get_or_init_https_client().await?;
                        transport::https_query(*addr, query_bytes, &client).await
                    }
                }
            })
            .await;
            let result = match result {
                Ok(inner) => inner,
                Err(_elapsed) => {
                    trace!(%addr, ?proto, "DNS query timed out");
                    Err(e!(DnsError::Transport {
                        source: std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "nameserver query timed out",
                        ),
                    }))
                }
            };
            match result {
                Ok(resp) => {
                    trace!(%addr, ?proto, len = resp.len(), "DNS query succeeded");
                    return Ok(resp);
                }
                Err(e) => {
                    trace!(%addr, ?proto, err = %e, "DNS query failed, trying next nameserver");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)))
    }

    pub(super) async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, DnsError> {
        if let Ok(mut cache) = self.cache.write()
            && let Some(CachedRecord::A(addrs)) = cache.get(&host, QueryType::A)
        {
            trace!(%host, count = addrs.len(), "A lookup cache hit");
            return Ok(addrs.into_iter());
        }

        trace!(%host, "resolving A record");
        let (id, query_bytes) = query::build_query(&host, TYPE::A)?;
        let response = self.send_query(&query_bytes).await?;
        let (addrs, ttl) = query::parse_a_response(&response, id)?;
        debug!(%host, count = addrs.len(), ttl, "resolved A record");

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(&host, QueryType::A, CachedRecord::A(addrs.clone()), ttl);
        }

        Ok(addrs.into_iter())
    }

    pub(super) async fn lookup_ipv6(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv6Addr> + use<>, DnsError> {
        if let Ok(mut cache) = self.cache.write()
            && let Some(CachedRecord::Aaaa(addrs)) = cache.get(&host, QueryType::AAAA)
        {
            trace!(%host, count = addrs.len(), "AAAA lookup cache hit");
            return Ok(addrs.into_iter());
        }

        trace!(%host, "resolving AAAA record");
        let (id, query_bytes) = query::build_query(&host, TYPE::AAAA)?;
        let response = self.send_query(&query_bytes).await?;
        let (addrs, ttl) = query::parse_aaaa_response(&response, id)?;
        debug!(%host, count = addrs.len(), ttl, "resolved AAAA record");

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                &host,
                QueryType::AAAA,
                CachedRecord::Aaaa(addrs.clone()),
                ttl,
            );
        }

        Ok(addrs.into_iter())
    }

    pub(super) async fn lookup_txt(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = TxtRecordData> + use<>, DnsError> {
        if let Ok(mut cache) = self.cache.write()
            && let Some(CachedRecord::Txt(records)) = cache.get(&host, QueryType::TXT)
        {
            trace!(%host, count = records.len(), "TXT lookup cache hit");
            return Ok(records.into_iter());
        }

        trace!(%host, "resolving TXT record");
        let (id, query_bytes) = query::build_query(&host, TYPE::TXT)?;
        let response = self.send_query(&query_bytes).await?;
        let (records, ttl) = query::parse_txt_response(&response, id)?;
        debug!(%host, count = records.len(), ttl, "resolved TXT record");

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                &host,
                QueryType::TXT,
                CachedRecord::Txt(records.clone()),
                ttl,
            );
        }

        Ok(records.into_iter())
    }

    pub(super) fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    pub(super) fn reset(&mut self) {
        self.nameservers = Self::build_nameservers(&self.builder);
        self.tls_config = self
            .builder
            .tls_client_config
            .as_ref()
            .map(|c: &ClientConfig| Arc::new(c.clone()));
        // Clear cached HTTPS client so it gets rebuilt with the new TLS config on next use
        *self.https_client.get_mut() = None;
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use n0_future::time::Duration;

    use super::super::{DnsProtocol, DnsResolver};

    const TIMEOUT: Duration = Duration::from_secs(5);
    const GOOGLE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    const CLOUDFLARE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    const GOOGLE_DNS_TLS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853);
    const CLOUDFLARE_DNS_HTTPS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

    fn with_proto(addr: SocketAddr, proto: DnsProtocol) -> DnsResolver {
        let mut builder = DnsResolver::builder().with_nameserver(addr, proto);
        if proto == DnsProtocol::Tls {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder = builder.tls_client_config(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            );
        }
        builder.build()
    }

    async fn assert_resolves_ipv4(resolver: &DnsResolver, host: &str) {
        let addrs: Vec<_> = resolver.lookup_ipv4(host, TIMEOUT).await.unwrap().collect();
        assert!(!addrs.is_empty(), "{host} should have IPv4 addresses");
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_udp() {
        assert_resolves_ipv4(&with_proto(GOOGLE_DNS, DnsProtocol::Udp), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv6_udp() {
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);
        let addrs: Vec<_> = resolver
            .lookup_ipv6("google.com", TIMEOUT)
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_tcp() {
        assert_resolves_ipv4(&with_proto(CLOUDFLARE_DNS, DnsProtocol::Tcp), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_tls() {
        assert_resolves_ipv4(&with_proto(GOOGLE_DNS_TLS, DnsProtocol::Tls), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_https() {
        assert_resolves_ipv4(
            &with_proto(CLOUDFLARE_DNS_HTTPS, DnsProtocol::Https),
            "google.com",
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_txt_udp() {
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);
        let records: Vec<_> = resolver
            .lookup_txt("google.com", TIMEOUT)
            .await
            .unwrap()
            .collect();
        assert!(!records.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_system_defaults() {
        assert_resolves_ipv4(&DnsResolver::new(), "google.com").await;
    }

    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_multiple_sites() {
        let resolver = DnsResolver::new();
        for host in ["google.com", "cloudflare.com", "example.com"] {
            assert_resolves_ipv4(&resolver, host).await;
        }
    }
}
