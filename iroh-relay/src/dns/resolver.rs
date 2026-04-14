//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use n0_error::e;
use n0_future::{
    FuturesUnorderedBounded, StreamExt,
    time::{self, Duration},
};
use rustls::ClientConfig;
use simple_dns::TYPE;
use tracing::{debug, trace};

use super::{
    Builder, DnsError, DnsProtocol, TxtRecordData,
    cache::{CachedRecord, DnsCache, QueryType},
    query::{self, MAX_CNAME_DEPTH},
    system_config, transport,
};

/// Per-nameserver timeout for a single attempt.
const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between launching queries to successive nameservers.
/// Gives the preferred nameserver a head start before trying alternates.
const NAMESERVER_STAGGER: Duration = Duration::from_millis(100);

/// Number of UDP retry attempts per nameserver before giving up.
/// UDP is unreliable, so a single dropped packet shouldn't be fatal.
const UDP_ATTEMPTS: usize = 2;

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

    /// Query a single nameserver, with UDP retry and truncation fallback.
    async fn query_nameserver(
        &self,
        addr: SocketAddr,
        proto: DnsProtocol,
        query_bytes: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        match proto {
            DnsProtocol::Udp => {
                let mut last_err = None;
                for attempt in 0..UDP_ATTEMPTS {
                    trace!(%addr, attempt, "sending UDP query");
                    match time::timeout(NAMESERVER_TIMEOUT, transport::udp_query(addr, query_bytes))
                        .await
                    {
                        Ok(Ok(resp)) => {
                            if query::is_truncated(&resp) {
                                debug!(%addr, "UDP response truncated, retrying over TCP");
                                return time::timeout(
                                    NAMESERVER_TIMEOUT,
                                    transport::tcp_query(addr, query_bytes),
                                )
                                .await
                                .unwrap_or_else(|_| {
                                    Err(e!(DnsError::Transport {
                                        source: std::io::Error::new(
                                            std::io::ErrorKind::TimedOut,
                                            "TCP fallback timed out",
                                        ),
                                    }))
                                });
                            }
                            return Ok(resp);
                        }
                        Ok(Err(e)) => {
                            trace!(%addr, attempt, err = %e, "UDP query failed");
                            last_err = Some(e);
                        }
                        Err(_) => {
                            trace!(%addr, attempt, "UDP query timed out");
                            last_err = Some(e!(DnsError::Transport {
                                source: std::io::Error::new(
                                    std::io::ErrorKind::TimedOut,
                                    "nameserver query timed out",
                                ),
                            }));
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)))
            }
            DnsProtocol::Tcp => {
                time::timeout(NAMESERVER_TIMEOUT, transport::tcp_query(addr, query_bytes))
                    .await
                    .unwrap_or_else(|_| {
                        Err(e!(DnsError::Transport {
                            source: std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "nameserver query timed out",
                            ),
                        }))
                    })
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Tls => {
                let tls_config = self.tls_config.as_ref().ok_or_else(|| {
                    e!(DnsError::Transport {
                        source: std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "TLS config required for DNS-over-TLS",
                        ),
                    })
                })?;
                time::timeout(
                    NAMESERVER_TIMEOUT,
                    transport::tls_query(addr, query_bytes, tls_config),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(e!(DnsError::Transport {
                        source: std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "nameserver query timed out",
                        ),
                    }))
                })
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Https => {
                let client = self.get_or_init_https_client().await?;
                time::timeout(
                    NAMESERVER_TIMEOUT,
                    transport::https_query(addr, query_bytes, &client),
                )
                .await
                .unwrap_or_else(|_| {
                    Err(e!(DnsError::Transport {
                        source: std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "nameserver query timed out",
                        ),
                    }))
                })
            }
        }
    }

    /// Send a query to all nameservers in parallel with staggered starts.
    ///
    /// Each nameserver gets a staggered start delay to give the preferred
    /// (first) nameserver a head start. The first successful response wins.
    /// UDP queries are retried once per nameserver on failure.
    async fn send_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, DnsError> {
        if self.nameservers.is_empty() {
            return Err(e!(DnsError::NoResponse));
        }

        let count = self.nameservers.len();
        let mut futures = FuturesUnorderedBounded::new(count);

        for (i, (addr, proto)) in self.nameservers.iter().enumerate() {
            let addr = *addr;
            let proto = *proto;
            let stagger = NAMESERVER_STAGGER * i as u32;
            futures.push(async move {
                if !stagger.is_zero() {
                    time::sleep(stagger).await;
                }
                trace!(%addr, ?proto, "sending DNS query");
                let result = self.query_nameserver(addr, proto, query_bytes).await;
                match &result {
                    Ok(resp) => {
                        trace!(%addr, ?proto, len = resp.len(), "DNS query succeeded");
                    }
                    Err(e) => {
                        trace!(%addr, ?proto, err = %e, "DNS query failed");
                    }
                }
                result
            });
        }

        let mut last_err = None;
        while let Some(result) = futures.next().await {
            match result {
                Ok(resp) => return Ok(resp),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)))
    }

    /// Send a query and follow CNAME chains recursively if the response contains
    /// a CNAME but no records of the requested type.
    async fn send_query_following_cnames(
        &self,
        host: &str,
        qtype: TYPE,
    ) -> Result<(Vec<u8>, u16), DnsError> {
        let mut current_host = host.to_string();
        for _ in 0..MAX_CNAME_DEPTH {
            let (id, query_bytes) = query::build_query(&current_host, qtype)?;
            let response = self.send_query(&query_bytes).await?;

            // Check if the response only has CNAMEs but no records of the
            // requested type. If so, follow the CNAME to a new query.
            let packet = simple_dns::Packet::parse(&response)
                .map_err(|e| e!(DnsError::InvalidPacket { source: e }))?;
            let has_target_records = packet.answers.iter().any(|rr| match (&rr.rdata, qtype) {
                (simple_dns::rdata::RData::A(_), TYPE::A) => true,
                (simple_dns::rdata::RData::AAAA(_), TYPE::AAAA) => true,
                (simple_dns::rdata::RData::TXT(_), TYPE::TXT) => true,
                _ => false,
            });

            if has_target_records {
                return Ok((response, id));
            }

            // No target records -- check for a CNAME to follow.
            match query::cname_target(&packet, &current_host) {
                Some(target) => {
                    debug!(
                        from = %current_host,
                        to = %target,
                        "following CNAME"
                    );
                    current_host = target;
                }
                None => {
                    // No CNAME either; return the response as-is (empty results).
                    return Ok((response, id));
                }
            }
        }
        // Exceeded max CNAME depth.
        Err(e!(DnsError::InvalidResponse))
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
        let (response, id) = self.send_query_following_cnames(&host, TYPE::A).await?;
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
        let (response, id) = self.send_query_following_cnames(&host, TYPE::AAAA).await?;
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
        let (response, id) = self.send_query_following_cnames(&host, TYPE::TXT).await?;
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
