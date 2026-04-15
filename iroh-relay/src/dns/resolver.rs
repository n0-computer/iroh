//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use n0_error::e;
use n0_future::{
    FuturesUnorderedBounded, StreamExt,
    time::{self, Duration},
};
use simple_dns::{TYPE, rdata::RData};
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

/// Default value for `ndots`: hostnames with at least this many dots are
/// tried as absolute names first, before appending search domains.
const DEFAULT_NDOTS: usize = 1;

#[derive(Debug)]
pub(super) struct SimpleDnsResolver {
    nameservers: Vec<(SocketAddr, DnsProtocol)>,
    search_domains: Vec<String>,
    #[cfg(with_crypto_provider)]
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Lazily initialized, cached reqwest client for DNS-over-HTTPS queries.
    https_client: Mutex<Option<reqwest::Client>>,
    cache: DnsCache,
    builder: Builder,
}

impl SimpleDnsResolver {
    pub(super) fn new(builder: Builder) -> Self {
        let (nameservers, search_domains) = Self::build_config(&builder);
        debug!(
            nameservers = nameservers.len(),
            search_domains = search_domains.len(),
            "configured DNS resolver"
        );
        for (addr, proto) in &nameservers {
            trace!(%addr, ?proto, "nameserver");
        }
        for domain in &search_domains {
            trace!(%domain, "search domain");
        }
        #[cfg(with_crypto_provider)]
        let tls_config = builder
            .tls_client_config
            .as_ref()
            .map(|c| Arc::new(c.clone()));
        Self {
            nameservers,
            search_domains,
            #[cfg(with_crypto_provider)]
            tls_config,
            https_client: Mutex::new(None),
            cache: DnsCache::new(),
            builder,
        }
    }

    fn build_config(builder: &Builder) -> (Vec<(SocketAddr, DnsProtocol)>, Vec<String>) {
        let mut nameservers = Vec::new();
        let mut search_domains = Vec::new();

        if builder.use_system_defaults {
            let config = system_config::system_config();
            nameservers.extend(config.nameservers);
            search_domains = config.search_domains;
        }

        nameservers.extend(builder.nameservers.iter().copied());

        if nameservers.is_empty() {
            nameservers.extend(system_config::fallback_nameservers());
        }

        (nameservers, search_domains)
    }

    /// Returns the list of candidate names to try for a given hostname,
    /// applying search domain expansion per resolv.conf(5) semantics.
    ///
    /// - If the name ends with `.` (FQDN), it is used as-is.
    /// - If the name has >= `ndots` dots, try the bare name first, then
    ///   each search domain suffix.
    /// - If the name has < `ndots` dots, try each search domain suffix
    ///   first, then the bare name.
    fn search_names(&self, host: &str) -> Vec<String> {
        // Explicit FQDN: no search domain expansion.
        if host.ends_with('.') || self.search_domains.is_empty() {
            return vec![host.to_string()];
        }

        let dot_count = host.bytes().filter(|&b| b == b'.').count();
        let mut names = Vec::with_capacity(self.search_domains.len() + 1);

        if dot_count >= DEFAULT_NDOTS {
            // Likely absolute -- try bare name first.
            names.push(host.to_string());
            for domain in &self.search_domains {
                names.push(format!("{host}.{domain}"));
            }
        } else {
            // Short name -- try search domains first.
            for domain in &self.search_domains {
                names.push(format!("{host}.{domain}"));
            }
            names.push(host.to_string());
        }

        names
    }

    /// Returns a clone of the cached reqwest client, creating it on first use.
    ///
    /// `reqwest::Client` uses an inner `Arc`, so cloning is cheap.
    fn get_or_init_https_client(&self) -> Result<reqwest::Client, DnsError> {
        let mut guard = self.https_client.lock().expect("poisoned");
        if let Some(client) = guard.as_ref() {
            return Ok(client.clone());
        }
        #[cfg(with_crypto_provider)]
        let tls = self.tls_config.as_ref();
        #[cfg(not(with_crypto_provider))]
        let tls = None;
        let client = transport::build_https_client(tls)?;
        *guard = Some(client.clone());
        Ok(client)
    }

    /// Run a future with [`NAMESERVER_TIMEOUT`].
    async fn with_timeout<T>(
        fut: impl Future<Output = Result<T, DnsError>>,
    ) -> Result<T, DnsError> {
        time::timeout(NAMESERVER_TIMEOUT, fut).await?
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
                    match Self::with_timeout(transport::udp_query(addr, query_bytes)).await {
                        Ok(resp) if query::is_truncated(&resp) => {
                            debug!(%addr, "UDP response truncated, retrying over TCP");
                            return Self::with_timeout(transport::tcp_query(addr, query_bytes))
                                .await;
                        }
                        Ok(resp) => return Ok(resp),
                        Err(e) => {
                            trace!(%addr, attempt, err = %e, "UDP query failed");
                            last_err = Some(e);
                        }
                    }
                }
                Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)))
            }
            DnsProtocol::Tcp => Self::with_timeout(transport::tcp_query(addr, query_bytes)).await,
            #[cfg(with_crypto_provider)]
            DnsProtocol::Tls => {
                let tls_config = self.tls_config.as_ref().ok_or_else(|| {
                    e!(DnsError::Transport {
                        source: std::io::Error::other("TLS config required for DNS-over-TLS"),
                    })
                })?;
                Self::with_timeout(transport::tls_query(addr, query_bytes, tls_config)).await
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Https => {
                let client = self.get_or_init_https_client()?;
                Self::with_timeout(transport::https_query(addr, query_bytes, &client)).await
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

        for (i, (addr, proto)) in self.nameservers.iter().copied().enumerate() {
            let stagger = NAMESERVER_STAGGER * i as u32;
            futures.push(async move {
                if !stagger.is_zero() {
                    time::sleep(stagger).await;
                }
                trace!(%addr, ?proto, "sending DNS query");
                self.query_nameserver(addr, proto, query_bytes).await
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
        host: String,
        qtype: TYPE,
    ) -> Result<(Vec<u8>, u16), DnsError> {
        let mut current_host = host;
        for _ in 0..MAX_CNAME_DEPTH {
            let (id, query_bytes) = query::build_query(&current_host, qtype)?;
            let response = self.send_query(&query_bytes).await?;

            // Check if the response only has CNAMEs but no records of the
            // requested type. If so, follow the CNAME to a new query.
            let packet = simple_dns::Packet::parse(&response)?;
            let has_target_records = packet.answers.iter().any(|rr| {
                matches!(
                    (&rr.rdata, qtype),
                    (RData::A(_), TYPE::A)
                        | (RData::AAAA(_), TYPE::AAAA)
                        | (RData::TXT(_), TYPE::TXT)
                )
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

    /// Shared lookup logic: check cache, try search names, parse response, cache result.
    async fn lookup<T: Clone>(
        &self,
        host: &str,
        qtype: QueryType,
        dns_type: TYPE,
        from_cache: fn(&CachedRecord) -> Option<Vec<T>>,
        parse: fn(&[u8], u16) -> Result<(Vec<T>, u32), DnsError>,
        to_cache: fn(Vec<T>) -> CachedRecord,
    ) -> Result<Vec<T>, DnsError> {
        if let Some(cached) = self.cache.get(host, qtype).and_then(|r| from_cache(&r)) {
            trace!(%host, count = cached.len(), ?qtype, "cache hit");
            return Ok(cached);
        }

        let mut last_err = None;
        for name in self.search_names(host) {
            trace!(%name, ?qtype, "resolving");
            match self.send_query_following_cnames(name, dns_type).await {
                Ok((response, id)) => {
                    let (results, ttl) = parse(&response, id)?;
                    if !results.is_empty() {
                        debug!(%host, count = results.len(), ttl, ?qtype, "resolved");
                        self.cache
                            .insert(host, qtype, to_cache(results.clone()), ttl);
                        return Ok(results);
                    }
                }
                Err(DnsError::NxDomain { .. }) => {
                    last_err = Some(e!(DnsError::NxDomain));
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)))
    }

    pub(super) async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, DnsError> {
        let addrs = self
            .lookup(
                &host,
                QueryType::A,
                TYPE::A,
                |r| match r {
                    CachedRecord::A(v) => Some(v.clone()),
                    _ => None,
                },
                query::parse_a_response,
                CachedRecord::A,
            )
            .await?;
        Ok(addrs.into_iter())
    }

    pub(super) async fn lookup_ipv6(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv6Addr> + use<>, DnsError> {
        let addrs = self
            .lookup(
                &host,
                QueryType::AAAA,
                TYPE::AAAA,
                |r| match r {
                    CachedRecord::Aaaa(v) => Some(v.clone()),
                    _ => None,
                },
                query::parse_aaaa_response,
                CachedRecord::Aaaa,
            )
            .await?;
        Ok(addrs.into_iter())
    }

    pub(super) async fn lookup_txt(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = TxtRecordData> + use<>, DnsError> {
        let records = self
            .lookup(
                &host,
                QueryType::TXT,
                TYPE::TXT,
                |r| match r {
                    CachedRecord::Txt(v) => Some(v.clone()),
                    _ => None,
                },
                query::parse_txt_response,
                CachedRecord::Txt,
            )
            .await?;
        Ok(records.into_iter())
    }

    pub(super) fn clear_cache(&self) {
        self.cache.clear();
    }

    pub(super) fn reset(&mut self) {
        let (nameservers, search_domains) = Self::build_config(&self.builder);
        self.nameservers = nameservers;
        self.search_domains = search_domains;
        #[cfg(with_crypto_provider)]
        {
            self.tls_config = self
                .builder
                .tls_client_config
                .as_ref()
                .map(|c| Arc::new(c.clone()));
        }
        // Clear cached HTTPS client so it gets rebuilt with the new TLS config on next use
        *self.https_client.lock().expect("poisoned") = None;
        self.clear_cache();
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

    mod search_names {
        use super::super::{super::Builder, *};

        fn resolver_with_search(domains: &[&str]) -> SimpleDnsResolver {
            let mut r = SimpleDnsResolver::new(Builder::default());
            r.search_domains = domains.iter().map(|s| s.to_string()).collect();
            r
        }

        #[test]
        fn no_search_domains() {
            let r = SimpleDnsResolver::new(Builder::default());
            assert_eq!(r.search_names("myhost"), vec!["myhost"]);
        }

        #[test]
        fn fqdn_bypasses_search() {
            let r = resolver_with_search(&["example.com"]);
            assert_eq!(
                r.search_names("myhost.example.com."),
                vec!["myhost.example.com."]
            );
        }

        #[test]
        fn short_name_tries_search_first() {
            let r = resolver_with_search(&["example.com", "test.local"]);
            // "myhost" has 0 dots (< ndots=1), so search domains come first.
            assert_eq!(
                r.search_names("myhost"),
                vec!["myhost.example.com", "myhost.test.local", "myhost"]
            );
        }

        #[test]
        fn dotted_name_tries_bare_first() {
            let r = resolver_with_search(&["example.com"]);
            // "foo.bar" has 1 dot (>= ndots=1), so bare name comes first.
            assert_eq!(
                r.search_names("foo.bar"),
                vec!["foo.bar", "foo.bar.example.com"]
            );
        }

        #[test]
        fn multi_dot_name_tries_bare_first() {
            let r = resolver_with_search(&["example.com"]);
            assert_eq!(r.search_names("a.b.c"), vec!["a.b.c", "a.b.c.example.com"]);
        }
    }
}
