//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use n0_error::{AnyError, e};
use n0_future::{
    FuturesUnordered, MaybeFuture, StreamExt,
    boxed::BoxFuture,
    time::{self, Duration},
};
use simple_dns::TYPE;
use tracing::{debug, trace};

use super::{
    BoxIter, Builder, DnsError, DnsProtocol, TxtRecordData,
    cache::{CachedRecord, DnsCache, QueryType},
    query::{self, MAX_CNAME_DEPTH},
    system_config, transport,
};
use crate::dns::{Resolver, system_config::DnsConfig};

/// Per-nameserver timeout for a single attempt.
const NAMESERVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum number of nameserver queries in flight at once.
///
/// Bounds how many servers we race so that growing the nameserver list does
/// not turn every lookup into an N-way fan-out.
const MAX_CONCURRENT_QUERIES: usize = 3;

/// Delay before starting the next nameserver attempt, unless the in-flight
/// attempt fails first. Gives faster servers a head start without blasting
/// the whole list at once (happy-eyeballs style).
const QUERY_ATTEMPT_DELAY: Duration = Duration::from_millis(100);

/// Number of UDP retry attempts per nameserver before giving up.
/// UDP is unreliable, so a single dropped packet shouldn't be fatal.
const UDP_ATTEMPTS: usize = 2;

/// EWMA weight for folding a new RTT sample into a nameserver's smoothed RTT.
const SRTT_ALPHA: f64 = 0.3;
/// Penalty added to a nameserver's smoothed RTT on a failed attempt, in
/// microseconds. Large enough to demote it below currently-healthy servers.
const SRTT_FAILURE_PENALTY_MICROS: f64 = 150_000.0;
/// Upper bound on a nameserver's smoothed RTT, in microseconds.
const SRTT_MAX_MICROS: f64 = 5_000_000.0;
/// Time constant (seconds) of the read-time decay of the smoothed RTT toward
/// zero, so demoted servers recover and get re-probed.
const SRTT_DECAY_SECS: f64 = 180.0;

/// Smoothed round-trip time estimate for one nameserver.
///
/// Used to order nameservers fastest-first and to demote ones that fail. A
/// read-time exponential decay pulls the estimate back toward zero so that a
/// demoted server eventually gets re-probed, and a once-fast server that has
/// gone away does not stay preferred forever.
#[derive(Debug)]
struct Srtt {
    /// Smoothed estimate in microseconds, as of `updated`.
    micros: f64,
    /// When `micros` was last written.
    updated: Instant,
}

impl Srtt {
    fn new() -> Self {
        Self {
            micros: 0.0,
            updated: Instant::now(),
        }
    }

    /// The decayed estimate at `now`, used for ordering.
    fn decayed(&self, now: Instant) -> f64 {
        let dt = now.saturating_duration_since(self.updated).as_secs_f64();
        self.micros * (-dt / SRTT_DECAY_SECS).exp()
    }

    /// Folds a successful round-trip time into the estimate.
    fn record_success(&mut self, rtt: Duration, now: Instant) {
        let sample = rtt.as_micros() as f64;
        let base = self.decayed(now);
        self.micros = (SRTT_ALPHA * sample + (1.0 - SRTT_ALPHA) * base).min(SRTT_MAX_MICROS);
        self.updated = now;
    }

    /// Penalizes the estimate after a failed attempt.
    fn record_failure(&mut self, now: Instant) {
        let base = self.decayed(now);
        self.micros = (base + SRTT_FAILURE_PENALTY_MICROS).min(SRTT_MAX_MICROS);
        self.updated = now;
    }
}

/// Default value for `ndots` per resolv.conf(5).
///
/// Names with at least this many dots are tried as absolute names first,
/// before appending search domains. Names with fewer dots try search
/// domains first. See <https://man7.org/linux/man-pages/man5/resolv.conf.5.html>.
const DEFAULT_NDOTS: usize = 1;

/// RFC 6761 Section 6.3: "localhost" and names under it resolve to loopback.
fn is_localhost(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost")
}

#[derive(Debug)]
pub(super) struct SimpleDnsResolver {
    nameservers: Vec<(SocketAddr, DnsProtocol)>,
    search_domains: Vec<String>,
    ndots: usize,
    #[cfg(with_crypto_provider)]
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Lazily initialized, cached reqwest client for DNS-over-HTTPS queries.
    #[cfg(with_crypto_provider)]
    https_client: Mutex<Option<reqwest::Client>>,
    /// Smoothed RTT per nameserver (parallel to `nameservers`), used to order
    /// servers and re-probe demoted ones.
    health: Mutex<Vec<Srtt>>,
    cache: DnsCache,
    builder: Builder,
}

impl SimpleDnsResolver {
    pub(super) fn new(builder: Builder) -> Self {
        let (nameservers, search_domains, ndots) = Self::build_config(&builder);
        debug!(
            ?nameservers,
            ?search_domains,
            ndots,
            "configured DNS resolver"
        );
        #[cfg(with_crypto_provider)]
        let tls_config = builder
            .tls_client_config
            .as_ref()
            .map(|c| Arc::new(c.clone()));
        let health = Mutex::new((0..nameservers.len()).map(|_| Srtt::new()).collect());
        Self {
            nameservers,
            search_domains,
            ndots,
            #[cfg(with_crypto_provider)]
            tls_config,
            #[cfg(with_crypto_provider)]
            https_client: Mutex::new(None),
            health,
            cache: DnsCache::new(),
            builder,
        }
    }

    fn build_config(builder: &Builder) -> (Vec<(SocketAddr, DnsProtocol)>, Vec<String>, usize) {
        let mut nameservers = Vec::new();
        let mut search_domains = Vec::new();
        let mut ndots = None;

        if builder.use_system_defaults {
            let config = DnsConfig::system_with_fallback();
            nameservers.extend(config.nameservers);
            search_domains = config.search_domains;
            ndots = config.ndots;
        }

        nameservers.extend(builder.nameservers.iter().copied());

        if nameservers.is_empty() {
            nameservers.extend(DnsConfig::fallback().nameservers);
        }

        (nameservers, search_domains, ndots.unwrap_or(DEFAULT_NDOTS))
    }

    /// Returns the list of candidate names to try for a given hostname,
    /// applying search domain expansion per resolv.conf(5) semantics.
    ///
    /// - If the name ends with `.` (FQDN), it is used as-is.
    /// - If the name has more labels than `ndots`, try the bare name first,
    ///   then each search domain suffix.
    /// - Otherwise, try each search domain suffix first, then the bare name.
    ///
    /// See <https://man7.org/linux/man-pages/man5/resolv.conf.5.html>.
    fn search_names(&self, host: &str) -> Vec<String> {
        // Explicit FQDN: no search domain expansion.
        if host.ends_with('.') || self.search_domains.is_empty() {
            return vec![host.to_string()];
        }

        // Label count = dots + 1 (e.g. "foo.bar" has 2 labels).
        // resolv.conf(5): "if the name has more dots than ndots, try as absolute first"
        // which is equivalent to num_labels > ndots.
        let num_labels = host.bytes().filter(|&b| b == b'.').count() + 1;
        let bare_first = num_labels > self.ndots;

        let mut names = Vec::with_capacity(self.search_domains.len() + 1);
        let mut push = |name: String| {
            if !names.contains(&name) {
                names.push(name);
            }
        };

        if bare_first {
            push(host.to_string());
        }
        for domain in &self.search_domains {
            push(format!("{host}.{domain}"));
        }
        if !bare_first {
            push(host.to_string());
        }

        names
    }

    /// Returns a clone of the cached reqwest client, creating it on first use.
    ///
    /// `reqwest::Client` uses an inner `Arc`, so cloning is cheap.
    #[cfg(with_crypto_provider)]
    fn get_or_init_https_client(&self) -> Result<reqwest::Client, DnsError> {
        let mut guard = self.https_client.lock().expect("poisoned");
        match guard.as_ref() {
            Some(client) => Ok(client.clone()),
            None => {
                let client = transport::build_https_client(self.tls_config.as_ref())?;
                *guard = Some(client.clone());
                Ok(client)
            }
        }
    }

    /// Run a future with [`NAMESERVER_TIMEOUT`].
    async fn with_timeout<T, E: Into<AnyError>>(
        fut: impl Future<Output = Result<T, E>>,
    ) -> Result<T, DnsError> {
        time::timeout(NAMESERVER_TIMEOUT, fut)
            .await
            .map(|r| r.map_err(|e| e!(DnsError::Resolve, e.into())))
            .map_err(|_| e!(DnsError::Timeout))?
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
                    e!(DnsError::Resolve {
                        source: std::io::Error::other("TLS config required for DNS-over-TLS")
                            .into(),
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

    /// Returns nameserver indices ordered fastest-first by smoothed RTT.
    fn nameserver_order(&self) -> Vec<usize> {
        let now = Instant::now();
        let health = self.health.lock().expect("poisoned");
        let mut order: Vec<usize> = (0..self.nameservers.len()).collect();
        order.sort_by(|&a, &b| health[a].decayed(now).total_cmp(&health[b].decayed(now)));
        order
    }

    /// Records a successful query against nameserver `idx`.
    fn record_success(&self, idx: usize, rtt: Duration) {
        self.health.lock().expect("poisoned")[idx].record_success(rtt, Instant::now());
    }

    /// Records a failed query against nameserver `idx`.
    fn record_failure(&self, idx: usize) {
        self.health.lock().expect("poisoned")[idx].record_failure(Instant::now());
    }

    /// Sends a query to the configured nameservers, racing them happy-eyeballs
    /// style: tries the historically fastest first, starts the next either
    /// [`QUERY_ATTEMPT_DELAY`] later or as soon as the in-flight attempt fails
    /// (fail-fast), and caps in-flight attempts at [`MAX_CONCURRENT_QUERIES`].
    ///
    /// The first successful response wins; UDP queries are retried per
    /// nameserver on failure. Per-server success and failure update the
    /// smoothed RTT used for ordering, so the server list is self-healing.
    async fn send_query(&self, query_bytes: &[u8]) -> Result<Vec<u8>, DnsError> {
        if self.nameservers.is_empty() {
            return Err(e!(DnsError::NoResponse));
        }

        let order = self.nameserver_order();
        // Index into `order` of the next nameserver to try.
        let mut next = 0;
        // In-flight attempts, each yielding (nameserver index, start, result).
        let mut dials = FuturesUnordered::new();
        let mut last_err = None;
        // Timer after which to start the next attempt, or `None` for immediately.
        let next_attempt = MaybeFuture::None;
        tokio::pin!(next_attempt);

        loop {
            // Start the next attempt if one is due (no pending delay), we are
            // under the concurrency cap, and a nameserver remains.
            if next_attempt.is_none() && dials.len() < MAX_CONCURRENT_QUERIES && next < order.len()
            {
                let idx = order[next];
                next += 1;
                let (addr, proto) = self.nameservers[idx];
                let start = Instant::now();
                dials.push(async move {
                    (
                        idx,
                        start,
                        self.query_nameserver(addr, proto, query_bytes).await,
                    )
                });
                // Pace the following attempt, unless this was the last server.
                if next < order.len() {
                    next_attempt
                        .as_mut()
                        .set_future(time::sleep(QUERY_ATTEMPT_DELAY));
                }
            }

            if dials.is_empty() && next >= order.len() {
                return Err(last_err.unwrap_or_else(|| e!(DnsError::NoResponse)));
            }

            tokio::select! {
                biased;
                // A dial attempt completed.
                Some((idx, start, res)) = dials.next(), if !dials.is_empty() => match res {
                    Ok(resp) => {
                        self.record_success(idx, start.elapsed());
                        return Ok(resp);
                    }
                    Err(e) => {
                        self.record_failure(idx);
                        last_err = Some(e);
                        // Fail fast: start the next attempt now rather than waiting.
                        next_attempt.as_mut().set_none();
                    }
                },
                // The next attempt is due.
                () = &mut next_attempt, if next_attempt.is_some() => {
                    next_attempt.as_mut().set_none();
                }
            }
        }
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
            let packet = simple_dns::Packet::parse(&response)
                .map_err(|err| e!(DnsError::Resolve, AnyError::from_std(err)))?;

            let has_answer = packet
                .answers
                .iter()
                .any(|rr| rr.rdata.type_code() == qtype);

            if has_answer {
                return Ok((response, id));
            }

            // No records of the requested type -- follow CNAME if present.
            let Some(target) = query::cname_target(&packet, &current_host) else {
                return Ok((response, id));
            };
            debug!(from = %current_host, to = %target, "following CNAME");
            current_host = target;
        }
        Err(e!(DnsError::InvalidResponse))
    }

    /// Shared lookup logic: check cache, try search names, parse response, cache result.
    #[allow(clippy::type_complexity)]
    async fn lookup<T: Clone + std::fmt::Debug>(
        &self,
        host: &str,
        qtype: QueryType,
        dns_type: TYPE,
        from_cache: fn(CachedRecord) -> Option<Vec<T>>,
        parse: fn(&[u8], u16) -> Result<(Vec<T>, u32), DnsError>,
        to_cache: fn(Vec<T>) -> CachedRecord,
    ) -> Result<Vec<T>, DnsError> {
        if let Some(cached) = self.cache.get(host, qtype).and_then(from_cache) {
            trace!(%host, records = cached.len(), ?qtype, "cache hit");
            return Ok(cached);
        }

        let mut last_err = None;
        let names = self.search_names(host);
        let total = names.len();
        for (i, name) in names.into_iter().enumerate() {
            trace!(%name, ?qtype, "resolving");
            let res = match self
                .send_query_following_cnames(name.clone(), dns_type)
                .await
            {
                Ok((response, id)) => parse(&response, id),
                Err(e) => Err(e),
            };
            match res {
                Ok((results, ttl)) if !results.is_empty() => {
                    debug!(%host, ?qtype, ?results, ttl, "resolved");
                    self.cache
                        .insert(host, qtype, to_cache(results.clone()), ttl);
                    return Ok(results);
                }
                Ok(_) => {}
                Err(ref e @ DnsError::NxDomain { .. })
                | Err(ref e @ DnsError::ServerError { .. }) => {
                    let remaining = total - i - 1;
                    trace!(%name, ?qtype, remaining, reason = %e, "lookup failed");
                    last_err = Some(e!(DnsError::NxDomain));
                }
                Err(e) => {
                    debug!(%name, ?qtype, reason = %e, "lookup failed");
                    return Err(e);
                }
            }
        }
        let err = last_err.unwrap_or_else(|| e!(DnsError::NoResponse));
        debug!(%host, ?qtype, reason = %err, "resolve failed");
        Err(err)
    }

    pub(super) async fn lookup_ipv4(
        &self,
        host: String,
    ) -> Result<impl Iterator<Item = Ipv4Addr> + use<>, DnsError> {
        // RFC 6761: localhost always resolves to loopback.
        if is_localhost(&host) {
            return Ok(vec![Ipv4Addr::LOCALHOST].into_iter());
        }
        let addrs = self
            .lookup(
                &host,
                QueryType::A,
                TYPE::A,
                CachedRecord::into_a,
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
        // RFC 6761: localhost always resolves to loopback.
        if is_localhost(&host) {
            return Ok(vec![Ipv6Addr::LOCALHOST].into_iter());
        }
        let addrs = self
            .lookup(
                &host,
                QueryType::AAAA,
                TYPE::AAAA,
                CachedRecord::into_aaaa,
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
                CachedRecord::into_txt,
                query::parse_txt_response,
                CachedRecord::Txt,
            )
            .await?;
        Ok(records.into_iter())
    }

    pub(super) fn clear_cache(&self) {
        self.cache.clear();
    }

    pub(super) fn reset(&self) -> Self {
        Self::new(self.builder.clone())
    }
}

impl Resolver for Arc<SimpleDnsResolver> {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let this = self.clone();
        Box::pin(async move {
            let iter = (*this).lookup_ipv4(host).await?;
            let iter: BoxIter<_> = Box::new(iter);
            Ok(iter)
        })
    }

    fn lookup_ipv6(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        let this = self.clone();
        Box::pin(async move {
            let iter = (*this).lookup_ipv6(host).await?;
            let iter: BoxIter<_> = Box::new(iter);
            Ok(iter)
        })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        let this = self.clone();
        Box::pin(async move {
            let iter = (*this).lookup_txt(host).await?;
            let iter: BoxIter<_> = Box::new(iter);
            Ok(iter)
        })
    }

    fn clear_cache(&self) {
        SimpleDnsResolver::clear_cache(self);
    }

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(Arc::new(SimpleDnsResolver::reset(self)))
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

    /// Run with `cargo test -p iroh-relay resolve_success_and_nxdomain -- --ignored --nocapture`
    /// and `RUST_LOG=iroh_relay::dns=trace` to see the log output.
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_success_and_nxdomain() {
        let _ = tracing_subscriber::fmt::try_init();
        let resolver = with_proto(GOOGLE_DNS, DnsProtocol::Udp);

        tracing::info!("--- resolving example.com (first, expect network query) ---");
        let addrs: Vec<_> = resolver
            .lookup_ipv4("example.com", TIMEOUT)
            .await
            .unwrap()
            .collect();
        assert!(!addrs.is_empty());

        tracing::info!("--- resolving example.com (second, expect cache hit) ---");
        let addrs2: Vec<_> = resolver
            .lookup_ipv4("example.com", TIMEOUT)
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, addrs2);

        tracing::info!("--- resolving nonexistent domain (expect NXDOMAIN) ---");
        let err = resolver
            .lookup_ipv4("this-domain-does-not-exist.example.invalid", TIMEOUT)
            .await
            .map(|i| i.collect::<Vec<_>>());
        assert!(err.is_err(), "expected NXDOMAIN, got {err:?}");
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

        #[test]
        fn high_ndots_k8s_style() {
            let mut r = SimpleDnsResolver::new(Builder::default());
            r.search_domains = vec!["ns.svc.cluster.local".into(), "svc.cluster.local".into()];
            r.ndots = 5;
            // 4 dots < ndots=5, so search domains come first (Kubernetes behavior).
            assert_eq!(
                r.search_names("my-svc.my-ns.svc.cluster.local"),
                vec![
                    "my-svc.my-ns.svc.cluster.local.ns.svc.cluster.local",
                    "my-svc.my-ns.svc.cluster.local.svc.cluster.local",
                    "my-svc.my-ns.svc.cluster.local",
                ]
            );
        }
    }
}
