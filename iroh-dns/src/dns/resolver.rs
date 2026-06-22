//! Built-in DNS resolver using `simple-dns` for packet construction/parsing
//! and tokio for transport.

#[cfg(with_crypto_provider)]
use std::sync::Mutex;
use std::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
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

use super::{BoxIter, Builder, DnsError, DnsProtocol, Nameserver, TxtRecordData};
use crate::dns::{
    Resolver,
    system_config::{DnsConfig, Hosts},
};

mod cache;
mod pool;
mod query;
mod rtt_map;
mod transport;

use self::{
    cache::{CachedRecord, DnsCache, QueryType},
    pool::ConnPool,
    query::{MAX_CNAME_DEPTH, QueryError},
    rtt_map::RttMap,
    transport::TransportError,
};

/// Maps a transport-layer failure onto the public [`DnsError`].
impl From<TransportError> for DnsError {
    fn from(err: TransportError) -> Self {
        e!(DnsError::Transport, AnyError::from_stack(err))
    }
}

/// Maps a query build or response-parse failure onto the public [`DnsError`].
impl From<QueryError> for DnsError {
    fn from(err: QueryError) -> Self {
        match err {
            QueryError::BuildQuery { source, .. } => e!(DnsError::InvalidQuery, source),
            QueryError::Malformed { .. } | QueryError::Unexpected { .. } => {
                e!(DnsError::InvalidResponse)
            }
            QueryError::NxDomain { .. } => e!(DnsError::NxDomain),
            QueryError::ServerFailure { rcode, .. } => e!(DnsError::ServerError { rcode }),
        }
    }
}

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
    nameservers: Vec<Nameserver>,
    search_domains: Vec<String>,
    ndots: usize,
    #[cfg(with_crypto_provider)]
    tls_config: Option<Arc<rustls::ClientConfig>>,
    /// Lazily initialized, cached reqwest client for DNS-over-HTTPS queries.
    #[cfg(with_crypto_provider)]
    https_client: Mutex<Option<reqwest::Client>>,
    /// Smoothed RTT per nameserver (parallel to `nameservers`), used to order
    /// servers and re-probe demoted ones.
    rtt_map: RttMap,
    /// Pooled TCP/DoT connections, reused across queries.
    conn_pool: ConnPool,
    cache: DnsCache,
    /// Static name-to-address mappings from the system hosts file, consulted
    /// ahead of the cache for A/AAAA lookups. Empty unless system defaults are
    /// in use.
    hosts: Hosts,
    builder: Builder,
}

impl SimpleDnsResolver {
    pub(super) fn new(builder: Builder) -> Self {
        Self::with_cache(builder, DnsCache::new())
    }

    /// Builds a resolver from `builder`, reusing an existing [`DnsCache`].
    ///
    /// Used by [`Self::reset`] to rebuild the resolver on a network change while
    /// carrying the cache across, so lookups keep hitting cached records while
    /// the new nameservers settle (see issue #4037).
    fn with_cache(builder: Builder, cache: DnsCache) -> Self {
        let config = Self::build_config(&builder);
        debug!(
            nameservers = ?config.nameservers,
            search_domains = ?config.search_domains,
            ndots = ?config.ndots,
            "configured DNS resolver"
        );
        #[cfg(with_crypto_provider)]
        let tls_config = builder
            .tls_client_config
            .as_ref()
            .map(|c| Arc::new(c.clone()));
        let health = RttMap::new(config.nameservers.len());
        // The hosts file is part of the system resolver configuration, so we
        // only consult it when the caller opted into system defaults. Reading
        // it here mirrors reading /etc/resolv.conf in `build_config`.
        let hosts = if builder.use_system_defaults {
            Hosts::from_system()
        } else {
            Hosts::default()
        };
        Self {
            nameservers: config.nameservers,
            search_domains: config.search_domains,
            ndots: config.ndots.unwrap_or(DEFAULT_NDOTS),
            #[cfg(with_crypto_provider)]
            tls_config,
            #[cfg(with_crypto_provider)]
            https_client: Mutex::new(None),
            rtt_map: health,
            conn_pool: ConnPool::new(),
            cache,
            hosts,
            builder,
        }
    }

    /// Builds the effective DNS config: system defaults (when requested) plus
    /// any explicitly configured nameservers, falling back to public resolvers
    /// only when neither provides any.
    fn build_config(builder: &Builder) -> DnsConfig {
        let mut config = if builder.use_system_defaults {
            DnsConfig::system().unwrap_or_default()
        } else {
            DnsConfig::default()
        };
        config
            .nameservers
            .extend(builder.nameservers.iter().cloned());
        if config.nameservers.is_empty() {
            config.nameservers = DnsConfig::fallback().nameservers;
        }
        config
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
                // Pin each named DoH server to its address so reqwest does not
                // recursively resolve the hostname.
                let resolves: Vec<(String, std::net::SocketAddr)> = self
                    .nameservers
                    .iter()
                    .filter(|ns| ns.protocol == DnsProtocol::Https)
                    .filter_map(|ns| ns.server_name.clone().map(|name| (name, ns.addr)))
                    .collect();
                let client = transport::build_https_client(self.tls_config.as_ref(), &resolves)?;
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
            .map(|r| r.map_err(|e| e!(DnsError::Transport, e.into())))
            .map_err(|_| e!(DnsError::Timeout))?
    }

    /// Query a single nameserver, with UDP retry and truncation fallback.
    async fn query_nameserver(
        &self,
        ns: &Nameserver,
        query_bytes: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        let addr = ns.addr;
        match ns.protocol {
            DnsProtocol::Udp => {
                let mut last_err = None;
                for attempt in 0..UDP_ATTEMPTS {
                    trace!(%addr, attempt, "sending UDP query");
                    match Self::with_timeout(transport::udp_query(addr, query_bytes)).await {
                        Ok(resp) if query::is_truncated(&resp) => {
                            debug!(%addr, "UDP response truncated, retrying over TCP");
                            return Self::with_timeout(transport::tcp_query(
                                &self.conn_pool,
                                addr,
                                query_bytes,
                            ))
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
            DnsProtocol::Tcp => {
                Self::with_timeout(transport::tcp_query(&self.conn_pool, addr, query_bytes)).await
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Tls => {
                let tls_config = self.tls_config.as_ref().ok_or_else(|| {
                    e!(DnsError::Resolve {
                        source: std::io::Error::other("TLS config required for DNS-over-TLS")
                            .into(),
                    })
                })?;
                Self::with_timeout(transport::tls_query(
                    &self.conn_pool,
                    addr,
                    query_bytes,
                    tls_config,
                    ns.server_name.as_deref(),
                ))
                .await
            }
            #[cfg(with_crypto_provider)]
            DnsProtocol::Https => {
                let client = self.get_or_init_https_client()?;
                Self::with_timeout(transport::https_query(
                    addr,
                    ns.server_name.as_deref(),
                    query_bytes,
                    &client,
                ))
                .await
            }
        }
    }

    /// Returns nameserver indices ordered fastest-first by smoothed RTT.
    fn nameserver_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.nameservers.len()).collect();
        order.sort_by(|&a, &b| {
            self.rtt_map
                .get_decayed(a)
                .total_cmp(&self.rtt_map.get_decayed(b))
        });
        order
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
                let start = Instant::now();
                dials.push(async move {
                    let ns = &self.nameservers[idx];
                    (idx, start, self.query_nameserver(ns, query_bytes).await)
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
                    // A SERVFAIL or REFUSED response means this server cannot
                    // answer for the name (overloaded, not authoritative, policy
                    // block). Treat it like a transport failure and race the next
                    // server rather than making it the final answer; another
                    // nameserver may still resolve the name.
                    Ok(resp) if let Some(rcode) = query::server_failure_rcode(&resp) => {
                        self.rtt_map.record_failure(idx);
                        last_err = Some(e!(DnsError::ServerError { rcode: rcode.to_string() }));
                        // Fail fast: start the next attempt now rather than waiting.
                        next_attempt.as_mut().set_none();
                    }
                    Ok(resp) => {
                        self.rtt_map.record_success(idx, start.elapsed());
                        return Ok(resp);
                    }
                    Err(e) => {
                        self.rtt_map.record_failure(idx);
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
    ) -> Result<Vec<u8>, DnsError> {
        let mut current_host = host;
        for _ in 0..MAX_CNAME_DEPTH {
            let name = simple_dns::Name::new(&current_host)
                .map_err(|e| e!(DnsError::InvalidQuery, AnyError::from_std(e)))?;
            let (id, query_bytes) = query::build_query(&current_host, qtype)?;
            let response = self.send_query(&query_bytes).await?;
            let packet =
                simple_dns::Packet::parse(&response).map_err(|_| e!(DnsError::InvalidResponse))?;

            // Validate the id, QR bit, question, and RCODE before trusting the
            // packet to decide the answer or the next CNAME target. This is the
            // only check of the response against the name we actually asked for.
            query::check_response(&packet, id, &name, qtype)?;

            let has_answer = packet
                .answers
                .iter()
                .any(|rr| rr.rdata.type_code() == qtype);

            if has_answer {
                return Ok(response);
            }

            // No records of the requested type -- follow CNAME if present.
            let Some(target) = query::cname_target(&packet, &current_host) else {
                return Ok(response);
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
        parse: fn(&[u8]) -> Result<(Vec<T>, u32), QueryError>,
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
                Ok(response) => parse(&response).map_err(DnsError::from),
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
        // A hosts-file entry overrides DNS, so check it ahead of the cache.
        if let Some(addrs) = self
            .search_names(&host)
            .iter()
            .find_map(|name| self.hosts.lookup_ipv4(name))
        {
            trace!(%host, ?addrs, "resolved from hosts file");
            return Ok(addrs.into_iter());
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
        // A hosts-file entry overrides DNS, so check it ahead of the cache.
        if let Some(addrs) = self
            .search_names(&host)
            .iter()
            .find_map(|name| self.hosts.lookup_ipv6(name))
        {
            trace!(%host, ?addrs, "resolved from hosts file");
            return Ok(addrs.into_iter());
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
        // Carry the cache across so a network change does not start DNS cold,
        // which would strand reconnects while the new nameservers settle (#4037).
        Self::with_cache(self.builder.clone(), self.cache.clone())
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
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use n0_future::time::Duration;

    use super::{
        super::{DnsProtocol, DnsResolver},
        Builder, CachedRecord, Hosts, QueryType, SimpleDnsResolver,
    };

    const TIMEOUT: Duration = Duration::from_secs(5);
    const GOOGLE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
    const CLOUDFLARE_DNS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    #[cfg(with_crypto_provider)]
    const GOOGLE_DNS_TLS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 853);
    #[cfg(with_crypto_provider)]
    const CLOUDFLARE_DNS_HTTPS: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443);

    fn with_proto(addr: SocketAddr, proto: DnsProtocol) -> DnsResolver {
        #[cfg_attr(not(with_crypto_provider), allow(unused_mut))]
        let mut builder = DnsResolver::builder().with_nameserver(addr, proto);
        #[cfg(with_crypto_provider)]
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

    #[cfg(with_crypto_provider)]
    #[tokio::test]
    #[ignore = "requires network access"]
    async fn resolve_ipv4_tls() {
        assert_resolves_ipv4(&with_proto(GOOGLE_DNS_TLS, DnsProtocol::Tls), "google.com").await;
    }

    #[cfg(with_crypto_provider)]
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

    /// Spawns a mock UDP nameserver that answers one query with `rcode`,
    /// echoing the question and adding `answer` as an A record when given.
    async fn spawn_mock_ns(
        rcode: simple_dns::RCODE,
        answer: Option<Ipv4Addr>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use simple_dns::{
            CLASS, Packet, PacketFlag, ResourceRecord,
            rdata::{A, RData},
        };

        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            let query = Packet::parse(&buf[..len]).unwrap();
            let question = query.questions[0].clone();
            let mut reply = Packet::new_reply(query.id());
            reply.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::RECURSION_AVAILABLE);
            *reply.rcode_mut() = rcode;
            if let Some(ip) = answer {
                reply.answers.push(ResourceRecord::new(
                    question.qname.clone(),
                    CLASS::IN,
                    300,
                    RData::A(A {
                        address: u32::from(ip),
                    }),
                ));
            }
            reply.questions.push(question);
            socket
                .send_to(&reply.build_bytes_vec().unwrap(), peer)
                .await
                .unwrap();
        });
        (addr, handle)
    }

    /// A SERVFAIL or REFUSED response from the fastest nameserver must not be
    /// the final answer: the resolver races on to a nameserver that can answer.
    #[tokio::test]
    async fn servfail_winner_falls_through_to_next_nameserver() {
        let (bad, bad_handle) = spawn_mock_ns(simple_dns::RCODE::ServerFailure, None).await;
        let (good, good_handle) =
            spawn_mock_ns(simple_dns::RCODE::NoError, Some(Ipv4Addr::new(10, 1, 2, 3))).await;

        // `bad` is listed first, so it is the fastest by default ordering and
        // wins the race with a SERVFAIL; the lookup must fall through to `good`.
        let resolver = DnsResolver::builder()
            .with_nameserver(bad, DnsProtocol::Udp)
            .with_nameserver(good, DnsProtocol::Udp)
            .build();

        let addrs: Vec<_> = resolver
            .lookup_ipv4("test.example", TIMEOUT)
            .await
            .unwrap()
            .collect();
        assert_eq!(addrs, [IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]);

        bad_handle.await.unwrap();
        good_handle.await.unwrap();
    }

    /// A hosts-file entry must override DNS and resolve without any network
    /// query, the way the old hickory-backed resolver honored `/etc/hosts`.
    #[tokio::test]
    async fn hosts_file_overrides_dns() {
        let mut resolver = SimpleDnsResolver::new(Builder::default());
        resolver.hosts = Hosts::from_content("10.0.1.10 myrelay.test\n::1 myrelay.test\n");

        let v4: Vec<_> = resolver
            .lookup_ipv4("myrelay.test".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(v4, [Ipv4Addr::new(10, 0, 1, 10)]);

        // A trailing dot (FQDN form) still matches the hosts entry.
        let v6: Vec<_> = resolver
            .lookup_ipv6("myrelay.test.".to_string())
            .await
            .unwrap()
            .collect();
        assert_eq!(v6, [Ipv6Addr::LOCALHOST]);
    }

    /// A major network change rebuilds the resolver via [`SimpleDnsResolver::reset`];
    /// the DNS cache must carry across so reconnects keep resolving while the new
    /// nameservers settle (issue #4037).
    #[test]
    fn cache_survives_reset() {
        let r = SimpleDnsResolver::new(Builder::default());
        r.cache.insert(
            "example.com",
            QueryType::A,
            CachedRecord::A(vec![Ipv4Addr::LOCALHOST]),
            300,
        );

        let reset = r.reset();

        let cached = reset.cache.get("example.com", QueryType::A);
        let survived = matches!(&cached, Some(CachedRecord::A(addrs)) if addrs.as_slice() == [Ipv4Addr::LOCALHOST]);
        assert!(survived, "cache entry should survive reset, got {cached:?}");
    }
}
