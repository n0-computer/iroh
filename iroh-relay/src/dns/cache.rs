//! Simple TTL-based DNS cache using LRU eviction.

use std::{
    hash::{Hash, Hasher},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;

use super::TxtRecordData;

/// Maximum number of entries in the DNS cache.
const MAX_CACHE_ENTRIES: usize = 512;

/// Maximum TTL for cache entries (1 day).
///
/// Prevents malicious or misconfigured servers from making entries
/// effectively permanent by returning very large TTL values.
const MAX_TTL_SECS: u32 = 86400;

/// Query type key for cache entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub(super) enum QueryType {
    A,
    AAAA,
    TXT,
}

/// Pre-hash `(host, qtype)` into a u64 key for allocation-free cache lookups.
///
/// A hash collision between different (host, qtype) pairs could return wrong
/// cached data (e.g. addresses for the wrong domain). The `from_cache` closure
/// in the resolver rejects type mismatches (A vs AAAA vs TXT), but a same-type
/// cross-domain collision would be silent. With 64-bit hashes and a 512-entry
/// cache, the birthday-bound probability is ~1.4e-14 per lookup -- negligible
/// in practice.
fn cache_key(host: &str, qtype: QueryType) -> u64 {
    let mut hasher = std::hash::DefaultHasher::new();
    host.hash(&mut hasher);
    qtype.hash(&mut hasher);
    hasher.finish()
}

/// A cached DNS result.
#[derive(Debug, Clone)]
pub(super) enum CachedRecord {
    A(Vec<Ipv4Addr>),
    Aaaa(Vec<Ipv6Addr>),
    Txt(Vec<TxtRecordData>),
}

/// A cache entry with TTL expiry tracking.
#[derive(Debug, Clone)]
struct CacheEntry {
    record: CachedRecord,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Thread-safe DNS cache with LRU eviction and TTL-based expiry.
///
/// Uses pre-hashed u64 keys to avoid allocating a `String` on every lookup.
/// The only remaining per-hit allocation is the `record.clone()` on cache hit,
/// necessary because the result must outlive the lock guard.
#[derive(Debug)]
pub(super) struct DnsCache {
    inner: Mutex<LruCache<u64, CacheEntry>>,
}

impl DnsCache {
    pub(super) fn new() -> Self {
        Self {
            inner: Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(MAX_CACHE_ENTRIES).expect("non-zero"),
            )),
        }
    }

    /// Look up a cached record. Returns `None` if not found or expired.
    pub(super) fn get(&self, host: &str, qtype: QueryType) -> Option<CachedRecord> {
        let key = cache_key(host, qtype);
        let mut inner = self.inner.lock().expect("poisoned");
        let entry = inner.get(&key)?;
        if entry.is_expired() {
            inner.pop(&key);
            return None;
        }
        Some(entry.record.clone())
    }

    /// Insert a record into the cache with the given TTL.
    ///
    /// A TTL of 0 means don't cache. This also means that negative responses
    /// (NXDOMAIN, NODATA) are never cached, since empty results have TTL 0.
    /// This matches the old hickory-resolver configuration which set
    /// `negative_max_ttl = Some(Duration::ZERO)`.
    ///
    /// **Known limitation:** Without negative caching, repeated queries for
    /// non-existent domains always hit the network. Under high concurrency
    /// this can become a thundering herd. A future improvement could cache
    /// negative results for a short duration (e.g. 5-10 seconds).
    pub(super) fn insert(&self, host: &str, qtype: QueryType, record: CachedRecord, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let entry = CacheEntry {
            record,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl.min(MAX_TTL_SECS) as u64),
        };
        self.inner
            .lock()
            .expect("poisoned")
            .put(cache_key(host, qtype), entry);
    }

    /// Clear all cache entries.
    pub(super) fn clear(&self) {
        self.inner.lock().expect("poisoned").clear();
    }
}
