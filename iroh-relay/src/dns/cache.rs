//! Simple TTL-based DNS cache using LRU eviction.

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use lru::LruCache;

use super::TxtRecordData;

/// Maximum number of entries in the DNS cache.
const MAX_CACHE_ENTRIES: usize = 512;

/// Query type key for cache entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub(super) enum QueryType {
    A,
    AAAA,
    TXT,
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

/// DNS cache with LRU eviction and TTL-based expiry.
///
/// # Allocation notes
///
/// - `get()` allocates a `String` for the lookup key because `LruCache::get`
///   requires `K: Borrow<Q>` and tuples don't implement cross-type `Borrow`.
///   This is ~20-50 bytes per lookup, negligible vs network I/O.
/// - `get()` clones the cached record (Vec of addresses). Necessary because
///   the cache is behind a `std::sync::RwLock` and the borrow can't outlive it.
/// - `insert()` allocates a `String` for the key. Unavoidable for owned storage.
#[derive(Debug)]
pub(super) struct DnsCache {
    inner: LruCache<(String, QueryType), CacheEntry>,
}

impl DnsCache {
    pub(super) fn new() -> Self {
        Self {
            inner: LruCache::new(std::num::NonZeroUsize::new(MAX_CACHE_ENTRIES).expect("non-zero")),
        }
    }

    /// Look up a cached record. Returns `None` if not found or expired.
    pub(super) fn get(&mut self, host: &str, qtype: QueryType) -> Option<CachedRecord> {
        let key = (host.to_string(), qtype);
        if let Some(entry) = self.inner.get(&key) {
            if entry.is_expired() {
                self.inner.pop(&key);
                return None;
            }
            Some(entry.record.clone())
        } else {
            None
        }
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
    pub(super) fn insert(&mut self, host: &str, qtype: QueryType, record: CachedRecord, ttl: u32) {
        if ttl == 0 {
            return;
        }
        let entry = CacheEntry {
            record,
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl as u64),
        };
        self.inner.put((host.to_string(), qtype), entry);
    }

    /// Clear all cache entries.
    pub(super) fn clear(&mut self) {
        self.inner.clear();
    }
}
