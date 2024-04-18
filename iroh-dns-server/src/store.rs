//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc};

use anyhow::Result;
use hickory_proto::rr::{Name, RecordSet, RecordType, RrKey};
use iroh_metrics::inc;
use lru::LruCache;
use parking_lot::Mutex;
use pkarr::SignedPacket;

use crate::{
    metrics::Metrics,
    util::{signed_packet_to_hickory_records_without_origin, PublicKeyBytes},
};

use self::signed_packets::SignedPacketStore;

mod signed_packets;

/// Cache up to 1 million pkarr zones by default
pub const DEFAULT_CACHE_CAPACITY: usize = 1024 * 1024;

/// Where a new pkarr packet comes from
pub enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent [`SignedPacketStore`], and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
#[derive(Debug, Clone)]
pub struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
}

impl ZoneStore {
    /// Create a persistent store
    pub fn persistent(path: impl AsRef<Path>) -> Result<Self> {
        let packet_store = SignedPacketStore::persistent(path)?;
        Ok(Self::new(packet_store))
    }

    /// Create an in-memory store.
    pub fn in_memory() -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory()?;
        Ok(Self::new(packet_store))
    }

    /// Create a new zone store.
    pub fn new(store: SignedPacketStore) -> Self {
        let zone_cache = ZoneCache::new(DEFAULT_CACHE_CAPACITY);
        Self {
            store: Arc::new(store),
            cache: Arc::new(Mutex::new(zone_cache)),
        }
    }

    /// Resolve a DNS query.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        if let Some(rset) = self.cache.lock().resolve(pubkey, name, record_type) {
            return Ok(Some(rset));
        }

        if let Some(packet) = self.store.get(pubkey)? {
            return self
                .cache
                .lock()
                .insert_and_resolve(&packet, name, record_type);
        };

        // This would be where mainline discovery could be added.

        Ok(None)
    }

    /// Get the latest signed packet for a pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub async fn get_signed_packet(&self, pubkey: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        self.store.get(pubkey)
    }

    /// Insert a signed packet into the cache and the store.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub async fn insert(&self, signed_packet: SignedPacket, _source: PacketSource) -> Result<bool> {
        let pubkey = PublicKeyBytes::from_signed_packet(&signed_packet);
        if self.store.upsert(signed_packet)? {
            inc!(Metrics, pkarr_publish_update);
            self.cache.lock().remove(&pubkey);
            Ok(true)
        } else {
            inc!(Metrics, pkarr_publish_noop);
            Ok(false)
        }
    }
}

#[derive(Debug)]
struct ZoneCache {
    cache: LruCache<PublicKeyBytes, CachedZone>,
}

impl ZoneCache {
    fn new(cap: usize) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
        Self { cache }
    }

    fn resolve(
        &mut self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        self.cache
            .get(pubkey)
            .and_then(|zone| zone.resolve(name, record_type))
    }

    fn insert_and_resolve(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        self.insert(signed_packet)?;
        Ok(self.resolve(&pubkey, name, record_type))
    }

    fn insert(&mut self, signed_packet: &SignedPacket) -> Result<()> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        if self
            .cache
            .peek(&pubkey)
            .map(|old| old.is_newer_than(signed_packet))
            .unwrap_or(false)
        {
            return Ok(());
        }
        self.cache
            .put(pubkey, CachedZone::from_signed_packet(signed_packet)?);
        Ok(())
    }

    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        self.cache.pop(pubkey);
    }
}

#[derive(Debug)]
struct CachedZone {
    timestamp: u64,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
}

impl CachedZone {
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self> {
        let (_label, records) =
            signed_packet_to_hickory_records_without_origin(signed_packet, |_| true)?;
        Ok(Self {
            records,
            timestamp: *signed_packet.timestamp(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > *signed_packet.timestamp()
    }

    fn resolve(&self, name: &Name, record_type: RecordType) -> Option<Arc<RecordSet>> {
        let key = RrKey::new(name.into(), record_type);
        self.records.get(&key).cloned()
    }
}
