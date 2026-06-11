//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

use hickory_server::proto::{
    ProtoError,
    rr::{Name, RecordSet, RecordType, RrKey},
};
use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp};
use lru::LruCache;
use mainline::{Dht, DhtBuilder, MutableItem};
use n0_error::{Result, StdResultExt};
pub(crate) use signed_packets::Options;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};
use ttl_cache::TtlCache;

use self::signed_packets::SignedPacketStore;
use crate::{
    config::BootstrapOption,
    metrics::Metrics,
    util::{PublicKeyBytes, signed_packet_to_hickory_records_without_origin},
};

mod signed_packets;

/// Cache up to 1 million pkarr zones by default
const DEFAULT_CACHE_CAPACITY: usize = 1024 * 1024;
/// Default TTL for DHT cache entries
const DHT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Where a new pkarr packet comes from
pub(crate) enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent `SignedPacketStore`, and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
#[derive(Debug, Clone)]
pub(crate) struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
    dht: Option<Dht>,
    metrics: Arc<Metrics>,
}

impl ZoneStore {
    /// Create a persistent store
    pub(crate) fn persistent(
        path: impl AsRef<Path>,
        options: Options,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let packet_store = SignedPacketStore::persistent(path, options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Create an in-memory store.
    #[cfg(test)]
    pub(crate) fn in_memory(options: Options, metrics: Arc<Metrics>) -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory(options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Configure a mainline DHT client for resolution of packets as a fallback.
    ///
    /// This will be used only as a fallback if there is no local info available.
    ///
    /// Optionally set custom bootstrap nodes. If `bootstrap` is empty it will use the default
    /// mainline bootstrap nodes.
    pub(crate) fn with_mainline_fallback(self, bootstrap: BootstrapOption) -> Self {
        let mut builder = DhtBuilder::default();
        if let BootstrapOption::Custom(ref nodes) = bootstrap {
            builder.bootstrap(nodes);
        }
        let dht = builder.build().expect("failed to build DHT node");
        Self {
            dht: Some(dht),
            ..self
        }
    }

    /// Create a new zone store.
    fn new(store: SignedPacketStore, metrics: Arc<Metrics>) -> Self {
        let zone_cache = ZoneCache::new(DEFAULT_CACHE_CAPACITY, metrics.clone());
        Self {
            store: Arc::new(store),
            cache: Arc::new(Mutex::new(zone_cache)),
            dht: None,
            metrics,
        }
    }

    /// Resolve a DNS query.
    #[tracing::instrument("resolve", skip_all, fields(pubkey=%pubkey,name=%name,typ=%record_type))]
    pub(crate) async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        trace!("store resolve");

        // Check cache first (short lock scope)
        {
            let mut cache = self.cache.lock().await;
            if let Some(rset) = cache.resolve(pubkey, name, record_type) {
                debug!(
                    len = rset.records_without_rrsigs().count(),
                    "resolved from cache"
                );
                return Ok(Some(rset));
            }
        }

        // Check persistent store
        if let Some(packet) = self.store.get(pubkey).await? {
            trace!(packet_timestamp = ?packet.timestamp(), "store hit");
            let mut cache = self.cache.lock().await;
            let result = cache.insert_and_resolve(&packet, name, record_type);
            return match result {
                Ok(Some(rset)) => {
                    debug!(
                        len = rset.records_without_rrsigs().count(),
                        "resolved from store"
                    );
                    Ok(Some(rset))
                }
                Ok(None) => {
                    debug!("resolved to zone, but no matching records in zone");
                    Ok(None)
                }
                Err(err) => {
                    warn!("failed to retrieve zone after inserting in cache: {err:#?}");
                    Err(err)
                }
            };
        };

        if let Some(dht) = self.dht.as_ref() {
            debug!("DHT resolve {}", pubkey.to_z32());
            let maybe_item = dht
                .clone()
                .as_async()
                .get_mutable_most_recent(pubkey.as_bytes(), None)
                .await;
            if let Some(item) = maybe_item
                && let Ok(packet) = mutable_item_to_signed_packet(&item)
            {
                debug!("DHT resolve successful {:?}", packet);
                return self
                    .cache
                    .lock()
                    .await
                    .insert_and_resolve_dht(&packet, name, record_type);
            }
            debug!("DHT resolve failed");
        }
        Ok(None)
    }

    /// Get the latest signed packet for a pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn get_signed_packet(
        &self,
        pubkey: &PublicKeyBytes,
    ) -> Result<Option<SignedPacket>> {
        self.store.get(pubkey).await
    }

    /// Insert a signed packet into the cache and the store.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub(crate) async fn insert(
        &self,
        signed_packet: SignedPacket,
        _source: PacketSource,
    ) -> Result<bool> {
        let pubkey = PublicKeyBytes::from_signed_packet(&signed_packet);
        if self.store.upsert(signed_packet).await? {
            self.metrics.pkarr_publish_update.inc();
            self.cache.lock().await.remove(&pubkey);
            Ok(true)
        } else {
            self.metrics.pkarr_publish_noop.inc();
            Ok(false)
        }
    }
}

/// Convert a mainline [`MutableItem`] to a [`SignedPacket`].
fn mutable_item_to_signed_packet(
    item: &MutableItem,
) -> Result<SignedPacket, SignedPacketVerifyError> {
    SignedPacket::from_parts_unchecked(
        item.key(),
        item.signature(),
        Timestamp::from_micros(item.seq() as u64),
        item.value(),
    )
}

#[derive(derive_more::Debug)]
struct ZoneCache {
    /// Cache for explicitly added entries
    cache: LruCache<PublicKeyBytes, CachedZone>,
    /// Cache for DHT entries, this must have a finite TTL
    /// so we don't cache stale entries indefinitely.
    #[debug("dht_cache")]
    dht_cache: TtlCache<PublicKeyBytes, CachedZone>,
    #[debug("metrics")]
    metrics: Arc<Metrics>,
}

impl ZoneCache {
    fn new(cap: usize, metrics: Arc<Metrics>) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
        let dht_cache = TtlCache::new(cap);
        Self {
            cache,
            dht_cache,
            metrics,
        }
    }

    fn resolve(
        &mut self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Option<Arc<RecordSet>> {
        let zone = if let Some(zone) = self.cache.get(pubkey) {
            trace!("cache hit {}", pubkey.to_z32());
            zone
        } else if let Some(zone) = self.dht_cache.get(pubkey) {
            trace!("dht cache hit {}", pubkey.to_z32());
            zone
        } else {
            return None;
        };
        zone.resolve(name, record_type)
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

    fn insert_and_resolve_dht(
        &mut self,
        signed_packet: &SignedPacket,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        let zone = CachedZone::from_signed_packet(signed_packet).anyerr()?;
        let res = zone.resolve(name, record_type);
        self.dht_cache.insert(pubkey, zone, DHT_CACHE_TTL);
        self.metrics
            .cache_zones_dht
            .set(self.dht_cache.iter().count() as i64);
        Ok(res)
    }

    fn insert(&mut self, signed_packet: &SignedPacket) -> Result<()> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        if self
            .cache
            .peek(&pubkey)
            .map(|old| old.is_newer_than(signed_packet))
            .unwrap_or(false)
        {
            trace!("insert skip: cached is newer");
            Ok(())
        } else {
            self.cache.put(
                pubkey,
                CachedZone::from_signed_packet(signed_packet).anyerr()?,
            );
            self.metrics.cache_zones.set(self.cache.len() as i64);
            trace!("inserted into cache");
            Ok(())
        }
    }

    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        self.cache.pop(pubkey);
        self.dht_cache.remove(pubkey);
        self.metrics.cache_zones.set(self.cache.len() as i64);
        self.metrics
            .cache_zones_dht
            .set(self.dht_cache.iter().count() as i64);
    }
}

#[derive(Debug)]
struct CachedZone {
    timestamp: Timestamp,
    records: BTreeMap<RrKey, Arc<RecordSet>>,
}

impl CachedZone {
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self, ProtoError> {
        let (_label, records) =
            signed_packet_to_hickory_records_without_origin(signed_packet, |_| true)?;
        Ok(Self {
            records,
            timestamp: signed_packet.timestamp(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > signed_packet.timestamp()
    }

    fn resolve(&self, name: &Name, record_type: RecordType) -> Option<Arc<RecordSet>> {
        trace!(name=%name, typ=%record_type, "resolve in zone");
        let key = RrKey::new(name.into(), record_type);
        self.records.get(&key).cloned()
    }
}
