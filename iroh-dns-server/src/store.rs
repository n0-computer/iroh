//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

use anyhow::Result;
use hickory_server::proto::rr::{Name, RecordSet, RecordType, RrKey};
use lru::LruCache;
use pkarr::{Client as PkarrClient, SignedPacket};
use tokio::sync::Mutex;
use tracing::{debug, trace};
use ttl_cache::TtlCache;

use self::signed_packets::SignedPacketStore;
use crate::{
    config::BootstrapOption,
    metrics::Metrics,
    util::{signed_packet_to_hickory_records_without_origin, PublicKeyBytes},
};

mod signed_packets;
pub use signed_packets::Options as ZoneStoreOptions;

/// Cache up to 1 million pkarr zones by default
pub const DEFAULT_CACHE_CAPACITY: usize = 1024 * 1024;
/// Default TTL for DHT cache entries
pub const DHT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Where a new pkarr packet comes from
pub enum PacketSource {
    /// Received via HTTPS relay PUT
    PkarrPublish,
}

/// A store for pkarr signed packets.
///
/// Packets are stored in the persistent `SignedPacketStore`, and cached on-demand in an in-memory LRU
/// cache used for resolving DNS queries.
#[derive(Debug, Clone)]
pub struct ZoneStore {
    cache: Arc<Mutex<ZoneCache>>,
    store: Arc<SignedPacketStore>,
    pkarr: Option<Arc<PkarrClient>>,
    metrics: Arc<Metrics>,
}

impl ZoneStore {
    /// Create a persistent store
    pub fn persistent(
        path: impl AsRef<Path>,
        options: ZoneStoreOptions,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        let packet_store = SignedPacketStore::persistent(path, options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Create an in-memory store.
    pub fn in_memory(options: ZoneStoreOptions, metrics: Arc<Metrics>) -> Result<Self> {
        let packet_store = SignedPacketStore::in_memory(options, metrics.clone())?;
        Ok(Self::new(packet_store, metrics))
    }

    /// Configure a pkarr client for resolution of packets from the bittorrent mainline DHT.
    ///
    /// This will be used only as a fallback if there is no local info available.
    ///
    /// Optionally set custom bootstrap nodes. If `bootstrap` is empty it will use the default
    /// mainline bootstrap nodes.
    pub fn with_mainline_fallback(self, bootstrap: BootstrapOption) -> Self {
        let pkarr_client = match bootstrap {
            BootstrapOption::Default => PkarrClient::builder().build().unwrap(),
            BootstrapOption::Custom(bootstrap) => PkarrClient::builder()
                .dht(|builder| builder.bootstrap(&bootstrap))
                .build()
                .unwrap(),
        };
        Self {
            pkarr: Some(Arc::new(pkarr_client)),
            ..self
        }
    }

    /// Create a new zone store.
    pub fn new(store: SignedPacketStore, metrics: Arc<Metrics>) -> Self {
        let zone_cache = ZoneCache::new(DEFAULT_CACHE_CAPACITY);
        Self {
            store: Arc::new(store),
            cache: Arc::new(Mutex::new(zone_cache)),
            pkarr: None,
            metrics,
        }
    }

    /// Resolve a DNS query.
    #[allow(clippy::unused_async)]
    pub async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &Name,
        record_type: RecordType,
    ) -> Result<Option<Arc<RecordSet>>> {
        tracing::info!("{} {}", name, record_type);
        if let Some(rset) = self.cache.lock().await.resolve(pubkey, name, record_type) {
            return Ok(Some(rset));
        }

        if let Some(packet) = self.store.get(pubkey).await? {
            return self
                .cache
                .lock()
                .await
                .insert_and_resolve(&packet, name, record_type);
        };

        if let Some(pkarr) = self.pkarr.as_ref() {
            let key = pkarr::PublicKey::try_from(pubkey.as_bytes()).expect("valid public key");
            // use the more expensive `resolve_most_recent` here.
            //
            // it will be cached for some time.
            debug!("DHT resolve {}", key.to_z32());
            let packet_opt = pkarr.resolve(&key).await;
            if let Some(packet) = packet_opt {
                debug!("DHT resolve successful {:?}", packet);
                return self
                    .cache
                    .lock()
                    .await
                    .insert_and_resolve_dht(&packet, name, record_type);
            } else {
                debug!("DHT resolve failed");
            }
        }
        Ok(None)
    }

    /// Get the latest signed packet for a pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub async fn get_signed_packet(&self, pubkey: &PublicKeyBytes) -> Result<Option<SignedPacket>> {
        self.store.get(pubkey).await
    }

    /// Insert a signed packet into the cache and the store.
    ///
    /// Returns whether this produced an update, i.e. whether the packet is the newest for its
    /// pubkey.
    // allow unused async: this will be async soon.
    #[allow(clippy::unused_async)]
    pub async fn insert(&self, signed_packet: SignedPacket, _source: PacketSource) -> Result<bool> {
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

#[derive(derive_more::Debug)]
struct ZoneCache {
    /// Cache for explicitly added entries
    cache: LruCache<PublicKeyBytes, CachedZone>,
    /// Cache for DHT entries, this must have a finite TTL
    /// so we don't cache stale entries indefinitely.
    #[debug("dht_cache")]
    dht_cache: TtlCache<PublicKeyBytes, CachedZone>,
}

impl ZoneCache {
    fn new(cap: usize) -> Self {
        let cache = LruCache::new(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
        let dht_cache = TtlCache::new(cap);
        Self { cache, dht_cache }
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
        let zone = CachedZone::from_signed_packet(signed_packet)?;
        let res = zone.resolve(name, record_type);
        self.dht_cache.insert(pubkey, zone, DHT_CACHE_TTL);
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
            return Ok(());
        }
        self.cache
            .put(pubkey, CachedZone::from_signed_packet(signed_packet)?);
        Ok(())
    }

    fn remove(&mut self, pubkey: &PublicKeyBytes) {
        self.cache.pop(pubkey);
        self.dht_cache.remove(pubkey);
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
            timestamp: signed_packet.timestamp().into(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > signed_packet.timestamp().into()
    }

    fn resolve(&self, name: &Name, record_type: RecordType) -> Option<Arc<RecordSet>> {
        let key = RrKey::new(name.into(), record_type);
        for record in self.records.keys() {
            tracing::info!("record {:?}", record);
        }
        self.records.get(&key).cloned()
    }
}
