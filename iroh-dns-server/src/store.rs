//! Pkarr packet store used to resolve DNS queries.

use std::{collections::BTreeMap, num::NonZeroUsize, path::Path, sync::Arc, time::Duration};

use iroh_dns::pkarr::{SignedPacket, SignedPacketVerifyError, Timestamp};
use lru::LruCache;
use n0_error::{Result, anyerr};
use n0_mainline::{Dht, DhtBuilder, MutableItem};
pub(crate) use signed_packets::Options;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};
use ttl_cache::TtlCache;

use self::signed_packets::SignedPacketStore;
use crate::{
    config::BootstrapOption,
    dns::message::{DnsName, QTYPE_ANY, record_type},
    metrics::Metrics,
    util::PublicKeyBytes,
};
use simple_dns::{CLASS, Packet, ResourceRecord, TYPE};

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
    ///
    /// `name` is the lowercased name relative to the zone of `pubkey`.
    /// Returns `None` if no zone is known for `pubkey`.
    #[tracing::instrument("resolve", skip_all, fields(pubkey=%pubkey,name=%name,typ=qtype))]
    pub(crate) async fn resolve(
        &self,
        pubkey: &PublicKeyBytes,
        name: &DnsName,
        qtype: u16,
    ) -> Result<Option<ZoneLookup>> {
        trace!("store resolve");

        // Check cache first (short lock scope)
        {
            let mut cache = self.cache.lock().await;
            if let Some(res) = cache.resolve(pubkey, name, qtype) {
                debug!(?res, "resolved from cache");
                return Ok(Some(res));
            }
        }

        // Check persistent store
        if let Some(packet) = self.store.get(pubkey).await? {
            trace!(packet_timestamp = ?packet.timestamp(), "store hit");
            let mut cache = self.cache.lock().await;
            let res = cache.insert_and_resolve(&packet, name, qtype);
            match &res {
                Ok(res) => debug!(?res, "resolved from store"),
                Err(err) => warn!("failed to retrieve zone after inserting in cache: {err:#?}"),
            }
            return res.map(Some);
        };

        if let Some(dht) = self.dht.as_ref() {
            debug!("DHT resolve {}", pubkey.to_z32());
            let maybe_item = dht.get_mutable_most_recent(pubkey.as_bytes(), None).await?;
            if let Some(item) = maybe_item
                && let Ok(packet) = mutable_item_to_signed_packet(&item)
            {
                debug!("DHT resolve successful {:?}", packet);
                return self
                    .cache
                    .lock()
                    .await
                    .insert_and_resolve_dht(&packet, name, qtype)
                    .map(Some);
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
        let cache =
            LruCache::sparse(NonZeroUsize::new(cap).expect("capacity must be larger than 0"));
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
        name: &DnsName,
        qtype: u16,
    ) -> Option<ZoneLookup> {
        let zone = if let Some(zone) = self.cache.get(pubkey) {
            trace!("cache hit {}", pubkey.to_z32());
            zone
        } else {
            let zone = self.dht_cache.get(pubkey)?;
            trace!("dht cache hit {}", pubkey.to_z32());
            zone
        };
        Some(zone.resolve(name, qtype))
    }

    fn insert_and_resolve(
        &mut self,
        signed_packet: &SignedPacket,
        name: &DnsName,
        qtype: u16,
    ) -> Result<ZoneLookup> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        self.insert(signed_packet)?;
        self.resolve(&pubkey, name, qtype)
            .ok_or_else(|| anyerr!("zone missing from cache after insert"))
    }

    fn insert_and_resolve_dht(
        &mut self,
        signed_packet: &SignedPacket,
        name: &DnsName,
        qtype: u16,
    ) -> Result<ZoneLookup> {
        let pubkey = PublicKeyBytes::from_signed_packet(signed_packet);
        let zone = CachedZone::from_signed_packet(signed_packet)?;
        let res = zone.resolve(name, qtype);
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
            self.cache
                .put(pubkey, CachedZone::from_signed_packet(signed_packet)?);
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

/// The result of looking up a name in a pkarr zone.
#[derive(Debug, Clone)]
pub(crate) enum ZoneLookup {
    /// The name does not exist in the zone.
    NxDomain,
    /// The name exists, with these records of the requested type (possibly none).
    Records(Vec<ResourceRecord<'static>>),
}

/// Records of a pkarr zone, keyed by name relative to the zone.
#[derive(Debug)]
struct CachedZone {
    timestamp: Timestamp,
    /// Records by lowercased relative name, with labels in root-first order.
    ///
    /// Root-first order makes all names below a given name a contiguous range.
    records: BTreeMap<Vec<Vec<u8>>, Vec<ResourceRecord<'static>>>,
}

impl CachedZone {
    /// Builds a zone from the records in a signed packet.
    ///
    /// Only records of class IN whose name ends in the z32-encoded public key are used,
    /// and SOA and NS records are dropped since the zone apex belongs to this server.
    fn from_signed_packet(signed_packet: &SignedPacket) -> Result<Self> {
        let zone_label = signed_packet.public_key().to_z32().into_bytes();
        let packet = Packet::parse(signed_packet.encoded_packet())
            .map_err(|err| anyerr!("invalid DNS packet in signed packet: {err}"))?;
        let mut records: BTreeMap<_, Vec<_>> = BTreeMap::new();
        for record in packet.answers {
            if record.class != CLASS::IN
                || matches!(record.rdata.type_code(), TYPE::SOA | TYPE::NS | TYPE::OPT)
            {
                continue;
            }
            let name = DnsName::from_simple(&record.name).to_ascii_lowercase();
            let Some((last, rest)) = name.labels().split_last() else {
                continue;
            };
            if *last != zone_label {
                continue;
            }
            let key: Vec<Vec<u8>> = rest.iter().rev().cloned().collect();
            records.entry(key).or_default().push(record.into_owned());
        }
        Ok(Self {
            records,
            timestamp: signed_packet.timestamp(),
        })
    }

    fn is_newer_than(&self, signed_packet: &SignedPacket) -> bool {
        self.timestamp > signed_packet.timestamp()
    }

    /// Looks up records for a lowercased relative name.
    fn resolve(&self, name: &DnsName, qtype: u16) -> ZoneLookup {
        trace!(name=%name, typ=qtype, "resolve in zone");
        let key: Vec<Vec<u8>> = name.labels().iter().rev().cloned().collect();
        if let Some(records) = self.records.get(&key) {
            let records = records
                .iter()
                .filter(|record| qtype == QTYPE_ANY || record_type(record) == qtype)
                .cloned()
                .collect();
            return ZoneLookup::Records(records);
        }
        // An empty non-terminal, i.e. a name with records only below it, exists too.
        let has_descendants = self
            .records
            .range(key.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&key));
        if has_descendants || key.is_empty() {
            ZoneLookup::Records(Vec::new())
        } else {
            ZoneLookup::NxDomain
        }
    }
}
