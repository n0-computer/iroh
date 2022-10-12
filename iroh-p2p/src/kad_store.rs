use std::{
    borrow::Cow,
    collections::BTreeMap,
    path::PathBuf,
    time::{self, Duration, Instant},
};

use bytecheck::CheckBytes;
use libp2p::{
    kad::{self, store::RecordStore},
    Multiaddr, PeerId,
};
use rkyv::{ser::serializers::AllocSerializer, Archive, Deserialize, Serialize};
use rocksdb::{
    BlockBasedOptions, Cache, DBIteratorWithThreadMode, IteratorMode, Options,
    SnapshotWithThreadMode, DB as RocksDb,
};
use std::fmt::Debug;

/// Column family that stores records
pub const CF_RECORDS_V0: &str = "records-v0";
/// Column familty that stores provider records
pub const CF_PROVIDER_RECORDS_V0: &str = "provider-records-v0";

pub(crate) struct RocksRecordStore {
    db: rocksdb::DB,
    _cache: rocksdb::Cache,
    startup: std::time::Instant,
}

pub(crate) struct Config {
    path: PathBuf,
}

/// Creates the default rocksdb options
fn default_options() -> (Options, Cache) {
    let mut opts = Options::default();
    opts.set_write_buffer_size(512 * 1024 * 1024);
    opts.optimize_for_point_lookup(64 * 1024 * 1024);
    let par = (std::thread::available_parallelism()
        .map(|s| s.get())
        .unwrap_or(2)
        / 4)
    .min(2);
    opts.increase_parallelism(par as _);
    opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
    opts.set_blob_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bytes_per_sync(1_048_576);
    opts.set_blob_file_size(512 * 1024 * 1024);

    let cache = Cache::new_lru_cache(128 * 1024 * 1024).unwrap();
    let mut bopts = BlockBasedOptions::default();
    // all our data is longer lived, so ribbon filters make sense
    bopts.set_ribbon_filter(10.0);
    bopts.set_block_cache(&cache);
    bopts.set_block_size(6 * 1024);
    bopts.set_cache_index_and_filter_blocks(true);
    bopts.set_pin_l0_filter_and_index_blocks_in_cache(true);
    opts.set_block_based_table_factory(&bopts);

    (opts, cache)
}

fn rocks_to_kad_error(_error: rocksdb::Error) -> kad::store::Error {
    // TODO: PR to libp2p to add more error variants
    kad::store::Error::ValueTooLarge
}

fn rkyv_to_kad_error<F: rkyv::Fallible>(_error: F::Error) -> kad::store::Error {
    // TODO: PR to libp2p to add more error variants
    kad::store::Error::ValueTooLarge
}

#[derive(Debug, Archive, Serialize, Deserialize)]
#[repr(C)]
#[archive_attr(repr(C), derive(CheckBytes))]
pub(crate) struct RecordValue {
    value: Vec<u8>,
    publisher: Option<Vec<u8>>,
    expires: Option<u64>,
}

#[derive(Debug, Archive, Serialize, Deserialize)]
#[repr(C)]
#[archive_attr(repr(C), derive(CheckBytes))]
pub(crate) struct ProviderRecordValue {
    addresses: Vec<Vec<u8>>,
    expires: Option<u64>,
}

impl RocksRecordStore {
    pub fn create(config: Config) -> std::result::Result<Self, rocksdb::Error> {
        let (mut options, cache) = default_options();
        options.create_if_missing(true);

        let path = config.path;
        let mut db = RocksDb::open(&options, path)?;
        {
            let opts = Options::default();
            db.create_cf(CF_RECORDS_V0, &opts)?;
        }
        {
            let opts = Options::default();
            db.create_cf(CF_PROVIDER_RECORDS_V0, &opts)?;
        }
        Ok(Self {
            db,
            _cache: cache,
            startup: Instant::now(),
        })
    }

    fn put0(&self, r: kad::Record) -> kad::store::Result<()> {
        let cf = self.db.cf_handle(CF_RECORDS_V0).expect("cf exists");
        let expires = r
            .expires
            .map(|x| x.duration_since(self.startup).as_nanos().try_into())
            .transpose()
            .expect("expiry fits in u64");

        if let (Some(expected), Some(actual_ns)) = (r.expires, expires) {
            let actual = self.startup + Duration::from_nanos(actual_ns);
            assert_eq!(expected, actual);
        }
        let value = RecordValue {
            value: r.value,
            publisher: r.publisher.map(|x| x.to_bytes()),
            expires,
        };
        // TODO: use fixed size buffer and prevent allocations
        let value = rkyv::to_bytes::<_, 1024>(&value).expect("rkyv ser should not fail");
        self.db
            .put_cf(cf, r.key, value)
            .map_err(rocks_to_kad_error)?;
        Ok(())
    }

    fn get0(&self, key: &kad::record::Key) -> Option<kad::Record> {
        let cf = self.db.cf_handle(CF_RECORDS_V0).expect("cf exists");
        // TODO: use get_pinned_cf and sort out the alignment issue
        let slice = self.db.get_cf(cf, key).unwrap()?;
        let value =
            rkyv::check_archived_root::<RecordValue>(&slice).expect("rkvy deser should not fail");
        Some(kad::Record {
            key: key.clone(),
            value: value.value.to_vec(),
            publisher: value
                .publisher
                .as_ref()
                .map(|x| PeerId::from_bytes(x).unwrap()),
            expires: value
                .expires
                .as_ref()
                .map(|x| self.startup + time::Duration::from_nanos(*x)),
        })
    }

    fn remove0(&mut self, key: &kad::record::Key) {
        let cf = self.db.cf_handle(CF_RECORDS_V0).expect("cf exists");
        let _ = self.db.delete_cf(cf, key);
    }

    fn records0(&self) -> RecordsIter {
        let snapshot = self.db.snapshot();
        let cf = self.db.cf_handle(CF_RECORDS_V0).expect("cf exists");
        RecordsIter {
            snapshot,
            iter: None,
            cf,
            startup: self.startup,
        }
    }

    fn add_provider0(&self, r: kad::ProviderRecord) -> kad::store::Result<()> {
        let cf = self
            .db
            .cf_handle(CF_PROVIDER_RECORDS_V0)
            .expect("cf exists");
        let slice = self
            .db
            .get_cf(cf, &r.key)
            .map_err(rocks_to_kad_error)?
            .unwrap_or_default();
        let mut existing = if !slice.is_empty() {
            rkyv::from_bytes::<BTreeMap<Vec<u8>, ProviderRecordValue>>(&slice).unwrap()
        } else {
            BTreeMap::new()
        };
        let provider_record_value = ProviderRecordValue {
            addresses: r.addresses.into_iter().map(|x| x.to_vec()).collect(),
            expires: r
                .expires
                .map(|x| x.duration_since(self.startup).as_nanos().try_into())
                .transpose()
                .expect("expiry fits in u64"),
        };
        existing.insert(r.provider.to_bytes(), provider_record_value);
        let slice1 = rkyv::to_bytes::<_, 32768>(&existing)
            .map_err(rkyv_to_kad_error::<AllocSerializer<32768>>)?;
        if slice1.as_slice() != slice.as_slice() {
            self.db
                .put_cf(cf, &r.key, slice1)
                .map_err(rocks_to_kad_error)?;
        }
        Ok(())
    }

    fn remove_provider0(&self, key: &kad::record::Key, peer: &PeerId) -> kad::store::Result<()> {
        let cf = self
            .db
            .cf_handle(CF_PROVIDER_RECORDS_V0)
            .expect("cf exists");
        let slice = self
            .db
            .get_cf(cf, key)
            .map_err(rocks_to_kad_error)?
            .unwrap_or_default();
        let mut existing =
            rkyv::from_bytes::<BTreeMap<Vec<u8>, ProviderRecordValue>>(&slice).unwrap();
        existing.remove(&peer.to_bytes());
        let slice1 = rkyv::to_bytes::<_, 32768>(&existing)
            .map_err(rkyv_to_kad_error::<AllocSerializer<32768>>)?;
        if slice1.as_slice() != slice.as_slice() {
            self.db
                .put_cf(cf, key, slice1)
                .map_err(rocks_to_kad_error)?;
        }
        Ok(())
    }

    fn providers0(&self, key: &kad::record::Key) -> kad::store::Result<Vec<kad::ProviderRecord>> {
        let cf = self
            .db
            .cf_handle(CF_PROVIDER_RECORDS_V0)
            .expect("cf exists");
        let slice = self
            .db
            .get_cf(cf, key)
            .map_err(rocks_to_kad_error)?
            .unwrap_or_default();
        let providers =
            rkyv::check_archived_root::<BTreeMap<Vec<u8>, ProviderRecordValue>>(&slice).unwrap();
        let mut res = Vec::with_capacity(providers.len());
        for (provider, value) in providers {
            let provider = PeerId::from_bytes(provider).unwrap();
            let addresses = value
                .addresses
                .iter()
                .map(|x| Multiaddr::try_from(x.to_vec()).unwrap())
                .collect();
            let expires = value
                .expires
                .as_ref()
                .map(|x| self.startup + time::Duration::from_nanos(*x));
            res.push(kad::ProviderRecord {
                key: key.clone(),
                provider,
                addresses,
                expires,
            });
        }
        Ok(res)
    }

    fn provided0(&self) -> ProviderRecordsIter {
        let snapshot = self.db.snapshot();
        let cf = self
            .db
            .cf_handle(CF_PROVIDER_RECORDS_V0)
            .expect("cf exists");
        ProviderRecordsIter {
            snapshot,
            iter: None,
            cf,
            startup: self.startup,
            records: Default::default(),
        }
    }
}
pub(crate) struct RecordsIter<'a> {
    iter: Option<DBIteratorWithThreadMode<'a, rocksdb::DB>>,
    snapshot: rocksdb::SnapshotWithThreadMode<'a, rocksdb::DB>,
    cf: &'a rocksdb::ColumnFamily,
    startup: std::time::Instant,
}

impl<'a> RecordsIter<'a> {
    fn next0(&mut self) -> Option<Cow<'a, kad::Record>> {
        if self.iter.is_none() {
            // TODO: use init once or some other trick
            let snapshot: &SnapshotWithThreadMode<'a, rocksdb::DB> =
                unsafe { std::mem::transmute(&self.snapshot) };
            self.iter = Some(snapshot.iterator_cf(self.cf, IteratorMode::Start))
        };
        let iter = self.iter.as_mut().unwrap();
        if let Ok((key, value)) = iter.next()? {
            let value = rkyv::check_archived_root::<RecordValue>(&value).unwrap();
            Some(Cow::Owned(kad::Record {
                key: kad::record::Key::new(&key),
                value: value.value.to_vec(),
                publisher: value
                    .publisher
                    .as_ref()
                    .map(|x| PeerId::from_bytes(x).unwrap()),
                expires: value
                    .expires
                    .as_ref()
                    .map(|x| self.startup + time::Duration::from_nanos(*x)),
            }))
        } else {
            None
        }
    }
}

impl<'a> Iterator for RecordsIter<'a> {
    type Item = Cow<'a, kad::Record>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next0()
    }
}

pub(crate) struct ProviderRecordsIter<'a> {
    iter: Option<DBIteratorWithThreadMode<'a, rocksdb::DB>>,
    snapshot: rocksdb::SnapshotWithThreadMode<'a, rocksdb::DB>,
    cf: &'a rocksdb::ColumnFamily,
    startup: std::time::Instant,
    records: Vec<kad::ProviderRecord>,
}

impl<'a> ProviderRecordsIter<'a> {
    fn next0(&mut self) -> Option<Cow<'a, kad::ProviderRecord>> {
        if self.iter.is_none() {
            // TODO: use init once or some other trick
            let snapshot: &SnapshotWithThreadMode<'static, rocksdb::DB> =
                unsafe { std::mem::transmute(&self.snapshot) };
            self.iter = Some(snapshot.iterator_cf(self.cf, IteratorMode::Start))
        };
        let iter = self.iter.as_mut().unwrap();
        loop {
            if let Some(record) = self.records.pop() {
                return Some(Cow::Owned(record));
            }
            if let Ok((key, value)) = iter.next()? {
                let value =
                    rkyv::check_archived_root::<BTreeMap<Vec<u8>, ProviderRecordValue>>(&value)
                        .unwrap();
                for (peer, value) in value {
                    let peer = PeerId::from_bytes(peer).unwrap();
                    let addresses = value
                        .addresses
                        .iter()
                        .map(|x| Multiaddr::try_from(x.to_vec()).unwrap())
                        .collect();
                    let expires = value
                        .expires
                        .as_ref()
                        .map(|x| self.startup + time::Duration::from_nanos(*x));
                    self.records.push(kad::ProviderRecord {
                        key: kad::record::Key::new(&key),
                        provider: peer,
                        addresses,
                        expires,
                    });
                }
            } else {
                return None;
            }
        }
    }
}

impl<'a> Iterator for ProviderRecordsIter<'a> {
    type Item = Cow<'a, kad::ProviderRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next0()
    }
}

impl<'a> RecordStore<'a> for RocksRecordStore {
    type RecordsIter = RecordsIter<'a>;

    type ProvidedIter = ProviderRecordsIter<'a>;

    fn get(&self, k: &kad::record::Key) -> Option<std::borrow::Cow<'_, libp2p::kad::Record>> {
        self.get0(k).map(Cow::Owned)
    }

    fn put(&mut self, r: kad::Record) -> kad::store::Result<()> {
        self.put0(r)
    }

    fn remove(&mut self, k: &kad::record::Key) {
        self.remove0(k);
    }

    fn records(&'a self) -> Self::RecordsIter {
        self.records0()
    }

    fn add_provider(&mut self, record: kad::ProviderRecord) -> kad::store::Result<()> {
        self.add_provider0(record)
    }

    fn providers(&self, key: &kad::record::Key) -> Vec<kad::ProviderRecord> {
        self.providers0(key).unwrap()
    }

    fn provided(&'a self) -> Self::ProvidedIter {
        self.provided0()
    }

    fn remove_provider(&mut self, key: &kad::record::Key, peer: &PeerId) {
        let _ = self.remove_provider0(key, peer);
    }
}

#[allow(clippy::redundant_clone)]
#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
        vec,
    };

    use super::*;
    use anyhow::Context;
    use libp2p::multiaddr::Protocol;
    use multihash::{Code, Multihash, MultihashDigest};
    use proptest::prelude::*;
    use tempfile::tempdir;

    fn record_roundtrip(store: &mut RocksRecordStore, record: kad::Record) -> anyhow::Result<()> {
        let actual = record.clone();
        store.put(record)?;
        let expected = store.get(&actual.key).context("expected value")?;
        anyhow::ensure!(actual == *expected);
        Ok(())
    }

    fn provider_record_roundtrip(
        store: &mut RocksRecordStore,
        mut records: Vec<kad::ProviderRecord>,
    ) -> anyhow::Result<()> {
        records.dedup_by(|a, b| a.key == b.key && a.provider == b.provider);
        for record in &records {
            store.add_provider(record.clone())?;
        }
        for record in &records {
            let actual = record.clone();
            let found = store.providers(&actual.key);
            anyhow::ensure!(found.contains(&actual));
        }
        Ok(())
    }

    fn canonicalize_records(records: &mut [kad::Record]) {
        records.sort_by(|a, b| a.key.as_ref().cmp(b.key.as_ref()));
    }

    fn canonicalize_provider_records(records: &mut [kad::ProviderRecord]) {
        records.sort_by(|a, b| (a.key.as_ref(), a.provider).cmp(&(b.key.as_ref(), b.provider)));
    }

    /// basic smoke test for plain records
    #[test]
    fn record_smoke() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let mut store = RocksRecordStore::create(Config { path })?;
        let r1 = kad::Record {
            key: kad::record::Key::new(b"foo"),
            value: b"bar".to_vec(),
            publisher: None,
            expires: None,
        };
        let r2 = kad::Record {
            key: kad::record::Key::new(b"something"),
            value: b"fnord!".to_vec(),
            publisher: None,
            expires: None,
        };
        record_roundtrip(&mut store, r1.clone())?;
        record_roundtrip(&mut store, r2.clone())?;
        let mut actual = store.records().map(|x| x.into_owned()).collect::<Vec<_>>();
        let mut expected = vec![r1.clone(), r2.clone()];
        canonicalize_records(&mut actual);
        canonicalize_records(&mut expected);
        anyhow::ensure!(actual == expected);
        store.remove(&r1.key);
        anyhow::ensure!(store.get(&r1.key).is_none());
        Ok(())
    }

    #[test]
    fn provider_record_smoke() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let mut store = RocksRecordStore::create(Config { path })?;
        let r1 = kad::ProviderRecord {
            key: kad::record::Key::new(b"foo"),
            provider: PeerId::from_str("1AdCMJ9wHcouMXXbS8MfrmtTi1rH77erFMDhLnyZKuL5vD")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/1234")?],
            expires: None,
        };
        let r2 = kad::ProviderRecord {
            key: kad::record::Key::new(b"something"),
            provider: PeerId::from_str("1Afg8BNJrks3N4wCfXvac3fEekDLTG3pAHCGogyrYxmKbQ")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/5678")?],
            expires: None,
        };
        provider_record_roundtrip(&mut store, vec![r1.clone(), r2.clone()])?;
        let mut actual = store.provided().map(Cow::into_owned).collect::<Vec<_>>();
        let mut expected = vec![r1, r2];
        canonicalize_provider_records(&mut actual);
        canonicalize_provider_records(&mut expected);
        anyhow::ensure!(actual == expected);
        Ok(())
    }

    #[test]
    fn provider_record_same_key_different_peer() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let mut store = RocksRecordStore::create(Config { path })?;
        let r1 = kad::ProviderRecord {
            key: kad::record::Key::new(b"foo"),
            provider: PeerId::from_str("1AdCMJ9wHcouMXXbS8MfrmtTi1rH77erFMDhLnyZKuL5vD")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/1234")?],
            expires: None,
        };
        let r2 = kad::ProviderRecord {
            key: kad::record::Key::new(b"foo"),
            provider: PeerId::from_str("1Afg8BNJrks3N4wCfXvac3fEekDLTG3pAHCGogyrYxmKbQ")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/5678")?],
            expires: None,
        };
        store.add_provider(r1.clone())?;
        store.add_provider(r2.clone())?;
        let mut actual = store.provided().map(Cow::into_owned).collect::<Vec<_>>();
        let mut expected = vec![r1, r2];
        canonicalize_provider_records(&mut actual);
        canonicalize_provider_records(&mut expected);
        anyhow::ensure!(actual == expected);
        Ok(())
    }

    #[test]
    fn provider_record_same_key_same_peer() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let mut store = RocksRecordStore::create(Config { path })?;
        let r1 = kad::ProviderRecord {
            key: kad::record::Key::new(b"foo"),
            provider: PeerId::from_str("1AdCMJ9wHcouMXXbS8MfrmtTi1rH77erFMDhLnyZKuL5vD")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/1234")?],
            expires: None,
        };
        let r2 = kad::ProviderRecord {
            key: kad::record::Key::new(b"foo"),
            provider: PeerId::from_str("1AdCMJ9wHcouMXXbS8MfrmtTi1rH77erFMDhLnyZKuL5vD")?,
            addresses: vec![Multiaddr::from_str("/ip4/127.0.0.1/tcp/5678")?],
            expires: None,
        };
        store.add_provider(r1.clone())?;
        store.add_provider(r2.clone())?;
        let mut actual = store.provided().map(Cow::into_owned).collect::<Vec<_>>();
        let mut expected = vec![r2];
        canonicalize_provider_records(&mut actual);
        canonicalize_provider_records(&mut expected);
        anyhow::ensure!(actual == expected);
        Ok(())
    }

    fn arb_kad_key() -> impl Strategy<Value = kad::record::Key> {
        proptest::collection::vec(any::<u8>(), 0..100).prop_map(|x| kad::record::Key::new(&x))
    }

    fn arb_kad_record() -> impl Strategy<Value = kad::Record> {
        (
            arb_kad_key(),
            any::<Vec<u8>>(),
            proptest::option::of(arb_peerid()),
            proptest::option::of(any::<Instant>()),
        )
            .prop_map(|(key, value, publisher, expires)| kad::Record {
                key,
                value,
                publisher,
                expires,
            })
    }

    fn arb_kad_provider_record() -> impl Strategy<Value = kad::ProviderRecord> {
        (
            arb_kad_key(),
            proptest::collection::vec(arb_ip_multiaddr(), 0..10),
            arb_peerid(),
            proptest::option::of(any::<Instant>()),
        )
            .prop_map(|(key, addresses, provider, expires)| kad::ProviderRecord {
                key,
                provider,
                addresses,
                expires,
            })
    }

    fn arb_multihash() -> impl Strategy<Value = Multihash> {
        let arb_multihash_code = proptest::sample::select(vec![Code::Sha2_256, Code::Sha2_512]);
        (any::<Vec<u8>>(), arb_multihash_code).prop_map(|(data, code)| code.digest(&data))
    }

    fn arb_peerid() -> impl Strategy<Value = PeerId> {
        (
            proptest::collection::vec(any::<u8>(), 0..42),
            proptest::sample::select(vec![Code::Sha2_256, Code::Identity]),
        )
            .prop_map(|(data, code)| {
                let hash = code.digest(&data);
                PeerId::from_multihash(hash).unwrap()
            })
    }

    fn arb_ip_multiaddr() -> impl Strategy<Value = Multiaddr> {
        fn arb_ip() -> impl Strategy<Value = Protocol<'static>> {
            let ip4 = any::<Ipv4Addr>().prop_map(Protocol::Ip4).boxed();
            let ip6 = any::<Ipv6Addr>().prop_map(Protocol::Ip6).boxed();
            prop_oneof![ip4, ip6]
        }
        fn arb_ip_protocol() -> impl Strategy<Value = Protocol<'static>> {
            let ip4 = any::<u16>().prop_map(Protocol::Tcp).boxed();
            let ip6 = any::<u16>().prop_map(Protocol::Udp).boxed();
            prop_oneof![ip4, ip6]
        }
        (arb_ip(), arb_ip_protocol()).prop_map(|(host, port)| {
            let mut t = Multiaddr::empty();
            t.push(host);
            t.push(port);
            t
        })
    }

    fn arb_multiaddr() -> impl Strategy<Value = Multiaddr> {
        arb_ip_multiaddr()
    }

    #[test]
    fn prop_add_get_record() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let store = RocksRecordStore::create(Config { path })?;
        proptest!(|(mut r in arb_kad_record())| {
            r.expires = None;
            store.put0(r.clone())?;
            let actual = store.get(&r.key).map(Cow::into_owned);
            let expected = Some(r);
            prop_assert_eq!(actual, expected);
        });
        Ok(())
    }

    #[test]
    fn prop_add_get_provider_record() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("db");
        let store = RocksRecordStore::create(Config { path })?;
        proptest!(|(mut r in arb_kad_provider_record())| {
            r.expires = None;
            store.add_provider0(r.clone()).unwrap();
            let actual = store.provided().next().unwrap().into_owned();
            prop_assert_eq!(actual, r.clone());
            store.remove_provider0(&r.key, &r.provider).unwrap();
        });
        Ok(())
    }
}
