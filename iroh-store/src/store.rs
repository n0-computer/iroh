use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::available_parallelism,
};

use anyhow::{anyhow, bail, Context, Result};
use cid::Cid;
use iroh_metrics::{
    core::{MObserver, MRecorder},
    inc, observe, record,
    store::{StoreHistograms, StoreMetrics},
};
use iroh_rpc_client::Client as RpcClient;
use multihash::Multihash;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, DBPinnableSlice, Direction, IteratorMode, Options,
    WriteBatch, DB as RocksDb,
};
use smallvec::SmallVec;
use tokio::task;

use crate::cf::{GraphV0, MetadataV0, CF_BLOBS_V0, CF_GRAPH_V0, CF_ID_V0, CF_METADATA_V0};
use crate::Config;

#[derive(Clone)]
pub struct Store {
    inner: Arc<InnerStore>,
}

struct InnerStore {
    content: RocksDb,
    next_id: AtomicU64,
    _cache: Cache,
    _rpc_client: RpcClient,
}

/// Creates the default rocksdb options
fn default_options() -> (Options, Cache) {
    let mut opts = Options::default();
    opts.set_write_buffer_size(512 * 1024 * 1024);
    opts.optimize_for_point_lookup(64 * 1024 * 1024);
    let par = (available_parallelism().map(|s| s.get()).unwrap_or(2) / 4).min(2);
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

fn default_blob_opts() -> Options {
    let mut opts = Options::default();
    opts.set_enable_blob_files(true);
    opts.set_min_blob_size(5 * 1024);

    opts
}

/// The key used in CF_ID_V0
///
/// The multihash followed by the be encoded code. This allows both looking up an id by multihash and code (aka Cid),
/// and looking up all codes and ids for a multihash, for the rare case that there are mulitple cids with the same
/// multihash but different codes.
fn id_key(cid: &Cid) -> SmallVec<[u8; 64]> {
    let mut key = SmallVec::new();
    cid.hash().write(&mut key).unwrap();
    key.extend_from_slice(&cid.codec().to_be_bytes());
    key
}

/// Struct used to iterate over all the ids for a multihash
struct CodeAndId {
    // the ipld code of the id
    #[allow(dead_code)]
    code: u64,
    // the id for the cid, used in most other column families
    id: u64,
}

impl Store {
    /// Creates a new database.
    #[tracing::instrument]
    pub async fn create(config: Config) -> Result<Self> {
        let (mut options, cache) = default_options();
        options.create_if_missing(true);

        let path = config.path.clone();
        let db = task::spawn_blocking(move || -> Result<_> {
            let mut db = RocksDb::open(&options, path)?;
            {
                let opts = default_blob_opts();
                db.create_cf(CF_BLOBS_V0, &opts)?;
            }
            {
                let opts = Options::default();
                db.create_cf(CF_METADATA_V0, &opts)?;
            }
            {
                let opts = Options::default();
                db.create_cf(CF_GRAPH_V0, &opts)?;
            }
            {
                let opts = Options::default();
                db.create_cf(CF_ID_V0, &opts)?;
            }

            Ok(db)
        })
        .await??;

        let _rpc_client = RpcClient::new(config.rpc_client)
            .await
            .context("Error creating rpc client for store")?;

        Ok(Store {
            inner: Arc::new(InnerStore {
                content: db,
                next_id: 1.into(),
                _cache: cache,
                _rpc_client,
            }),
        })
    }

    /// Opens an existing database.
    #[tracing::instrument]
    pub async fn open(config: Config) -> Result<Self> {
        let (mut options, cache) = default_options();
        options.create_if_missing(false);
        // TODO: find a way to read existing options

        let path = config.path.clone();
        let (db, next_id) = task::spawn_blocking(move || -> Result<_> {
            let db = RocksDb::open_cf(
                &options,
                path,
                [CF_BLOBS_V0, CF_METADATA_V0, CF_GRAPH_V0, CF_ID_V0],
            )?;

            // read last inserted id
            let next_id = {
                let cf_meta = db
                    .cf_handle(CF_METADATA_V0)
                    .ok_or_else(|| anyhow!("missing column family: metadata"))?;

                let mut iter = db.full_iterator_cf(&cf_meta, IteratorMode::End);
                let last_id = iter
                    .next()
                    .and_then(|r| r.ok())
                    .and_then(|(key, _)| key[..8].try_into().ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or_default();

                last_id + 1
            };

            Ok((db, next_id))
        })
        .await??;

        let _rpc_client = RpcClient::new(config.rpc_client)
            .await
            // TODO: first conflict between `anyhow` & `anyhow`
            // .map_err(|e| e.context("Error creating rpc client for store"))?;
            .map_err(|e| anyhow!("Error creating rpc client for store: {:?}", e))?;

        Ok(Store {
            inner: Arc::new(InnerStore {
                content: db,
                next_id: next_id.into(),
                _cache: cache,
                _rpc_client,
            }),
        })
    }

    #[tracing::instrument(skip(self, links, blob))]
    pub async fn put<T: AsRef<[u8]>, L>(&self, cid: Cid, blob: T, links: L) -> Result<()>
    where
        L: IntoIterator<Item = Cid>,
    {
        inc!(StoreMetrics::PutRequests);

        if self.has(&cid).await? {
            return Ok(());
        }

        let id = self.next_id();

        let start = std::time::Instant::now();

        let id_bytes = id.to_be_bytes();

        // guranteed that the key does not exists, so we want to store it

        let metadata = MetadataV0 {
            codec: cid.codec(),
            multihash: cid.hash().to_bytes(),
        };
        let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
        let id_key = id_key(&cid);

        let children = self.ensure_id_many(links.into_iter()).await?;

        let graph = GraphV0 { children };
        let graph_bytes = rkyv::to_bytes::<_, 1024>(&graph)?; // TODO: is this the right amount of scratch space?

        let cf_id = self.cf_id()?;
        let cf_meta = self.cf_metadata()?;
        let cf_graph = self.cf_graph()?;
        let cf_blobs = self.cf_blobs()?;
        let blob_size = blob.as_ref().len();

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_id, id_key, &id_bytes);
        batch.put_cf(cf_blobs, &id_bytes, blob);
        batch.put_cf(cf_meta, &id_bytes, metadata_bytes);
        batch.put_cf(cf_graph, &id_bytes, graph_bytes);
        self.db().write(batch)?;
        observe!(StoreHistograms::PutRequests, start.elapsed().as_secs_f64());
        record!(StoreMetrics::PutBytes, blob_size as u64);

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_blob_by_hash(&self, hash: &Multihash) -> Result<Option<DBPinnableSlice<'_>>> {
        let cf_blobs = self
            .inner
            .content
            .cf_handle(CF_BLOBS_V0)
            .ok_or_else(|| anyhow!("missing column family: blobs"))?;
        for elem in self.get_ids_for_hash(hash)? {
            let id = elem?.id;
            let id_bytes = id.to_be_bytes();
            if let Some(blob) = self.inner.content.get_pinned_cf(&cf_blobs, &id_bytes)? {
                return Ok(Some(blob));
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    pub async fn has_blob_for_hash(&self, hash: &Multihash) -> Result<bool> {
        let cf_blobs = self
            .inner
            .content
            .cf_handle(CF_BLOBS_V0)
            .ok_or_else(|| anyhow!("missing column family: blobs"))?;
        for elem in self.get_ids_for_hash(hash)? {
            let id = elem?.id;
            let id_bytes = id.to_be_bytes();
            if let Some(_blob) = self.inner.content.get_pinned_cf(&cf_blobs, &id_bytes)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: &Cid) -> Result<Option<DBPinnableSlice<'_>>> {
        inc!(StoreMetrics::GetRequests);
        let start = std::time::Instant::now();
        let res = match self.get_id(cid).await? {
            Some(id) => {
                let maybe_blob = self.get_by_id(id).await?;
                inc!(StoreMetrics::StoreHit);
                record!(
                    StoreMetrics::GetBytes,
                    maybe_blob.as_ref().map(|b| b.len()).unwrap_or(0) as u64
                );
                Ok(maybe_blob)
            }
            None => {
                inc!(StoreMetrics::StoreMiss);
                Ok(None)
            }
        };
        observe!(StoreHistograms::GetRequests, start.elapsed().as_secs_f64());
        res
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_size(&self, cid: &Cid) -> Result<Option<usize>> {
        match self.get_id(cid).await? {
            Some(id) => {
                inc!(StoreMetrics::StoreHit);
                let maybe_size = self.get_size_by_id(id).await?;
                Ok(maybe_size)
            }
            None => {
                inc!(StoreMetrics::StoreMiss);
                Ok(None)
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn has(&self, cid: &Cid) -> Result<bool> {
        match self.get_id(cid).await? {
            Some(id) => {
                let cf_blobs = self.cf_blobs()?;
                let exists = self
                    .db()
                    .get_pinned_cf(cf_blobs, id.to_be_bytes())?
                    .is_some();
                Ok(exists)
            }
            None => Ok(false),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        inc!(StoreMetrics::GetLinksRequests);
        let start = std::time::Instant::now();
        let res = match self.get_id(cid).await? {
            Some(id) => {
                let maybe_links = self.get_links_by_id(id).await?;
                inc!(StoreMetrics::GetLinksHit);
                Ok(maybe_links)
            }
            None => {
                inc!(StoreMetrics::GetLinksMiss);
                Ok(None)
            }
        };
        observe!(
            StoreHistograms::GetLinksRequests,
            start.elapsed().as_secs_f64()
        );
        res
    }

    #[tracing::instrument(skip(self))]
    async fn get_id(&self, cid: &Cid) -> Result<Option<u64>> {
        let cf_id = self.cf_id()?;
        let id_key = id_key(cid);
        let maybe_id_bytes = self.db().get_pinned_cf(cf_id, id_key)?;
        match maybe_id_bytes {
            Some(bytes) => {
                let arr = bytes[..8].try_into().map_err(|e| anyhow!("{:?}", e))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    fn get_ids_for_hash(
        &self,
        hash: &Multihash,
    ) -> Result<impl Iterator<Item = Result<CodeAndId>> + '_> {
        let hash = hash.to_bytes();
        let cf_id = self
            .inner
            .content
            .cf_handle(CF_ID_V0)
            .ok_or_else(|| anyhow!("missing column family: id"))?;
        let iter = self
            .inner
            .content
            .iterator_cf(cf_id, IteratorMode::From(&hash, Direction::Forward));
        let hash_len = hash.len();
        Ok(iter
            .take_while(move |elem| {
                if let Ok((k, _)) = elem {
                    k.len() == hash_len + 8 && k.starts_with(&hash)
                } else {
                    // we don't want to swallow errors. An error is not the same as no result!
                    true
                }
            })
            .map(move |elem| {
                let (k, v) = elem?;
                let code = u64::from_be_bytes(k[hash_len..].try_into()?);
                let id = u64::from_be_bytes(v[..8].try_into()?);
                Ok(CodeAndId { code, id })
            }))
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_id(&self, id: u64) -> Result<Option<DBPinnableSlice<'_>>> {
        let cf_blobs = self.cf_blobs()?;
        let maybe_blob = self.db().get_pinned_cf(cf_blobs, id.to_be_bytes())?;

        Ok(maybe_blob)
    }

    #[tracing::instrument(skip(self))]
    async fn get_size_by_id(&self, id: u64) -> Result<Option<usize>> {
        let cf_blobs = self
            .inner
            .content
            .cf_handle(CF_BLOBS_V0)
            .ok_or_else(|| anyhow!("missing column family: blobs"))?;
        let maybe_blob = self
            .inner
            .content
            .get_pinned_cf(cf_blobs, id.to_be_bytes())?;
        let maybe_size = maybe_blob.map(|b| b.len());
        Ok(maybe_size)
    }

    #[tracing::instrument(skip(self))]
    async fn get_links_by_id(&self, id: u64) -> Result<Option<Vec<Cid>>> {
        let cf_graph = self.cf_graph()?;
        let id_bytes = id.to_be_bytes();
        // FIXME: can't use pinned because otherwise this can trigger alignment issues :/
        match self.db().get_cf(cf_graph, &id_bytes)? {
            Some(links_id) => {
                let cf_meta = self.cf_metadata()?;
                let graph = rkyv::check_archived_root::<GraphV0>(&links_id)
                    .map_err(|e| anyhow!("{:?}", e))?;
                let keys = graph.children.iter().map(|id| (&cf_meta, id.to_be_bytes()));
                let meta = self.db().multi_get_cf(keys);
                let mut links = Vec::with_capacity(meta.len());
                for (i, meta) in meta.into_iter().enumerate() {
                    match meta? {
                        Some(meta) => {
                            let meta = rkyv::check_archived_root::<MetadataV0>(&meta)
                                .map_err(|e| anyhow!("{:?}", e))?;
                            let multihash = cid::multihash::Multihash::from_bytes(&meta.multihash)?;
                            let c = cid::Cid::new_v1(meta.codec, multihash);
                            links.push(c);
                        }
                        None => {
                            bail!("invalid link: {}", graph.children[i]);
                        }
                    }
                }
                Ok(Some(links))
            }
            None => Ok(None),
        }
    }

    /// Takes a list of cids and gives them ids, which are boths stored and then returned.
    #[tracing::instrument(skip(self, cids))]
    async fn ensure_id_many<I>(&self, cids: I) -> Result<Vec<u64>>
    where
        I: IntoIterator<Item = Cid>,
    {
        let cf_id = self.cf_id()?;
        let cf_meta = self.cf_metadata()?;

        let mut ids = Vec::new();
        let mut batch = WriteBatch::default();
        for cid in cids {
            let id_key = id_key(&cid);
            let id = if let Some(id) = self.db().get_pinned_cf(cf_id, &id_key)? {
                u64::from_be_bytes(id.as_ref().try_into()?)
            } else {
                let id = self.next_id();
                let id_bytes = id.to_be_bytes();

                let metadata = MetadataV0 {
                    codec: cid.codec(),
                    multihash: cid.hash().to_bytes(),
                };
                let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
                batch.put_cf(&cf_id, id_key, &id_bytes);
                batch.put_cf(&cf_meta, &id_bytes, metadata_bytes);
                id
            };
            ids.push(id);
        }
        self.db().write(batch)?;

        Ok(ids)
    }

    #[tracing::instrument(skip(self))]
    fn next_id(&self) -> u64 {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        // TODO: better handling
        assert!(id > 0, "this store is full");
        id
    }

    fn db(&self) -> &RocksDb {
        &self.inner.content
    }

    fn cf_id(&self) -> Result<&ColumnFamily> {
        self.db()
            .cf_handle(CF_ID_V0)
            .context("missing column family: id")
    }

    fn cf_metadata(&self) -> Result<&ColumnFamily> {
        self.db()
            .cf_handle(CF_METADATA_V0)
            .context("missing column family: metadata")
    }

    fn cf_blobs(&self) -> Result<&ColumnFamily> {
        self.db()
            .cf_handle(CF_BLOBS_V0)
            .context("missing column family: blobs")
    }

    fn cf_graph(&self) -> Result<&ColumnFamily> {
        self.db()
            .cf_handle(CF_GRAPH_V0)
            .context("missing column family: graph")
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    use iroh_metrics::config::Config as MetricsConfig;
    use iroh_rpc_client::Config as RpcClientConfig;

    use cid::multihash::{Code, MultihashDigest};
    use libipld::{prelude::Encode, IpldCodec};
    use tempfile::TempDir;
    const RAW: u64 = 0x55;

    #[tokio::test]
    async fn test_basics() {
        let dir = tempfile::tempdir().unwrap();
        let rpc_client = RpcClientConfig::default();
        let config = Config {
            path: dir.path().into(),
            rpc_client,
            metrics: MetricsConfig::default(),
        };

        let store = Store::create(config).await.unwrap();

        let mut values = Vec::new();

        for i in 0..100 {
            let data = vec![i as u8; i * 16];
            let hash = Code::Sha2_256.digest(&data);
            let c = cid::Cid::new_v1(RAW, hash);

            let link_hash = Code::Sha2_256.digest(&[(i + 1) as u8; 64]);
            let link = cid::Cid::new_v1(RAW, link_hash);

            let links = [link];

            store.put(c, &data, links).await.unwrap();
            values.push((c, data, links));
        }

        for (i, (c, expected_data, expected_links)) in values.iter().enumerate() {
            dbg!(i);
            assert!(store.has(c).await.unwrap());
            let data = store.get(c).await.unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).await.unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }
    }

    #[tokio::test]
    async fn test_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let rpc_client = RpcClientConfig::default();
        let config = Config {
            path: dir.path().into(),
            rpc_client,
            metrics: MetricsConfig::default(),
        };

        let store = Store::create(config.clone()).await.unwrap();

        let mut values = Vec::new();

        for i in 0..100 {
            let data = vec![i as u8; i * 16];
            let hash = Code::Sha2_256.digest(&data);
            let c = cid::Cid::new_v1(RAW, hash);

            let link_hash = Code::Sha2_256.digest(&[(i + 1) as u8; 64]);
            let link = cid::Cid::new_v1(RAW, link_hash);

            let links = [link];

            store.put(c, &data, links).await.unwrap();
            values.push((c, data, links));
        }

        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).await.unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).await.unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }

        drop(store);

        let store = Store::open(config).await.unwrap();
        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).await.unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).await.unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }

        for i in 100..200 {
            let data = vec![i as u8; i * 16];
            let hash = Code::Sha2_256.digest(&data);
            let c = cid::Cid::new_v1(RAW, hash);

            let link_hash = Code::Sha2_256.digest(&[(i + 1) as u8; 64]);
            let link = cid::Cid::new_v1(RAW, link_hash);

            let links = [link];

            store.put(c, &data, links).await.unwrap();
            values.push((c, data, links));
        }

        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).await.unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).await.unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }
    }

    async fn test_store() -> anyhow::Result<(Store, TempDir)> {
        let dir = tempfile::tempdir()?;
        let rpc_client = RpcClientConfig::default();
        let config = Config {
            path: dir.path().into(),
            rpc_client,
            metrics: MetricsConfig::default(),
        };

        let store = Store::create(config).await?;
        Ok((store, dir))
    }

    #[tokio::test]
    async fn test_multiple_cids_same_hash() -> anyhow::Result<()> {
        let link1 = Cid::from_str("bafybeib4tddkl4oalrhe7q66rrz5dcpz4qwv5lmpstuqrls3djikw566y4")?;
        let link2 = Cid::from_str("QmcBphfXUFUNLcfAm31WEqYjrjEh19G5x4iAQANSK151DD")?;
        // some data with links
        let data = libipld::ipld!({
            "link1": link1,
            "link2": link2,
        });
        let mut blob = Vec::new();
        data.encode(IpldCodec::DagCbor, &mut blob)?;
        let hash = Code::Sha2_256.digest(&blob);
        let raw_cid = Cid::new_v1(IpldCodec::Raw.into(), hash);
        let cbor_cid = Cid::new_v1(IpldCodec::DagCbor.into(), hash);

        let (store, _dir) = test_store().await?;
        store.put(raw_cid, &blob, vec![]).await?;
        store.put(cbor_cid, &blob, vec![link1, link2]).await?;
        assert_eq!(store.get_links(&raw_cid).await?.unwrap().len(), 0);
        assert_eq!(store.get_links(&cbor_cid).await?.unwrap().len(), 2);

        let ids = store.get_ids_for_hash(&hash)?;
        assert_eq!(ids.count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn test_blob_by_hash() -> anyhow::Result<()> {
        let link1 = Cid::from_str("bafybeib4tddkl4oalrhe7q66rrz5dcpz4qwv5lmpstuqrls3djikw566y4")?;
        let link2 = Cid::from_str("QmcBphfXUFUNLcfAm31WEqYjrjEh19G5x4iAQANSK151DD")?;
        // some data with links
        let data = libipld::ipld!({
            "link1": link1,
            "link2": link2,
        });
        let mut expected = Vec::new();
        data.encode(IpldCodec::DagCbor, &mut expected)?;
        let hash = Code::Sha2_256.digest(&expected);
        let raw_cid = Cid::new_v1(IpldCodec::Raw.into(), hash);
        let cbor_cid = Cid::new_v1(IpldCodec::DagCbor.into(), hash);

        let (store, _dir) = test_store().await?;
        // we don't have it yet
        assert!(!store.has_blob_for_hash(&hash).await?);
        let actual = store.get_blob_by_hash(&hash).await?.map(|x| x.to_vec());
        assert_eq!(actual, None);

        store.put(raw_cid, &expected, vec![]).await?;
        assert!(store.has_blob_for_hash(&hash).await?);
        let actual = store.get_blob_by_hash(&hash).await?.map(|x| x.to_vec());
        assert_eq!(actual, Some(expected.clone()));

        store.put(cbor_cid, &expected, vec![link1, link2]).await?;
        assert!(store.has_blob_for_hash(&hash).await?);
        let actual = store.get_blob_by_hash(&hash).await?.map(|x| x.to_vec());
        assert_eq!(actual, Some(expected));
        Ok(())
    }
}
