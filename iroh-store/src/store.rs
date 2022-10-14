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
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, DBPinnableSlice, IteratorMode, Options, WriteBatch,
    DB as RocksDb,
};
use tokio::task;

use crate::cf::{
    GraphV0, MetadataV0, Versioned, CF_BLOBS_V0, CF_GRAPH_V0, CF_ID_V0, CF_METADATA_V0,
};
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

        let metadata = Versioned(MetadataV0 {
            codec: cid.codec(),
            multihash: cid.hash().to_bytes(),
        });
        let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
        let multihash = &metadata.0.multihash;

        let children = self.ensure_id_many(links.into_iter()).await?;

        let graph = Versioned(GraphV0 { children });
        let graph_bytes = rkyv::to_bytes::<_, 1024>(&graph)?; // TODO: is this the right amount of scratch space?

        let cf_id = self.cf_id()?;
        let cf_meta = self.cf_metadata()?;
        let cf_graph = self.cf_graph()?;
        let cf_blobs = self.cf_blobs()?;
        let blob_size = blob.as_ref().len();

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_id, multihash, &id_bytes);
        batch.put_cf(cf_blobs, &id_bytes, blob);
        batch.put_cf(cf_meta, &id_bytes, metadata_bytes);
        batch.put_cf(cf_graph, &id_bytes, graph_bytes);
        self.db().write(batch)?;
        observe!(StoreHistograms::PutRequests, start.elapsed().as_secs_f64());
        record!(StoreMetrics::PutBytes, blob_size as u64);

        Ok(())
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
        let multihash = cid.hash().to_bytes();
        let maybe_id_bytes = self.db().get_pinned_cf(cf_id, multihash)?;
        match maybe_id_bytes {
            Some(bytes) => {
                let arr = bytes[..8].try_into().map_err(|e| anyhow!("{:?}", e))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self))]
    async fn get_by_id(&self, id: u64) -> Result<Option<DBPinnableSlice<'_>>> {
        let cf_blobs = self.cf_blobs()?;
        let maybe_blob = self.db().get_pinned_cf(cf_blobs, id.to_be_bytes())?;

        Ok(maybe_blob)
    }

    #[tracing::instrument(skip(self))]
    async fn get_links_by_id(&self, id: u64) -> Result<Option<Vec<Cid>>> {
        let cf_graph = self.cf_graph()?;
        let id_bytes = id.to_be_bytes();
        // FIXME: can't use pinned because otherwise this can trigger alignment issues :/
        match self.db().get_cf(cf_graph, &id_bytes)? {
            Some(links_id) => {
                let cf_meta = self.cf_metadata()?;
                let graph = rkyv::check_archived_root::<Versioned<GraphV0>>(&links_id)
                    .map_err(|e| anyhow!("{:?}", e))?;
                let keys = graph
                    .0
                    .children
                    .iter()
                    .map(|id| (&cf_meta, id.to_be_bytes()));
                let meta = self.db().multi_get_cf(keys);
                let mut links = Vec::with_capacity(meta.len());
                for (i, meta) in meta.into_iter().enumerate() {
                    match meta? {
                        Some(meta) => {
                            let meta = rkyv::check_archived_root::<Versioned<MetadataV0>>(&meta)
                                .map_err(|e| anyhow!("{:?}", e))?;
                            let multihash =
                                cid::multihash::Multihash::from_bytes(&meta.0.multihash)?;
                            let c = cid::Cid::new_v1(meta.0.codec, multihash);
                            links.push(c);
                        }
                        None => {
                            bail!("invalid link: {}", graph.0.children[i]);
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
            let multihash = cid.hash().to_bytes();
            let id = if let Some(id) = self.db().get_pinned_cf(cf_id, &multihash)? {
                u64::from_be_bytes(id.as_ref().try_into()?)
            } else {
                let id = self.next_id();
                let id_bytes = id.to_be_bytes();

                let metadata = Versioned(MetadataV0 {
                    codec: cid.codec(),
                    multihash,
                });
                let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?

                let multihash = &metadata.0.multihash;
                batch.put_cf(&cf_id, multihash, &id_bytes);
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
    use super::*;

    use iroh_metrics::config::Config as MetricsConfig;
    use iroh_rpc_client::Config as RpcClientConfig;

    use cid::multihash::{Code, MultihashDigest};
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
}
