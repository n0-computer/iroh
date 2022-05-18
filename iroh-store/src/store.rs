use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use cid::Cid;
use eyre::{bail, Result};
use iroh_rpc_client::Client as RpcClient;
use rocksdb::{DBPinnableSlice, IteratorMode, Options, WriteBatch, DB as RocksDb};
use tokio::task;

use crate::cf::{
    GraphV0, MetadataV0, Versioned, CF_BLOBS_V0, CF_GRAPH_V0, CF_ID_V0, CF_METADATA_V0,
};
use crate::Config;

#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<InnerStore>,
}
#[derive(Debug)]
struct InnerStore {
    content: RocksDb,
    #[allow(dead_code)]
    config: Config,
    next_id: AtomicU64,
    _rpc_client: RpcClient,
}

impl Store {
    /// Creates a new database.
    #[tracing::instrument]
    pub async fn create(config: Config) -> Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        // TODO: more options

        let path = config.path.clone();
        let db = task::spawn_blocking(move || -> Result<_> {
            let mut db = RocksDb::open(&options, path)?;
            {
                let mut opts = Options::default();
                opts.set_enable_blob_files(true);
                opts.set_blob_file_size(1024);
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

        let _rpc_client = RpcClient::new(&config.rpc)
            .await
            // TODO: first conflict between `anyhow` & `eyre`
            // .map_err(|e| e.context("Error creating rpc client for store"))?;
            .map_err(|e| eyre::eyre!("Error creating rpc client for store: {:?}", e))?;

        Ok(Store {
            inner: Arc::new(InnerStore {
                content: db,
                config,
                next_id: 1.into(),
                _rpc_client,
            }),
        })
    }

    /// Opens an existing database.
    #[tracing::instrument]
    pub async fn open(config: Config) -> Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(false);
        // TODO: more options

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
                    .ok_or_else(|| eyre::eyre!("missing column family: metadata"))?;

                let mut iter = db.full_iterator_cf(&cf_meta, IteratorMode::End);
                let last_id = iter
                    .next()
                    .and_then(|(key, _)| key[..8].try_into().ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or_default();

                last_id + 1
            };

            Ok((db, next_id))
        })
        .await??;

        let _rpc_client = RpcClient::new(&config.rpc)
            .await
            // TODO: first conflict between `anyhow` & `eyre`
            // .map_err(|e| e.context("Error creating rpc client for store"))?;
            .map_err(|e| eyre::eyre!("Error creating rpc client for store: {:?}", e))?;

        Ok(Store {
            inner: Arc::new(InnerStore {
                content: db,
                config,
                next_id: next_id.into(),
                _rpc_client,
            }),
        })
    }

    #[tracing::instrument(skip(self, links, blob))]
    pub async fn put<T: AsRef<[u8]>, L>(&self, cid: Cid, blob: T, links: L) -> Result<()>
    where
        L: IntoIterator<Item = Cid>,
    {
        let id = self.next_id();

        let id_bytes = id.to_be_bytes();
        let metadata = Versioned(MetadataV0 {
            codec: cid.codec(),
            multihash: cid.hash().to_bytes(),
        });
        let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is 64 bytes the write amount of scratch space?
        let multihash = &metadata.0.multihash;

        let children = self.ensure_id_many(links.into_iter()).await?;

        let graph = Versioned(GraphV0 { children });
        let graph_bytes = rkyv::to_bytes::<_, 1024>(&graph)?; // TODO: is 64 bytes the write amount of scratch space?

        let cf_id = self
            .inner
            .content
            .cf_handle(CF_ID_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: id"))?;
        let cf_blobs = self
            .inner
            .content
            .cf_handle(CF_BLOBS_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: blobs"))?;
        let cf_meta = self
            .inner
            .content
            .cf_handle(CF_METADATA_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: metadata"))?;
        let cf_graph = self
            .inner
            .content
            .cf_handle(CF_GRAPH_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: metadata"))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(cf_id, multihash, &id_bytes);
        batch.put_cf(cf_blobs, &id_bytes, blob);
        batch.put_cf(cf_meta, &id_bytes, metadata_bytes);
        batch.put_cf(cf_graph, &id_bytes, graph_bytes);
        self.inner.content.write(batch)?;

        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn get(&self, cid: &Cid) -> Result<Option<DBPinnableSlice<'_>>> {
        match self.get_id(cid).await? {
            Some(id) => {
                let maybe_blob = self.get_by_id(id).await?;
                Ok(maybe_blob)
            }
            None => Ok(None),
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        match self.get_id(cid).await? {
            Some(id) => {
                let maybe_links = self.get_links_by_id(id).await?;
                Ok(maybe_links)
            }
            None => Ok(None),
        }
    }

    async fn get_id(&self, cid: &Cid) -> Result<Option<u64>> {
        let cf_id = self
            .inner
            .content
            .cf_handle(CF_ID_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: id"))?;
        let multihash = cid.hash().to_bytes();
        let maybe_id_bytes = self.inner.content.get_pinned_cf(cf_id, multihash)?;
        match maybe_id_bytes {
            Some(bytes) => {
                let arr = bytes[..8].try_into().map_err(|e| eyre::eyre!("{:?}", e))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    async fn get_by_id(&self, id: u64) -> Result<Option<DBPinnableSlice<'_>>> {
        let cf_blobs = self
            .inner
            .content
            .cf_handle(CF_BLOBS_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: blobs"))?;
        let maybe_blob = self
            .inner
            .content
            .get_pinned_cf(cf_blobs, id.to_be_bytes())?;

        Ok(maybe_blob)
    }

    async fn get_links_by_id(&self, id: u64) -> Result<Option<Vec<Cid>>> {
        let cf_graph = self
            .inner
            .content
            .cf_handle(CF_GRAPH_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: graph"))?;
        let id_bytes = id.to_be_bytes();
        // FIXME: can't use pinned because otherwise this can trigger alignment issues :/
        match self.inner.content.get_cf(cf_graph, &id_bytes)? {
            Some(links_id) => {
                let cf_meta = self
                    .inner
                    .content
                    .cf_handle(CF_METADATA_V0)
                    .ok_or_else(|| eyre::eyre!("missing column family: metadata"))?;

                let graph = rkyv::check_archived_root::<Versioned<GraphV0>>(&links_id)
                    .map_err(|e| eyre::eyre!("{:?}", e))?;
                let keys = graph
                    .0
                    .children
                    .iter()
                    .map(|id| (&cf_meta, id.to_be_bytes()));
                let meta = self.inner.content.multi_get_cf(keys);
                let mut links = Vec::with_capacity(meta.len());
                for (i, meta) in meta.into_iter().enumerate() {
                    match meta? {
                        Some(meta) => {
                            let meta = rkyv::check_archived_root::<Versioned<MetadataV0>>(&meta)
                                .map_err(|e| eyre::eyre!("{:?}", e))?;
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
    async fn ensure_id_many<I>(&self, cids: I) -> Result<Vec<u64>>
    where
        I: IntoIterator<Item = Cid>,
    {
        let cf_id = self
            .inner
            .content
            .cf_handle(CF_ID_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: id"))?;

        let cf_meta = self
            .inner
            .content
            .cf_handle(CF_METADATA_V0)
            .ok_or_else(|| eyre::eyre!("missing column family: metadata"))?;

        let mut ids = Vec::new();
        let mut batch = WriteBatch::default();
        for cid in cids {
            let id = self.next_id();
            let id_bytes = id.to_be_bytes();

            let metadata = Versioned(MetadataV0 {
                codec: cid.codec(),
                multihash: cid.hash().to_bytes(),
            });
            let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is 64 bytes the write amount of scratch space?

            let multihash = &metadata.0.multihash;
            // TODO: is it worth to check for existence instead of just writing?
            batch.put_cf(&cf_id, multihash, &id_bytes);
            batch.put_cf(&cf_meta, &id_bytes, metadata_bytes);
            ids.push(id);
        }
        self.inner.content.write(batch)?;

        Ok(ids)
    }

    fn next_id(&self) -> u64 {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        // TODO: better handling
        assert!(id > 0, "this store is full");
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use iroh_rpc_client::RpcClientConfig;

    use cid::multihash::{Code, MultihashDigest};
    const RAW: u64 = 0x55;

    #[tokio::test]
    async fn test_basics() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            path: dir.path().into(),
            rpc: RpcClientConfig::default(),
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
            let data = store.get(c).await.unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).await.unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }
    }

    #[tokio::test]
    async fn test_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            path: dir.path().into(),
            rpc: RpcClientConfig::default(),
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
