use std::{fmt, sync::Arc};

use ahash::AHashSet;
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use cid::Cid;
use iroh_metrics::{
    core::{MObserver, MRecorder},
    inc, observe, record,
    store::{StoreHistograms, StoreMetrics},
};
use iroh_rpc_client::Client as RpcClient;
use multihash::Multihash;
use redb::{Database, ReadableTable, Table};
use smallvec::SmallVec;
use std::sync::RwLock;
use tokio::task;

use crate::cf::{GraphV0, MetadataV0, CF_BLOBS_V0, CF_GRAPH_V0, CF_ID_V0, CF_METADATA_V0};
use crate::Config;

#[derive(Clone, Debug)]
pub struct Store {
    inner: Arc<InnerStore>,
}

struct InnerStore {
    content: Database,
    next_id: RwLock<u64>,
    _rpc_client: RpcClient,
}

impl fmt::Debug for InnerStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InnerStore")
            .field("content", &self.content)
            .field("next_id", &self.next_id)
            .field("_rpc_client", &self._rpc_client)
            .finish()
    }
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
        Self::open(config).await
    }

    /// Opens an existing database.
    #[tracing::instrument]
    pub async fn open(config: Config) -> Result<Self> {
        let path = config.path;
        let (db, next_id) = task::spawn_blocking(move || -> Result<_> {
            let db = Database::create(path.join("iroh.db"))?;
            let next_id = {
                let txn = db.begin_write()?;
                {
                    txn.open_table(CF_BLOBS_V0)?;
                }
                {
                    txn.open_table(CF_METADATA_V0)?;
                }
                {
                    txn.open_table(CF_GRAPH_V0)?;
                }
                let next_id = {
                    let id_table = txn.open_table(CF_ID_V0)?;
                    // read last inserted id

                    let iter = id_table.iter()?;
                    let last_id: u64 = iter.last().map(|(_, g)| g.value()).unwrap_or_default();
                    last_id + 1
                };
                txn.commit()?;
                next_id
            };
            Ok((db, next_id))
        })
        .await??;

        let _rpc_client = RpcClient::new(config.rpc_client)
            .await
            .context("Error creating rpc client for store")?;

        Ok(Store {
            inner: Arc::new(InnerStore {
                content: db,
                next_id: next_id.into(),
                _rpc_client,
            }),
        })
    }

    #[tracing::instrument(skip(self, links, blob))]
    pub fn put<T: AsRef<[u8]>, L>(&self, cid: Cid, blob: T, links: L) -> Result<()>
    where
        L: IntoIterator<Item = Cid>,
    {
        inc!(StoreMetrics::PutRequests);

        if self.has(&cid)? {
            return Ok(());
        }

        let id = self.next_id();

        let start = std::time::Instant::now();

        // guranteed that the key does not exists, so we want to store it

        let metadata = MetadataV0 {
            codec: cid.codec(),
            multihash: cid.hash().to_bytes().into_boxed_slice(),
        };
        let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
        let id_key = id_key(&cid);
        let blob_size = blob.as_ref().len();

        let txn = self.inner.content.begin_write()?;
        {
            let mut id_table = txn.open_table(CF_ID_V0)?;
            let mut metadata_table = txn.open_table(CF_METADATA_V0)?;

            let children =
                self.ensure_id_many(links.into_iter(), &mut id_table, &mut metadata_table)?;

            let graph = GraphV0 {
                children: children.into_boxed_slice(),
            };
            let graph_bytes = rkyv::to_bytes::<_, 1024>(&graph)?; // TODO: is this the right amount of scratch space?

            id_table.insert(&id_key, &id)?;
            txn.open_table(CF_BLOBS_V0)?.insert(&id, blob.as_ref())?;
            metadata_table.insert(&id, &metadata_bytes)?;
            txn.open_table(CF_GRAPH_V0)?.insert(&id, &graph_bytes)?;
        }
        txn.commit()?;

        observe!(StoreHistograms::PutRequests, start.elapsed().as_secs_f64());
        record!(StoreMetrics::PutBytes, blob_size as u64);

        Ok(())
    }

    #[tracing::instrument(skip(self, blocks))]
    pub fn put_many(&self, blocks: impl IntoIterator<Item = (Cid, Bytes, Vec<Cid>)>) -> Result<()> {
        inc!(StoreMetrics::PutRequests);
        let start = std::time::Instant::now();
        let mut total_blob_size = 0;

        let txn = self.inner.content.begin_write()?;
        {
            let mut id_table = txn.open_table(CF_ID_V0)?;
            let mut blobs_table = txn.open_table(CF_BLOBS_V0)?;
            let mut metadata_table = txn.open_table(CF_METADATA_V0)?;
            let mut graph_table = txn.open_table(CF_GRAPH_V0)?;

            let mut cid_tracker: AHashSet<Cid> = AHashSet::default();
            for (cid, blob, links) in blocks.into_iter() {
                println!("putting {}", cid);
                if cid_tracker.contains(&cid) || self.has(&cid)? {
                    continue;
                }

                cid_tracker.insert(cid);

                let id = self.next_id();

                // guranteed that the key does not exists, so we want to store it

                let metadata = MetadataV0 {
                    codec: cid.codec(),
                    multihash: cid.hash().to_bytes().into_boxed_slice(),
                };
                let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
                let id_key = id_key(&cid);

                let children =
                    self.ensure_id_many(links.into_iter(), &mut id_table, &mut metadata_table)?;

                let graph = GraphV0 {
                    children: children.into_boxed_slice(),
                };
                let graph_bytes = rkyv::to_bytes::<_, 1024>(&graph)?; // TODO: is this the right amount of scratch space?

                let blob_size = blob.as_ref().len();
                total_blob_size += blob_size as u64;

                id_table.insert(&id_key, &id)?;
                blobs_table.insert(&id, &blob)?;
                metadata_table.insert(&id, &metadata_bytes)?;
                graph_table.insert(&id, &graph_bytes)?;
            }
        }
        txn.commit()?;

        observe!(StoreHistograms::PutRequests, start.elapsed().as_secs_f64());
        record!(StoreMetrics::PutBytes, total_blob_size);

        Ok(())
    }

    /// Takes a list of cids and gives them ids, which are both stored and then returned.
    #[tracing::instrument(skip(self, cids, id_table, metadata_table))]
    fn ensure_id_many<I>(
        &self,
        cids: I,
        id_table: &mut Table<&[u8], u64>,
        metadata_table: &mut Table<u64, &[u8]>,
    ) -> Result<Vec<u64>>
    where
        I: IntoIterator<Item = Cid>,
    {
        let mut ids = Vec::new();

        for cid in cids {
            let id_key = id_key(&cid);
            let maybe_id = id_table.get(&id_key)?;

            let id = if let Some(id) = maybe_id {
                id.value()
            } else {
                drop(maybe_id);
                let id = self.next_id();

                let metadata = MetadataV0 {
                    codec: cid.codec(),
                    multihash: cid.hash().to_bytes().into_boxed_slice(),
                };
                let metadata_bytes = rkyv::to_bytes::<_, 1024>(&metadata)?; // TODO: is this the right amount of scratch space?
                id_table.insert(&id_key, &id)?;
                metadata_table.insert(&id, &metadata_bytes)?;
                id
            };
            ids.push(id);
        }

        Ok(ids)
    }

    #[tracing::instrument(skip(self))]
    fn next_id(&self) -> u64 {
        let mut id = self.inner.next_id.write().unwrap();
        if let Some(next_id) = id.checked_add(1) {
            *id = next_id;
            next_id
        } else {
            panic!("this store is full");
        }
    }

    #[tracing::instrument(skip(self))]
    fn get_id(&self, cid: &Cid) -> Result<Option<u64>> {
        let id_key = id_key(cid);

        let txn = self.inner.content.begin_read()?;
        let id_table = txn.open_table(CF_ID_V0)?;
        let maybe_id_bytes = id_table.get(&id_key)?;
        match maybe_id_bytes {
            Some(bytes) => Ok(Some(bytes.value())),
            None => Ok(None),
        }
    }

    pub fn has(&self, cid: &Cid) -> Result<bool> {
        match self.get_id(cid)? {
            Some(id) => {
                let txn = self.inner.content.begin_read()?;
                let blobs_table = txn.open_table(CF_BLOBS_V0)?;
                let exists = blobs_table.get(&id)?.is_some();
                Ok(exists)
            }
            None => Ok(false),
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn get_blob_by_hash(&self, hash: &Multihash) -> Result<Option<Vec<u8>>> {
        let txn = self.inner.content.begin_read()?;
        let blobs_table = txn.open_table(CF_BLOBS_V0)?;
        let id_table = txn.open_table(CF_ID_V0)?;

        for elem in self.get_ids_for_hash(hash, &id_table)? {
            let id = elem?.id;
            if let Some(blob) = blobs_table.get(&id)? {
                return Ok(Some(blob.value().to_vec()));
            }
        }
        Ok(None)
    }

    #[tracing::instrument(skip(self))]
    pub fn has_blob_for_hash(&self, hash: &Multihash) -> Result<bool> {
        let txn = self.inner.content.begin_read()?;
        let blobs_table = txn.open_table(CF_BLOBS_V0)?;
        let id_table = txn.open_table(CF_ID_V0)?;

        for elem in self.get_ids_for_hash(hash, &id_table)? {
            let id = elem?.id;
            if let Some(_blob) = blobs_table.get(&id)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[tracing::instrument(skip(self))]
    pub fn get(&self, cid: &Cid) -> Result<Option<Vec<u8>>> {
        inc!(StoreMetrics::GetRequests);
        let start = std::time::Instant::now();
        let res = match self.get_id(cid)? {
            Some(id) => {
                let maybe_blob = self.get_by_id(id)?;
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
    pub fn get_size(&self, cid: &Cid) -> Result<Option<usize>> {
        match self.get_id(cid)? {
            Some(id) => {
                inc!(StoreMetrics::StoreHit);
                let maybe_size = self.get_size_by_id(id)?;
                Ok(maybe_size)
            }
            None => {
                inc!(StoreMetrics::StoreMiss);
                Ok(None)
            }
        }
    }

    #[tracing::instrument(skip(self))]
    pub fn get_links(&self, cid: &Cid) -> Result<Option<Vec<Cid>>> {
        inc!(StoreMetrics::GetLinksRequests);
        let start = std::time::Instant::now();
        let res = match self.get_id(cid)? {
            Some(id) => {
                let maybe_links = self.get_links_by_id(id)?;
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

    /// Perform an internal consistency check on the store, and return all internal errors found.
    #[tracing::instrument(skip(self))]
    pub fn consistency_check(&self) -> Result<Vec<String>> {
        let mut res = Vec::new();

        let txn = self.inner.content.begin_read()?;
        let n_meta = txn.open_table(CF_METADATA_V0)?.len()?;
        let n_id = txn.open_table(CF_ID_V0)?.len()?;
        if n_meta != n_id {
            res.push(format!(
                "non bijective mapping between cid and id. Metadata and id cfs have different lengths: {n_meta} != {n_id}"
            ));
        }
        Ok(res)
    }

    #[tracing::instrument(skip(self))]
    fn get_by_id(&self, id: u64) -> Result<Option<Vec<u8>>> {
        let txn = self.inner.content.begin_read()?;
        let blobs_table = txn.open_table(CF_BLOBS_V0)?;
        let maybe_blob = blobs_table.get(&id)?.map(|b| b.value().to_vec());

        Ok(maybe_blob)
    }

    #[tracing::instrument(skip(self))]
    fn get_size_by_id(&self, id: u64) -> Result<Option<usize>> {
        let txn = self.inner.content.begin_read()?;
        let blobs_table = txn.open_table(CF_BLOBS_V0)?;
        let maybe_blob = blobs_table.get(&id)?;
        let maybe_size = maybe_blob.map(|b| b.value().len());
        Ok(maybe_size)
    }

    #[tracing::instrument(skip(self))]
    fn get_links_by_id(&self, id: u64) -> Result<Option<Vec<Cid>>> {
        // FIXME: can't use pinned because otherwise this can trigger alignment issues :/
        let txn = self.inner.content.begin_read()?;
        let graph_table = txn.open_table(CF_GRAPH_V0)?;
        let meta_table = txn.open_table(CF_METADATA_V0)?;

        let res = match graph_table.get(&id)? {
            Some(links_id) => {
                let graph = rkyv::check_archived_root::<GraphV0>(&links_id.value())
                    .map_err(|e| anyhow!("invalid graph {:?}", e))?;

                let meta = graph.children.iter().map(|id| meta_table.get(id));
                let mut links = Vec::with_capacity(graph.children.len());
                for (i, meta) in meta.into_iter().enumerate() {
                    match meta? {
                        Some(meta) => {
                            let meta = rkyv::check_archived_root::<MetadataV0>(&meta.value())
                                .map_err(|e| anyhow!("invalid metadata {:?}", e))?;
                            let multihash = cid::multihash::Multihash::from_bytes(&meta.multihash)?;
                            let c = Cid::new_v1(meta.codec, multihash);
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
        };

        res
    }

    fn get_ids_for_hash<'a, R: ReadableTable<&'a [u8], u64>>(
        &self,
        hash: &Multihash,
        id_table: &'a R,
    ) -> Result<impl Iterator<Item = Result<CodeAndId>> + 'a> {
        let hash = hash.to_bytes();
        let iter = id_table.iter()?;
        let hash_len = hash.len();
        Ok(iter
            .take_while(move |(k, _)| {
                k.value().len() == hash_len + 8 && k.value().starts_with(&hash)
            })
            .map(move |(k, v)| {
                let code = u64::from_be_bytes(k.value()[hash_len..].try_into()?);
                let id = v.value();
                Ok(CodeAndId { code, id })
            }))
    }

    pub(crate) async fn spawn_blocking<T: Send + Sync + 'static>(
        &self,
        f: impl FnOnce(Self) -> anyhow::Result<T> + Send + Sync + 'static,
    ) -> anyhow::Result<T> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || f(this)).await?
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, sync::Mutex};

    use super::*;

    use iroh_metrics::config::Config as MetricsConfig;
    use iroh_rpc_client::Config as RpcClientConfig;

    use cid::multihash::{Code, MultihashDigest};
    use libipld::{
        cbor::DagCborCodec,
        prelude::{Codec, Encode},
        Ipld, IpldCodec,
    };
    use tempfile::TempDir;
    const RAW: u64 = 0x55;
    const DAG_CBOR: u64 = 0x71;

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

            store.put(c, &data, links).unwrap();
            values.push((c, data, links));
        }

        for (i, (c, expected_data, expected_links)) in values.iter().enumerate() {
            dbg!(i);
            assert!(store.has(c).unwrap());
            let data = store.get(c).unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).unwrap().unwrap();
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

            store.put(c, &data, links).unwrap();
            values.push((c, data, links));
        }

        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }

        drop(store);

        let store = Store::open(config).await.unwrap();
        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).unwrap().unwrap();
            assert_eq!(expected_links, &links[..]);
        }

        for i in 100..200 {
            let data = vec![i as u8; i * 16];
            let hash = Code::Sha2_256.digest(&data);
            let c = cid::Cid::new_v1(RAW, hash);

            let link_hash = Code::Sha2_256.digest(&[(i + 1) as u8; 64]);
            let link = cid::Cid::new_v1(RAW, link_hash);

            let links = [link];

            store.put(c, &data, links).unwrap();
            values.push((c, data, links));
        }

        for (c, expected_data, expected_links) in values.iter() {
            let data = store.get(c).unwrap().unwrap();
            assert_eq!(expected_data, &data[..]);

            let links = store.get_links(c).unwrap().unwrap();
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
        store.put(raw_cid, &blob, vec![])?;
        store.put(cbor_cid, &blob, vec![link1, link2])?;
        assert_eq!(store.get_links(&raw_cid)?.unwrap().len(), 0);
        assert_eq!(store.get_links(&cbor_cid)?.unwrap().len(), 2);

        let txn = store.inner.content.begin_read()?;
        let id_table = txn.open_table(CF_ID_V0)?;
        let ids = store.get_ids_for_hash(&hash, &id_table)?;
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
        assert!(!store.has_blob_for_hash(&hash)?);
        let actual = store.get_blob_by_hash(&hash)?;
        assert_eq!(actual, None);

        store.put(raw_cid, &expected, vec![])?;
        assert!(store.has_blob_for_hash(&hash)?);
        let actual = store.get_blob_by_hash(&hash)?;
        assert_eq!(actual, Some(expected.clone()));

        store.put(cbor_cid, &expected, vec![link1, link2])?;
        assert!(store.has_blob_for_hash(&hash)?);
        let actual = store.get_blob_by_hash(&hash)?;
        assert_eq!(actual, Some(expected));
        Ok(())
    }

    /*
    #[tokio::test]
    async fn test_add_consistency() -> anyhow::Result<()> {
        use rayon::prelude::*;
        let leafs = (0..10000u64)
            .map(|i| Cid::new_v1(RAW, Code::Sha2_256.digest(&i.to_be_bytes())))
            .collect::<Vec<_>>();
        let branches = leafs
            .chunks(100)
            .map(|links| {
                let data = Ipld::List(links.iter().cloned().map(Ipld::Link).collect());
                let data = DagCborCodec.encode(&data).unwrap();
                let cid = Cid::new_v1(DAG_CBOR, Code::Sha2_256.digest(&data));
                (cid, data, links.to_vec())
            })
            .collect::<Vec<_>>();
        let (store, _dir) = futures::executor::block_on(test_store())?;
        let workers = (0..std::thread::available_parallelism()?.get()).collect::<Vec<_>>();
        let mutex = Arc::new(Mutex::new(()));
        for branch in branches {
            // for each batch, do a concurrent insert from as many parallel threads as possible
            workers
                .par_iter()
                .map(|_| {
                    let txn = store.inner.content.begin_write()?;
                    let (cid, data, links) = branch.clone();
                    let t = mutex.lock().unwrap();
                    store.put(cid, &data, links)?;
                    drop(t);
                    anyhow::Ok(())
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
        }
        assert_eq!(Vec::<String>::new(), store.consistency_check()?);
        Ok(())
    }*/

    #[tokio::test]
    async fn test_put_many_repeat_ids() -> anyhow::Result<()> {
        let cid1 = Cid::from_str("bafybeib4tddkl4oalrhe7q66rrz5dcpz4qwv5lmpstuqrls3djikw566y4")?;
        let cid2 = Cid::from_str("QmcBphfXUFUNLcfAm31WEqYjrjEh19G5x4iAQANSK151DD")?;
        let cid3 = Cid::from_str("bafkreieq5jui4j25lacwomsqgjeswwl3y5zcdrresptwgmfylxo2depppq")?;

        let blob = Bytes::from(vec![0u8]);

        let (store, _dir) = test_store().await?;
        let blocks = vec![(cid1, blob.clone(), vec![]), (cid2, blob.clone(), vec![])];
        store.put_many(blocks)?;
        assert!(store.has(&cid1)?);
        assert!(store.has(&cid2)?);

        let blocks = vec![
            (cid1, blob.clone(), vec![]),
            (cid2, blob.clone(), vec![]),
            (cid3, blob.clone(), vec![]),
        ];

        store.put_many(blocks)?;
        assert!(store.has(&cid1)?);
        assert!(store.has(&cid2)?);
        assert!(store.has(&cid3)?);

        Ok(())
    }
}
