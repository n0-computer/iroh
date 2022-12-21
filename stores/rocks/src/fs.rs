use std::fmt;
use std::path::Path;

use anyhow::{anyhow, Result};
use rocksdb::{Cache, DBPinnableSlice, WriteBatch, DB};

pub struct RocksFs {
    db: DB,
    #[allow(dead_code)]
    cache: Option<Cache>,
}

impl fmt::Debug for RocksFs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RocksFs")
            .field("db", &self.db)
            .field("cache", &"rocksdb::db_options::Cache")
            .finish()
    }
}

pub use rocksdb::Options;

pub fn default_options() -> (Options, Cache) {
    use rocksdb::BlockBasedOptions;

    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.set_enable_blob_files(true);
    opts.set_min_blob_size(5 * 1024);
    opts.optimize_for_point_lookup(64 * 1024 * 1024);
    opts.increase_parallelism(32); // TODO: dynamic
    opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bottommost_compression_type(rocksdb::DBCompressionType::Zstd);
    opts.set_blob_compression_type(rocksdb::DBCompressionType::Lz4);
    opts.set_bytes_per_sync(1_048_576);

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

impl RocksFs {
    pub fn new<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let (opts, cache) = default_options();
        Self::with_options(opts, Some(cache), path)
    }

    pub fn with_options<P>(options: Options, cache: Option<Cache>, path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        let db = DB::open(&options, path)?;

        Ok(RocksFs { db, cache })
    }

    pub fn compact(&self) {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
    }

    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        Ok(self.db.put(key, value)?)
    }

    pub fn del<K>(&self, key: K) -> Result<()>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.db.delete(key)?)
    }

    pub fn bulk_put<'b, K, V>(&self, values: impl Iterator<Item = (&'b K, &'b V)>) -> Result<()>
    where
        K: AsRef<[u8]> + 'b,
        V: AsRef<[u8]> + 'b,
    {
        let mut batch = WriteBatch::default();
        for (k, v) in values {
            batch.put(k, v);
        }
        Ok(self.db.write(batch)?)
    }

    pub fn bulk_delete<'b, K>(&self, keys: impl Iterator<Item = &'b K>) -> Result<()>
    where
        K: AsRef<[u8]> + 'b,
    {
        let mut batch = WriteBatch::default();
        for k in keys {
            batch.delete(k);
        }
        Ok(self.db.write(batch)?)
    }

    pub fn get<K>(&self, key: K) -> Result<DBPinnableSlice<'_>>
    where
        K: AsRef<[u8]>,
    {
        let res = self
            .db
            .get_pinned(key)?
            .ok_or_else(|| anyhow!("key not found"))?;
        Ok(res)
    }

    pub fn get_size<K>(&self, key: K) -> Result<usize>
    where
        K: AsRef<[u8]>,
    {
        let res = self
            .db
            .get_pinned(key)?
            .ok_or_else(|| anyhow!("key not found"))?;
        Ok(res.len())
    }

    pub fn has<K>(&self, key: K) -> Result<bool>
    where
        K: AsRef<[u8]>,
    {
        self.db
            .get_pinned(key)
            .map(|v| v.is_some())
            .map_err(Into::into)
    }

    /// Deletes all elements in the database.
    pub fn clear(&self) -> Result<()> {
        for r in self.db.full_iterator(rocksdb::IteratorMode::Start) {
            let (key, _) = r?;
            self.db.delete(key)?;
        }

        Ok(())
    }

    pub fn number_of_keys(&self) -> Result<u64> {
        let keys = self
            .db
            .property_int_value("rocksdb.estimate-num-keys")?
            .unwrap_or_default();
        Ok(keys)
    }

    pub fn stats(&self) -> Result<String> {
        let stats = self.db.property_value(rocksdb::properties::STATS)?;
        Ok(stats.unwrap_or_default())
    }

    pub fn sst_files_size(&self) -> Result<u64> {
        let size = self
            .db
            .property_int_value(rocksdb::properties::TOTAL_SST_FILES_SIZE)?;
        Ok(size.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_empty() {
        let dir = tempfile::tempdir().unwrap();

        let rocksfs = RocksFs::new(dir.path()).unwrap();
        assert_eq!(rocksfs.number_of_keys().unwrap(), 0);
    }

    #[test]
    fn test_open_empty() {
        let dir = tempfile::tempdir().unwrap();

        {
            let _rocksfs = RocksFs::new(dir.path()).unwrap();
        }

        {
            let _rocksfs = RocksFs::new(dir.path()).unwrap();
        }
    }

    #[test]
    fn test_put_get_number_of_keys() {
        let dir = tempfile::tempdir().unwrap();
        let rocksfs = RocksFs::new(dir.path()).unwrap();

        for i in 0..10 {
            rocksfs.put(format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(rocksfs.number_of_keys().unwrap(), 10);

        for i in 0..10 {
            assert_eq!(&rocksfs.get(&format!("foo{i}")).unwrap()[..], [i; 128]);
            assert_eq!(rocksfs.get_size(format!("foo{i}")).unwrap(), 128);
        }

        drop(rocksfs);

        // Reread for size
        let rocksfs = RocksFs::new(dir.path()).unwrap();
        assert_eq!(rocksfs.number_of_keys().unwrap(), 10);
    }

    #[test]
    fn test_put_get_del() {
        let dir = tempfile::tempdir().unwrap();
        let rocksfs = RocksFs::new(dir.path()).unwrap();

        for i in 0..10 {
            rocksfs.put(format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(rocksfs.number_of_keys().unwrap(), 10);

        for i in 0..10 {
            assert_eq!(&rocksfs.get(&format!("foo{i}")).unwrap()[..], [i; 128]);
        }

        for i in 0..5 {
            rocksfs.del(format!("foo{i}")).unwrap();
        }

        assert_eq!(rocksfs.number_of_keys().unwrap(), 5);

        for i in 0..10 {
            if i < 5 {
                assert!(rocksfs.get(&format!("foo{i}")).is_err());
            } else {
                assert_eq!(&rocksfs.get(&format!("foo{i}")).unwrap()[..], [i; 128]);
            }
        }
    }

    #[test]
    fn test_iter() {
        let dir = tempfile::tempdir().unwrap();
        let rocksfs = RocksFs::new(dir.path()).unwrap();

        for i in 0..10 {
            rocksfs.put(format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(rocksfs.number_of_keys().unwrap(), 10);

        // for r in rocksfs.iter() {
        //     let (key, value) = r.unwrap();
        //     let i: u8 = key.strip_prefix("foo").unwrap().parse().unwrap();
        //     assert_eq!(value, [i; 128]);
        // }

        // for r in rocksfs.keys() {
        //     let key = r.unwrap();
        //     let i: u8 = key.strip_prefix("foo").unwrap().parse().unwrap();
        //     assert!(i < 10);
        // }

        // for r in rocksfs.values() {
        //     let value = r.unwrap();
        //     assert_eq!(value.len(), 128);
        // }
    }
}
