use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use anyhow::{anyhow, Context, Result};

use crate::shard::{self, Shard};

#[derive(Debug)]
pub struct Flatfs {
    /// Path to the root of the storage on disk.
    path: PathBuf,
    /// The sharding strategy.
    shard: Shard,
    /// Current disk usage in bytes.
    disk_usage: AtomicU64,
}

const EXTENSION: &str = "data";
const EXTENSION_WITH_DOT: &str = ".data";
const DISK_USAGE_CACHE: &str = "disk_usage.cache";

/// Timeout (in ms) for a backoff on retrying operations.
const RETRY_DELAY: u64 = 200;

/// The maximum number of retries that will be attempted.
const RETRY_ATTEMPTS: usize = 6;

impl Flatfs {
    /// Creates or opens an existing store at the provided path as the root.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::with_shard(path, Shard::default())
    }

    /// Creates or opens an existing store at the provided path as the root.
    pub fn with_shard<P: AsRef<Path>>(path: P, shard: Shard) -> Result<Self> {
        if path.as_ref().exists() && path.as_ref().join(shard::FILE_NAME).exists() {
            Self::open(path, shard)
        } else {
            Self::create(path, shard)
        }
    }

    /// Stores the given value under the given key.
    pub fn put<T: AsRef<[u8]>>(&self, key: &str, value: T) -> Result<()> {
        ensure_valid_key(key)?;
        let filepath = self.as_path(key);
        let parent_dir = filepath.parent().unwrap();

        // Make sure the sharding directory exists.
        if !parent_dir.exists() {
            if let Err(err) = retry(|| fs::create_dir(parent_dir)) {
                // Directory got already created, that's fine.
                if err.kind() != io::ErrorKind::AlreadyExists {
                    return Err(err)
                        .with_context(|| format!("Failed to create {:?}", filepath.parent()));
                }
            }
        }

        // Write to temp location
        let temp_filepath = filepath.with_extension(".temp");
        let value = value.as_ref();
        retry(|| fs::write(&temp_filepath, value))
            .with_context(|| format!("Failed to write {temp_filepath:?}"))?;

        // Rename after successfull write
        retry(|| fs::rename(&temp_filepath, &filepath))
            .with_context(|| format!("Failed to reaname: {temp_filepath:?} -> {filepath:?}"))?;

        self.disk_usage
            .fetch_add(value.len() as u64, Ordering::SeqCst);

        Ok(())
    }

    /// Retrieves the value under the given key.
    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        ensure_valid_key(key)?;
        let filepath = self.as_path(key);

        let value = retry(|| fs::read(&filepath))
            .with_context(|| format!("Failed to read {filepath:?}"))?;

        Ok(value)
    }

    /// Retrieves the size of the value under the given key.
    pub fn get_size(&self, key: &str) -> Result<u64> {
        ensure_valid_key(key)?;
        let filepath = self.as_path(key);

        let metadata = filepath
            .metadata()
            .with_context(|| format!("Failed to read metadata for {filepath:?}"))?;

        Ok(metadata.len())
    }

    /// Deletes the value under the given key, if it doesn't exists, returns an error.
    pub fn del(&self, key: &str) -> Result<()> {
        ensure_valid_key(key)?;
        let filepath = self.as_path(key);

        let metadata = filepath
            .metadata()
            .with_context(|| format!("Failed to read metadata for {filepath:?}"))?;
        let filesize = metadata.len();

        retry(|| fs::remove_file(&filepath))
            .with_context(|| format!("Failed to remove {filepath:?}"))?;

        self.disk_usage.fetch_sub(filesize, Ordering::SeqCst);

        Ok(())
    }

    fn create<P: AsRef<Path>>(path: P, shard: Shard) -> Result<Self> {
        fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create {:?}", path.as_ref()))?;

        shard
            .write_to_file(&path)
            .context("Failed to write shard to file")?;

        Self::open(path, shard)
    }

    fn open<P: AsRef<Path>>(path: P, shard: Shard) -> Result<Self> {
        let existing_shard = Shard::from_file(&path)?;
        if shard != existing_shard {
            return Err(anyhow!(
                "Tried to open store with {:?}, found {:?}",
                shard,
                existing_shard
            ));
        }

        let disk_usage = calculate_disk_usage(&path)?;

        Ok(Flatfs {
            path: path.as_ref().to_path_buf(),
            shard,
            disk_usage: AtomicU64::new(disk_usage),
        })
    }

    fn as_path(&self, key: &str) -> PathBuf {
        let mut p = self.path.join(self.shard.dir(key)).join(key);
        p.set_extension(EXTENSION);
        p
    }

    pub fn disk_usage(&self) -> u64 {
        self.disk_usage.load(Ordering::SeqCst)
    }

    /// Safely close the store.
    pub fn close(&self) -> Result<()> {
        write_disk_usage(&self.path, self.disk_usage.load(Ordering::SeqCst))?;
        Ok(())
    }

    /// Iterates over all key, value pairs (in no guranteed order).
    pub fn iter(&self) -> impl Iterator<Item = Result<(String, Vec<u8>)>> {
        let read_file = |p: &Path| {
            let content = fs::read(p)?;
            let key = key_from_path(p)?;

            Ok((key, content))
        };

        self.walk().filter_map(move |r| match r {
            Ok(entry) => entry.path().is_file().then(|| read_file(entry.path())),
            Err(err) => Some(Err(err.into())),
        })
    }

    /// Iterates over all keys (in no guranteed order).
    pub fn keys(&self) -> impl Iterator<Item = Result<String>> {
        self.walk().filter_map(move |r| match r {
            Ok(entry) => entry.path().is_file().then(|| key_from_path(entry.path())),
            Err(err) => Some(Err(err.into())),
        })
    }

    /// Iterates over all keys and returns stats for them (in no guranteed order).
    pub fn stats(&self) -> impl Iterator<Item = Result<KvStats>> {
        self.walk().filter_map(move |r| match r {
            Ok(entry) => entry
                .path()
                .is_file()
                .then(|| KvStats::from_path(entry.path())),
            Err(err) => Some(Err(err.into())),
        })
    }

    /// Iterates over all values (in no guranteed order).
    pub fn values(&self) -> impl Iterator<Item = Result<Vec<u8>>> {
        self.walk().filter_map(move |r| match r {
            Ok(entry) => entry
                .path()
                .is_file()
                .then(|| fs::read(entry.path()).map_err(Into::into)),
            Err(err) => Some(Err(err.into())),
        })
    }

    fn walk(&self) -> ignore::Walk {
        // Walk the walk
        let mut typ = ignore::types::TypesBuilder::new();
        typ.add("data", &format!("*.{EXTENSION}")).unwrap();
        typ.select("data");

        ignore::WalkBuilder::new(&self.path)
            .standard_filters(false)
            .hidden(true)
            .max_depth(None)
            .types(typ.build().unwrap())
            .build()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KvStats {
    pub key: String,
    pub size: u64,
    pub path: PathBuf,
    pub modified: Option<SystemTime>,
}

impl KvStats {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let key = key_from_path(&path)?;
        let m = path.metadata()?;
        Ok(KvStats {
            key,
            path,
            size: m.len(),
            modified: m.modified().ok(),
        })
    }
}

fn key_from_path(path: &Path) -> Result<String> {
    let filename = path
        .file_name()
        .ok_or_else(|| anyhow!("No filename"))?
        .to_str()
        .ok_or_else(|| anyhow!("Invalid keyname"))?;
    let key = filename
        .strip_suffix(EXTENSION_WITH_DOT)
        .ok_or_else(|| anyhow!("Invalid key: {}", filename))?;
    Ok(key.to_string())
}

fn ensure_valid_key(key: &str) -> Result<()> {
    if key.len() < 2 || !key.is_ascii() || key.contains('/') {
        return Err(anyhow!("Invalid key: {:?}", key));
    }

    Ok(())
}

fn retry<T, E, F: FnMut() -> std::result::Result<T, E>>(mut f: F) -> std::result::Result<T, E> {
    use backoff::{backoff::Constant, Error};

    let mut count = 0;

    let res = backoff::retry(
        Constant::new(Duration::from_millis(RETRY_DELAY)),
        || match f() {
            Ok(res) => Ok(res),
            Err(err) => {
                count += 1;
                if count < RETRY_ATTEMPTS {
                    Err(err.into())
                } else {
                    Err(Error::Permanent(err))
                }
            }
        },
    );
    res.map_err(|err| match err {
        Error::Permanent(err) => err,
        Error::Transient { err, .. } => err,
    })
}

impl Drop for Flatfs {
    fn drop(&mut self) {
        self.close().expect("failed to close Flatfs");
    }
}

fn write_disk_usage<P: AsRef<Path>>(path: P, usage: u64) -> Result<()> {
    let disk_usage_path = path.as_ref().join(DISK_USAGE_CACHE);
    fs::write(&disk_usage_path, &usage.to_string()[..])
        .with_context(|| format!("Failed to write to {disk_usage_path:?}"))?;
    Ok(())
}

fn calculate_disk_usage<P: AsRef<Path>>(path: P) -> Result<u64> {
    // Check for an existing diskusage file
    let disk_usage_path = path.as_ref().join(DISK_USAGE_CACHE);
    if disk_usage_path.exists() {
        let usage: u64 = fs::read_to_string(&disk_usage_path)
            .with_context(|| format!("Failed to read {disk_usage_path:?}"))?
            .parse()?;
        return Ok(usage);
    }

    // Walk the walk
    let mut typ = ignore::types::TypesBuilder::new();
    typ.add("data", &format!("*.{EXTENSION}")).unwrap();
    typ.select("data");

    let walker = ignore::WalkBuilder::new(&path)
        .standard_filters(false)
        .hidden(true)
        .max_depth(None)
        .types(typ.build().unwrap())
        .build_parallel();

    let sum = AtomicU64::new(0);

    walker.run(|| {
        Box::new(|result| match result {
            Ok(entry) => {
                if entry.file_type().is_some() && entry.file_type().unwrap().is_file() {
                    if let Ok(m) = entry.metadata() {
                        sum.fetch_add(m.len(), Ordering::SeqCst);
                        return ignore::WalkState::Continue;
                    }
                }
                ignore::WalkState::Continue
            }
            Err(_) => ignore::WalkState::Skip,
        })
    });

    let disk_usage = sum.load(Ordering::SeqCst);
    write_disk_usage(path, disk_usage)?;

    Ok(disk_usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_empty() {
        let dir = tempfile::tempdir().unwrap();

        let flatfs = Flatfs::new(dir.path()).unwrap();

        let shard_file_path = dir.path().join("SHARDING");
        assert!(shard_file_path.exists());
        assert_eq!(
            fs::read_to_string(&shard_file_path).unwrap(),
            Shard::default().to_string(),
        );

        assert_eq!(flatfs.disk_usage(), 0);
    }

    #[test]
    fn test_open_empty() {
        let dir = tempfile::tempdir().unwrap();

        {
            let _flatfs = Flatfs::with_shard(dir.path(), Shard::Prefix(2)).unwrap();
            let shard_file_path = dir.path().join("SHARDING");
            assert!(shard_file_path.exists());
            assert_eq!(
                fs::read_to_string(&shard_file_path).unwrap(),
                Shard::Prefix(2).to_string(),
            );
        }

        let _flatfs = Flatfs::with_shard(dir.path(), Shard::Prefix(2)).unwrap();
        assert!(Flatfs::new(dir.path()).is_err());
    }

    #[test]
    fn test_paths() {
        let dir = tempfile::tempdir().unwrap();
        let flatfs = Flatfs::new(dir.path()).unwrap();

        assert_eq!(flatfs.as_path("foobar"), dir.path().join("ba/foobar.data"),);

        assert_eq!(
            key_from_path(&dir.path().join("ba/foobar.data")).unwrap(),
            "foobar"
        );
    }

    #[test]
    fn test_put_get_disk_usage() {
        let dir = tempfile::tempdir().unwrap();
        let flatfs = Flatfs::new(dir.path()).unwrap();

        for i in 0..10 {
            flatfs.put(&format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(flatfs.disk_usage(), 10 * 128);

        for i in 0..10 {
            assert_eq!(flatfs.get(&format!("foo{i}")).unwrap(), [i; 128]);
            assert_eq!(flatfs.get_size(&format!("foo{i}")).unwrap(), 128);
        }

        drop(flatfs);

        // Reread for size
        let flatfs = Flatfs::new(dir.path()).unwrap();
        assert_eq!(flatfs.disk_usage(), 10 * 128);

        drop(flatfs);
        // Recalculate size
        fs::remove_file(dir.path().join(DISK_USAGE_CACHE)).unwrap();
        let flatfs = Flatfs::new(dir.path()).unwrap();
        assert_eq!(flatfs.disk_usage(), 10 * 128);
    }

    #[test]
    fn test_put_get_del() {
        let dir = tempfile::tempdir().unwrap();
        let flatfs = Flatfs::new(dir.path()).unwrap();

        for i in 0..10 {
            flatfs.put(&format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(flatfs.disk_usage(), 10 * 128);

        for i in 0..10 {
            assert_eq!(flatfs.get(&format!("foo{i}")).unwrap(), [i; 128]);
        }

        for i in 0..5 {
            flatfs.del(&format!("foo{i}")).unwrap();
        }

        assert_eq!(flatfs.disk_usage(), 5 * 128);

        for i in 0..10 {
            if i < 5 {
                assert!(flatfs.get(&format!("foo{i}")).is_err());
                assert!(flatfs.del(&format!("foo{i}")).is_err());
            } else {
                assert_eq!(flatfs.get(&format!("foo{i}")).unwrap(), [i; 128]);
            }
        }
    }

    #[test]
    fn test_iter() {
        let dir = tempfile::tempdir().unwrap();
        let flatfs = Flatfs::new(dir.path()).unwrap();

        for i in 0..10 {
            flatfs.put(&format!("foo{i}"), [i; 128]).unwrap();
        }

        assert_eq!(flatfs.disk_usage(), 10 * 128);

        for r in flatfs.iter() {
            let (key, value) = r.unwrap();
            let i: u8 = key.strip_prefix("foo").unwrap().parse().unwrap();
            assert_eq!(value, [i; 128]);
        }

        for r in flatfs.keys() {
            let key = r.unwrap();
            let i: u8 = key.strip_prefix("foo").unwrap().parse().unwrap();
            assert!(i < 10);
        }

        for r in flatfs.values() {
            let value = r.unwrap();
            assert_eq!(value.len(), 128);
        }
    }
}
