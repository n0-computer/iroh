#![allow(missing_docs)]
//! Quick-and-dirty writable database
//!
//! I wrote this while diving into iroh-bytes, wildly copying code around. This will be solved much
//! nicer with the upcoming generic writable database branch by @rklaehn.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use bytes::Bytes;
use iroh_io::{AsyncSliceWriter, File};
use range_collections::RangeSet2;
use tokio::io::AsyncRead;

use iroh_bytes::{
    get::fsm,
    protocol::{GetRequest, RangeSpecSeq, Request},
    Hash,
};

use crate::database::flat::{create_collection, DataSource, Database, DbEntry, FNAME_PATHS};

/// A blob database into which new blobs can be inserted.
///
/// Blobs can be inserted either from bytes or by downloading from open connections to peers.
/// New blobs will be saved as files with a filename based on their hash.
///
/// TODO: Replace with the generic writable database.
#[derive(Debug, Clone)]
pub struct WritableFileDatabase {
    db: Database,
    storage: Arc<StoragePaths>,
}

impl WritableFileDatabase {
    pub async fn new(data_path: PathBuf) -> anyhow::Result<Self> {
        let storage = Arc::new(StoragePaths::new(data_path).await?);
        let db = if storage.db_path.join(FNAME_PATHS).exists() {
            Database::load(&storage.db_path).await.with_context(|| {
                format!(
                    "Failed to load iroh database from {}",
                    storage.db_path.display()
                )
            })?
        } else {
            Database::default()
        };
        Ok(Self { db, storage })
    }

    pub fn db(&self) -> &Database {
        &self.db
    }

    pub async fn save(&self) -> anyhow::Result<()> {
        self.db.save(&self.storage.db_path).await?;
        Ok(())
    }

    pub async fn put_bytes(&self, data: Bytes) -> anyhow::Result<(Hash, u64)> {
        let (hash, size, entry) = self.storage.put_bytes(data).await?;
        self.db.union_with(HashMap::from_iter([(hash, entry)]));
        Ok((hash, size))
    }

    pub async fn put_reader(&self, data: impl AsyncRead + Unpin) -> anyhow::Result<(Hash, u64)> {
        let (hash, size, entry) = self.storage.put_reader(data).await?;
        self.db.union_with(HashMap::from_iter([(hash, entry)]));
        Ok((hash, size))
    }

    pub async fn get_size(&self, hash: &Hash) -> Option<u64> {
        Some(self.db.get(hash)?.size().await)
    }

    pub fn has(&self, hash: &Hash) -> bool {
        self.db.to_inner().contains_key(hash)
    }
    pub async fn download_single(
        &self,
        conn: quinn::Connection,
        hash: Hash,
    ) -> anyhow::Result<Option<(Hash, u64)>> {
        // 1. Download to temp file
        let temp_path = {
            let temp_path = self.storage.temp_path();
            let request =
                Request::Get(GetRequest::new(hash, RangeSpecSeq::new([RangeSet2::all()])));
            let response = fsm::start(conn, request);
            let connected = response.next().await?;

            let fsm::ConnectedNext::StartRoot(curr) = connected.next().await? else {
                return Ok(None)
            };
            let header = curr.next();

            let path = temp_path.clone();
            let mut data_file = File::create(move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(path)
            })
            .await
            .context("failed to create local tempfile")?;

            let (curr, _size) = header.next().await.context("failed to read blob content")?;
            let _curr = curr
                .write_all(&mut data_file)
                .await
                .context("failed to write blob content to tempfile")?;
            // Flush the data file first, it is the only thing that matters at this point
            data_file.sync().await.context("fsync failed")?;
            temp_path
        };

        // 2. Insert into database
        let (hash, size, entry) = self
            .storage
            .move_to_blobs(&temp_path)
            .await
            .context("failed to move to blobs dir")?;
        let entries = HashMap::from_iter([(hash, entry)]);
        self.db.union_with(entries);
        Ok(Some((hash, size)))
    }
}

#[derive(Debug)]
pub struct StoragePaths {
    blob_path: PathBuf,
    temp_path: PathBuf,
    db_path: PathBuf,
}

impl StoragePaths {
    pub async fn new(data_path: PathBuf) -> anyhow::Result<Self> {
        let blob_path = data_path.join("blobs");
        let temp_path = data_path.join("temp");
        let db_path = data_path.join("db");
        tokio::fs::create_dir_all(&blob_path).await?;
        tokio::fs::create_dir_all(&temp_path).await?;
        tokio::fs::create_dir_all(&db_path).await?;
        Ok(Self {
            blob_path,
            temp_path,
            db_path,
        })
    }

    pub async fn put_bytes(&self, data: Bytes) -> anyhow::Result<(Hash, u64, DbEntry)> {
        let temp_path = self.temp_path();
        tokio::fs::write(&temp_path, &data).await?;
        let (hash, size, entry) = self.move_to_blobs(&temp_path).await?;
        Ok((hash, size, entry))
    }

    pub async fn put_reader(
        &self,
        mut reader: impl AsyncRead + Unpin,
    ) -> anyhow::Result<(Hash, u64, DbEntry)> {
        let temp_path = self.temp_path();
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(&temp_path)
            .await?;
        tokio::io::copy(&mut reader, &mut file).await?;
        let (hash, size, entry) = self.move_to_blobs(&temp_path).await?;
        Ok((hash, size, entry))
    }

    async fn move_to_blobs(&self, path: &PathBuf) -> anyhow::Result<(Hash, u64, DbEntry)> {
        let datasource = DataSource::new(path.clone());
        // TODO: this needlessly creates a collection, but that's what's pub atm in iroh-bytes
        let (db, _collection_hash) = create_collection(vec![datasource]).await?;
        // the actual blob is the first entry in the external entries in the created collection
        let (hash, _path, _len) = db.external().next().unwrap();
        let Some(DbEntry::External { outboard, size, .. }) = db.get(&hash) else {
            unreachable!("just inserted");
        };

        let final_path = prepare_hash_dir(&self.blob_path, &hash).await?;
        tokio::fs::rename(&path, &final_path).await?;
        let entry = DbEntry::External {
            outboard,
            path: final_path,
            size,
        };
        Ok((hash, size, entry))
    }

    fn temp_path(&self) -> PathBuf {
        let name = hex::encode(rand::random::<u64>().to_be_bytes());
        self.temp_path.join(name)
    }
}

async fn prepare_hash_dir(path: &Path, hash: &Hash) -> anyhow::Result<PathBuf> {
    let hash = hex::encode(hash.as_ref());
    let path = path.join(&hash[0..2]).join(&hash[2..4]).join(&hash[4..]);
    tokio::fs::create_dir_all(path.parent().unwrap()).await?;
    Ok(path)
}
