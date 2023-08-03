//! An in memory implementation of [BaoMap] and [BaoReadonlyDb], useful for
//! testing and short lived nodes.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use bao_tree::blake3;
use bao_tree::io::fsm::Outboard;
use bao_tree::io::outboard::PreOrderMemOutboard;
use bytes::Bytes;
use futures::future::{self, BoxFuture};
use futures::FutureExt;
use iroh_bytes::provider::ValidateProgress;
use iroh_bytes::provider::{BaoMap, BaoMapEntry, BaoReadonlyDb};
use iroh_bytes::{Hash, IROH_BLOCK_SIZE};
use tokio::sync::mpsc;

/// An in memory database for iroh-bytes.
#[derive(Debug, Clone, Default)]
pub struct Database(Arc<HashMap<Hash, (PreOrderMemOutboard, Bytes)>>);

impl Database {
    /// Create a new [Database] from a sequence of entries.
    ///
    /// Returns the database and a map of names to computed blake3 hashes.
    /// In case of duplicate names, the last entry is used.
    pub fn new(
        entries: impl IntoIterator<Item = (impl Into<String>, impl AsRef<[u8]>)>,
    ) -> (Self, BTreeMap<String, blake3::Hash>) {
        let mut names = BTreeMap::new();
        let mut res = HashMap::new();
        for (name, data) in entries.into_iter() {
            let name = name.into();
            let data: &[u8] = data.as_ref();
            // compute the outboard
            let (outboard, hash) = bao_tree::io::outboard(data, IROH_BLOCK_SIZE);
            // add the name, this assumes that names are unique
            names.insert(name, hash);
            // wrap into the right types
            let outboard =
                PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, outboard.into()).unwrap();
            let data = Bytes::from(data.to_vec());
            let hash = Hash::from(hash);
            res.insert(hash, (outboard, data));
        }
        (Self(Arc::new(res)), names)
    }

    /// Insert a new entry into the database, and return the hash of the entry.
    pub fn insert(&mut self, data: impl AsRef<[u8]>) -> Hash {
        let inner = Arc::make_mut(&mut self.0);
        let data: &[u8] = data.as_ref();
        // compute the outboard
        let (outboard, hash) = bao_tree::io::outboard(data, IROH_BLOCK_SIZE);
        // wrap into the right types
        let outboard = PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, outboard.into()).unwrap();
        let data = Bytes::from(data.to_vec());
        let hash = Hash::from(hash);
        inner.insert(hash, (outboard, data));
        hash
    }

    /// Get the bytes associated with a hash, if they exist.
    pub fn get(&self, hash: &Hash) -> Option<Bytes> {
        let entry = self.0.get(hash)?;
        Some(entry.1.clone())
    }
}

/// The [BaoMapEntry] implementation for [Database].
#[derive(Debug, Clone)]
pub struct DbEntry {
    outboard: PreOrderMemOutboard<Bytes>,
    data: Bytes,
}

impl BaoMapEntry<Database> for DbEntry {
    fn hash(&self) -> blake3::Hash {
        self.outboard.root()
    }

    fn outboard(&self) -> BoxFuture<'_, io::Result<PreOrderMemOutboard<Bytes>>> {
        futures::future::ok(self.outboard.clone()).boxed()
    }

    fn data_reader(&self) -> BoxFuture<'_, io::Result<Bytes>> {
        futures::future::ok(self.data.clone()).boxed()
    }
}

impl BaoMap for Database {
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Bytes;
    type Entry = DbEntry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let (o, d) = self.0.get(hash)?;
        Some(DbEntry {
            outboard: o.clone(),
            data: d.clone(),
        })
    }
}

impl BaoReadonlyDb for Database {
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(self.0.keys().cloned().collect::<Vec<_>>().into_iter())
    }

    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static> {
        Box::new(std::iter::empty())
    }

    fn validate(
        &self,
        _tx: mpsc::Sender<ValidateProgress>,
    ) -> BoxFuture<'static, anyhow::Result<()>> {
        future::ok(()).boxed()
    }
}
