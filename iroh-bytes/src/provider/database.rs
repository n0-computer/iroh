//! The database used by the iroh node.
//!
//! Databases are key value stores that store data and associated outboard data
//! for blake3 hashes, in addition to some metadata.
use crate::{
    provider::ValidateProgress,
    Hash,
};
use bao_tree::{io::fsm::Outboard, io::outboard::PreOrderMemOutboard};
use bytes::Bytes;
use futures::{
    future::{self, BoxFuture},
    FutureExt,
};
use iroh_io::AsyncSliceReader;
use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::Arc,
};
use tokio::sync::mpsc;

/// An in memory implementation of [BaoMap] and [BaoReadonlyDb], useful for
/// testing and short lived nodes.
#[derive(Debug, Clone, Default)]
pub struct InMemDatabase(Arc<HashMap<Hash, (PreOrderMemOutboard, Bytes)>>);

impl InMemDatabase {
    /// Create a new [InMemDatabase] from a sequence of entries.
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
            let (outboard, hash) = bao_tree::io::outboard(data, crate::IROH_BLOCK_SIZE);
            // add the name, this assumes that names are unique
            names.insert(name, hash);
            // wrap into the right types
            let outboard =
                PreOrderMemOutboard::new(hash, crate::IROH_BLOCK_SIZE, outboard.into()).unwrap();
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
        let (outboard, hash) = bao_tree::io::outboard(data, crate::IROH_BLOCK_SIZE);
        // wrap into the right types
        let outboard =
            PreOrderMemOutboard::new(hash, crate::IROH_BLOCK_SIZE, outboard.into()).unwrap();
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

/// The [BaoMapEntry] implementation for [InMemDatabase].
#[derive(Debug, Clone)]
pub struct InMemDatabaseEntry {
    outboard: PreOrderMemOutboard<Bytes>,
    data: Bytes,
}

impl BaoMapEntry<InMemDatabase> for InMemDatabaseEntry {
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

impl BaoMap for InMemDatabase {
    type Outboard = PreOrderMemOutboard<Bytes>;
    type DataReader = Bytes;
    type Entry = InMemDatabaseEntry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let (o, d) = self.0.get(hash)?;
        Some(InMemDatabaseEntry {
            outboard: o.clone(),
            data: d.clone(),
        })
    }
}

impl BaoReadonlyDb for InMemDatabase {
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

/// An entry for one hash in a bao collection
///
/// The entry has the ability to provide you with an (outboard, data)
/// reader pair. Creating the reader is async and may fail. The futures that
/// create the readers must be `Send`, but the readers themselves don't have to
/// be.
pub trait BaoMapEntry<D: BaoMap>: Clone + Send + Sync + 'static {
    /// The hash of the entry
    fn hash(&self) -> blake3::Hash;
    /// A future that resolves to a reader that can be used to read the outboard
    fn outboard(&self) -> BoxFuture<'_, io::Result<D::Outboard>>;
    /// A future that resolves to a reader that can be used to read the data
    fn data_reader(&self) -> BoxFuture<'_, io::Result<D::DataReader>>;
}

/// A generic collection of blobs with precomputed outboards
pub trait BaoMap: Clone + Send + Sync + 'static {
    /// The outboard type. This can be an in memory outboard or an outboard that
    /// retrieves the data asynchronously from a remote database.
    type Outboard: bao_tree::io::fsm::Outboard;
    /// The reader type.
    type DataReader: AsyncSliceReader;
    /// The entry type. An entry is a cheaply cloneable handle that can be used
    /// to open readers for both the data and the outboard
    type Entry: BaoMapEntry<Self>;
    /// Get an entry for a hash.
    ///
    /// This can also be used for a membership test by just checking if there
    /// is an entry. Creating an entry should be cheap, any expensive ops should
    /// be deferred to the creation of the actual readers.
    fn get(&self, hash: &Hash) -> Option<Self::Entry>;
}

/// Extension of BaoMap to add misc methods used by the rpc calls
pub trait BaoReadonlyDb: BaoMap {
    /// list all blobs in the database. This should include collections, since
    /// collections are blobs and can be requested as blobs.
    fn blobs(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;
    /// list all roots (collections or other explicitly added things) in the database
    fn roots(&self) -> Box<dyn Iterator<Item = Hash> + Send + Sync + 'static>;
    /// Validate the database
    fn validate(&self, tx: mpsc::Sender<ValidateProgress>) -> BoxFuture<'_, anyhow::Result<()>>;
}
