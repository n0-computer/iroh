//! redb backed storage

use std::{
    io,
    sync::{Arc, RwLock},
};

use bao_tree::blake3;
use futures::{future, FutureExt};

use self::bao_file::BaoFileHandle;
use iroh_base::hash::Hash;
use redb::TableDefinition;

mod bao_file;

const BLOBS_TABLE: TableDefinition<&[u8; 32], EntryStatus> = TableDefinition::new("blobs-0");

const INLINE_DATA_TABLE: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("inline-data-0");

const INLINE_OUTBOARD_TABLE: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("inline-outboard-0");

#[derive(Debug)]
enum EntryStatus {
    Partial,
    Complete { size: u64 },
}

impl redb::RedbValue for EntryStatus {}

#[derive(Debug)]
struct Inner {
    redb: redb::Database,
    state: RwLock<State>,
}

#[derive(Debug)]
struct State {
    /// LRU cache of open bao files
    lru: lru::LruCache<Hash, Entry>,
}

#[derive(Debug, Clone)]
struct Store {
    inner: Arc<Inner>,
}

#[derive(Debug, Clone)]
struct Entry {
    inner: bao_file::BaoFileHandle,
    is_complete: bool,
}

impl super::MapEntry<Store> for Entry {
    fn hash(&self) -> blake3::Hash {
        self.inner.hash()
    }

    fn size(&self) -> u64 {
        self.inner.current_size().unwrap()
    }

    fn is_complete(&self) -> bool {
        self.is_complete
    }

    fn available_ranges(&self) -> future::BoxFuture<'_, io::Result<bao_tree::ChunkRanges>> {
        todo!()
    }

    fn outboard(&self) -> future::BoxFuture<'_, io::Result<bao_file::OutboardType>> {
        futures::future::ready(self.inner.outboard()).boxed()
    }

    fn data_reader(&self) -> future::BoxFuture<'_, io::Result<bao_file::DataReader>> {
        futures::future::ok(self.inner.data_reader()).boxed()
    }
}

impl super::Map for Store {
    type Outboard = bao_file::OutboardType;

    type DataReader = bao_file::DataReader;

    type Entry = Entry;

    fn get(&self, hash: &Hash) -> Option<Self::Entry> {
        let state = self.inner.state.write().unwrap();
        let lru = state.lru.get(hash);
        if let Some(entry) = lru {
            return Some(entry.clone());
        }
        let tx = self.inner.redb.begin_read().unwrap();

        // check the cache
        // check redb if the entry is complete
        // if so, either load in mem or open the file readonly and put in the cache
        // if not, open readwrite and put in the cache
        todo!()
    }
}

impl super::PartialMap for Store {
    type OutboardMut = bao_file::OutboardMutType;

    type DataWriter;

    type PartialEntry;

    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Self::PartialEntry> {
        todo!()
    }

    fn entry_status(&self, hash: &Hash) -> super::EntryStatus {
        todo!()
    }

    fn get_possibly_partial(&self, hash: &Hash) -> super::PossiblyPartialEntry<Self> {
        todo!()
    }

    fn insert_complete(&self, entry: Self::PartialEntry) -> future::BoxFuture<'_, io::Result<()>> {
        todo!()
    }
}
