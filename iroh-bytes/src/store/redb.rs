//! redb backed storage

use std::{
    io,
    sync::{Arc, RwLock},
};

use futures::{future, FutureExt};

use iroh_base::hash::Hash;
use redb::TableDefinition;

use super::BaoBatchWriter;

mod bao_file;

const BLOBS_TABLE: TableDefinition<Hash, EntryStatus> = TableDefinition::new("blobs-0");

const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> = TableDefinition::new("inline-data-0");

const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-outboard-0");

#[derive(Debug)]
enum EntryStatus {
    Partial,
    Complete { size: u64 },
}

impl redb::RedbValue for EntryStatus {
    type SelfType<'a> = EntryStatus;

    type AsBytes<'a> = [u8; 9];

    fn fixed_width() -> Option<usize> {
        Some(9)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        todo!()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        todo!()
    }

    fn type_name() -> redb::TypeName {
        todo!()
    }
}

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
    fn hash(&self) -> Hash {
        self.inner.hash().into()
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

impl super::PartialMapEntry<Store> for Entry {
    fn batch_writer(&self) -> future::BoxFuture<'_, io::Result<BaoFileBatchWriter>> {
        todo!()
    }
}

impl super::Map for Store {
    type Outboard = bao_file::OutboardType;

    type DataReader = bao_file::DataReader;

    type Entry = Entry;

    fn get(&self, hash: &Hash) -> io::Result<Option<Self::Entry>> {
        let mut state = self.inner.state.write().unwrap();
        let lru = state.lru.get(hash);
        if let Some(entry) = lru {
            return Ok(Some(entry.clone()));
        }
        let tx = self.inner.redb.begin_read().unwrap();

        // check the cache
        // check redb if the entry is complete
        // if so, either load in mem or open the file readonly and put in the cache
        // if not, open readwrite and put in the cache
        todo!()
    }
}

#[derive(Debug)]
#[repr(transparent)]
struct BaoFileBatchWriter(bao_file::BaoFileWriter);

impl BaoBatchWriter for BaoFileBatchWriter {
    fn write_batch(
        &mut self,
        size: u64,
        batch: Vec<bao_tree::io::fsm::BaoContentItem>,
    ) -> future::LocalBoxFuture<'_, io::Result<()>> {
        self.0.write_batch(size, batch).boxed_local()
    }

    fn sync(&mut self) -> future::LocalBoxFuture<'_, io::Result<()>> {
        self.0.sync().boxed_local()
    }
}

impl super::PartialMap for Store {
    type PartialEntry = Entry;

    type BatchWriter = BaoFileBatchWriter;

    fn get_or_create_partial(&self, hash: Hash, size: u64) -> io::Result<Self::PartialEntry> {
        todo!()
    }

    fn entry_status(&self, hash: &Hash) -> io::Result<super::EntryStatus> {
        todo!()
    }

    fn get_possibly_partial(&self, hash: &Hash) -> io::Result<super::PossiblyPartialEntry<Self>> {
        todo!()
    }

    fn insert_complete(&self, entry: Self::PartialEntry) -> future::BoxFuture<'_, io::Result<()>> {
        todo!()
    }
}
