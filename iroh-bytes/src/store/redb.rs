//! redb backed storage

use std::{
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use futures::{future, FutureExt};

use iroh_base::hash::Hash;
use postcard::experimental::max_size::MaxSize;
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use self::bao_file::{BaoFileConfig, BaoFileWriter};

use super::Map;

mod bao_file;

const BLOBS_TABLE: TableDefinition<Hash, EntryData> = TableDefinition::new("blobs-0");

const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> = TableDefinition::new("inline-data-0");

const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-outboard-0");

#[derive(Debug, Serialize, Deserialize, MaxSize)]
enum EntryData {
    Partial,
    Complete { size: u64 },
}

impl redb::RedbValue for EntryData {
    type SelfType<'a> = EntryData;

    type AsBytes<'a> = [u8; Self::POSTCARD_MAX_SIZE];

    fn fixed_width() -> Option<usize> {
        Some(Self::POSTCARD_MAX_SIZE)
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        postcard::from_bytes(data).unwrap()
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'a,
        Self: 'b,
    {
        let mut buf = [0; Self::POSTCARD_MAX_SIZE];
        postcard::to_slice(value, &mut buf).unwrap();
        buf
    }

    fn type_name() -> redb::TypeName {
        redb::TypeName::new("EntryStatus")
    }
}

#[derive(Debug)]
struct Inner {
    redb: redb::Database,
    state: RwLock<State>,
    config: Config,
}

#[derive(Debug)]
struct Config {
    config: Arc<BaoFileConfig>,
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
    is_complete: Arc<AtomicBool>,
}

impl super::MapEntry<Store> for Entry {
    fn hash(&self) -> Hash {
        self.inner.hash().into()
    }

    fn size(&self) -> u64 {
        self.inner.current_size().unwrap()
    }

    fn is_complete(&self) -> bool {
        self.is_complete.load(Ordering::SeqCst)
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
    fn batch_writer(&self) -> future::BoxFuture<'_, io::Result<BaoFileWriter>> {
        async move { Ok(self.inner.writer()) }.boxed()
    }
}

impl super::Map for Store {
    type Outboard = bao_file::OutboardType;

    type DataReader = bao_file::DataReader;

    type Entry = Entry;

    fn get(&self, hash: &Hash) -> io::Result<Option<Entry>> {
        let mut state = self.inner.state.write().unwrap();
        let lru = state.lru.get(hash);
        if let Some(entry) = lru {
            return Ok(Some(entry.clone()));
        }
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let Some(entry) = blobs.get(hash).map_err(to_io_err)? else {
            return Ok(None);
        };
        let entry = entry.value();
        let hash = (*hash).into();
        let config = self.inner.config.config.clone();
        let inner = bao_file::BaoFileHandle::new(config, hash);
        let is_complete = match entry {
            EntryData::Complete { .. } => true,
            EntryData::Partial => false,
        };
        Ok(Some(Entry {
            inner,
            is_complete: AtomicBool::new(is_complete).into(),
        }))
    }
}

impl super::PartialMap for Store {
    type PartialEntry = Entry;

    type BatchWriter = BaoFileWriter;

    fn get_or_create_partial(&self, hash: Hash, _size: u64) -> io::Result<Entry> {
        let mut state = self.inner.state.write().unwrap();
        let lru = state.lru.get(&hash);
        if let Some(entry) = lru {
            return Ok(entry.clone());
        }
        let entry = Entry {
            inner: bao_file::BaoFileHandle::new(self.inner.config.config.clone(), hash.into()),
            is_complete: AtomicBool::new(false).into(),
        };
        Ok(entry)
    }

    fn entry_status(&self, hash: &Hash) -> io::Result<super::EntryStatus> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let Some(guard) = blobs.get(hash).map_err(to_io_err)? else {
            return Ok(crate::store::EntryStatus::NotFound);
        };
        Ok(match guard.value() {
            EntryData::Complete { .. } => crate::store::EntryStatus::Complete,
            EntryData::Partial => crate::store::EntryStatus::Partial,
        })
    }

    fn get_possibly_partial(&self, hash: &Hash) -> io::Result<super::PossiblyPartialEntry<Self>> {
        match self.get(hash)? {
            Some(entry) => Ok({
                if entry.is_complete.load(Ordering::SeqCst) {
                    super::PossiblyPartialEntry::Complete(entry)
                } else {
                    super::PossiblyPartialEntry::Partial(entry)
                }
            }),
            None => Ok(super::PossiblyPartialEntry::NotFound),
        }
    }

    fn insert_complete(&self, entry: Entry) -> future::BoxFuture<'_, io::Result<()>> {
        async move {
            let hash: Hash = entry.inner.hash().into();
            let size = entry.inner.current_size()?;
            let tx = self.inner.redb.begin_write().map_err(to_io_err)?;
            let mut blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
            blobs
                .insert(hash, EntryData::Complete { size })
                .map_err(to_io_err)?;
            drop(blobs);
            tx.commit().map_err(to_io_err)?;
            Ok(())
        }
        .boxed()
    }
}

fn to_io_err(e: impl Into<redb::Error>) -> io::Error {
    let e = e.into();
    match e {
        redb::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::Other, e),
    }
}
