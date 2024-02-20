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

use super::{BaoBlobSize, Map};

mod bao_file;

mod mem {
    use bao_tree::{io::outboard::PreOrderOutboard, BaoTree, ByteNum, ChunkRanges};
    use bytes::Bytes;
    use iroh_base::hash::Hash;
    use iroh_io::AsyncSliceReader;
    use std::{
        collections::BTreeMap,
        io,
        sync::{Arc, RwLock},
    };

    use crate::{
        store::{BaoBlobSize, MapEntry, MapEntryMut, ReadableStore},
        IROH_BLOCK_SIZE,
    };

    use super::bao_file;

    #[derive(Debug, Clone)]
    struct Store {
        inner: Arc<RwLock<StateInner>>,
    }

    #[derive(Debug)]
    struct StateInner {
        entries: BTreeMap<Hash, Entry>,
    }

    #[derive(Debug, Clone)]
    struct Entry {
        inner: Arc<EntryInner>,
        complete: bool,
    }

    #[derive(Debug)]
    struct EntryInner {
        hash: Hash,
        data: RwLock<bao_file::MutableMemStorage>,
    }

    impl MapEntry for Entry {
        fn hash(&self) -> Hash {
            self.inner.hash
        }

        fn size(&self) -> BaoBlobSize {
            let size = self.inner.data.read().unwrap().current_size();
            BaoBlobSize::new(size, self.complete)
        }

        fn is_complete(&self) -> bool {
            self.complete
        }

        async fn available_ranges(&self) -> io::Result<bao_tree::ChunkRanges> {
            Ok(ChunkRanges::all())
        }

        async fn outboard(&self) -> io::Result<PreOrderOutboard<OutboardReader>> {
            let size = self.inner.data.read().unwrap().current_size();
            Ok(PreOrderOutboard {
                root: self.hash().into(),
                tree: BaoTree::new(ByteNum(size), IROH_BLOCK_SIZE),
                data: OutboardReader(self.inner.clone()),
            })
        }

        async fn data_reader(&self) -> io::Result<DataReader> {
            Ok(DataReader(self.inner.clone()))
        }
    }

    impl MapEntryMut for Entry {
        async fn batch_writer(&self) -> io::Result<BatchWriter> {
            Ok(BatchWriter(self.inner.clone()))
        }
    }

    struct DataReader(Arc<EntryInner>);

    impl AsyncSliceReader for DataReader {
        async fn read_at(&mut self, offset: u64, len: usize) -> std::io::Result<Bytes> {
            Ok(self.0.data.read().unwrap().read_data_at(offset, len))
        }

        async fn len(&mut self) -> std::io::Result<u64> {
            Ok(self.0.data.read().unwrap().data_len())
        }
    }

    struct OutboardReader(Arc<EntryInner>);

    impl AsyncSliceReader for OutboardReader {
        async fn read_at(&mut self, offset: u64, len: usize) -> std::io::Result<Bytes> {
            Ok(self.0.data.read().unwrap().read_outboard_at(offset, len))
        }

        async fn len(&mut self) -> std::io::Result<u64> {
            Ok(self.0.data.read().unwrap().outboard_len())
        }
    }

    struct BatchWriter(Arc<EntryInner>);

    impl crate::store::BaoBatchWriter for BatchWriter {
        async fn write_batch(
            &mut self,
            size: u64,
            batch: Vec<bao_tree::io::fsm::BaoContentItem>,
        ) -> io::Result<()> {
            self.0.data.write().unwrap().write_batch(size, &batch)?;
            Ok(())
        }

        async fn sync(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::store::Map for Store {
        type Entry = Entry;

        fn get(&self, hash: &Hash) -> std::io::Result<Option<Self::Entry>> {
            Ok(self
                .inner
                .read()
                .unwrap()
                .entries
                .get(hash)
                .map(|e| e.clone()))
        }
    }

    impl crate::store::MapMut for Store {
        type EntryMut = Entry;

        fn get_or_create_partial(&self, hash: Hash, _size: u64) -> std::io::Result<Entry> {
            let entry = Entry {
                inner: Arc::new(EntryInner {
                    hash,
                    data: RwLock::new(bao_file::MutableMemStorage::default()),
                }),
                complete: false,
            };
            Ok(entry)
        }

        fn entry_status(&self, hash: &Hash) -> std::io::Result<crate::store::EntryStatus> {
            Ok(match self.inner.read().unwrap().entries.get(hash) {
                Some(entry) => {
                    if entry.complete {
                        crate::store::EntryStatus::Complete
                    } else {
                        crate::store::EntryStatus::Partial
                    }
                }
                None => crate::store::EntryStatus::NotFound,
            })
        }

        fn get_possibly_partial(
            &self,
            hash: &Hash,
        ) -> std::io::Result<crate::store::PossiblyPartialEntry<Self>> {
            Ok(match self.inner.read().unwrap().entries.get(hash) {
                Some(entry) => {
                    let entry = entry.clone();
                    if entry.complete {
                        crate::store::PossiblyPartialEntry::Complete(entry)
                    } else {
                        crate::store::PossiblyPartialEntry::Partial(entry)
                    }
                }
                None => crate::store::PossiblyPartialEntry::NotFound,
            })
        }

        async fn insert_complete(&self, mut entry: Entry) -> std::io::Result<()> {
            let hash = entry.hash();
            let mut inner = self.inner.write().unwrap();
            let complete = inner
                .entries
                .get(&hash)
                .map(|x| x.complete)
                .unwrap_or_default();
            if complete {
                entry.complete = true;
                inner.entries.insert(hash, entry);
            }
            Ok(())
        }
    }

    impl ReadableStore for Store {
        fn blobs(&self) -> io::Result<crate::store::DbIter<Hash>> {
            let entries = self.inner.read().unwrap().entries.clone();
            Ok(Box::new(
                entries
                    .into_values()
                    .filter(|x| x.complete)
                    .map(|x| Ok(x.hash())),
            ))
        }

        fn partial_blobs(&self) -> io::Result<crate::store::DbIter<Hash>> {
            let entries = self.inner.read().unwrap().entries.clone();
            Ok(Box::new(
                entries
                    .into_values()
                    .filter(|x| !x.complete)
                    .map(|x| Ok(x.hash())),
            ))
        }

        fn tags(
            &self,
        ) -> io::Result<crate::store::DbIter<(crate::Tag, iroh_base::hash::HashAndFormat)>>
        {
            todo!()
        }

        fn temp_tags(
            &self,
        ) -> Box<dyn Iterator<Item = iroh_base::hash::HashAndFormat> + Send + Sync + 'static>
        {
            todo!()
        }

        async fn validate(
            &self,
            tx: tokio::sync::mpsc::Sender<crate::store::ValidateProgress>,
        ) -> io::Result<()> {
            todo!()
        }

        async fn export(
            &self,
            hash: Hash,
            target: std::path::PathBuf,
            mode: crate::store::ExportMode,
            progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
        ) -> io::Result<()> {
            todo!()
        }
    }
}

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

impl super::MapEntry for Entry {
    fn hash(&self) -> Hash {
        self.inner.hash().into()
    }

    fn size(&self) -> BaoBlobSize {
        let size = self.inner.current_size().unwrap();
        BaoBlobSize::new(size, self.is_complete())
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

impl super::MapEntryMut for Entry {
    fn batch_writer(&self) -> future::BoxFuture<'_, io::Result<BaoFileWriter>> {
        async move { Ok(self.inner.writer()) }.boxed()
    }
}

impl super::Map for Store {
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

impl super::MapMut for Store {
    type EntryMut = Entry;

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
