//! redb backed storage

use std::{
    collections::BTreeSet,
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use bao_tree::io::fsm::Outboard;
use futures::{future, FutureExt};

use iroh_base::hash::{Hash, HashAndFormat};
use iroh_io::AsyncSliceReader;
use postcard::experimental::max_size::MaxSize;
use redb::{ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{util::LivenessTracker, Tag, TempTag};

use super::{
    bao_file::{self, BaoFileConfig, BaoFileWriter},
    BaoBatchWriter, ReadableStore, TempCounterMap,
};

use super::{BaoBlobSize, Map};

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

impl LivenessTracker for Inner {
    fn on_clone(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tagging: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.inc(inner);
    }

    fn on_drop(&self, inner: &HashAndFormat) {
        tracing::trace!("temp tag drop: {:?}", inner);
        let mut state = self.state.write().unwrap();
        state.temp.dec(inner);
    }
}

#[derive(Debug)]
struct Config {
    config: Arc<BaoFileConfig>,
}

#[derive(Debug)]
struct State {
    /// LRU cache of open bao files
    lru: lru::LruCache<Hash, Entry>,
    temp: TempCounterMap,
    live: BTreeSet<Hash>,
}

///
#[derive(Debug, Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

impl Store {
    ///
    pub async fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let redb = redb::Database::open(path)?;
        let config = Config {
            config: Arc::new(todo!()),
        };
        let state = State {
            lru: lru::LruCache::new(1024.try_into().unwrap()),
            temp: Default::default(),
            live: Default::default(),
        };
        let inner = Inner {
            redb,
            state: RwLock::new(state),
            config,
        };
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl ReadableStore for Store {
    fn blobs(&self) -> io::Result<super::DbIter<Hash>> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let mut res = blobs
            .iter()
            .map_err(to_io_err)?
            .filter_map(|r| {
                let (hash, entry) = match r {
                    Ok((k, v)) => (k, v),
                    Err(e) => return Some(Err(to_io_err(e))),
                };
                let hash = hash.value();
                let entry = entry.value();
                if let EntryData::Complete { .. } = entry {
                    Some(Ok(hash))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(Box::new(res.into_iter()))
    }

    fn partial_blobs(&self) -> io::Result<super::DbIter<Hash>> {
        let tx = self.inner.redb.begin_read().map_err(to_io_err)?;
        let blobs = tx.open_table(BLOBS_TABLE).map_err(to_io_err)?;
        let mut res = blobs
            .iter()
            .map_err(to_io_err)?
            .filter_map(|r| {
                let (hash, entry) = match r {
                    Ok((k, v)) => (k, v),
                    Err(e) => return Some(Err(to_io_err(e))),
                };
                let hash = hash.value();
                let entry = entry.value();
                if let EntryData::Partial { .. } = entry {
                    Some(Ok(hash))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(Box::new(res.into_iter()))
    }

    fn tags(&self) -> io::Result<super::DbIter<(crate::Tag, iroh_base::hash::HashAndFormat)>> {
        todo!()
    }

    fn temp_tags(
        &self,
    ) -> Box<dyn Iterator<Item = iroh_base::hash::HashAndFormat> + Send + Sync + 'static> {
        let tags = self.inner.state.read().unwrap().temp.keys();
        Box::new(tags)
    }

    async fn validate(
        &self,
        _tx: tokio::sync::mpsc::Sender<super::ValidateProgress>,
    ) -> io::Result<()> {
        todo!()
    }

    async fn export(
        &self,
        hash: Hash,
        target: std::path::PathBuf,
        mode: super::ExportMode,
        progress: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> io::Result<()> {
        todo!()
    }
}

impl super::Store for Store {
    async fn import_file(
        &self,
        data: std::path::PathBuf,
        mode: super::ImportMode,
        format: iroh_base::hash::BlobFormat,
        progress: impl crate::util::progress::ProgressSender<Msg = super::ImportProgress>
            + crate::util::progress::IdGenerator,
    ) -> io::Result<(crate::TempTag, u64)> {
        todo!()
    }

    async fn import_bytes(
        &self,
        bytes: bytes::Bytes,
        format: iroh_base::hash::BlobFormat,
    ) -> io::Result<crate::TempTag> {
        todo!()
    }

    async fn import_stream(
        &self,
        data: impl futures::prelude::Stream<Item = io::Result<bytes::Bytes>> + Send + Unpin + 'static,
        format: iroh_base::hash::BlobFormat,
        progress: impl crate::util::progress::ProgressSender<Msg = super::ImportProgress>
            + crate::util::progress::IdGenerator,
    ) -> io::Result<(crate::TempTag, u64)> {
        todo!()
    }

    async fn set_tag(&self, name: crate::Tag, hash: Option<HashAndFormat>) -> io::Result<()> {
        todo!()
    }

    async fn create_tag(&self, hash: HashAndFormat) -> io::Result<Tag> {
        todo!()
    }

    fn temp_tag(&self, content: HashAndFormat) -> TempTag {
        TempTag::new(content, Some(self.inner.clone()))
    }

    fn clear_live(&self) {
        let mut state = self.inner.state.write().unwrap();
        state.live.clear();
    }

    fn add_live(&self, elements: impl IntoIterator<Item = Hash>) {
        let mut state = self.inner.state.write().unwrap();
        state.live.extend(elements);
    }

    fn is_live(&self, hash: &Hash) -> bool {
        let state = self.inner.state.read().unwrap();
        // a blob is live if it is either in the live set, or it is temp tagged
        state.live.contains(hash) || state.temp.contains(hash)
    }

    async fn delete(&self, hashes: Vec<Hash>) -> io::Result<()> {
        todo!()
    }
}

///
#[derive(Debug, Clone)]
pub struct Entry {
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

    async fn available_ranges(&self) -> io::Result<bao_tree::ChunkRanges> {
        todo!()
    }

    async fn outboard(&self) -> io::Result<impl Outboard> {
        self.inner.outboard()
    }

    async fn data_reader(&self) -> io::Result<impl AsyncSliceReader> {
        Ok(self.inner.data_reader())
    }
}

impl super::MapEntryMut for Entry {
    async fn batch_writer(&self) -> io::Result<impl BaoBatchWriter> {
        Ok(self.inner.writer())
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

    async fn insert_complete(&self, entry: Entry) -> io::Result<()> {
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
}

fn to_io_err(e: impl Into<redb::Error>) -> io::Error {
    let e = e.into();
    match e {
        redb::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::Other, e),
    }
}
