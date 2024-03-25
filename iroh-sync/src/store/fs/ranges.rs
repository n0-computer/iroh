//! Ranges on [`redb`] tables
//!
//! Because the [`redb`] types all contain references, this uses [`ouroboros`] to create
//! self-referential structs so that we can embed the [`Range`] iterator together with the
//! [`ReadableTable`] and the [`ReadTransaction`] in a struct for our iterators returned from the
//! store.

use std::{fmt, sync::Arc};

use redb::{
    Database, Key as RedbKey, Range, ReadOnlyTable, ReadTransaction, ReadableTable, StorageError,
    TableError, Value as RedbValue,
};

use crate::{store::SortDirection, SignedEntry};

use super::{
    bounds::{ByKeyBounds, RecordsBounds},
    into_entry, RecordsByKeyId, RecordsId, RecordsValue, RECORDS_BY_KEY_TABLE, RECORDS_TABLE,
};

/// A [`ReadTransaction`] with a [`ReadOnlyTable`] that can be stored in a struct.
///
/// This uses [`ouroboros::self_referencing`] to store a [`ReadTransaction`] and a [`ReadOnlyTable`]
/// with self-referencing.
pub struct TableReader<K: RedbKey + 'static, V: redb::Value + 'static> {
    read_tx: ReadTransaction,
    table: ReadOnlyTable<K, V>,
}

impl<'a, K: RedbKey + 'static, V: RedbValue + 'static> TableReader<K, V> {
    /// Create a new [`TableReader`]
    pub fn new(
        db: &'a Arc<Database>,
        table_fn: impl FnOnce(&ReadTransaction) -> Result<ReadOnlyTable<K, V>, TableError>,
    ) -> anyhow::Result<Self> {
        let read_tx = db.begin_read()?;
        let table = table_fn(&read_tx).map_err(anyhow::Error::from)?;
        Ok(Self { read_tx, table })
    }

    /// Get a reference to the [`ReadOnlyTable`];
    pub fn table(&self) -> &ReadOnlyTable<K, V> {
        &self.table
    }
}

impl<K: RedbKey + 'static, V: redb::Value + 'static> fmt::Debug for TableReader<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableReader({:?})", self.table())
    }
}

/// A range reader for a [`ReadOnlyTable`] that can be stored in a struct.
///
/// This uses [`ouroboros::self_referencing`] to store a [`ReadTransaction`], a [`ReadOnlyTable`]
/// and a [`Range`] together. Useful to build iterators with.
pub struct TableRange<K: RedbKey + 'static, V: redb::Value + 'static> {
    read_tx: ReadTransaction,
    table: ReadOnlyTable<K, V>,
    range: Range<'static, K, V>,
}

impl<K: RedbKey + 'static, V: RedbValue + 'static> TableRange<K, V> {
    /// Create a new [`TableReader`]
    pub fn new<TF, RF>(db: &Arc<Database>, table_fn: TF, range_fn: RF) -> anyhow::Result<Self>
    where
        TF: FnOnce(&ReadTransaction) -> Result<ReadOnlyTable<K, V>, TableError>,
        RF: FnOnce(&ReadOnlyTable<K, V>) -> Result<Range<'static, K, V>, StorageError>,
    {
        let read_tx = db.begin_read()?;
        let table = table_fn(&read_tx).map_err(anyhow_err)?;
        let range = range_fn(&table).map_err(anyhow_err)?;
        Ok(Self {
            read_tx,
            table,
            range,
        })
    }

    /// Get a reference to the [`ReadOnlyTable`];
    pub fn table(&self) -> &ReadOnlyTable<K, V> {
        &self.table
    }

    pub fn next_mapped<T>(
        &mut self,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.range
            .next()
            .map(|r| r.map_err(Into::into).map(|r| map(r.0.value(), r.1.value())))
    }

    pub fn next_filtered<T>(
        &mut self,
        direction: &SortDirection,
        filter: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> bool,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        loop {
            let next = match direction {
                SortDirection::Asc => self.range.next(),
                SortDirection::Desc => self.range.next_back(),
            };
            match next {
                None => break None,
                Some(Err(err)) => break Some(Err(err.into())),
                Some(Ok(res)) => match filter(res.0.value(), res.1.value()) {
                    false => continue,
                    true => break Some(Ok(map(res.0.value(), res.1.value()))),
                },
            }
        }
    }
}

impl<K: RedbKey + 'static, V: redb::Value + 'static> fmt::Debug for TableRange<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableRangeReader({:?})", self.table())
    }
}

/// An iterator over a range of entries from the records table.
#[derive(Debug)]
pub struct RecordsRange(TableRange<RecordsId<'static>, RecordsValue<'static>>);
impl RecordsRange {
    pub(super) fn new<RF>(db: &Arc<Database>, range_fn: RF) -> anyhow::Result<Self>
    where
        RF: FnOnce(
            &ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>,
        ) -> Result<
            Range<'static, RecordsId<'static>, RecordsValue<'static>>,
            StorageError,
        >,
    {
        Ok(Self(TableRange::new(
            db,
            |tx| tx.open_table(RECORDS_TABLE),
            range_fn,
        )?))
    }

    pub(super) fn with_bounds(db: &Arc<Database>, bounds: RecordsBounds) -> anyhow::Result<Self> {
        Self::new(db, |table| table.range(bounds.as_ref()))
    }

    /// Get the next item in the range.
    ///
    /// Omit items for which the `matcher` function returns false.
    pub(super) fn next_filtered(
        &mut self,
        direction: &SortDirection,
        filter: impl for<'x> Fn(RecordsId<'x>, RecordsValue<'x>) -> bool,
    ) -> Option<anyhow::Result<SignedEntry>> {
        self.0.next_filtered(direction, filter, into_entry)
    }

    pub(super) fn next_mapped<T>(
        &mut self,
        map: impl for<'x> Fn(RecordsId<'x>, RecordsValue<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.0.next_mapped(map)
    }
}

impl Iterator for RecordsRange {
    type Item = anyhow::Result<SignedEntry>;
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next_mapped(into_entry)
    }
}

#[derive(derive_more::Debug)]
#[debug("RecordsByKeyRange")]
pub struct RecordsByKeyRange {
    read_tx: ReadTransaction,
    records_table: ReadOnlyTable<RecordsId<'static>, RecordsValue<'static>>,
    by_key_table: ReadOnlyTable<RecordsByKeyId<'static>, ()>,
    by_key_range: Range<'static, RecordsByKeyId<'static>, ()>,
}

impl RecordsByKeyRange {
    pub fn new<RF>(db: &Arc<Database>, range_fn: RF) -> anyhow::Result<Self>
    where
        RF: FnOnce(
            &ReadOnlyTable<RecordsByKeyId<'static>, ()>,
        ) -> Result<Range<'static, RecordsByKeyId<'static>, ()>, StorageError>,
    {
        let read_tx = db.begin_read()?;
        let records_table = read_tx.open_table(RECORDS_TABLE).map_err(anyhow_err)?;
        let by_key_table = read_tx
            .open_table(RECORDS_BY_KEY_TABLE)
            .map_err(anyhow_err)?;
        let by_key_range = range_fn(&by_key_table).map_err(anyhow_err)?;
        Ok(Self {
            read_tx,
            records_table,
            by_key_table,
            by_key_range,
        })
    }

    pub fn with_bounds(db: &Arc<Database>, bounds: ByKeyBounds) -> anyhow::Result<Self> {
        Self::new(db, |table| table.range(bounds.as_ref()))
    }

    /// Get the next item in the range.
    ///
    /// Omit items for which the `matcher` function returns false.
    pub fn next_filtered(
        &mut self,
        direction: &SortDirection,
        filter: impl for<'x> Fn(RecordsByKeyId<'x>) -> bool,
    ) -> Option<anyhow::Result<SignedEntry>> {
        let by_key_id = loop {
            let next = match direction {
                SortDirection::Asc => self.by_key_range.next(),
                SortDirection::Desc => self.by_key_range.next_back(),
            };
            match next {
                Some(Ok(res)) => match filter(res.0.value()) {
                    false => continue,
                    true => break res.0,
                },
                Some(Err(err)) => return Some(Err(err.into())),
                None => return None,
            }
        };

        let (namespace, key, author) = by_key_id.value();
        let records_id = (namespace, author, key);
        let entry = self.records_table.get(&records_id);
        match entry {
            Ok(Some(entry)) => Some(Ok(into_entry(records_id, entry.value()))),
            Ok(None) => None,
            Err(err) => Some(Err(err.into())),
        }
    }
}

fn anyhow_err(err: impl Into<anyhow::Error>) -> anyhow::Error {
    err.into()
}
