use std::{fmt, sync::Arc};

use ouroboros::self_referencing;
use redb::{
    Database, Range, ReadOnlyTable, ReadTransaction, ReadableTable, RedbKey, RedbValue,
    StorageError, TableError,
};

use crate::{store::SortDirection, SignedEntry};

use super::{
    into_entry, RecordsByKeyId, RecordsId, RecordsValue, RECORDS_BY_KEY_TABLE, RECORDS_TABLE,
};

/// A [`ReadTransaction`] with a [`ReadOnlyTable`] that can be stored in a struct.
///
/// This uses [`ouroboros::self_referencing`] to store a [`ReadTransaction`] and a [`ReadOnlyTable`]
/// with self-referencing.
pub struct TableReader<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static>(
    TableReaderInner<'a, K, V>,
);

#[self_referencing]
struct TableReaderInner<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> {
    #[debug("ReadTransaction")]
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    table: ReadOnlyTable<'this, K, V>,
}

impl<'a, K: RedbKey + 'static, V: RedbValue + 'static> TableReader<'a, K, V> {
    /// Create a new [`TableReader`]
    pub fn new(
        db: &'a Arc<Database>,
        table_fn: impl for<'this> FnOnce(
            &'this ReadTransaction<'this>,
        ) -> Result<ReadOnlyTable<K, V>, TableError>,
    ) -> anyhow::Result<Self> {
        let reader = TableReaderInner::try_new(db.begin_read()?, |read_tx| {
            table_fn(read_tx).map_err(anyhow::Error::from)
        })?;
        Ok(Self(reader))
    }

    /// Get a reference to the [`ReadOnlyTable`];
    pub fn table(&self) -> &ReadOnlyTable<K, V> {
        self.0.borrow_table()
    }
}

impl<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> fmt::Debug for TableReader<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableReader({:?})", self.table())
    }
}

/// A range reader for a [`ReadOnlyTable`] that can be stored in a struct.
///
/// This uses [`ouroboros::self_referencing`] to store a [`ReadTransaction`], a [`ReadOnlyTable`]
/// and a [`Range`] together. Useful to build iterators with.
pub struct TableRange<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static>(
    TableRangeReaderInner<'a, K, V>,
);

#[self_referencing]
struct TableRangeReaderInner<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> {
    #[debug("ReadTransaction")]
    read_tx: ReadTransaction<'a>,
    #[borrows(read_tx)]
    #[covariant]
    table: ReadOnlyTable<'this, K, V>,
    #[covariant]
    #[borrows(table)]
    range: Range<'this, K, V>,
}

impl<'a, K: RedbKey + 'static, V: RedbValue + 'static> TableRange<'a, K, V> {
    /// Create a new [`TableReader`]
    pub fn new<TF, RF>(db: &'a Arc<Database>, table_fn: TF, range_fn: RF) -> anyhow::Result<Self>
    where
        TF: for<'s> FnOnce(&'s ReadTransaction<'s>) -> Result<ReadOnlyTable<K, V>, TableError>,
        RF: for<'s> FnOnce(&'s ReadOnlyTable<'s, K, V>) -> Result<Range<'s, K, V>, StorageError>,
    {
        let reader = TableRangeReaderInner::try_new(
            db.begin_read()?,
            |tx| table_fn(tx).map_err(anyhow_err),
            |table| range_fn(table).map_err(anyhow_err),
        )?;
        Ok(Self(reader))
    }

    /// Get a reference to the [`ReadOnlyTable`];
    pub fn table(&self) -> &ReadOnlyTable<K, V> {
        self.0.borrow_table()
    }

    pub fn next_mapped<T>(
        &mut self,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.0.with_range_mut(|records| {
            records
                .next()
                .map(|r| r.map_err(Into::into).map(|r| map(r.0.value(), r.1.value())))
        })
    }

    pub fn next_filtered<T>(
        &mut self,
        direction: &SortDirection,
        filter: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> bool,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.0.with_range_mut(|records| loop {
            let next = match direction {
                SortDirection::Asc => records.next(),
                SortDirection::Desc => records.next_back(),
            };
            match next {
                None => break None,
                Some(Err(err)) => break Some(Err(err.into())),
                Some(Ok(res)) => match filter(res.0.value(), res.1.value()) {
                    false => continue,
                    true => break Some(Ok(map(res.0.value(), res.1.value()))),
                },
            }
        })
    }
}

impl<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> fmt::Debug for TableRange<'a, K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableRangeReader({:?})", self.table())
    }
}

#[derive(derive_more::Debug)]
#[debug("RecordsIndexReader")]
pub struct RecordsByKeyRange<'a>(RecordsByKeyRangeInner<'a>);

#[self_referencing]
struct RecordsByKeyRangeInner<'a> {
    #[debug("ReadTransaction")]
    read_tx: ReadTransaction<'a>,

    #[covariant]
    #[borrows(read_tx)]
    records_table: ReadOnlyTable<'this, RecordsId<'static>, RecordsValue<'static>>,

    #[covariant]
    #[borrows(read_tx)]
    by_key_table: ReadOnlyTable<'this, RecordsByKeyId<'static>, ()>,

    #[borrows(by_key_table)]
    #[covariant]
    by_key_range: Range<'this, RecordsByKeyId<'static>, ()>,
}

impl<'a> RecordsByKeyRange<'a> {
    pub fn new<RF>(db: &'a Arc<Database>, range_fn: RF) -> anyhow::Result<Self>
    where
        RF: for<'s> FnOnce(
            &'s ReadOnlyTable<'s, RecordsByKeyId<'static>, ()>,
        ) -> Result<Range<'s, RecordsByKeyId<'static>, ()>, StorageError>,
    {
        let inner = RecordsByKeyRangeInner::try_new(
            db.begin_read()?,
            |tx| tx.open_table(RECORDS_TABLE).map_err(anyhow_err),
            |tx| tx.open_table(RECORDS_BY_KEY_TABLE).map_err(anyhow_err),
            |table| range_fn(table).map_err(Into::into),
        )?;
        Ok(Self(inner))
    }

    /// Get the next item in the range.
    ///
    /// Omit items for which the `matcher` function returns false.
    pub fn next_filtered(
        &mut self,
        direction: &SortDirection,
        filter: impl for<'x> Fn(RecordsByKeyId<'x>) -> bool,
    ) -> Option<anyhow::Result<SignedEntry>> {
        self.0.with_mut(|fields| {
            let by_key_id = loop {
                let next = match direction {
                    SortDirection::Asc => fields.by_key_range.next(),
                    SortDirection::Desc => fields.by_key_range.next_back(),
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
            let entry = fields.records_table.get(&records_id);
            match entry {
                Ok(Some(entry)) => Some(Ok(into_entry(records_id, entry.value()))),
                Ok(None) => None,
                Err(err) => Some(Err(err.into())),
            }
        })
    }
}

fn anyhow_err(err: impl Into<anyhow::Error>) -> anyhow::Error {
    err.into()
}
