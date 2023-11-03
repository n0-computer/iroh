use std::{fmt, sync::Arc};

use ouroboros::self_referencing;
use redb::{
    Database, Range as TableRange, ReadOnlyTable, ReadTransaction, RedbKey, RedbValue,
    StorageError, TableError,
};

use crate::store::SortDirection;

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

/// A range reader for a [`redb::ReadOnlyTable`] that can be stored in a struct.
///
/// This uses [`ouroboros::self_referencing`] to store a [`ReadTransaction`], a [`ReadOnlyTable`]
/// and a [`TableRange`] together. Useful to build iterators with.
pub struct TableRangeReader<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static>(
    TableRangeReaderInner<'a, K, V>,
);

#[self_referencing]
struct TableRangeReaderInner<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> {
    table: TableReader<'a, K, V>,
    #[covariant]
    #[borrows(table)]
    range: TableRange<'this, K, V>,
}

impl<'a, K: RedbKey + 'static, V: RedbValue + 'static> TableRangeReader<'a, K, V> {
    /// Create a new [`TableReader`]
    pub fn new(
        db: &'a Arc<Database>,
        table_fn: impl for<'this> FnOnce(
            &'this ReadTransaction<'this>,
        ) -> Result<ReadOnlyTable<K, V>, TableError>,
        range_fn: impl for<'this> FnOnce(
            &'this ReadOnlyTable<'this, K, V>,
        ) -> Result<TableRange<'this, K, V>, StorageError>,
    ) -> anyhow::Result<Self> {
        let table = TableReader::new(db, table_fn)?;
        let reader = TableRangeReaderInner::try_new(table, |table| {
            range_fn(table.table()).map_err(anyhow::Error::from)
        })?;
        Ok(Self(reader))
    }

    /// Get a reference to the [`ReadOnlyTable`];
    pub fn table(&self) -> &ReadOnlyTable<K, V> {
        self.0.borrow_table().table()
    }

    /// Get a mutable reference to the [`TableRange`].
    pub fn with_range<T>(&mut self, f: impl FnMut(&mut TableRange<K, V>) -> T) -> T {
        self.0.with_range_mut(f)
    }

    pub fn next_mapped<T>(
        &mut self,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.with_range(|records| {
            records
                .next()
                .map(|r| r.map_err(Into::into).map(|r| map(r.0.value(), r.1.value())))
        })
    }

    pub fn next_matching<T>(
        &mut self,
        direction: &SortDirection,
        matcher: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> bool,
        map: impl for<'x> Fn(K::SelfType<'x>, V::SelfType<'x>) -> T,
    ) -> Option<anyhow::Result<T>> {
        self.with_range(|records| loop {
            let next = match direction {
                SortDirection::Asc => records.next(),
                SortDirection::Desc => records.next_back(),
            };
            match next {
                None => break None,
                Some(Err(err)) => break Some(Err(err.into())),
                Some(Ok(res)) => match matcher(res.0.value(), res.1.value()) {
                    false => continue,
                    true => break Some(Ok(map(res.0.value(), res.1.value()))),
                },
            }
        })
    }
}

impl<'a, K: RedbKey + 'static, V: redb::RedbValue + 'static> fmt::Debug
    for TableRangeReader<'a, K, V>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TableRangeReader({:?})", self.table())
    }
}
