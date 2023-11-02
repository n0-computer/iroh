use std::sync::Arc;

use ouroboros::self_referencing;
use redb::{
    Database, Range as TableRange, ReadOnlyTable, ReadTransaction, RedbKey, RedbValue,
    StorageError, TableError,
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

    /// Get a mutable reference to the [`TableRange`].
    pub fn with_range<T>(&mut self, f: impl FnMut(&mut TableRange<K, V>) -> T) -> T {
        self.0.with_range_mut(f)
    }
}
