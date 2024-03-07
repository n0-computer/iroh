//! Table definitions and accessors for the redb database.
use redb::{ReadableTable, TableDefinition, TableError};

use iroh_base::hash::{Hash, HashAndFormat};

use super::EntryState;
use crate::util::Tag;

pub(super) const BLOBS_TABLE: TableDefinition<Hash, EntryState> = TableDefinition::new("blobs-0");

pub(super) const TAGS_TABLE: TableDefinition<Tag, HashAndFormat> = TableDefinition::new("tags-0");

pub(super) const INLINE_DATA_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-data-0");

pub(super) const INLINE_OUTBOARD_TABLE: TableDefinition<Hash, &[u8]> =
    TableDefinition::new("inline-outboard-0");

/// A trait similar to [`redb::ReadableTable`] but for all tables that make up
/// the blob store. This can be used in places where either a readonly or
/// mutable table is needed.
pub(super) trait ReadableTables {
    fn blobs(&self) -> &impl ReadableTable<Hash, EntryState>;
    fn tags(&self) -> &impl ReadableTable<Tag, HashAndFormat>;
    fn inline_data(&self) -> &impl ReadableTable<Hash, &'static [u8]>;
    fn inline_outboard(&self) -> &impl ReadableTable<Hash, &'static [u8]>;
}

/// A struct similar to [`redb::Table`] but for all tables that make up the
/// blob store.
pub(super) struct Tables<'a, 'b> {
    pub blobs: redb::Table<'a, 'b, Hash, EntryState>,
    pub tags: redb::Table<'a, 'b, Tag, HashAndFormat>,
    pub inline_data: redb::Table<'a, 'b, Hash, &'static [u8]>,
    pub inline_outboard: redb::Table<'a, 'b, Hash, &'static [u8]>,
}

impl<'db, 'txn> Tables<'db, 'txn> {
    pub fn new(tx: &'txn redb::WriteTransaction<'db>) -> std::result::Result<Self, TableError> {
        Ok(Self {
            blobs: tx.open_table(BLOBS_TABLE)?,
            tags: tx.open_table(TAGS_TABLE)?,
            inline_data: tx.open_table(INLINE_DATA_TABLE)?,
            inline_outboard: tx.open_table(INLINE_OUTBOARD_TABLE)?,
        })
    }
}

impl ReadableTables for Tables<'_, '_> {
    fn blobs(&self) -> &impl ReadableTable<Hash, EntryState> {
        &self.blobs
    }
    fn tags(&self) -> &impl ReadableTable<Tag, HashAndFormat> {
        &self.tags
    }
    fn inline_data(&self) -> &impl ReadableTable<Hash, &'static [u8]> {
        &self.inline_data
    }
    fn inline_outboard(&self) -> &impl ReadableTable<Hash, &'static [u8]> {
        &self.inline_outboard
    }
}

/// A struct similar to [`redb::ReadOnlyTable`] but for all tables that make up
/// the blob store.
pub(super) struct ReadOnlyTables<'txn> {
    pub blobs: redb::ReadOnlyTable<'txn, Hash, EntryState>,
    pub tags: redb::ReadOnlyTable<'txn, Tag, HashAndFormat>,
    pub inline_data: redb::ReadOnlyTable<'txn, Hash, &'static [u8]>,
    pub inline_outboard: redb::ReadOnlyTable<'txn, Hash, &'static [u8]>,
}

impl<'txn> ReadOnlyTables<'txn> {
    pub fn new(tx: &'txn redb::ReadTransaction<'txn>) -> std::result::Result<Self, TableError> {
        Ok(Self {
            blobs: tx.open_table(BLOBS_TABLE)?,
            tags: tx.open_table(TAGS_TABLE)?,
            inline_data: tx.open_table(INLINE_DATA_TABLE)?,
            inline_outboard: tx.open_table(INLINE_OUTBOARD_TABLE)?,
        })
    }
}

impl ReadableTables for ReadOnlyTables<'_> {
    fn blobs(&self) -> &impl ReadableTable<Hash, EntryState> {
        &self.blobs
    }
    fn tags(&self) -> &impl ReadableTable<Tag, HashAndFormat> {
        &self.tags
    }
    fn inline_data(&self) -> &impl ReadableTable<Hash, &'static [u8]> {
        &self.inline_data
    }
    fn inline_outboard(&self) -> &impl ReadableTable<Hash, &'static [u8]> {
        &self.inline_outboard
    }
}
