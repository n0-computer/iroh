//! Table definitions and accessors for the redb database.
use std::collections::BTreeSet;

use redb::{ReadableTable, TableDefinition, TableError};

use iroh_base::hash::{Hash, HashAndFormat};

use super::{EntryState, PathOptions};
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
pub(super) struct Tables<'a> {
    pub blobs: redb::Table<'a, Hash, EntryState>,
    pub tags: redb::Table<'a, Tag, HashAndFormat>,
    pub inline_data: redb::Table<'a, Hash, &'static [u8]>,
    pub inline_outboard: redb::Table<'a, Hash, &'static [u8]>,
    pub delete_after_commit: &'a mut DeleteSet,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum BaoFilePart {
    Outboard,
    Data,
    Sizes,
}

impl<'txn> Tables<'txn> {
    pub fn new(
        tx: &'txn redb::WriteTransaction,
        delete_after_commit: &'txn mut DeleteSet,
    ) -> std::result::Result<Self, TableError> {
        Ok(Self {
            blobs: tx.open_table(BLOBS_TABLE)?,
            tags: tx.open_table(TAGS_TABLE)?,
            inline_data: tx.open_table(INLINE_DATA_TABLE)?,
            inline_outboard: tx.open_table(INLINE_OUTBOARD_TABLE)?,
            delete_after_commit,
        })
    }
}

impl ReadableTables for Tables<'_> {
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
pub(super) struct ReadOnlyTables {
    pub blobs: redb::ReadOnlyTable<Hash, EntryState>,
    pub tags: redb::ReadOnlyTable<Tag, HashAndFormat>,
    pub inline_data: redb::ReadOnlyTable<Hash, &'static [u8]>,
    pub inline_outboard: redb::ReadOnlyTable<Hash, &'static [u8]>,
}

impl<'txn> ReadOnlyTables {
    pub fn new(tx: &'txn redb::ReadTransaction) -> std::result::Result<Self, TableError> {
        Ok(Self {
            blobs: tx.open_table(BLOBS_TABLE)?,
            tags: tx.open_table(TAGS_TABLE)?,
            inline_data: tx.open_table(INLINE_DATA_TABLE)?,
            inline_outboard: tx.open_table(INLINE_OUTBOARD_TABLE)?,
        })
    }
}

impl ReadableTables for ReadOnlyTables {
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

/// Helper to keep track of files to delete after a transaction is committed.
#[derive(Debug, Default)]
pub(super) struct DeleteSet(BTreeSet<(Hash, BaoFilePart)>);

impl DeleteSet {
    /// Mark a file as to be deleted after the transaction is committed.
    pub fn insert(&mut self, hash: Hash, parts: impl IntoIterator<Item = BaoFilePart>) {
        for part in parts {
            self.0.insert((hash, part));
        }
    }

    /// Mark a file as to be kept after the transaction is committed.
    ///
    /// This will cancel any previous delete for the same file in the same transaction.
    pub fn remove(&mut self, hash: Hash, parts: impl IntoIterator<Item = BaoFilePart>) {
        for part in parts {
            self.0.remove(&(hash, part));
        }
    }

    /// Get the inner set of files to delete.
    pub fn into_inner(self) -> BTreeSet<(Hash, BaoFilePart)> {
        self.0
    }

    /// Apply the delete set and clear it.
    ///
    /// This will delete all files marked for deletion and then clear the set.
    /// Errors will just be logged.
    pub fn apply_and_clear(&mut self, options: &PathOptions) {
        for (hash, to_delete) in &self.0 {
            tracing::info!("deleting {:?}", to_delete);
            let path = match to_delete {
                BaoFilePart::Data => options.owned_data_path(hash),
                BaoFilePart::Outboard => options.owned_outboard_path(hash),
                BaoFilePart::Sizes => options.owned_sizes_path(hash),
            };
            if let Err(cause) = std::fs::remove_file(&path) {
                tracing::warn!(
                    "failed to delete {:?} {}: {}",
                    to_delete,
                    path.display(),
                    cause
                );
            }
        }
        self.0.clear();
    }
}
