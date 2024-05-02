use std::collections::HashMap;

use anyhow::Result;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableHandle, WriteTransaction};
use tracing::{debug, info};

use crate::{Capability, NamespaceSecret};

use super::tables::{
    LATEST_PER_AUTHOR_TABLE, NAMESPACES_TABLE, NAMESPACES_TABLE_V1, RECORDS_BY_KEY_TABLE,
    RECORDS_TABLE,
};

/// Run all database migrations, if needed.
pub fn run_migrations(db: &Database) -> Result<()> {
    run_migration(db, migration_001_populate_latest_table)?;
    run_migration(db, migration_002_namespaces_populate_v2)?;
    run_migration(db, migration_003_namespaces_delete_v1)?;
    run_migration(db, migration_004_populate_by_key_index)?;
    Ok(())
}

fn run_migration<F>(db: &Database, f: F) -> Result<()>
where
    F: Fn(&WriteTransaction) -> Result<MigrateOutcome>,
{
    let name = std::any::type_name::<F>();
    let name = name.split("::").last().unwrap();
    let tx = db.begin_write()?;
    debug!("Start migration {name}");
    match f(&tx)? {
        MigrateOutcome::Execute(len) => {
            tx.commit()?;
            info!("Executed migration {name} ({len} rows affected)");
        }
        MigrateOutcome::Skip => debug!("Skip migration {name}: Not needed"),
    }
    Ok(())
}

enum MigrateOutcome {
    Skip,
    Execute(usize),
}

/// migration 001: populate the latest table (which did not exist before)
fn migration_001_populate_latest_table(tx: &WriteTransaction) -> Result<MigrateOutcome> {
    let mut latest_table = tx.open_table(LATEST_PER_AUTHOR_TABLE)?;
    let records_table = tx.open_table(RECORDS_TABLE)?;
    if !latest_table.is_empty()? || records_table.is_empty()? {
        return Ok(MigrateOutcome::Skip);
    }

    #[allow(clippy::type_complexity)]
    let mut heads: HashMap<([u8; 32], [u8; 32]), (u64, Vec<u8>)> = HashMap::new();
    let iter = records_table.iter()?;

    for next in iter {
        let next = next?;
        let (namespace, author, key) = next.0.value();
        let (timestamp, _namespace_sig, _author_sig, _len, _hash) = next.1.value();
        heads
            .entry((*namespace, *author))
            .and_modify(|e| {
                if timestamp >= e.0 {
                    *e = (timestamp, key.to_vec());
                }
            })
            .or_insert_with(|| (timestamp, key.to_vec()));
    }
    let len = heads.len();
    for ((namespace, author), (timestamp, key)) in heads {
        latest_table.insert((&namespace, &author), (timestamp, key.as_slice()))?;
    }
    Ok(MigrateOutcome::Execute(len))
}

/// Copy the namespaces data from V1 to V2.
fn migration_002_namespaces_populate_v2(tx: &WriteTransaction) -> Result<MigrateOutcome> {
    let namespaces_v1_exists = tx
        .list_tables()?
        .any(|handle| handle.name() == NAMESPACES_TABLE_V1.name());
    if !namespaces_v1_exists {
        return Ok(MigrateOutcome::Skip);
    }
    let namespaces_v1 = tx.open_table(NAMESPACES_TABLE_V1)?;
    let mut namespaces_v2 = tx.open_table(NAMESPACES_TABLE)?;
    let mut entries = 0;
    for res in namespaces_v1.iter()? {
        let db_value = res?.1;
        let secret_bytes = db_value.value();
        let capability = Capability::Write(NamespaceSecret::from_bytes(secret_bytes));
        let id = capability.id().to_bytes();
        let (raw_kind, raw_bytes) = capability.raw();
        namespaces_v2.insert(&id, (raw_kind, &raw_bytes))?;
        entries += 1;
    }
    Ok(MigrateOutcome::Execute(entries))
}

/// Delete the v1 namespaces table.
///
/// This should be part of [`migration_002_namespaces_populate_v2`] but due to a limitation in
/// [`redb`] up to v1.3.0 a table cannot be deleted in a transaction that also opens this table.
/// Therefore the table deletion has to be in a separate transaction.
///
/// This limitation was removed in <https://github.com/cberner/redb/pull/716> so this can be merged
/// back into [`migration_002_namespaces_populate_v2`] once we upgrade to the next redb version
/// after 1.3.
fn migration_003_namespaces_delete_v1(tx: &WriteTransaction) -> Result<MigrateOutcome> {
    let namespaces_v1_exists = tx
        .list_tables()?
        .any(|handle| handle.name() == NAMESPACES_TABLE_V1.name());
    if !namespaces_v1_exists {
        return Ok(MigrateOutcome::Skip);
    }
    tx.delete_table(NAMESPACES_TABLE_V1)?;
    Ok(MigrateOutcome::Execute(1))
}

/// migration 004: populate the by_key index table(which did not exist before)
fn migration_004_populate_by_key_index(tx: &WriteTransaction) -> Result<MigrateOutcome> {
    let mut by_key_table = tx.open_table(RECORDS_BY_KEY_TABLE)?;
    let records_table = tx.open_table(RECORDS_TABLE)?;
    if !by_key_table.is_empty()? {
        return Ok(MigrateOutcome::Skip);
    }

    let iter = records_table.iter()?;
    let mut len = 0;
    for next in iter {
        let next = next?;
        let (namespace, author, key) = next.0.value();
        let id = (namespace, key, author);
        by_key_table.insert(id, ())?;
        len += 1;
    }
    Ok(MigrateOutcome::Execute(len))
}
