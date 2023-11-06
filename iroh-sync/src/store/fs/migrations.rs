use std::collections::HashMap;

use anyhow::Result;
use redb::{Database, ReadableTable, WriteTransaction};
use tracing::{debug, info};

use super::{LATEST_TABLE, RECORDS_BY_KEY_TABLE, RECORDS_TABLE};

/// Run all database migrations, if needed.
pub fn run_migrations(db: &Database) -> Result<()> {
    run_migration(db, migration_001_populate_latest_table)?;
    run_migration(db, migration_002_populate_by_key_index)?;
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
    let mut latest_table = tx.open_table(LATEST_TABLE)?;
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

/// migration 002: populate the by_key index table(which did not exist before)
fn migration_002_populate_by_key_index(tx: &WriteTransaction) -> Result<MigrateOutcome> {
    let mut by_key_table = tx.open_table(RECORDS_BY_KEY_TABLE)?;
    let records_table = tx.open_table(RECORDS_TABLE)?;
    if !by_key_table.is_empty()? || records_table.is_empty()? {
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
