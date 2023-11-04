use std::collections::HashMap;

use anyhow::Result;
use redb::{ReadableTable, Table};
use tracing::info;

use super::{LatestKey, LatestValue, RecordsByKeyId, RecordsId, RecordsValue};

/// migration 001: populate the latest table (which did not exist before)
pub fn migration_001_populate_latest_table(
    records_table: &Table<RecordsId<'static>, RecordsValue<'static>>,
    latest_table: &mut Table<LatestKey<'static>, LatestValue<'static>>,
) -> Result<()> {
    info!("Starting migration: 001_populate_latest_table");
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
    info!("Migration finished (inserted {len} entries)");
    Ok(())
}

/// migration 002: populate the by_key index table(which did not exist before)
pub fn migration_002_populate_by_key_index(
    records_table: &Table<RecordsId<'static>, RecordsValue<'static>>,
    by_key_table: &mut Table<RecordsByKeyId<'static>, ()>,
) -> Result<()> {
    info!("Starting migration: 002_populate_by_key_index");
    let iter = records_table.iter()?;

    let mut len = 0;
    for next in iter {
        let next = next?;
        let (namespace, author, key) = next.0.value();
        let id = (namespace, key, author);
        by_key_table.insert(id, ())?;
        len += 1;
    }
    info!("Migration finished (inserted {len} entries)");
    Ok(())
}
