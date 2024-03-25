use std::path::Path;

use anyhow::{Context, Result};
use redb::{MultimapTableHandle, TableHandle};
use redb_v1::{ReadableMultimapTable, ReadableTable};
use tempfile::NamedTempFile;
use tracing::info;

macro_rules! migrate_table {
    ($rtx:expr, $wtx:expr, $old:expr, $new:expr) => {{
        let old_table = $rtx.open_table($old)?;
        let mut new_table = $wtx.open_table($new)?;
        let name = $new.name();
        let len = old_table.len()?;
        info!("migrate {name} ({len} rows)..");
        let ind = (len as usize / 1000) + 1;
        for (i, entry) in old_table.iter()?.enumerate() {
            let (key, value) = entry?;
            let key = key.value();
            let value = value.value();
            if i > 0 && i % 100 == 0 {
                info!("    {name} {i:>ind$}/{len}");
            }
            new_table.insert(key, value)?;
        }
        info!("migrate {name} done");
    }};
}

macro_rules! migrate_multimap_table {
    ($rtx:expr, $wtx:expr, $old:expr, $new:expr) => {{
        let old_table = $rtx.open_multimap_table($old)?;
        let mut new_table = $wtx.open_multimap_table($new)?;
        let name = $new.name();
        let len = old_table.len()?;
        info!("migrate {name} ({len} rows)");
        let ind = (len as usize / 1000) + 1;
        for (i, entry) in old_table.iter()?.enumerate() {
            let (key, values) = entry?;
            let key = key.value();
            if i > 0 && i % 100 == 0 {
                info!("    {name} {i:>ind$}/{len}");
            }
            for value in values {
                let value = value?;
                new_table.insert(key, value.value())?;
            }
        }
        info!("migrate {name} done");
    }};
}

pub fn run(source: impl AsRef<Path>) -> Result<redb::Database> {
    let source = source.as_ref();
    // create the database to a tempfile
    let target = NamedTempFile::new()?;
    let target = target.into_temp_path();
    info!("migrate {} to {}", source.display(), target.display());
    let old_db = redb_v1::Database::open(source)?;
    let new_db = redb::Database::create(&target)?;

    let rtx = old_db.begin_read()?;
    let wtx = new_db.begin_write()?;

    migrate_table!(rtx, wtx, old::AUTHORS_TABLE, new::AUTHORS_TABLE);
    migrate_table!(rtx, wtx, old::NAMESPACES_TABLE, new::NAMESPACES_TABLE);
    migrate_table!(rtx, wtx, old::RECORDS_TABLE, new::RECORDS_TABLE);
    migrate_table!(
        rtx,
        wtx,
        old::LATEST_PER_AUTHOR_TABLE,
        new::LATEST_PER_AUTHOR_TABLE
    );
    migrate_table!(
        rtx,
        wtx,
        old::RECORDS_BY_KEY_TABLE,
        new::RECORDS_BY_KEY_TABLE
    );
    migrate_multimap_table!(
        rtx,
        wtx,
        old::NAMESPACE_PEERS_TABLE,
        new::NAMESPACE_PEERS_TABLE
    );
    migrate_table!(
        rtx,
        wtx,
        old::DOWNLOAD_POLICY_TABLE,
        new::DOWNLOAD_POLICY_TABLE
    );

    wtx.commit()?;
    drop(rtx);
    drop(old_db);
    drop(new_db);

    let backup_path = {
        let mut file_name = source.file_name().context("must be a file")?.to_owned();
        file_name.push(".backup-redb-v1");
        let mut path = source.to_owned();
        path.set_file_name(file_name);
        path
    };
    info!("rename {} to {}", source.display(), backup_path.display());
    std::fs::rename(source, &backup_path)?;
    info!("rename {} to {}", target.display(), source.display());
    target.persist_noclobber(source)?;
    info!("opening migrated database from {}", source.display());
    let db = redb::Database::open(source)?;
    Ok(db)
}

mod new {
    pub use super::super::*;
}

mod old {
    use redb_v1::{MultimapTableDefinition, TableDefinition};

    use crate::PeerIdBytes;

    use super::new::{
        LatestPerAuthorKey, LatestPerAuthorValue, Nanos, RecordsByKeyId, RecordsId, RecordsValue,
    };

    pub const AUTHORS_TABLE: TableDefinition<&[u8; 32], &[u8; 32]> =
        TableDefinition::new("authors-1");
    pub const NAMESPACES_TABLE: TableDefinition<&[u8; 32], (u8, &[u8; 32])> =
        TableDefinition::new("namespaces-2");
    pub const RECORDS_TABLE: TableDefinition<RecordsId, RecordsValue> =
        TableDefinition::new("records-1");
    pub const LATEST_PER_AUTHOR_TABLE: TableDefinition<LatestPerAuthorKey, LatestPerAuthorValue> =
        TableDefinition::new("latest-by-author-1");
    pub const RECORDS_BY_KEY_TABLE: TableDefinition<RecordsByKeyId, ()> =
        TableDefinition::new("records-by-key-1");
    pub const NAMESPACE_PEERS_TABLE: MultimapTableDefinition<&[u8; 32], (Nanos, &PeerIdBytes)> =
        MultimapTableDefinition::new("sync-peers-1");
    pub const DOWNLOAD_POLICY_TABLE: TableDefinition<&[u8; 32], &[u8]> =
        TableDefinition::new("download-policy-1");
}
