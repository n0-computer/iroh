//! Validation of the store's contents.
use std::collections::BTreeSet;

use redb::ReadableTable;

use crate::store::{fs::tables::BaoFilePart, ValidateLevel, ValidateProgress};

use super::{
    raw_outboard_size, tables::Tables, ActorResult, ActorState, DataLocation, EntryState, Hash,
    OutboardLocation,
};

impl ActorState {
    //! This performs a full consistency check. Eventually it will also validate
    //! file content again, but that part is not yet implemented.
    //!
    //! Currently the following checks are performed for complete entries:
    //!
    //! Check that the data in the entries table is consistent with the data in
    //! the inline_data and inline_outboard tables.
    //!
    //! For every entry where data_location is inline, the inline_data table
    //! must contain the data. For every entry where
    //! data_location is not inline, the inline_data table must not contain data.
    //! Instead, the data must exist as a file in the data directory or be
    //! referenced to one or many external files.
    //!
    //! For every entry where outboard_location is inline, the inline_outboard
    //! table must contain the outboard. For every entry where outboard_location
    //! is not inline, the inline_outboard table must not contain data, and the
    //! outboard must exist as a file in the data directory. Outboards are never
    //! external.
    //!
    //! In addition to these consistency checks, it is checked that the size of
    //! the outboard is consistent with the size of the data.
    //!
    //! For partial entries, it is checked that the data and outboard files
    //! exist.
    //!
    //! In addition to the consistency checks, it is checked that there are no
    //! orphaned or unexpected files in the data directory. Also, all entries of
    //! all tables are dumped at trace level. This is helpful for debugging and
    //! also ensures that the data can be read.
    //!
    //! Note that during validation, a set of all hashes will be kept in memory.
    //! So to validate exceedingly large stores, the validation process will
    //! consume a lot of memory.
    //!
    //! In addition, validation is a blocking operation that will make the store
    //! unresponsive for the duration of the validation.
    pub(super) fn validate(
        &mut self,
        db: &redb::Database,
        repair: bool,
        progress: tokio::sync::mpsc::Sender<ValidateProgress>,
    ) -> ActorResult<()> {
        let mut invalid_entries = BTreeSet::new();
        macro_rules! send {
            ($level:expr, $entry:expr, $($arg:tt)*) => {
                if let Err(_) = progress.blocking_send(ValidateProgress::ConsistencyCheckUpdate { message: format!($($arg)*), level: $level, entry: $entry }) {
                    return Ok(());
                }
            };
        }
        macro_rules! trace {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Trace, None, $($arg)*)
            };
        }
        macro_rules! info {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Info, None, $($arg)*)
            };
        }
        macro_rules! warn {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Warn, None, $($arg)*)
            };
        }
        macro_rules! entry_warn {
            ($hash:expr, $($arg:tt)*) => {
                send!(ValidateLevel::Warn, Some($hash), $($arg)*)
            };
        }
        macro_rules! entry_info {
            ($hash:expr, $($arg:tt)*) => {
                send!(ValidateLevel::Info, Some($hash), $($arg)*)
            };
        }
        macro_rules! error {
            ($($arg:tt)*) => {
                send!(ValidateLevel::Error, None, $($arg)*)
            };
        }
        macro_rules! entry_error {
            ($hash:expr, $($arg:tt)*) => {
                invalid_entries.insert($hash);
                send!(ValidateLevel::Error, Some($hash), $($arg)*)
            };
        }
        let mut delete_after_commit = Default::default();
        let txn = db.begin_write()?;
        {
            let mut tables = Tables::new(&txn, &mut delete_after_commit)?;
            let blobs = &mut tables.blobs;
            let inline_data = &mut tables.inline_data;
            let inline_outboard = &mut tables.inline_outboard;
            let tags = &mut tables.tags;
            let mut orphaned_inline_data = BTreeSet::new();
            let mut orphaned_inline_outboard = BTreeSet::new();
            let mut orphaned_data = BTreeSet::new();
            let mut orphaned_outboardard = BTreeSet::new();
            let mut orphaned_sizes = BTreeSet::new();
            // first, dump the entire data content at trace level
            trace!("dumping blobs");
            match blobs.iter() {
                Ok(iter) => {
                    for item in iter {
                        match item {
                            Ok((k, v)) => {
                                let hash = k.value();
                                let entry = v.value();
                                trace!("blob {} -> {:?}", hash.to_hex(), entry);
                            }
                            Err(cause) => {
                                error!("failed to access blob item: {}", cause);
                            }
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate blobs: {}", cause);
                }
            }
            trace!("dumping inline_data");
            match inline_data.iter() {
                Ok(iter) => {
                    for item in iter {
                        match item {
                            Ok((k, v)) => {
                                let hash = k.value();
                                let data = v.value();
                                trace!("inline_data {} -> {:?}", hash.to_hex(), data.len());
                            }
                            Err(cause) => {
                                error!("failed to access inline data item: {}", cause);
                            }
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate inline_data: {}", cause);
                }
            }
            trace!("dumping inline_outboard");
            match inline_outboard.iter() {
                Ok(iter) => {
                    for item in iter {
                        match item {
                            Ok((k, v)) => {
                                let hash = k.value();
                                let data = v.value();
                                trace!("inline_outboard {} -> {:?}", hash.to_hex(), data.len());
                            }
                            Err(cause) => {
                                error!("failed to access inline outboard item: {}", cause);
                            }
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate inline_outboard: {}", cause);
                }
            }
            trace!("dumping tags");
            match tags.iter() {
                Ok(iter) => {
                    for item in iter {
                        match item {
                            Ok((k, v)) => {
                                let tag = k.value();
                                let value = v.value();
                                trace!("tags {} -> {:?}", tag, value);
                            }
                            Err(cause) => {
                                error!("failed to access tag item: {}", cause);
                            }
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate tags: {}", cause);
                }
            }

            // perform consistency check for each entry
            info!("validating blobs");
            // set of a all hashes that are referenced by the blobs table
            let mut entries = BTreeSet::new();
            match blobs.iter() {
                Ok(iter) => {
                    for item in iter {
                        let Ok((hash, entry)) = item else {
                            error!("failed to access blob item");
                            continue;
                        };
                        let hash = hash.value();
                        entries.insert(hash);
                        entry_info!(hash, "validating blob");
                        let entry = entry.value();
                        match entry {
                            EntryState::Complete {
                                data_location,
                                outboard_location,
                            } => {
                                let data_size = match data_location {
                                    DataLocation::Inline(_) => {
                                        let Ok(inline_data) = inline_data.get(hash) else {
                                            entry_error!(hash, "inline data can not be accessed");
                                            continue;
                                        };
                                        let Some(inline_data) = inline_data else {
                                            entry_error!(hash, "inline data missing");
                                            continue;
                                        };
                                        inline_data.value().len() as u64
                                    }
                                    DataLocation::Owned(size) => {
                                        let path = self.options.path.owned_data_path(&hash);
                                        let Ok(metadata) = path.metadata() else {
                                            entry_error!(hash, "owned data file does not exist");
                                            continue;
                                        };
                                        if metadata.len() != size {
                                            entry_error!(
                                                hash,
                                                "owned data file size mismatch: {}",
                                                path.display()
                                            );
                                            continue;
                                        }
                                        size
                                    }
                                    DataLocation::External(paths, size) => {
                                        for path in paths {
                                            let Ok(metadata) = path.metadata() else {
                                                entry_error!(
                                                    hash,
                                                    "external data file does not exist: {}",
                                                    path.display()
                                                );
                                                invalid_entries.insert(hash);
                                                continue;
                                            };
                                            if metadata.len() != size {
                                                entry_error!(
                                                    hash,
                                                    "external data file size mismatch: {}",
                                                    path.display()
                                                );
                                                invalid_entries.insert(hash);
                                                continue;
                                            }
                                        }
                                        size
                                    }
                                };
                                match outboard_location {
                                    OutboardLocation::Inline(_) => {
                                        let Ok(inline_outboard) = inline_outboard.get(hash) else {
                                            entry_error!(
                                                hash,
                                                "inline outboard can not be accessed"
                                            );
                                            continue;
                                        };
                                        let Some(inline_outboard) = inline_outboard else {
                                            entry_error!(hash, "inline outboard missing");
                                            continue;
                                        };
                                        let outboard_size = inline_outboard.value().len() as u64;
                                        if outboard_size != raw_outboard_size(data_size) {
                                            entry_error!(hash, "inline outboard size mismatch");
                                        }
                                    }
                                    OutboardLocation::Owned => {
                                        let Ok(metadata) =
                                            self.options.path.owned_outboard_path(&hash).metadata()
                                        else {
                                            entry_error!(
                                                hash,
                                                "owned outboard file does not exist"
                                            );
                                            continue;
                                        };
                                        let outboard_size = metadata.len();
                                        if outboard_size != raw_outboard_size(data_size) {
                                            entry_error!(hash, "owned outboard size mismatch");
                                        }
                                    }
                                    OutboardLocation::NotNeeded => {
                                        if raw_outboard_size(data_size) != 0 {
                                            entry_error!(
                                                hash,
                                                "outboard not needed but data size is not zero"
                                            );
                                        }
                                    }
                                }
                            }
                            EntryState::Partial { .. } => {
                                if !self.options.path.owned_data_path(&hash).exists() {
                                    entry_error!(hash, "persistent partial entry has no data");
                                }
                                if !self.options.path.owned_outboard_path(&hash).exists() {
                                    entry_error!(hash, "persistent partial entry has no outboard");
                                }
                            }
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate blobs: {}", cause);
                }
            };
            if repair {
                info!("repairing - removing invalid entries found so far");
                for hash in &invalid_entries {
                    blobs.remove(hash)?;
                }
            }
            info!("checking for orphaned inline data");
            match inline_data.iter() {
                Ok(iter) => {
                    for item in iter {
                        let Ok((hash, _)) = item else {
                            error!("failed to access inline data item");
                            continue;
                        };
                        let hash = hash.value();
                        if !entries.contains(&hash) {
                            orphaned_inline_data.insert(hash);
                            entry_error!(hash, "orphaned inline data");
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate inline_data: {}", cause);
                }
            };
            info!("checking for orphaned inline outboard data");
            match inline_outboard.iter() {
                Ok(iter) => {
                    for item in iter {
                        let Ok((hash, _)) = item else {
                            error!("failed to access inline outboard item");
                            continue;
                        };
                        let hash = hash.value();
                        if !entries.contains(&hash) {
                            orphaned_inline_outboard.insert(hash);
                            entry_error!(hash, "orphaned inline outboard");
                        }
                    }
                }
                Err(cause) => {
                    error!("failed to iterate inline_outboard: {}", cause);
                }
            };
            info!("checking for unexpected or orphaned files");
            for entry in self.options.path.data_path.read_dir()? {
                let entry = entry?;
                let path = entry.path();
                if !path.is_file() {
                    warn!("unexpected entry in data directory: {}", path.display());
                    continue;
                }
                match path.extension().and_then(|x| x.to_str()) {
                    Some("data") => match path.file_stem().and_then(|x| x.to_str()) {
                        Some(stem) => {
                            let mut hash = [0u8; 32];
                            let Ok(_) = hex::decode_to_slice(stem, &mut hash) else {
                                warn!("unexpected data file in data directory: {}", path.display());
                                continue;
                            };
                            let hash = Hash::from(hash);
                            if !entries.contains(&hash) {
                                orphaned_data.insert(hash);
                                entry_warn!(hash, "orphaned data file");
                            }
                        }
                        None => {
                            warn!("unexpected data file in data directory: {}", path.display());
                        }
                    },
                    Some("obao4") => match path.file_stem().and_then(|x| x.to_str()) {
                        Some(stem) => {
                            let mut hash = [0u8; 32];
                            let Ok(_) = hex::decode_to_slice(stem, &mut hash) else {
                                warn!(
                                    "unexpected outboard file in data directory: {}",
                                    path.display()
                                );
                                continue;
                            };
                            let hash = Hash::from(hash);
                            if !entries.contains(&hash) {
                                orphaned_outboardard.insert(hash);
                                entry_warn!(hash, "orphaned outboard file");
                            }
                        }
                        None => {
                            warn!(
                                "unexpected outboard file in data directory: {}",
                                path.display()
                            );
                        }
                    },
                    Some("sizes4") => match path.file_stem().and_then(|x| x.to_str()) {
                        Some(stem) => {
                            let mut hash = [0u8; 32];
                            let Ok(_) = hex::decode_to_slice(stem, &mut hash) else {
                                warn!(
                                    "unexpected outboard file in data directory: {}",
                                    path.display()
                                );
                                continue;
                            };
                            let hash = Hash::from(hash);
                            if !entries.contains(&hash) {
                                orphaned_sizes.insert(hash);
                                entry_warn!(hash, "orphaned outboard file");
                            }
                        }
                        None => {
                            warn!(
                                "unexpected outboard file in data directory: {}",
                                path.display()
                            );
                        }
                    },
                    _ => {
                        warn!("unexpected file in data directory: {}", path.display());
                    }
                }
            }
            if repair {
                info!("repairing - removing orphaned files and inline data");
                for hash in orphaned_inline_data {
                    entry_info!(hash, "deleting orphaned inline data");
                    inline_data.remove(&hash)?;
                }
                for hash in orphaned_inline_outboard {
                    entry_info!(hash, "deleting orphaned inline outboard");
                    inline_outboard.remove(&hash)?;
                }
                for hash in orphaned_data {
                    tables.delete_after_commit.insert(hash, [BaoFilePart::Data]);
                }
                for hash in orphaned_outboardard {
                    tables
                        .delete_after_commit
                        .insert(hash, [BaoFilePart::Outboard]);
                }
                for hash in orphaned_sizes {
                    tables
                        .delete_after_commit
                        .insert(hash, [BaoFilePart::Sizes]);
                }
            }
        }
        txn.commit()?;
        if repair {
            info!("repairing - deleting orphaned files");
            for (hash, part) in delete_after_commit.into_inner() {
                let path = match part {
                    BaoFilePart::Data => self.options.path.owned_data_path(&hash),
                    BaoFilePart::Outboard => self.options.path.owned_outboard_path(&hash),
                    BaoFilePart::Sizes => self.options.path.owned_sizes_path(&hash),
                };
                entry_info!(hash, "deleting orphaned file: {}", path.display());
                if let Err(cause) = std::fs::remove_file(&path) {
                    entry_error!(hash, "failed to delete orphaned file: {}", cause);
                }
            }
        }

        Ok(())
    }
}
