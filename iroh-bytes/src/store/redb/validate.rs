//! Validation of the store's contents.
//!
//! This performs a full consistency check. Eventually it will also validate
//! file content again, but that part is not yet implemented.
use std::collections::BTreeSet;

use redb::ReadableTable;

use crate::store::{ValidateLevel, ValidateProgress};

use super::{
    raw_outboard_size, tables::ReadableTables, ActorResult, ActorState, DataLocation, EntryState,
    Hash, OutboardLocation,
};

impl ActorState {
    pub(super) fn validate(
        &mut self,
        tables: &impl ReadableTables,
        progress: tokio::sync::mpsc::Sender<ValidateProgress>,
    ) -> ActorResult<()> {
        let blobs = tables.blobs();
        let inline_data = tables.inline_data();
        let inline_outboard = tables.inline_outboard();
        let tags = tables.tags();
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
            send!(ValidateLevel::Error, Some($hash), $($arg)*)
        };
    }
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
                                    let path = self.path_options.owned_data_path(&hash);
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
                                            continue;
                                        };
                                        if metadata.len() != size {
                                            entry_error!(
                                                hash,
                                                "external data file size mismatch: {}",
                                                path.display()
                                            );
                                            continue;
                                        }
                                    }
                                    size
                                }
                            };
                            match outboard_location {
                                OutboardLocation::Inline(_) => {
                                    let Ok(inline_outboard) = inline_outboard.get(hash) else {
                                        entry_error!(hash, "inline outboard can not be accessed");
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
                                        self.path_options.owned_outboard_path(&hash).metadata()
                                    else {
                                        entry_error!(hash, "owned outboard file does not exist");
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
                            if !self.path_options.owned_data_path(&hash).exists() {
                                entry_error!(hash, "persistent partial entry has no data");
                            }
                            if !self.path_options.owned_outboard_path(&hash).exists() {
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
                        entry_error!(hash, "orphaned inline outboard");
                    }
                }
            }
            Err(cause) => {
                error!("failed to iterate inline_outboard: {}", cause);
            }
        };
        info!("checking for unexpected or orphaned files");
        for entry in self.path_options.data_path.read_dir()? {
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
        Ok(())
    }
}
