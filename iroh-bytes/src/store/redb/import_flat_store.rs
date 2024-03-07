//! Import a flat store into the redb store
//!
//! This is a separate module since it contains a lot of code that is unrelated
//! to the rest of the redb store.
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
};

use crate::{
    store::{
        bao_file::raw_outboard_size,
        redb::{tables::Tables, DataLocation, EntryState, OutboardLocation},
    },
    util::Tag,
    IROH_BLOCK_SIZE,
};

use super::{ActorResult, ActorState, FlatStorePaths};
use iroh_base::hash::{Hash, HashAndFormat};
use redb::ReadableTable;
use std::str::FromStr;

/// A file name that indicates the purpose of the file.
#[derive(Clone, PartialEq, Eq)]
pub enum FileName {
    /// Incomplete data for the hash, with an unique id
    PartialData(Hash, [u8; 16]),
    /// File is storing data for the hash
    Data(Hash),
    /// File is storing a partial outboard
    PartialOutboard(Hash, [u8; 16]),
    /// File is storing an outboard
    ///
    /// We can have multiple files with the same outboard, in case the outboard
    /// does not contain hashes. But we don't store those outboards.
    Outboard(Hash),
    #[allow(dead_code)]
    /// Temporary paths file
    TempPaths(Hash, [u8; 16]),
    /// External paths for the hash
    Paths(Hash),
    /// File is going to be used to store metadata
    Meta(Vec<u8>),
}

impl FileName {
    /// Get the file purpose from a path, handling weird cases
    pub fn from_path(path: impl AsRef<Path>) -> std::result::Result<Self, &'static str> {
        let path = path.as_ref();
        let name = path.file_name().ok_or("no file name")?;
        let name = name.to_str().ok_or("invalid file name")?;
        let purpose = Self::from_str(name).map_err(|_| "invalid file name")?;
        Ok(purpose)
    }
}

impl FromStr for FileName {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        const OUTBOARD_EXT: &str = "obao4";
        // split into base and extension
        let Some((base, ext)) = s.rsplit_once('.') else {
            return Err(());
        };
        // strip optional leading dot
        let base = base.strip_prefix('.').unwrap_or(base);
        let mut hash = [0u8; 32];
        if let Some((base, uuid_text)) = base.split_once('-') {
            let mut uuid = [0u8; 16];
            hex::decode_to_slice(uuid_text, &mut uuid).map_err(|_| ())?;
            if ext == "data" {
                hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
                Ok(Self::PartialData(hash.into(), uuid))
            } else if ext == OUTBOARD_EXT {
                hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
                Ok(Self::PartialOutboard(hash.into(), uuid))
            } else {
                Err(())
            }
        } else if ext == "meta" {
            let data = hex::decode(base).map_err(|_| ())?;
            Ok(Self::Meta(data))
        } else {
            hex::decode_to_slice(base, &mut hash).map_err(|_| ())?;
            if ext == "data" {
                Ok(Self::Data(hash.into()))
            } else if ext == OUTBOARD_EXT {
                Ok(Self::Outboard(hash.into()))
            } else if ext == "paths" {
                Ok(Self::Paths(hash.into()))
            } else {
                Err(())
            }
        }
    }
}

impl ActorState {
    pub(super) fn import_flat_store(
        &mut self,
        db: &redb::Database,
        paths: FlatStorePaths,
    ) -> ActorResult<bool> {
        #[derive(Debug, Default)]
        struct EntryPaths {
            data: Option<(PathBuf, u64)>,
            outboard: Option<(PathBuf, u64)>,
            external: Vec<(PathBuf, u64)>,
            #[allow(clippy::type_complexity)]
            partial: BTreeMap<[u8; 16], (Option<(PathBuf, u64)>, Option<(PathBuf, u64)>)>,
        }

        fn copy_outboard(src: &Path, tgt: &Path) -> io::Result<()> {
            let mut data = std::fs::read(src)?;
            if data.len() % 64 != 8 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "outboard without length prefix",
                ));
            }
            data.splice(0..8, []);
            std::fs::write(tgt, data)
        }

        let FlatStorePaths {
            complete: complete_path,
            partial: partial_path,
            meta: meta_path,
        } = &paths;
        let mut index = BTreeMap::<Hash, EntryPaths>::new();
        let mut have_partial = false;
        let mut have_complete = false;
        let mut have_meta = false;
        if partial_path.exists() {
            tracing::info!("importing partial data from {:?}", partial_path);
            for entry in std::fs::read_dir(partial_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let Ok(meta) = entry.metadata() else {
                        tracing::warn!("unable to open file {}", path.display());
                        continue;
                    };
                    let size = meta.len();
                    if let Ok(purpose) = FileName::from_path(&path) {
                        match purpose {
                            FileName::PartialData(hash, uuid) => {
                                let m = index.entry(hash).or_default();
                                m.partial.entry(uuid).or_default().0 = Some((path, size));
                            }
                            FileName::PartialOutboard(hash, uuid) => {
                                let m = index.entry(hash).or_default();
                                m.partial.entry(uuid).or_default().0 = Some((path, size));
                            }
                            _ => {
                                // silently ignore other files, there could be a valid reason for them
                            }
                        }
                    }
                }
            }
            have_partial = true;
        }

        if complete_path.exists() {
            tracing::info!("importing complete data from {:?}", complete_path);
            for entry in std::fs::read_dir(complete_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let Ok(meta) = entry.metadata() else {
                        tracing::warn!("unable to open file {}", path.display());
                        continue;
                    };
                    let size = meta.len();
                    if let Ok(purpose) = FileName::from_path(&path) {
                        match purpose {
                            FileName::Data(hash) => {
                                let m = index.entry(hash).or_default();
                                m.data = Some((path, size));
                            }
                            FileName::Outboard(hash) => {
                                let m = index.entry(hash).or_default();
                                m.outboard = Some((path, size));
                            }
                            FileName::Paths(hash) => {
                                let m = index.entry(hash).or_default();
                                let paths = std::fs::read(path)?;
                                let paths: BTreeSet<PathBuf> = postcard::from_bytes(&paths)
                                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                                for path in paths {
                                    let Ok(meta) = path.metadata() else {
                                        tracing::warn!(
                                            "unable to open external file {}",
                                            path.display()
                                        );
                                        continue;
                                    };
                                    m.external.push((path, meta.len()));
                                }
                            }
                            _ => {
                                // silently ignore other files, there could be a valid reason for them
                            }
                        }
                    }
                }
            }
            have_complete = true;
        }

        let txn = db.begin_write()?;
        let mut tables = Tables::new(&txn)?;
        for (hash, entry) in index {
            if tables.blobs.get(hash)?.is_some() {
                tracing::info!("hash {} already exists in the db", hash.to_hex());
                continue;
            }
            if let Some((data_path, data_size)) = entry.data {
                let needs_outboard = data_size > IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, outboard_size)) = entry.outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    if outboard_size != raw_outboard_size(data_size) + 8 {
                        tracing::warn!("outboard file has wrong size for {}", hash.to_hex());
                        continue;
                    }
                    Some(outboard_path)
                } else {
                    None
                };
                if let Err(cause) =
                    std::fs::rename(data_path, self.path_options.owned_data_path(&hash))
                {
                    tracing::error!("failed to move data file: {}", cause);
                    continue;
                }
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let entry = EntryState::Complete {
                    data_location: DataLocation::Owned(data_size),
                    outboard_location: if needs_outboard {
                        OutboardLocation::Owned
                    } else {
                        OutboardLocation::NotNeeded
                    },
                };
                tables.blobs.insert(hash, entry)?;
                continue;
            }
            if !entry.external.is_empty() {
                let sizes = entry.external.iter().map(|x| x.1).collect::<Vec<_>>();
                if sizes.iter().min() != sizes.iter().max() {
                    tracing::warn!("external files for {} have different sizes", hash.to_hex());
                    continue;
                }
                let size = sizes[0];
                let needs_outboard = size > IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, outboard_size)) = entry.outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    if outboard_size != raw_outboard_size(size) + 8 {
                        tracing::warn!("outboard file has wrong size for {}", hash.to_hex());
                        continue;
                    }
                    Some(outboard_path)
                } else {
                    None
                };
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let paths = entry
                    .external
                    .into_iter()
                    .map(|(path, _size)| path)
                    .collect();
                let entry = EntryState::Complete {
                    data_location: DataLocation::External(paths, size),
                    outboard_location: if needs_outboard {
                        OutboardLocation::Owned
                    } else {
                        OutboardLocation::NotNeeded
                    },
                };
                tables.blobs.insert(hash, entry)?;
                continue;
            }
            // partial entries that have data
            let partial_with_data = entry
                .partial
                .into_iter()
                .filter_map(|(_k, (d, o))| d.map(|d| (d, o)));
            let largest_partial = partial_with_data.max_by_key(|((_, size), _o)| *size);
            if let Some(((data_path, data_size), outboard)) = largest_partial {
                let needs_outboard = data_size >= IROH_BLOCK_SIZE.bytes() as u64;
                let outboard_path = if needs_outboard {
                    let Some((outboard_path, _)) = outboard else {
                        tracing::warn!("missing outboard file for {}", hash.to_hex());
                        continue;
                    };
                    Some(outboard_path)
                } else {
                    None
                };
                if let Err(cause) =
                    std::fs::rename(data_path, self.path_options.owned_data_path(&hash))
                {
                    tracing::error!("failed to move data file: {}", cause);
                    continue;
                }
                if let Some(outboard_path) = outboard_path {
                    if let Err(cause) = copy_outboard(
                        &outboard_path,
                        &self.path_options.owned_outboard_path(&hash),
                    ) {
                        tracing::error!("failed to move outboard file: {}", cause);
                        continue;
                    }
                }
                let entry = EntryState::Partial { size: None };
                tables.blobs.insert(hash, entry)?;
                continue;
            }
        }
        // import tags, this is pretty straightforward
        if meta_path.exists() {
            tracing::info!("importing metadata from {:?}", meta_path);
            let tags_path = meta_path.join("tags.meta");
            if tags_path.exists() {
                let data = std::fs::read(&tags_path)?;
                #[allow(clippy::mutable_key_type)]
                let tags: BTreeMap<Tag, HashAndFormat> = postcard::from_bytes(&data)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                tracing::debug!("loaded tags. {} entries", tags.len());
                for (tag, content) in tags {
                    tables.tags.insert(tag, content)?;
                }
                std::fs::remove_file(tags_path).ok();
            };
            have_meta = true;
        }

        drop(tables);
        txn.commit()?;

        if have_partial {
            tracing::trace!("removing flat db partial path {:?}", partial_path);
            if let Err(cause) = std::fs::remove_dir_all(partial_path) {
                tracing::error!("failed to remove partial path: {}", cause);
            }
        }
        if have_complete {
            tracing::trace!("removing flat db complete path {:?}", complete_path);
            if let Err(cause) = std::fs::remove_dir_all(complete_path) {
                tracing::error!("failed to remove complete path: {}", cause);
            }
        }
        if have_meta {
            tracing::trace!("removing flat db meta path {:?}", meta_path);
            if let Err(cause) = std::fs::remove_dir_all(meta_path) {
                tracing::error!("failed to remove meta path: {}", cause);
            }
        }
        Ok(have_partial || have_complete)
    }
}
