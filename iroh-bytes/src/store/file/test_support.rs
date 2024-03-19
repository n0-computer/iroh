//! DB functions to support testing
//!
//! For some tests we need to modify the state of the store in ways that are not
//! possible through the public API. This module provides functions to do that.
use std::{
    io,
    path::{Path, PathBuf},
};

use futures::channel::oneshot;

use super::{
    tables::{ReadableTables, Tables},
    ActorError, ActorMessage, ActorResult, ActorState, DataLocation, EntryState, FilterPredicate,
    OutboardLocation, OuterResult, Store, StoreInner,
};
use crate::{
    store::{
        bao_file::{raw_outboard_size, SizeInfo},
        DbIter,
    },
    Hash,
};
use redb::ReadableTable;

/// The full state of an entry, including the data.
#[derive(derive_more::Debug)]
pub enum EntryData {
    /// Complete
    Complete {
        /// Data
        #[debug("data")]
        data: Vec<u8>,
        /// Outboard
        #[debug("outboard")]
        outboard: Vec<u8>,
    },
    /// Partial
    Partial {
        /// Data
        #[debug("data")]
        data: Vec<u8>,
        /// Outboard
        #[debug("outboard")]
        outboard: Vec<u8>,
        /// Sizes
        #[debug("sizes")]
        sizes: Vec<u8>,
    },
}

impl Store {
    /// Get the complete state of an entry, both in memory and in redb.
    #[cfg(test)]
    pub(crate) async fn entry_state(&self, hash: Hash) -> io::Result<EntryStateResponse> {
        Ok(self.0.entry_state(hash).await?)
    }

    async fn all_blobs(&self) -> io::Result<DbIter<Hash>> {
        Ok(Box::new(self.0.all_blobs().await?.into_iter()))
    }

    /// Transform all entries in the store. This is for testing and can be used to get the store
    /// in a wrong state.
    pub async fn transform_entries(
        &self,
        transform: impl Fn(Hash, EntryData) -> Option<EntryData> + Send + Sync,
    ) -> io::Result<()> {
        let blobs = self.all_blobs().await?;
        for blob in blobs {
            let hash = blob?;
            let entry = self.get_full_entry_state(hash).await?;
            if let Some(entry) = entry {
                let entry1 = transform(hash, entry);
                self.set_full_entry_state(hash, entry1).await?;
            }
        }
        Ok(())
    }

    /// Set the full entry state for a hash. This is for testing and can be used to get the store
    /// in a wrong state.
    pub(crate) async fn set_full_entry_state(
        &self,
        hash: Hash,
        entry: Option<EntryData>,
    ) -> io::Result<()> {
        Ok(self.0.set_full_entry_state(hash, entry).await?)
    }

    /// Set the full entry state for a hash. This is for testing and can be used to get the store
    /// in a wrong state.
    pub(crate) async fn get_full_entry_state(&self, hash: Hash) -> io::Result<Option<EntryData>> {
        Ok(self.0.get_full_entry_state(hash).await?)
    }

    /// Owned data path
    pub fn owned_data_path(&self, hash: &Hash) -> PathBuf {
        self.0.path_options.owned_data_path(hash)
    }

    /// Owned outboard path
    pub fn owned_outboard_path(&self, hash: &Hash) -> PathBuf {
        self.0.path_options.owned_outboard_path(hash)
    }
}

impl StoreInner {
    #[cfg(test)]
    async fn entry_state(&self, hash: Hash) -> OuterResult<EntryStateResponse> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(ActorMessage::EntryState { hash, tx })
            .await?;
        Ok(rx.recv_async().await??)
    }

    async fn set_full_entry_state(&self, hash: Hash, entry: Option<EntryData>) -> OuterResult<()> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(ActorMessage::SetFullEntryState { hash, entry, tx })
            .await?;
        Ok(rx.recv_async().await??)
    }

    async fn get_full_entry_state(&self, hash: Hash) -> OuterResult<Option<EntryData>> {
        let (tx, rx) = flume::bounded(1);
        self.tx
            .send_async(ActorMessage::GetFullEntryState { hash, tx })
            .await?;
        Ok(rx.recv_async().await??)
    }

    async fn all_blobs(&self) -> OuterResult<Vec<io::Result<Hash>>> {
        let (tx, rx) = oneshot::channel();
        let filter: FilterPredicate<Hash, EntryState> =
            Box::new(|_i, k, v| Some((k.value(), v.value())));
        self.tx
            .send_async(ActorMessage::Blobs { filter, tx })
            .await?;
        let blobs = rx.await?;
        let res = blobs
            .into_iter()
            .map(|r| {
                r.map(|(hash, _)| hash)
                    .map_err(|e| ActorError::from(e).into())
            })
            .collect::<Vec<_>>();
        Ok(res)
    }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct EntryStateResponse {
    pub mem: Option<crate::store::bao_file::BaoFileHandle>,
    pub db: Option<EntryState<Vec<u8>>>,
}

impl ActorState {
    pub(super) fn get_full_entry_state(
        &mut self,
        tables: &impl ReadableTables,
        hash: Hash,
    ) -> ActorResult<Option<EntryData>> {
        let data_path = self.path_options.owned_data_path(&hash);
        let outboard_path = self.path_options.owned_outboard_path(&hash);
        let sizes_path = self.path_options.owned_sizes_path(&hash);
        let entry = match tables.blobs().get(hash)? {
            Some(guard) => match guard.value() {
                EntryState::Complete {
                    data_location,
                    outboard_location,
                } => {
                    let data = match data_location {
                        DataLocation::External(paths, size) => {
                            let path = paths.first().ok_or_else(|| {
                                ActorError::Inconsistent("external data missing".to_owned())
                            })?;
                            let res = std::fs::read(path)?;
                            if res.len() != size as usize {
                                return Err(ActorError::Inconsistent(
                                    "external data size mismatch".to_owned(),
                                ));
                            }
                            res
                        }
                        DataLocation::Owned(size) => {
                            let res = std::fs::read(data_path)?;
                            if res.len() != size as usize {
                                return Err(ActorError::Inconsistent(
                                    "owned data size mismatch".to_owned(),
                                ));
                            }
                            res
                        }
                        DataLocation::Inline(_) => {
                            let data = tables.inline_data().get(hash)?.ok_or_else(|| {
                                ActorError::Inconsistent("inline data missing".to_owned())
                            })?;
                            data.value().to_vec()
                        }
                    };
                    let expected_outboard_size = raw_outboard_size(data.len() as u64);
                    let outboard = match outboard_location {
                        OutboardLocation::Owned => std::fs::read(outboard_path)?,
                        OutboardLocation::Inline(_) => tables
                            .inline_outboard()
                            .get(hash)?
                            .ok_or_else(|| {
                                ActorError::Inconsistent("inline outboard missing".to_owned())
                            })?
                            .value()
                            .to_vec(),
                        OutboardLocation::NotNeeded => Vec::new(),
                    };
                    if outboard.len() != expected_outboard_size as usize {
                        return Err(ActorError::Inconsistent(
                            "outboard size mismatch".to_owned(),
                        ));
                    }
                    Some(EntryData::Complete { data, outboard })
                }
                EntryState::Partial { .. } => {
                    let data = std::fs::read(data_path)?;
                    let outboard = std::fs::read(outboard_path)?;
                    let sizes = std::fs::read(sizes_path)?;
                    Some(EntryData::Partial {
                        data,
                        outboard,
                        sizes,
                    })
                }
            },
            None => None,
        };
        Ok(entry)
    }

    pub(super) fn set_full_entry_state(
        &mut self,
        tables: &mut Tables,
        hash: Hash,
        entry: Option<EntryData>,
    ) -> ActorResult<()> {
        let data_path = self.path_options.owned_data_path(&hash);
        let outboard_path = self.path_options.owned_outboard_path(&hash);
        let sizes_path = self.path_options.owned_sizes_path(&hash);
        // tabula rasa
        std::fs::remove_file(&outboard_path).ok();
        std::fs::remove_file(&data_path).ok();
        std::fs::remove_file(&sizes_path).ok();
        tables.inline_data.remove(&hash)?;
        tables.inline_outboard.remove(&hash)?;
        let Some(entry) = entry else {
            tables.blobs.remove(&hash)?;
            return Ok(());
        };
        // write the new data and determine the new state
        let entry = match entry {
            EntryData::Complete { data, outboard } => {
                let data_size = data.len() as u64;
                let data_location = if data_size > self.inline_options.max_data_inlined {
                    std::fs::write(data_path, &data)?;
                    DataLocation::Owned(data_size)
                } else {
                    tables.inline_data.insert(hash, data.as_slice())?;
                    DataLocation::Inline(())
                };
                let outboard_size = outboard.len() as u64;
                let outboard_location = if outboard_size > self.inline_options.max_outboard_inlined
                {
                    std::fs::write(outboard_path, &outboard)?;
                    OutboardLocation::Owned
                } else if outboard_size > 0 {
                    tables.inline_outboard.insert(hash, outboard.as_slice())?;
                    OutboardLocation::Inline(())
                } else {
                    OutboardLocation::NotNeeded
                };
                EntryState::Complete {
                    data_location,
                    outboard_location,
                }
            }
            EntryData::Partial {
                data,
                outboard,
                sizes,
            } => {
                std::fs::write(data_path, data)?;
                std::fs::write(outboard_path, outboard)?;
                std::fs::write(sizes_path, sizes)?;
                EntryState::Partial { size: None }
            }
        };
        // finally, write the state
        tables.blobs.insert(hash, entry)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn entry_state(
        &mut self,
        tables: &impl ReadableTables,
        hash: Hash,
    ) -> ActorResult<EntryStateResponse> {
        let mem = self.handles.get(&hash).and_then(|weak| weak.upgrade());
        let db = match tables.blobs().get(hash)? {
            Some(entry) => Some({
                match entry.value() {
                    EntryState::Complete {
                        data_location,
                        outboard_location,
                    } => {
                        let data_location = match data_location {
                            DataLocation::Inline(()) => {
                                let data = tables.inline_data().get(hash)?.ok_or_else(|| {
                                    ActorError::Inconsistent("inline data missing".to_owned())
                                })?;
                                DataLocation::Inline(data.value().to_vec())
                            }
                            DataLocation::Owned(x) => DataLocation::Owned(x),
                            DataLocation::External(p, s) => DataLocation::External(p, s),
                        };
                        let outboard_location = match outboard_location {
                            OutboardLocation::Inline(()) => {
                                let outboard =
                                    tables.inline_outboard().get(hash)?.ok_or_else(|| {
                                        ActorError::Inconsistent(
                                            "inline outboard missing".to_owned(),
                                        )
                                    })?;
                                OutboardLocation::Inline(outboard.value().to_vec())
                            }
                            OutboardLocation::Owned => OutboardLocation::Owned,
                            OutboardLocation::NotNeeded => OutboardLocation::NotNeeded,
                        };
                        EntryState::Complete {
                            data_location,
                            outboard_location,
                        }
                    }
                    EntryState::Partial { size } => EntryState::Partial { size },
                }
            }),
            None => None,
        };
        Ok(EntryStateResponse { mem, db })
    }
}

/// What do to with a file pair when making partial files
#[derive(Debug)]
pub enum MakePartialResult {
    /// leave the file as is
    Retain,
    /// remove it entirely
    Remove,
    /// truncate the data file to the given size
    Truncate(u64),
}

/// Open a database and make it partial.
pub fn make_partial(
    path: &Path,
    f: impl Fn(Hash, u64) -> MakePartialResult + Send + Sync,
) -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .build()?
        .block_on(async move {
            let blobs_path = path.join("blobs");
            let store = Store::load(blobs_path).await?;
            store
                .transform_entries(|hash, entry| match &entry {
                    EntryData::Complete { data, outboard } => match f(hash, data.len() as u64) {
                        MakePartialResult::Retain => Some(entry),
                        MakePartialResult::Remove => None,
                        MakePartialResult::Truncate(size) => {
                            let current_size = data.len() as u64;
                            if size < current_size {
                                let size = size as usize;
                                let sizes = SizeInfo::complete(current_size).to_vec();
                                Some(EntryData::Partial {
                                    data: data[..size].to_vec(),
                                    outboard: outboard.to_vec(),
                                    sizes,
                                })
                            } else {
                                Some(entry)
                            }
                        }
                    },
                    EntryData::Partial { .. } => Some(entry),
                })
                .await?;
            Ok(())
        })
}
