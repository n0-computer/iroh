//! Functions to export data from a store

use std::path::PathBuf;

use anyhow::Context;
use bytes::Bytes;
use iroh_base::rpc::RpcError;
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    format::collection::Collection,
    store::{ExportMode, MapEntry, Store as BaoStore},
    util::progress::{IdGenerator, ProgressSender},
    Hash,
};

/// Export a hash to the local file system.
///
/// This exports a single hash, or a collection `recursive` is true, from the `db` store to the
/// local filesystem. Depending on `mode` the data is either copied or reflinked (if possible).
///
/// Progress is reported as [`ExportProgress`] through a [`ProgressSender`]. Note that the
/// [`ExportProgress::AllDone`] event is not emitted from here, but left to an upper layer to send,
/// if desired.
pub async fn export<D: BaoStore>(
    db: &D,
    hash: Hash,
    out: PathBuf,
    recursive: bool,
    mode: ExportMode,
    progress: impl ProgressSender<Msg = ExportProgress> + IdGenerator,
) -> anyhow::Result<()> {
    let path = PathBuf::from(&out);
    if recursive {
        tokio::fs::create_dir_all(&path).await?;
        let collection = Collection::load(db, &hash).await?;
        for (name, hash) in collection.into_iter() {
            #[allow(clippy::needless_borrow)]
            let path = path.join(pathbuf_from_name(&name));
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            trace!("exporting blob {} to {}", hash, path.display());
            let entry = db.get(&hash).context("entry not there")?;
            let id = progress.new_id();
            progress
                .send(ExportProgress::Found {
                    id,
                    hash,
                    outpath: path.clone(),
                    size: entry.size(),
                    meta: None,
                })
                .await?;
            let progress1 = progress.clone();
            db.export(hash, path, mode, move |offset| {
                Ok(progress1.try_send(ExportProgress::Progress { id, offset })?)
            })
            .await?;
            progress.send(ExportProgress::Done { id }).await?;
        }
    } else if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        let id = progress.new_id();
        let entry = db.get(&hash).context("entry not there")?;
        progress
            .send(ExportProgress::Found {
                id,
                hash,
                outpath: out,
                size: entry.size(),
                meta: None,
            })
            .await?;
        let progress1 = progress.clone();
        db.export(hash, path, mode, move |offset| {
            Ok(progress1.try_send(ExportProgress::Progress { id, offset })?)
        })
        .await?;
        progress.send(ExportProgress::Done { id }).await?;
    }
    anyhow::Ok(())
}

/// Progress events for an export operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExportProgress {
    /// The download part is done for this id, we are now exporting the data
    /// to the specified out path.
    Found {
        /// Unique id of the entry.
        id: u64,
        /// The hash of the entry.
        hash: Hash,
        /// The size of the entry in bytes.
        size: u64,
        /// The path to the file where the data is exported.
        outpath: PathBuf,
        /// Operation-specific metadata.
        meta: Option<Bytes>,
    },
    /// We have made progress exporting the data.
    ///
    /// This is only sent for large blobs.
    Progress {
        /// Unique id of the entry that is being exported.
        id: u64,
        /// The offset of the progress, in bytes.
        offset: u64,
    },
    /// We finished exporting a blob
    Done {
        /// Unique id of the entry that is being exported.
        id: u64,
    },
    /// We are done with the whole operation.
    AllDone,
    /// We got an error and need to abort.
    Abort(RpcError),
}

fn pathbuf_from_name(name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        path.push(part);
    }
    path
}
