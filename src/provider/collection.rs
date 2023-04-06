//! Tools to build a collection to be added to a provider database.
//!
//! To create a collection one needs to create the [`Collection`] struct itself from all the
//! blobs and treat this as a blob itself.  Then all blobs, including the "collection blob"
//! are inserted in a hashmap.

use std::collections::HashMap;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use bao_tree::outboard::PostOrderMemOutboard;
use bytes::Bytes;
use futures::{stream, StreamExt};
use tracing::{trace, trace_span};

use crate::blobs::{Blob, Collection};
use crate::protocol::MAX_MESSAGE_SIZE;
use crate::rpc_protocol::ProvideProgress;
use crate::util::{Progress, ProgressReader, ProgressReaderUpdate};
use crate::{Hash, IROH_BLOCK_SIZE};

use super::{BlobOrCollection, DataSource};

/// Creates a collection blob and returns all blobs in a hashmap.
///
/// Returns the hashmap with all blobs, including the created collection blob itself, as
/// well as the [`Hash`] of the collection blob.
pub(super) async fn create_collection(
    data_sources: Vec<DataSource>,
    progress: Progress<ProvideProgress>,
) -> Result<(HashMap<Hash, BlobOrCollection>, Hash)> {
    let mut outboards = compute_all_outboards(data_sources, progress.clone()).await?;

    // TODO: Don't sort on async runtime?
    outboards.sort_by_key(|o| (o.name.clone(), o.hash));

    let mut map = HashMap::with_capacity(outboards.len() + 1);
    let mut blobs = Vec::with_capacity(outboards.len());
    let mut total_blobs_size: u64 = 0;

    for BlobWithOutboard {
        path,
        name,
        size,
        hash,
        outboard,
    } in outboards
    {
        debug_assert!(outboard.len() >= 8, "outboard must at least contain size");
        map.insert(
            hash,
            BlobOrCollection::Blob {
                outboard,
                path,
                size,
            },
        );
        total_blobs_size += size;
        blobs.push(Blob { name, hash });
    }

    let collection = Collection::new(blobs, total_blobs_size)?;
    let data = postcard::to_stdvec(&collection).context("collection blob encoding")?;
    if data.len() > MAX_MESSAGE_SIZE {
        bail!("Serialised collection exceeds {MAX_MESSAGE_SIZE}");
    }
    let (outboard, hash) = bao_tree::outboard(&data, IROH_BLOCK_SIZE);
    let hash = Hash::from(hash);
    map.insert(
        hash,
        BlobOrCollection::Collection {
            outboard: Bytes::from(outboard),
            data: Bytes::from(data.to_vec()),
        },
    );
    progress.send(ProvideProgress::AllDone { hash }).await?;
    Ok((map, hash))
}

/// Outboard data for a blob.
struct BlobWithOutboard {
    /// The path of the file containing the original blob data.
    path: PathBuf,
    /// The blob name.
    // TODO: This is not optional!  crate::blobs::Blob::name is String.
    name: String,
    /// The size of the original data.
    size: u64,
    /// The hash of the blob.
    hash: Hash,
    /// The bao outboard data.
    outboard: Bytes,
}

/// Computes all the outboards, using parallelism.
async fn compute_all_outboards(
    data_sources: Vec<DataSource>,
    progress: Progress<ProvideProgress>,
) -> Result<Vec<BlobWithOutboard>> {
    let outboards: Vec<_> = stream::iter(data_sources)
        .enumerate()
        .map(|(id, data)| {
            let progress = progress.clone();
            tokio::task::spawn_blocking(move || outboard_from_datasource(id as u64, data, progress))
        })
        // Allow at most num_cpus tasks at a time, otherwise we might get too many open
        // files.
        // TODO: this assumes that this is 100% cpu bound, which is likely not true.  we
        // might get better performance by using a larger number here.
        .buffer_unordered(num_cpus::get())
        .collect()
        .await;

    // Flatten JoinError and computation error, then bail on any error.
    outboards
        .into_iter()
        .map(|join_res| {
            join_res
                .map_err(|_| anyhow::Error::msg("Task JoinError"))
                .and_then(|res| res)
        })
        .collect::<Result<Vec<BlobWithOutboard>>>()
}

/// Computes a single outboard synchronously.
///
/// This includes the file access and sending progress reports.  Moving all file access here
/// is simpler and faster to do on the sync pool anyway.
fn outboard_from_datasource(
    id: u64,
    data_source: DataSource,
    progress: Progress<ProvideProgress>,
) -> Result<BlobWithOutboard> {
    let file_meta = data_source.path().metadata().with_context(|| {
        format!(
            "Failed to read file size from {}",
            data_source.path().display()
        )
    })?;
    let size = file_meta.len();
    // TODO: Found should really send the PathBuf, not the name?
    progress.blocking_send(ProvideProgress::Found {
        name: data_source.name().to_string(),
        id,
        size,
    });
    let (hash, outboard) = {
        let progress = progress.clone();
        compute_outboard(data_source.path(), size, move |offset| {
            progress.try_send(ProvideProgress::Progress { id, offset })
        })?
    };
    progress.blocking_send(ProvideProgress::Done { id, hash });
    Ok(BlobWithOutboard {
        path: data_source.path().to_path_buf(),
        name: data_source.name().to_string(),
        size,
        hash,
        outboard: Bytes::from(outboard),
    })
}

/// Synchronously compute the outboard of a file, and return hash and outboard.
///
/// It is assumed that the file is not modified while this is running.
///
/// If it is modified while or after this is running, the outboard will be
/// invalid, so any attempt to compute a slice from it will fail.
///
/// If the size of the file is changed while this is running, an error will be
/// returned.
fn compute_outboard(
    path: &Path,
    size: u64,
    progress: impl Fn(u64) + Send + Sync + 'static,
) -> anyhow::Result<(Hash, Vec<u8>)> {
    ensure!(
        path.is_file(),
        "can only transfer blob data: {}",
        path.display()
    );
    let span = trace_span!("outboard.compute", path = %path.display());
    let _guard = span.enter();
    let file = std::fs::File::open(path)?;
    // compute outboard size so we can pre-allocate the buffer.
    //
    // outboard is ~1/16 of data size, so this will fail for really large files
    // on really small devices. E.g. you want to transfer a 1TB file from a pi4 with 1gb ram.
    //
    // The way to solve this would be to have larger blocks than the blake3 chunk size of 1024.
    // I think we really want to keep the outboard in memory for simplicity.
    let outboard_size = usize::try_from(bao_tree::outboard_size(size, IROH_BLOCK_SIZE))
        .context("outboard too large to fit in memory")?;
    let mut outboard = Vec::with_capacity(outboard_size);

    // wrap the reader in a progress reader, so we can report progress.
    let reader = ProgressReader::new(file, |p| {
        if let ProgressReaderUpdate::Progress(offset) = p {
            progress(offset);
        }
    });
    // wrap the reader in a buffered reader, so we read in large chunks
    // this reduces the number of io ops and also the number of progress reports
    let mut reader = BufReader::with_capacity(1024 * 1024, reader);

    let hash =
        bao_tree::io::sync::outboard_post_order(&mut reader, size, IROH_BLOCK_SIZE, &mut outboard)?;
    let ob = PostOrderMemOutboard::load(hash, Cursor::new(&outboard), IROH_BLOCK_SIZE)?.flip();
    trace!(%hash, "done");

    Ok((hash.into(), ob.into_inner()))
}
