//! Path utilities for iroh
use std::path::{Path, PathBuf};

use bao_tree::{outboard::PreOrderMemOutboard, ByteNum, ChunkNum};
use iroh_bytes::{blobs::Collection, protocol::RangeSpecSeq, util::pathbuf_from_name, Hash};
use range_collections::RangeSet2;

/// Get missing range for a single file, given a temp and target directory
///
/// This will check missing ranges from the outboard, but for the data file itself
/// just use the length of the file.
pub fn get_missing_range(
    hash: &Hash,
    name: &str,
    temp_dir: &Path,
    target_dir: &Path,
) -> std::io::Result<RangeSet2<ChunkNum>> {
    if target_dir.exists() && !temp_dir.exists() {
        // target directory exists yet does not contain the temp dir
        // refuse to continue
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Target directory exists but does not contain temp directory",
        ));
    }
    let range = get_missing_range_impl(hash, name, temp_dir, target_dir)?;
    Ok(range)
}

/// Get missing range for a single file
fn get_missing_range_impl(
    hash: &Hash,
    name: &str,
    temp_dir: &Path,
    target_dir: &Path,
) -> std::io::Result<RangeSet2<ChunkNum>> {
    let paths = FilePaths::new(hash, name, temp_dir, target_dir);
    Ok(if paths.is_final() {
        tracing::debug!("Found final file: {:?}", paths.target);
        // we assume that the file is correct
        RangeSet2::empty()
    } else if paths.is_incomplete() {
        tracing::debug!("Found incomplete file: {:?}", paths.temp);
        // we got incomplete data
        let outboard = std::fs::read(&paths.outboard)?;
        let outboard =
            PreOrderMemOutboard::new((*hash).into(), iroh_bytes::IROH_BLOCK_SIZE, outboard);
        match outboard {
            Ok(outboard) => {
                // compute set of valid ranges from the outboard and the file
                //
                // We assume that the file is correct and does not contain holes.
                // Otherwise, we would have to rehash the file.
                //
                // Do a quick check of the outboard in case something went wrong when writing.
                let mut valid = bao_tree::io::sync::valid_ranges(&outboard)?;
                let valid_from_file =
                    RangeSet2::from(..ByteNum(paths.temp.metadata()?.len()).full_chunks());
                tracing::debug!("valid_from_file: {:?}", valid_from_file);
                tracing::debug!("valid_from_outboard: {:?}", valid);
                valid &= valid_from_file;
                RangeSet2::all().difference(&valid)
            }
            Err(cause) => {
                tracing::debug!("Outboard damaged, assuming missing {cause:?}");
                // the outboard is invalid, so we assume that the file is missing
                RangeSet2::all()
            }
        }
    } else {
        tracing::debug!("Found missing file: {:?}", paths.target);
        // we don't know anything about this file, so we assume it's missing
        RangeSet2::all()
    })
}

/// Given a target directory and a temp directory, get a set of ranges that we are missing
///
/// Assumes that the temp directory contains at least the data for the collection.
/// Also assumes that partial data files do not contain gaps.
pub fn get_missing_ranges(
    hash: Hash,
    target_dir: &Path,
    temp_dir: &Path,
) -> anyhow::Result<(RangeSpecSeq, Option<Collection>)> {
    if target_dir.exists() && !temp_dir.exists() {
        // target directory exists yet does not contain the temp dir
        // refuse to continue
        anyhow::bail!("Target directory exists but does not contain temp directory");
    }
    // try to load the collection from the temp directory
    //
    // if the collection can not be deserialized, we treat it as if it does not exist
    let collection = load_collection(temp_dir, hash).ok().flatten();
    let collection = match collection {
        Some(collection) => collection,
        None => return Ok((RangeSpecSeq::all(), None)),
    };
    let mut ranges = collection
        .blobs()
        .iter()
        .map(|blob| get_missing_range_impl(&blob.hash, blob.name.as_str(), temp_dir, target_dir))
        .collect::<std::io::Result<Vec<_>>>()?;
    ranges
        .iter()
        .zip(collection.blobs())
        .for_each(|(ranges, blob)| {
            if ranges.is_empty() {
                tracing::debug!("{} is complete", blob.name);
            } else if ranges.is_all() {
                tracing::debug!("{} is missing", blob.name);
            } else {
                tracing::debug!("{} is partial {:?}", blob.name, ranges);
            }
        });
    // make room for the collection at offset 0
    // if we get here, we already have the collection, so we don't need to ask for it again.
    ranges.insert(0, RangeSet2::empty());
    Ok((RangeSpecSeq::new(ranges), Some(collection)))
}

#[derive(Debug)]
struct FilePaths {
    target: PathBuf,
    temp: PathBuf,
    outboard: PathBuf,
}

impl FilePaths {
    fn new(hash: &Hash, name: &str, temp_dir: &Path, target_dir: &Path) -> Self {
        let target = target_dir.join(pathbuf_from_name(name));
        let hash = blake3::Hash::from(*hash).to_hex();
        let temp = temp_dir.join(format!("{hash}.data.part"));
        let outboard = temp_dir.join(format!("{hash}.outboard.part"));
        Self {
            target,
            temp,
            outboard,
        }
    }

    fn is_final(&self) -> bool {
        self.target.exists()
    }

    fn is_incomplete(&self) -> bool {
        self.temp.exists() && self.outboard.exists()
    }
}

/// get data path for a hash
pub fn get_data_path(data_path: &Path, hash: Hash) -> PathBuf {
    let hash = blake3::Hash::from(hash).to_hex();
    data_path.join(format!("{hash}.data"))
}

/// Load a collection from a data path
fn load_collection(data_path: &Path, hash: Hash) -> anyhow::Result<Option<Collection>> {
    let collection_path = get_data_path(data_path, hash);
    Ok(if collection_path.exists() {
        let collection = std::fs::read(&collection_path)?;
        let collection = Collection::from_bytes(&collection)?;
        Some(collection)
    } else {
        None
    })
}
