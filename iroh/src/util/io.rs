//! Utilities for working with tokio io
use anyhow::Context;
use derive_more::Display;
use range_collections::RangeSet2;
use std::path::{Component, Path};
use std::{io::Write, path::PathBuf, result};
use thiserror::Error;

// use bao_tree::blake3;
use bao_tree::io::sync::encode_ranges_validated;
use bao_tree::io::{
    sync::{ReadAt, Size},
    EncodeError,
};
use bytes::Bytes;
use iroh_bytes::Hash;
use iroh_bytes::IROH_BLOCK_SIZE;

/// Create a pathbuf from a name.
pub fn pathbuf_from_name(name: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for part in name.split('/') {
        path.push(part);
    }
    path
}

/// Todo: gather more information about validation errors. E.g. offset
///
/// io::Error should be just the fallback when a more specific error is not available.
#[derive(Debug, Display, Error)]
pub enum BaoValidationError {
    /// Generic io error. We were unable to read the data.
    IoError(#[from] std::io::Error),
    /// The data failed to validate
    EncodeError(#[from] EncodeError),
}

/// Validate that the data matches the outboard.
pub fn validate_bao<F: Fn(u64)>(
    hash: Hash,
    data_reader: impl ReadAt + Size,
    outboard: Bytes,
    progress: F,
) -> result::Result<(), BaoValidationError> {
    let hash = blake3::Hash::from(hash);
    let outboard =
        bao_tree::io::outboard::PreOrderMemOutboard::new(hash, IROH_BLOCK_SIZE, &outboard)?;

    // do not wrap the data_reader in a BufReader, that is slow wnen seeking
    encode_ranges_validated(
        data_reader,
        outboard,
        &RangeSet2::all(),
        DevNull(0, progress),
    )?;
    Ok(())
}

/// little util that discards data but prints progress every 1MB
struct DevNull<F>(u64, F);

impl<F: Fn(u64)> Write for DevNull<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        const NOTIFY_EVERY: u64 = 1024 * 1024;
        let prev = self.0;
        let curr = prev + buf.len() as u64;
        if prev % NOTIFY_EVERY != curr % NOTIFY_EVERY {
            (self.1)(curr);
        }
        self.0 = curr;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// converts a canonicalized relative path to a string, returning an error if
/// the path is not valid unicode
///
/// this will also fail if the path is non canonical, i.e. contains `..` or `.`,
/// or if the path components contain any windows or unix path separators
pub fn canonicalize_path(path: impl AsRef<Path>) -> anyhow::Result<String> {
    let parts = path
        .as_ref()
        .components()
        .map(|c| {
            let c = if let Component::Normal(x) = c {
                x.to_str().context("invalid character in path")?
            } else {
                anyhow::bail!("invalid path component {:?}", c)
            };
            anyhow::ensure!(
                !c.contains('/') && !c.contains('\\'),
                "invalid path component {:?}",
                c
            );
            Ok(c)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_canonicalize_path() {
        assert_eq!(super::canonicalize_path("foo/bar").unwrap(), "foo/bar");
    }
}
