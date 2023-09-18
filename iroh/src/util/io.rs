//! Utilities for working with tokio io
use bao_tree::io::EncodeError;
use derive_more::Display;
use std::{io::Write, path::PathBuf};
use thiserror::Error;

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
