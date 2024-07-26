//! Utilities for working with tokio io
use bao_tree::io::EncodeError;
use derive_more::Display;
use thiserror::Error;

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
