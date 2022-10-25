use anyhow::{anyhow, Error};
use std::io;
use thiserror::Error as ThisError;

/// LockError is the set of known program lock errors
#[derive(ThisError, Debug)]
pub enum ApiError<'a> {
    #[error("Can't connect to {service}. Is the service running?")]
    ConnectionRefused { service: &'a str },
    /// catchall error type
    #[error("{source}")]
    Uncategorized {
        #[from]
        source: anyhow::Error,
    },
}

pub fn map_service_error(service: &'static str, e: Error) -> Error {
    let io_error = e.root_cause().downcast_ref::<io::Error>();
    if let Some(io_error) = io_error {
        if io_error.kind() == io::ErrorKind::ConnectionRefused {
            return anyhow!(ApiError::ConnectionRefused { service });
        }
    }
    e
}
