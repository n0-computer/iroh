//! Various database implementations for storing blob data

use rand::Rng;

#[cfg(feature = "flat-db")]
pub mod flat;
#[cfg(feature = "mem-db")]
pub mod mem;

pub mod readonly_mem;

#[cfg(any(feature = "mem-db", feature = "flat-db"))]
fn flatten_to_io<T>(
    e: std::result::Result<std::io::Result<T>, tokio::task::JoinError>,
) -> std::io::Result<T> {
    match e {
        Ok(x) => x,
        Err(cause) => Err(std::io::Error::new(std::io::ErrorKind::Other, cause)),
    }
}

/// Create a 16 byte unique ID.
#[cfg(any(feature = "mem-db", feature = "flat-db"))]
fn new_uuid() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}

/// Create temp file name based on a 16 byte UUID.
#[cfg(any(feature = "mem-db", feature = "flat-db"))]
fn temp_name() -> String {
    format!("{}.temp", hex::encode(new_uuid()))
}
