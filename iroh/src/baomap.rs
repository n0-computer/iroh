//! Various database implementations for storing blob data
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
