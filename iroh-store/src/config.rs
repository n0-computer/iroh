use std::path::PathBuf;

/// The configuration for the store.
#[derive(Debug, Clone)]
pub struct Config {
    /// The location of the content database.
    pub path: PathBuf,
}
