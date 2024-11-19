//! Utilities to get default paths for configuration, data, and cache directories.
use std::{env, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};

/// Parse "<bin>_FILE_RUST_LOG` as [`tracing_subscriber::EnvFilter`]. Returns `None` if not
/// present.
pub fn env_file_rust_log(bin: &'static str) -> Option<Result<crate::logging::EnvFilter>> {
    let env_file_rust_log = format!("{}_FILE_RUST_LOG", bin.to_uppercase());
    match env::var(env_file_rust_log) {
        Ok(s) => Some(crate::logging::EnvFilter::from_str(&s).map_err(Into::into)),
        Err(e) => match e {
            env::VarError::NotPresent => None,
            e @ env::VarError::NotUnicode(_) => Some(Err(e.into())),
        },
    }
}

/// Returns the path to the user's config directory for the given binary.
///
/// This is determined by the following steps:
/// - If the environment variable `<BIN>_CONFIG_DIR` is set, return that.
/// - If the operating environment provides a config directory, return $CONFIG_DIR/<bin>.
/// - Otherwise, return an error.
pub fn config_root(bin: &'static str) -> Result<PathBuf> {
    let env_config_dir = format!("{}_CONFIG_DIR", bin.to_uppercase());
    if let Some(val) = env::var_os(env_config_dir) {
        return Ok(PathBuf::from(val));
    }
    let cfg = dirs_next::config_dir()
        .ok_or_else(|| anyhow!("operating environment provides no directory for configuration"))?;
    Ok(cfg.join(bin))
}

/// Returns the path to the user's data directory for the given binary.
///
/// This is determined by the following steps:
/// - If the environment variable `<BIN>_DATA_DIR` is set, return that.
/// - If the operating environment provides a data directory, return $DATA_DIR/<bin>.
/// - Otherwise, return an error.
pub fn data_root(bin: &'static str) -> Result<PathBuf> {
    let env_data_dir = format!("{}_DATA_DIR", bin.to_uppercase());
    let path = if let Some(val) = env::var_os(env_data_dir) {
        PathBuf::from(val)
    } else {
        let path = dirs_next::data_dir().ok_or_else(|| {
            anyhow!("operating environment provides no directory for application data")
        })?;
        path.join(bin)
    };
    let path = if !path.is_absolute() {
        std::env::current_dir()?.join(path)
    } else {
        path
    };
    Ok(path)
}

/// Returns the path to the user's cache directory for the given binary.
///
/// This is determined by the following steps:
/// - If the environment variable `<BIN>_CACHE_DIR` is set, return that.
/// - If the operating environment provides a cache directory, return $CACHE_DIR/<bin>.
/// - Otherwise, return an error.
pub fn cache_root(bin: &'static str) -> Result<PathBuf> {
    let env_cache_dir = format!("{}_CACHE_DIR", bin.to_uppercase());
    if let Some(val) = env::var_os(env_cache_dir) {
        return Ok(PathBuf::from(val));
    }
    let path = dirs_next::cache_dir().ok_or_else(|| {
        anyhow!("operating environment provides no directory for application data")
    })?;
    Ok(path.join(bin))
}
