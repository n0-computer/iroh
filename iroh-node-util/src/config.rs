//! Utilities to get default paths for configuration, data, and cache directories.
use std::{env, path::PathBuf};

use anyhow::{anyhow, Result};

/// Returns the path to the user's config directory for the given binary.
///
/// This is determined by the following steps:
/// - If the environment variable `<BIN>_CONFIG_DIR` is set, return that.
/// - If the operating environment provides a config directory, return `$CONFIG_DIR/<bin>`.
/// - Otherwise, return an error.
///
/// The default directories are as follows:
///
/// | Platform | Value                                 | Example                          |
/// | -------- | ------------------------------------- | -------------------------------- |
/// | Linux    | `$XDG_CONFIG_HOME` or `$HOME`/.config/iroh | /home/alice/.config/iroh              |
/// | macOS    | `$HOME`/Library/Application Support/iroh   | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}`/iroh           | C:\Users\Alice\AppData\Roaming\iroh   |
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
/// - If the operating environment provides a data directory, return `$DATA_DIR/<bin>`.
/// - Otherwise, return an error.
///
/// The default directories are as follows:
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_DATA_HOME`/iroh or `$HOME`/.local/share/iroh | /home/alice/.local/share/iroh                 |
/// | macOS    | `$HOME`/Library/Application Support/iroh      | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}/iroh`              | C:\Users\Alice\AppData\Roaming\iroh           |
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
/// - If the operating environment provides a cache directory, return `$CACHE_DIR/<bin>`.
/// - Otherwise, return an error.
///
/// The default directories are as follows:
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_CACHE_HOME`/iroh or `$HOME`/.cache/iroh | /home/.cache/iroh                        |
/// | macOS    | `$HOME`/Library/Caches/iroh                   | /Users/Alice/Library/Caches/iroh         |
/// | Windows  | `{FOLDERID_LocalAppData}/iroh`                | C:\Users\Alice\AppData\Roaming\iroh      |
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
