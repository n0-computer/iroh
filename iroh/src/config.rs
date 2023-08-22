//! Configuration for the iroh CLI.

use std::{
    collections::HashMap,
    env, fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{anyhow, bail, Result};
use config::{Environment, File, Value};
use iroh_net::{
    defaults::{default_eu_derp_region, default_na_derp_region},
    derp::{DerpMap, DerpRegion},
};
use serde::{Deserialize, Serialize};
use tracing::debug;

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "iroh.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_PATH=/path/to/config` would set the value of the `Config.path` field
pub const ENV_PREFIX: &str = "IROH";

/// Paths to files or directory within the [`iroh_data_root`] used by Iroh.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum IrohPaths {
    /// Path to the node's secret key for the [`iroh_net::PublicKey`].
    SecretKey,
    /// Path to the node's [flat-file store](iroh::baomap::flat) for complete blobs.
    BaoFlatStoreComplete,
    /// Path to the node's [flat-file store](iroh::baomap::flat) for partial blobs.
    BaoFlatStorePartial,
}
impl From<&IrohPaths> for &'static str {
    fn from(value: &IrohPaths) -> Self {
        match value {
            IrohPaths::SecretKey => "keypair",
            IrohPaths::BaoFlatStoreComplete => "blobs.v0",
            IrohPaths::BaoFlatStorePartial => "blobs-partial.v0",
        }
    }
}
impl FromStr for IrohPaths {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "keypair" => Self::SecretKey,
            "blobs.v0" => Self::BaoFlatStoreComplete,
            "blobs-partial.v0" => Self::BaoFlatStorePartial,
            _ => bail!("unknown file or directory"),
        })
    }
}
impl fmt::Display for IrohPaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self.into();
        write!(f, "{s}")
    }
}
impl AsRef<Path> for IrohPaths {
    fn as_ref(&self) -> &Path {
        let s: &str = self.into();
        Path::new(s)
    }
}
impl IrohPaths {
    /// Get the path for this [`IrohPath`] by joining the name to `IROH_DATA_DIR` environment variable.
    pub fn with_env(self) -> Result<PathBuf> {
        let mut root = iroh_data_root()?;
        if !root.is_absolute() {
            root = std::env::current_dir()?.join(root);
        }
        Ok(self.with_root(root))
    }

    /// Get the path for this [`IrohPath`] by joining the name to a root directory.
    pub fn with_root(self, root: impl AsRef<Path>) -> PathBuf {
        let path = root.as_ref().join(self);
        path
    }
}

/// The configuration for the iroh cli.
#[derive(PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub struct Config {
    /// The regions for DERP to use.
    pub derp_regions: Vec<DerpRegion>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // TODO(ramfox): this should probably just be a derp map
            derp_regions: [default_na_derp_region(), default_eu_derp_region()].into(),
        }
    }
}

impl Config {
    /// Make a config using a default, files, environment variables, and commandline flags.
    ///
    /// Later items in the *file_paths* slice will have a higher priority than earlier ones.
    ///
    /// Environment variables are expected to start with the *env_prefix*. Nested fields can be
    /// accessed using `.`, if your environment allows env vars with `.`
    ///
    /// Note: For the metrics configuration env vars, it is recommended to use the metrics
    /// specific prefix `IROH_METRICS` to set a field in the metrics config. You can use the
    /// above dot notation to set a metrics field, eg, `IROH_CONFIG_METRICS.SERVICE_NAME`, but
    /// only if your environment allows it
    pub fn load<S, V>(
        file_paths: &[Option<&Path>],
        env_prefix: &str,
        flag_overrides: HashMap<S, V>,
    ) -> Result<Config>
    where
        S: AsRef<str>,
        V: Into<Value>,
    {
        let mut builder = config::Config::builder();

        // layer on config options from files
        for path in file_paths.iter().flatten() {
            if path.exists() {
                let p = path.to_str().ok_or_else(|| anyhow::anyhow!("empty path"))?;
                builder = builder.add_source(File::with_name(p));
            }
        }

        // next, add any environment variables
        builder = builder.add_source(
            Environment::with_prefix(env_prefix)
                .separator("__")
                .try_parsing(true),
        );

        // finally, override any values
        for (flag, val) in flag_overrides.into_iter() {
            builder = builder.set_override(flag, val)?;
        }

        let cfg = builder.build()?;
        debug!("make_config:\n{:#?}\n", cfg);
        let cfg = cfg.try_deserialize()?;
        Ok(cfg)
    }

    /// Constructs a `DerpMap` based on the current configuration.
    pub fn derp_map(&self) -> Option<DerpMap> {
        if self.derp_regions.is_empty() {
            return None;
        }

        let dm: DerpMap = self.derp_regions.iter().cloned().into();
        Some(dm)
    }
}

/// Name of directory that wraps all iroh files in a given application directory
const IROH_DIR: &str = "iroh";

/// Returns the path to the user's iroh config directory.
///
/// If the `IROH_CONFIG_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                 | Example                          |
/// | -------- | ------------------------------------- | -------------------------------- |
/// | Linux    | `$XDG_CONFIG_HOME` or `$HOME`/.config/iroh | /home/alice/.config/iroh              |
/// | macOS    | `$HOME`/Library/Application Support/iroh   | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}`/iroh           | C:\Users\Alice\AppData\Roaming\iroh   |
pub fn iroh_config_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_CONFIG_DIR") {
        return Ok(PathBuf::from(val));
    }
    let cfg = dirs_next::config_dir()
        .ok_or_else(|| anyhow!("operating environment provides no directory for configuration"))?;
    Ok(cfg.join(IROH_DIR))
}

/// Path that leads to a file in the iroh config directory.
pub fn iroh_config_path(file_name: impl AsRef<Path>) -> Result<PathBuf> {
    let path = iroh_config_root()?.join(file_name);
    Ok(path)
}

/// Returns the path to the user's iroh data directory.
///
/// If the `IROH_DATA_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_DATA_HOME`/iroh or `$HOME`/.local/share/iroh | /home/alice/.local/share/iroh                 |
/// | macOS    | `$HOME`/Library/Application Support/iroh      | /Users/Alice/Library/Application Support/iroh |
/// | Windows  | `{FOLDERID_RoamingAppData}/iroh`              | C:\Users\Alice\AppData\Roaming\iroh           |
pub fn iroh_data_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_DATA_DIR") {
        return Ok(PathBuf::from(val));
    }
    let path = dirs_next::data_dir().ok_or_else(|| {
        anyhow!("operating environment provides no directory for application data")
    })?;
    Ok(path.join(IROH_DIR))
}

/// Path that leads to a file in the iroh data directory.
#[allow(dead_code)]
pub fn iroh_data_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_data_root()?.join(file_name);
    Ok(path)
}

/// Returns the path to the user's iroh cache directory.
///
/// If the `IROH_CACHE_DIR` environment variable is set it will be used unconditionally.
/// Otherwise the returned value depends on the operating system according to the following
/// table.
///
/// | Platform | Value                                         | Example                                  |
/// | -------- | --------------------------------------------- | ---------------------------------------- |
/// | Linux    | `$XDG_CACHE_HOME`/iroh or `$HOME`/.cache/iroh | /home/.cache/iroh                        |
/// | macOS    | `$HOME`/Library/Caches/iroh                   | /Users/Alice/Library/Caches/iroh         |
/// | Windows  | `{FOLDERID_LocalAppData}/iroh`                | C:\Users\Alice\AppData\Roaming\iroh      |
#[allow(dead_code)]
pub fn iroh_cache_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os("IROH_CACHE_DIR") {
        return Ok(PathBuf::from(val));
    }
    let path = dirs_next::cache_dir().ok_or_else(|| {
        anyhow!("operating environment provides no directory for application data")
    })?;
    Ok(path.join(IROH_DIR))
}

/// Path that leads to a file in the iroh cache directory.
#[allow(dead_code)]
pub fn iroh_cache_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_cache_root()?.join(file_name);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let config = Config::load::<String, String>(&[][..], "__FOO", Default::default()).unwrap();

        assert_eq!(config.derp_regions.len(), 2);
    }

    #[test]
    fn test_iroh_paths_parse_roundtrip() {
        let kinds = [
            IrohPaths::BaoFlatStoreComplete,
            IrohPaths::BaoFlatStorePartial,
            IrohPaths::SecretKey,
        ];
        for iroh_path in &kinds {
            let root = PathBuf::from("/tmp");
            let path = root.join(iroh_path);
            let fname = path.file_name().unwrap().to_str().unwrap();
            let parsed = IrohPaths::from_str(fname).unwrap();
            assert_eq!(*iroh_path, parsed);
        }
    }
}
