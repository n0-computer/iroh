//! Configuration for the iroh CLI.

use std::{
    env, fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::{anyhow, bail, Context, Result};
use iroh::net::{
    defaults::{default_eu_relay_node, default_na_relay_node, default_test_relay_node},
    relay::{RelayMap, RelayNode},
};
use iroh::node::GcPolicy;
use iroh::sync::{AuthorId, NamespaceId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

const ENV_AUTHOR: &str = "IROH_AUTHOR";
const ENV_DOC: &str = "IROH_DOC";
const ENV_CONFIG_DIR: &str = "IROH_CONFIG_DIR";
const ENV_FILE_RUST_LOG: &str = "IROH_FILE_RUST_LOG";

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub(crate) const CONFIG_FILE_NAME: &str = "iroh.config.toml";

#[derive(Debug, Clone, Copy)]
pub(crate) enum ConsolePaths {
    DefaultAuthor,
    History,
}

impl From<&ConsolePaths> for &'static str {
    fn from(value: &ConsolePaths) -> Self {
        match value {
            ConsolePaths::DefaultAuthor => "default_author.pubkey",
            ConsolePaths::History => "history",
        }
    }
}
impl FromStr for ConsolePaths {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "default_author.pubkey" => Self::DefaultAuthor,
            "history" => Self::History,
            _ => bail!("unknown file or directory"),
        })
    }
}

impl fmt::Display for ConsolePaths {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: &str = self.into();
        write!(f, "{s}")
    }
}
impl AsRef<Path> for ConsolePaths {
    fn as_ref(&self) -> &Path {
        let s: &str = self.into();
        Path::new(s)
    }
}

impl ConsolePaths {
    pub fn with_root(self, root: impl AsRef<Path>) -> PathBuf {
        PathBuf::from(root.as_ref()).join(self)
    }
}

/// The configuration for an iroh node.
#[derive(PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
#[serde(default)]
pub(crate) struct NodeConfig {
    /// The nodes for relay to use.
    pub(crate) relay_nodes: Vec<RelayNode>,
    /// How often to run garbage collection.
    pub(crate) gc_policy: GcPolicy,
    /// Bind address on which to serve Prometheus metrics
    pub(crate) metrics_addr: Option<SocketAddr>,
    pub(crate) file_logs: super::logging::FileLogging,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            // TODO(ramfox): this should probably just be a relay map
            relay_nodes: [
                /*default_na_relay_node(), default_eu_relay_node(), */
                default_test_relay_node(),
            ]
            .into(),
            gc_policy: GcPolicy::Disabled,
            metrics_addr: Some(([127, 0, 0, 1], 9090).into()),
            file_logs: Default::default(),
        }
    }
}

impl NodeConfig {
    /// Create a config using defaults, and the passed in config file.
    pub async fn load(file: Option<&Path>) -> Result<NodeConfig> {
        let default_config = iroh_config_path(CONFIG_FILE_NAME)?;

        let config_file = match file {
            Some(file) => Some(file),
            None => {
                if default_config.exists() {
                    Some(default_config.as_ref())
                } else {
                    None
                }
            }
        };
        let mut config = if let Some(file) = config_file {
            let config = tokio::fs::read_to_string(file).await?;
            toml::from_str(&config)?
        } else {
            Self::default()
        };

        // override from env var
        if let Some(env_filter) = env_file_rust_log().transpose()? {
            config.file_logs.rust_log = env_filter;
        }
        Ok(config)
    }

    /// Constructs a `RelayMap` based on the current configuration.
    pub(crate) fn relay_map(&self) -> Result<Option<RelayMap>> {
        if self.relay_nodes.is_empty() {
            return Ok(None);
        }
        Some(RelayMap::from_nodes(self.relay_nodes.iter().cloned())).transpose()
    }
}

/// Environment for CLI and REPL
///
/// This is cheaply cloneable and has interior mutability. If not running in the console
/// environment, [Self::set_doc] and [Self::set_author] will lead to an error, as changing the
/// environment is only supported within the console.
#[derive(Clone, Debug)]
pub(crate) struct ConsoleEnv(Arc<RwLock<ConsoleEnvInner>>);

#[derive(PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
struct ConsoleEnvInner {
    /// Active author. Read from IROH_AUTHOR env variable.
    /// For console also read from/persisted to a file (see [`ConsolePaths::DefaultAuthor`])
    author: Option<AuthorId>,
    /// Active doc. Read from IROH_DOC env variable. Not persisted.
    doc: Option<NamespaceId>,
    is_console: bool,
    iroh_data_dir: PathBuf,
}

impl ConsoleEnv {
    /// Read from environment variables and the console config file.
    pub(crate) fn for_console(iroh_data_root: &Path) -> Result<Self> {
        let author = match env_author()? {
            Some(author) => Some(author),
            None => Self::get_console_default_author(iroh_data_root)?,
        };
        let env = ConsoleEnvInner {
            author,
            doc: env_doc()?,
            is_console: true,
            iroh_data_dir: iroh_data_root.to_path_buf(),
        };
        Ok(Self(Arc::new(RwLock::new(env))))
    }

    /// Read only from environment variables.
    pub(crate) fn for_cli(iroh_data_root: &Path) -> Result<Self> {
        let env = ConsoleEnvInner {
            author: env_author()?,
            doc: env_doc()?,
            is_console: false,
            iroh_data_dir: iroh_data_root.to_path_buf(),
        };
        Ok(Self(Arc::new(RwLock::new(env))))
    }

    fn get_console_default_author(root: &Path) -> anyhow::Result<Option<AuthorId>> {
        let author_path = ConsolePaths::DefaultAuthor.with_root(root);
        if let Ok(s) = std::fs::read(&author_path) {
            let author = String::from_utf8(s)
                .map_err(Into::into)
                .and_then(|s| AuthorId::from_str(&s))
                .with_context(|| {
                    format!(
                        "Failed to parse author file at {}",
                        author_path.to_string_lossy()
                    )
                })?;
            Ok(Some(author))
        } else {
            Ok(None)
        }
    }

    /// True if running in a Iroh console session, false for a CLI command
    pub(crate) fn is_console(&self) -> bool {
        self.0.read().is_console
    }

    /// Return the iroh data directory
    pub(crate) fn iroh_data_dir(&self) -> PathBuf {
        self.0.read().iroh_data_dir.clone()
    }

    /// Set the active author.
    ///
    /// Will error if not running in the Iroh console.
    /// Will persist to a file in the Iroh data dir otherwise.
    pub(crate) fn set_author(&self, author: AuthorId) -> anyhow::Result<()> {
        let author_path = ConsolePaths::DefaultAuthor.with_root(self.iroh_data_dir());
        let mut inner = self.0.write();
        if !inner.is_console {
            bail!("Switching the author is only supported within the Iroh console, not on the command line");
        }
        inner.author = Some(author);
        std::fs::write(author_path, author.to_string().as_bytes())?;
        Ok(())
    }

    /// Set the active document.
    ///
    /// Will error if not running in the Iroh console.
    /// Will not persist, only valid for the current console session.
    pub(crate) fn set_doc(&self, doc: NamespaceId) -> anyhow::Result<()> {
        let mut inner = self.0.write();
        if !inner.is_console {
            bail!("Switching the document is only supported within the Iroh console, not on the command line");
        }
        inner.doc = Some(doc);
        Ok(())
    }

    /// Get the active document.
    pub(crate) fn doc(&self, arg: Option<NamespaceId>) -> anyhow::Result<NamespaceId> {
        let inner = self.0.read();
        let doc_id = arg.or(inner.doc).ok_or_else(|| {
            anyhow!(
                "Missing document id. Set the active document with the `IROH_DOC` environment variable or the `-d` option.\n\
                In the console, you can also set the active document with `doc switch`."
            )
        })?;
        Ok(doc_id)
    }

    /// Get the active author.
    pub(crate) fn author(&self, arg: Option<AuthorId>) -> anyhow::Result<AuthorId> {
        let inner = self.0.read();
        let author_id = arg.or(inner.author).ok_or_else(|| {
            anyhow!(
                "Missing author id. Set the active author with the `IROH_AUTHOR` environment variable or the `-a` option.\n\
                In the console, you can also set the active author with `author switch`."
            )
        })?;
        Ok(author_id)
    }
}

fn env_author() -> Result<Option<AuthorId>> {
    env::var(ENV_AUTHOR)
        .ok()
        .map(|s| {
            s.parse()
                .context("Failed to parse IROH_AUTHOR environment variable")
        })
        .transpose()
}

fn env_doc() -> Result<Option<NamespaceId>> {
    env::var(ENV_DOC)
        .ok()
        .map(|s| {
            s.parse()
                .context("Failed to parse IROH_DOC environment variable")
        })
        .transpose()
}

/// Parse [`ENV_FILE_RUST_LOG`] as [`tracing_subscriber::EnvFilter`]. Returns `None` if not
/// present.
fn env_file_rust_log() -> Option<Result<crate::logging::EnvFilter>> {
    match env::var(ENV_FILE_RUST_LOG) {
        Ok(s) => Some(crate::logging::EnvFilter::from_str(&s).map_err(Into::into)),
        Err(e) => match e {
            env::VarError::NotPresent => None,
            e @ env::VarError::NotUnicode(_) => Some(Err(e.into())),
        },
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
pub(crate) fn iroh_config_root() -> Result<PathBuf> {
    if let Some(val) = env::var_os(ENV_CONFIG_DIR) {
        return Ok(PathBuf::from(val));
    }
    let cfg = dirs_next::config_dir()
        .ok_or_else(|| anyhow!("operating environment provides no directory for configuration"))?;
    Ok(cfg.join(IROH_DIR))
}

/// Path that leads to a file in the iroh config directory.
pub(crate) fn iroh_config_path(file_name: impl AsRef<Path>) -> Result<PathBuf> {
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
pub(crate) fn iroh_data_root() -> Result<PathBuf> {
    let path = if let Some(val) = env::var_os("IROH_DATA_DIR") {
        PathBuf::from(val)
    } else {
        let path = dirs_next::data_dir().ok_or_else(|| {
            anyhow!("operating environment provides no directory for application data")
        })?;
        path.join(IROH_DIR)
    };
    let path = if !path.is_absolute() {
        std::env::current_dir()?.join(path)
    } else {
        path
    };
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
pub(crate) fn iroh_cache_root() -> Result<PathBuf> {
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
pub(crate) fn iroh_cache_path(file_name: &Path) -> Result<PathBuf> {
    let path = iroh_cache_root()?.join(file_name);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_settings() {
        let config = NodeConfig::load(None).await.unwrap();

        assert_eq!(config.relay_nodes.len(), 2);
    }
}
