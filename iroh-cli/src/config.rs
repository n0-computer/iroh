//! Configuration for the iroh CLI.

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use iroh::{
    net::{RelayMap, RelayNode},
    node::GcPolicy,
};
use iroh_node_util::config::{config_root, env_file_rust_log};
use serde::Deserialize;

/// BIN_NAME is the name of the binary. This is used in various places, e.g. for the home directory
/// and for environment variables.
pub(crate) const BIN_NAME: &str = "iroh";

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub(crate) const CONFIG_FILE_NAME: &str = "iroh.config.toml";

#[derive(Debug, Clone, Copy, Eq, PartialEq, strum::AsRefStr, strum::EnumString, strum::Display)]
pub(crate) enum ConsolePaths {
    #[strum(serialize = "current-author")]
    CurrentAuthor,
    #[strum(serialize = "history")]
    History,
}

impl ConsolePaths {
    fn root(iroh_data_dir: impl AsRef<Path>) -> PathBuf {
        PathBuf::from(iroh_data_dir.as_ref()).join("console")
    }
    pub fn with_iroh_data_dir(self, iroh_data_dir: impl AsRef<Path>) -> PathBuf {
        Self::root(iroh_data_dir).join(self.as_ref())
    }
}

/// The configuration for an iroh node.
// Please note that this is documented in the `iroh.computer` repository under
// `src/app/docs/reference/config/page.mdx`.  Any changes to this need to be updated there.
#[derive(PartialEq, Eq, Debug, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct NodeConfig {
    /// The nodes for relay to use.
    pub(crate) relay_nodes: Vec<RelayNode>,
    /// How often to run garbage collection.
    pub(crate) gc_policy: GcPolicyConfig,
    /// Bind address on which to serve Prometheus metrics
    pub(crate) metrics_addr: Option<SocketAddr>,
    /// Configuration for the logfile.
    pub(crate) file_logs: iroh_node_util::logging::FileLogging,
    /// Path to dump metrics to in CSV format.
    pub(crate) metrics_dump_path: Option<PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let relay_map = iroh::net::endpoint::default_relay_mode().relay_map();
        let relay_nodes = relay_map
            .nodes()
            .map(|v| Arc::unwrap_or_clone(v.clone()))
            .collect();
        Self {
            relay_nodes,
            gc_policy: GcPolicyConfig::default(),
            metrics_addr: None,
            file_logs: Default::default(),
            metrics_dump_path: None,
        }
    }
}

impl NodeConfig {
    /// Creates a config from default config file.
    ///
    /// If the *file* is `Some` the configuration will be read from it.  Otherwise the
    /// default config file will be loaded.  If that is not present the default config will
    /// be used.
    pub(crate) async fn load(file: Option<&Path>) -> Result<NodeConfig> {
        let default_config = config_root(BIN_NAME)?.join(CONFIG_FILE_NAME);

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
            Self::load_toml(&config)?
        } else {
            Self::default()
        };

        // override from env var
        if let Some(env_filter) = env_file_rust_log(BIN_NAME).transpose()? {
            config.file_logs.rust_log = env_filter;
        }
        Ok(config)
    }

    fn load_toml(s: &str) -> Result<NodeConfig> {
        let config = toml::from_str(s)?;
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

/// Serde-compatible configuration for [`GcPolicy`].
///
/// The [`GcPolicy`] struct is not amenable to TOML serialisation, this covers this gap.
#[derive(PartialEq, Eq, Debug, Default, Deserialize, Clone)]
#[serde(default, deny_unknown_fields, rename = "gc_policy")]
pub(crate) struct GcPolicyConfig {
    enabled: bool,
    interval: Option<u64>,
}

impl From<GcPolicyConfig> for GcPolicy {
    fn from(source: GcPolicyConfig) -> Self {
        if source.enabled {
            match source.interval {
                Some(interval) => Self::Interval(Duration::from_secs(interval)),
                None => Self::default(),
            }
        } else {
            Self::Disabled
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };

    use iroh_node_util::logging::{EnvFilter, Rotation};
    use url::Url;

    use super::*;

    #[test]
    fn test_toml_invalid_field() {
        let source = r#"
          not_a_field = true
        "#;
        let res = NodeConfig::load_toml(source);
        assert!(res.is_err());
    }

    #[test]
    fn test_toml_relay_nodes() {
        let source = r#"
          [[relay_nodes]]
          url = "https://example.org."
          stun_only = false
          stun_port = 123
        "#;
        let config = NodeConfig::load_toml(source).unwrap();

        let expected = RelayNode {
            url: Url::parse("https://example.org./").unwrap().into(),
            stun_only: false,
            stun_port: 123,
        };
        assert_eq!(config.relay_nodes, vec![expected]);
    }

    #[test]
    fn test_toml_gc_policy() {
        let source = r#"
          [gc_policy]
          enabled = false
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(GcPolicy::from(config.gc_policy), GcPolicy::Disabled);

        // Default interval should be used.
        let source = r#"
          [gc_policy]
          enabled = true
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        let gc_policy = GcPolicy::from(config.gc_policy);
        assert!(matches!(gc_policy, GcPolicy::Interval(_)));
        assert_eq!(gc_policy, GcPolicy::default());

        let source = r#"
          [gc_policy]
          enabled = true
          interval = 1234
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(
            GcPolicy::from(config.gc_policy),
            GcPolicy::Interval(Duration::from_secs(1234))
        );

        let source = r#"
            [gc_policy]
            not_a_field = true
        "#;
        let res = NodeConfig::load_toml(source);
        assert!(res.is_err());
    }

    #[test]
    fn test_toml_metrics_addr() {
        let source = r#"
            metrics_addr = "1.2.3.4:1234"
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(
            config.metrics_addr,
            Some(SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 1234)),
        );

        let source = r#"
            metrics_addr = "[123:456::789:abc]:1234"
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(
            config.metrics_addr,
            Some(SocketAddr::new(
                Ipv6Addr::new(0x123, 0x456, 0, 0, 0, 0, 0x789, 0xabc).into(),
                1234
            )),
        );
    }

    #[test]
    fn test_toml_file_logs() {
        let source = r#"
            [file_logs]
            rust_log = "iroh_net=trace"
            max_files = 123
            rotation = "daily"
            dir = "/var/log/iroh"
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(
            config.file_logs.rust_log,
            EnvFilter::from_str("iroh_net=trace").unwrap()
        );
        assert_eq!(config.file_logs.max_files, 123);
        assert_eq!(config.file_logs.rotation, Rotation::Daily);
        assert_eq!(config.file_logs.dir, Some(PathBuf::from("/var/log/iroh")));

        let source = r#"
            [file_logs]
            rust_log = "info"
        "#;
        let config = NodeConfig::load_toml(source).unwrap();
        assert_eq!(
            config.file_logs.rust_log,
            EnvFilter::from_str("info").unwrap()
        );
        assert_eq!(config.file_logs.max_files, 4);
        assert_eq!(config.file_logs.rotation, Rotation::Hourly);
        assert_eq!(config.file_logs.dir, None);
    }
}
