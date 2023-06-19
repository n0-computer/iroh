//! Configuration for the iroh CLI.

use std::{collections::HashMap, path::Path};

use anyhow::Result;
use config::{Environment, File, Value};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::hp::derp::{DerpMap, DerpNode, DerpRegion, UseIpv4, UseIpv6};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "iroh.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_PATH=/path/to/config` would set the value of the `Config.path` field
pub const ENV_PREFIX: &str = "IROH";

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
            derp_regions: vec![default_derp_region()],
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

        let mut regions = HashMap::new();
        for region in &self.derp_regions {
            regions.insert(region.region_id, region.clone());
        }

        Some(DerpMap { regions })
    }
}

fn default_derp_region() -> DerpRegion {
    // The default derper run by number0.
    let default_n0_derp = DerpNode {
        name: "default-1".into(),
        region_id: 1,
        host_name: "derp.iroh.network".into(),
        stun_only: false,
        stun_port: 3478,
        ipv4: UseIpv4::Some("35.175.99.113".parse().unwrap()),
        ipv6: UseIpv6::None,
        derp_port: 443,
        stun_test_ip: None,
    };
    DerpRegion {
        region_id: 1,
        nodes: vec![default_n0_derp],
        avoid: false,
        region_code: "default-1".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let config = Config::load::<String, String>(&[][..], "__FOO", Default::default()).unwrap();

        assert_eq!(config.derp_regions.len(), 1);
    }
}
