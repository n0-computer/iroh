use anyhow::Result;
use config::{ConfigError, Map, Source, Value};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

/// CONFIG_FILE_NAME is the name of the optional config file located in the iroh home directory
pub const CONFIG_FILE_NAME: &str = "cli.config.toml";
/// ENV_PREFIX should be used along side the config field name to set a config field using
/// environment variables
/// For example, `IROH_CLI_PATH=/path/to/config` would set the value of the `Config.path` field
pub const ENV_PREFIX: &str = "IROH_CLI";

/// The configuration for the iroh cli.
#[derive(PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// The set of services to start if no arguments are given to 'iroh start'
    pub start_default_services: Vec<String>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            start_default_services: vec![
                "store".to_string(),
                "p2p".to_string(),
                "gateway".to_string(),
            ],
        }
    }
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::new();
        insert_into_config_map(
            &mut map,
            "start_default_services",
            self.start_default_services.clone(),
        );

        Ok(map)
    }
}


// TODO(b5): TESTS