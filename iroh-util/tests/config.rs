use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use config::{ConfigError, Map, Source, Value};
use serde::{Deserialize, Serialize};

use iroh_util::{insert_into_config_map, make_config};

const CONFIG_A: &str = "tests/config.a.toml";
const CONFIG_B: &str = "tests/config.b.toml";

// write test config with nested tables & lists
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct TestConfig {
    port: u16,
    addr: SocketAddr,
    enabled: bool,
    list: Vec<String>,
    map: HashMap<String, i32>,
    metrics: Metrics,
}

// impl default
impl TestConfig {
    fn new() -> Self {
        let mut map: HashMap<String, i32> = HashMap::default();
        map.insert("one".to_string(), 1);
        map.insert("two".to_string(), 2);
        map.insert("three".to_string(), 3);
        Self {
            port: 3030,
            addr: "0.0.0.0:3031".parse().unwrap(),
            enabled: true,
            list: vec!["hello".to_string(), "world".to_string()],
            map,
            metrics: Metrics::new(),
        }
    }
}

impl Source for TestConfig {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map: Map<String, Value> = Map::default();
        insert_into_config_map(&mut map, "port", self.port as i32);
        insert_into_config_map(&mut map, "addr", self.addr.to_string());
        insert_into_config_map(&mut map, "enabled", self.enabled);
        insert_into_config_map(&mut map, "list", self.list.clone());
        insert_into_config_map(&mut map, "map", self.map.clone());
        let metrics = self.metrics.collect().unwrap();
        insert_into_config_map(&mut map, "metrics", metrics);
        Ok(map)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct Metrics {
    // #[serde(alias = "metrics_service_name")]
    service_name: String,
}

impl Metrics {
    fn new() -> Self {
        Self {
            service_name: "test_service".to_string(),
        }
    }
}

impl Source for Metrics {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map = Map::new();
        insert_into_config_map(&mut map, "service_name", self.service_name.clone());
        Ok(map)
    }
}

#[test]
fn test_collect() {
    let default = TestConfig::new();
    let mut expect: Map<String, Value> = Map::new();
    expect.insert("port".to_string(), Value::new(None, default.port as i32));
    expect.insert(
        "addr".to_string(),
        Value::new(None, default.addr.to_string()),
    );
    expect.insert("enabled".to_string(), Value::new(None, default.enabled));
    expect.insert("list".to_string(), Value::new(None, default.list));
    expect.insert("map".to_string(), Value::new(None, default.map));
    let mut metrics = Map::new();
    metrics.insert(
        "service_name".to_string(),
        Value::new(None, default.metrics.service_name),
    );
    expect.insert("metrics".to_string(), Value::new(None, metrics));

    let got = TestConfig::new().collect().unwrap();
    for key in got.keys() {
        let left = expect.get(key).unwrap_or_else(|| panic!("{}", key));
        let right = got.get(key).unwrap();
        assert_eq!(left, right);
    }
}

#[test]
fn test_make_config() {
    let map = HashMap::from([
        ("one".to_string(), 1),
        ("two".to_string(), 2),
        ("three".to_string(), 3),
        ("four".to_string(), 4),
        ("five".to_string(), 5),
        ("six".to_string(), 6),
        ("seven".to_string(), 7),
        ("eight".to_string(), 8),
        ("nine".to_string(), 9),
    ]);

    // expect
    let expect = TestConfig {
        // changed by env var
        port: 4000,
        // stays default
        addr: "0.0.0.0:3031".parse().unwrap(),
        // changed by flag
        enabled: false,
        // changed by CONFIG_A
        list: vec!["changed".to_string(), "values".to_string()],
        // added to by by default, CONFIG_A, & CONFIG_B
        map,
        metrics: Metrics {
            service_name: "new_name".to_string(),
        },
    };
    std::env::set_var("IROH_TEST_CONFIG_PORT", "4000");
    std::env::set_var("IROH_TEST_CONFIG_METRICS.SERVICE_NAME", "new_name");
    let got = make_config(
        TestConfig::new(),
        vec![
            Some(PathBuf::from(CONFIG_A)),
            Some(PathBuf::from(CONFIG_B)),
            None,
        ],
        "IROH_TEST_CONFIG",
        HashMap::from([("enabled", "false")]),
    )
    .unwrap();
    assert_eq!(expect, got);
    std::env::remove_var("IROH_TEST_CONFIG_PORT");
    std::env::remove_var("IROH_TEST_METRICS_SERVICE_NAME");
}

// add metrics
