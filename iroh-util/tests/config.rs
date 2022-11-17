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
    service_env: String,
    instance_id: String,
    foo: bool,
    bar: i32,
}

impl Metrics {
    fn new() -> Self {
        Self {
            instance_id: "test_instance_id".to_string(),
            service_env: "test_service".to_string(),
            foo: false,
            bar: 0,
        }
    }
}

impl Source for Metrics {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map = Map::new();
        insert_into_config_map(&mut map, "service_env", self.service_env.clone());
        insert_into_config_map(&mut map, "instance_id", self.instance_id.clone());
        insert_into_config_map(&mut map, "foo", self.foo);
        insert_into_config_map(&mut map, "bar", self.bar);
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
        "service_env".to_string(),
        Value::new(None, default.metrics.service_env),
    );
    metrics.insert(
        "instance_id".to_string(),
        Value::new(None, default.metrics.instance_id),
    );
    metrics.insert("foo".to_string(), Value::new(None, default.metrics.foo));
    metrics.insert("bar".to_string(), Value::new(None, default.metrics.bar));
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
            // set by custom metrics env var
            service_env: "new_service_env".to_string(),
            // set by custom metrics env var
            instance_id: "new_id".to_string(),
            // set by `env_prefix` env var
            foo: true,
            // set by metrics env var
            bar: 10,
        },
    };

    temp_env::with_vars(
        vec![
            // set config field using env var
            ("IROH_TEST__PORT", Some("4000")),
            // set metrics fiels using `env_prefix`, double-underbar for deep
            // nesting
            ("IROH_TEST__METRICS__FOO", Some("true")),
            // set metrics field using `IROH_METRICS` prefix
            ("IROH_METRICS__BAR", Some("10")),
            // custom metrics env var
            ("IROH_INSTANCE_ID", Some("new_id")),
            // custom metrics env var
            ("IROH_ENV", Some("new_service_env")),
        ],
        || {
            let got = make_config(
                TestConfig::new(),
                &[
                    Some(&PathBuf::from(CONFIG_A)),
                    Some(&PathBuf::from(CONFIG_B)),
                    None,
                ],
                "IROH_TEST",
                HashMap::from([("enabled", "false"), ("metrics.debug", "true")]),
            )
            .unwrap();
            assert_eq!(expect, got);
        },
    );
}

// add metrics
