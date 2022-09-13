use config::{ConfigError, Map, Source, Value};
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// The name of the service. Should be the same as the Cargo package name.
    pub service_name: String,
    /// A unique identifier for this instance of the service.
    pub instance_id: String,
    /// The build version of the service (commit hash).
    pub build: String,
    /// The version of the service. Should be the same as the Cargo package version.
    pub version: String,
    /// The environment of the service.
    pub service_env: String,
    /// Flag to enable metrics collection.
    pub collect: bool,
    /// Flag to enable tracing collection.
    pub tracing: bool,
    /// The endpoint of the trace collector.
    pub collector_endpoint: String,
    /// The endpoint of the prometheus push gateway.
    #[serde(alias = "prom_gateway_endpoint")]
    pub prom_gateway_endpoint: String,
}

impl Source for Config {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }

    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let mut map = Map::new();
        insert_into_config_map(&mut map, "service_name", self.service_name.clone());
        insert_into_config_map(&mut map, "instance_id", self.instance_id.clone());
        insert_into_config_map(&mut map, "build", self.build.clone());
        insert_into_config_map(&mut map, "version", self.version.clone());
        insert_into_config_map(&mut map, "service_env", self.service_env.clone());
        insert_into_config_map(&mut map, "collect", self.collect);
        insert_into_config_map(&mut map, "tracing", self.tracing);
        insert_into_config_map(
            &mut map,
            "collector_endpoint",
            self.collector_endpoint.clone(),
        );
        insert_into_config_map(
            &mut map,
            "prom_gateway_endpoint",
            self.prom_gateway_endpoint.clone(),
        );
        Ok(map)
    }
}

impl Config {
    pub fn with_service_name(mut self, name: String) -> Self {
        self.service_name = name;
        self
    }
    pub fn with_build(mut self, build: String) -> Self {
        self.build = build;
        self
    }
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service_name: "unknown".to_string(),
            instance_id: names::Generator::default().next().unwrap(),
            build: "unknown".to_string(),
            version: "unknown".to_string(),
            service_env: "dev".to_string(),
            collect: false,
            tracing: false,
            collector_endpoint: "http://localhost:4317".to_string(),
            prom_gateway_endpoint: "http://localhost:9091".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> Config {
        Config::default()
            .with_service_name("test_service_name".into())
            .with_build("test_build".into())
            .with_version("test_version".into())
    }

    #[test]
    fn test_collect() {
        let cfg = make_test_config();
        let mut expect: Map<String, Value> = Map::new();
        expect.insert(
            "service_name".to_string(),
            Value::new(None, cfg.service_name.clone()),
        );
        expect.insert(
            "instance_id".to_string(),
            Value::new(None, cfg.instance_id.clone()),
        );
        expect.insert("build".to_string(), Value::new(None, cfg.build.clone()));
        expect.insert("version".to_string(), Value::new(None, cfg.version.clone()));
        expect.insert(
            "service_env".to_string(),
            Value::new(None, cfg.service_env.clone()),
        );
        expect.insert("collect".to_string(), Value::new(None, cfg.collect));
        expect.insert("tracing".to_string(), Value::new(None, cfg.tracing));
        expect.insert(
            "collector_endpoint".to_string(),
            Value::new(None, cfg.collector_endpoint.clone()),
        );
        expect.insert(
            "prom_gateway_endpoint".to_string(),
            Value::new(None, cfg.prom_gateway_endpoint.clone()),
        );
        let got = cfg.collect().unwrap();
        for key in got.keys() {
            let left = expect.get(key).unwrap();
            let right = got.get(key).unwrap();
            assert_eq!(left, right);
        }
    }

    #[test]
    fn test_build_config_from_struct() {
        let expect = make_test_config();
        let got: Config = config::Config::builder()
            .add_source(expect.clone())
            .build()
            .unwrap()
            .try_deserialize()
            .unwrap();

        assert_eq!(expect, got);
    }
}
