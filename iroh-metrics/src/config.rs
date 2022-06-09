use config::{ConfigError, Map, Source, Value};
use git_version::git_version;
use iroh_util::insert_into_config_map;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Flag to enable debug mode.
    pub debug: bool,
    /// The endpoint of the trace collector.
    pub collector_endpoint: String,
    /// The endpoint of the prometheus push gateway.
    pub prometheus_gateway_endpoint: String,
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
        insert_into_config_map(&mut map, "debug", self.debug);
        insert_into_config_map(
            &mut map,
            "collector_endpoint",
            self.collector_endpoint.clone(),
        );
        insert_into_config_map(
            &mut map,
            "prometheus_gateway_endpoint",
            self.prometheus_gateway_endpoint.clone(),
        );
        Ok(map)
    }
}

impl Config {
    pub fn new(
        service_name: String,
        instance_id: String,
        build: String,
        version: String,
        service_env: String,
        debug: bool,
    ) -> Self {
        let debug: bool = std::env::var("IROH_METRICS_DEBUG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(debug);
        let collector_endpoint = std::env::var("IROH_METRICS_COLLECTOR_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string());
        let prometheus_gateway_endpoint = std::env::var("IROH_METRICS_PROM_GATEWAY_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:9091".to_string());
        Config {
            service_name,
            instance_id,
            build,
            version,
            service_env,
            debug,
            collector_endpoint,
            prometheus_gateway_endpoint,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            service_name: "unknown".to_string(),
            instance_id: names::Generator::default().next().unwrap(),
            build: git_version!().to_string(),
            version: "unknown".to_string(),
            service_env: "dev".to_string(),
            debug: false,
            collector_endpoint: "http://localhost:4317".to_string(),
            prometheus_gateway_endpoint: "http://localhost:9091".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_config() -> Config {
        Config::new(
            "test_service_name".into(),
            "test_instance_id".into(),
            "test_build".into(),
            "test_version".into(),
            "test_service_env".into(),
            true,
        )
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
        expect.insert("debug".to_string(), Value::new(None, cfg.debug));
        expect.insert(
            "collector_endpoint".to_string(),
            Value::new(None, cfg.collector_endpoint.clone()),
        );
        expect.insert(
            "prometheus_gateway_endpoint".to_string(),
            Value::new(None, cfg.prometheus_gateway_endpoint.clone()),
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
