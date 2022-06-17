use std::{
    cell::RefCell,
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use anyhow::Result;
use config::{Config, ConfigError, Environment, File, Map, Source, Value, ValueKind};
use dirs::home_dir;
use tracing::debug;

const IROH_DIR: &str = ".iroh";

/// Blocks current thread until ctrl-c is received
pub async fn block_until_sigint() {
    let (ctrlc_send, ctrlc_oneshot) = futures::channel::oneshot::channel();
    let ctrlc_send_c = RefCell::new(Some(ctrlc_send));

    let running = Arc::new(AtomicUsize::new(0));
    ctrlc::set_handler(move || {
        let prev = running.fetch_add(1, Ordering::SeqCst);
        if prev == 0 {
            println!("Got interrupt, shutting down...");
            // Send sig int in channel to blocking task
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                ctrlc_send.send(()).expect("Error sending ctrl-c message");
            }
        } else {
            std::process::exit(0);
        }
    })
    .expect("Error setting Ctrl-C handler");

    ctrlc_oneshot.await.unwrap();
}

pub fn iroh_home_root() -> Option<PathBuf> {
    let home = home_dir()?;
    Some(Path::new(&home).join(IROH_DIR))
}

/// Path that leads to a file in the iroh home directory
pub fn iroh_home_path(file_name: &str) -> Option<PathBuf> {
    let path = iroh_home_root()?.join(file_name);
    Some(path)
}

/// insert a value into a `config::Map`
pub fn insert_into_config_map<I: Into<String>, V: Into<ValueKind>>(
    map: &mut Map<String, Value>,
    field: I,
    val: V,
) {
    map.insert(field.into(), Value::new(None, val));
}

// struct made to shoe-horn in the ability to use the `IROH_METRICS` env var prefix
#[derive(Debug, Clone)]
struct MetricsSource {
    metrics: Config,
}

impl Source for MetricsSource {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.clone())
    }
    fn collect(&self) -> Result<Map<String, Value>, ConfigError> {
        let metrics = self.metrics.collect()?;
        let mut map = Map::new();
        insert_into_config_map(&mut map, "metrics", metrics);
        Ok(map)
    }
}

/// make a config using a default, file sources, environment variables, and commandline flag
/// overrides
///
/// environment variables are expected to start with the `env_prefix`. Nested fields can be
/// accessed using `.`, if your environment allows env vars with `.`
///
/// Note: For the metrics configuration env vars, it is recommended to use the metrics specific
/// prefix `IROH_METRICS` to set a field in the metrics config. You can use the above dot notation to set
/// a metrics field, eg, `IROH_CONFIG_METRICS.SERVICE_NAME`, but only if your environment allows it
pub fn make_config<T, S, V>(
    default: T,
    file_paths: Vec<Option<PathBuf>>,
    env_prefix: &str,
    flag_overrides: HashMap<S, V>,
) -> Result<T>
where
    T: serde::de::DeserializeOwned + Source + Send + Sync + 'static,
    S: AsRef<str>,
    V: Into<Value>,
{
    // create config builder and add default as first source
    let mut builder = Config::builder().add_source(default);

    // layer on config options from files
    for path in file_paths.into_iter().flatten() {
        if path.exists() {
            let p = path.to_str().ok_or_else(|| anyhow::anyhow!("empty path"))?;
            builder = builder.add_source(File::with_name(p));
        }
    }

    // next, add any environment variables
    builder = builder.add_source(Environment::with_prefix(env_prefix).try_parsing(true));

    // pull metrics config from env variables
    // nesting into this odd `MetricsSource` struct, gives us the option of
    // using the more convienient prefix `IROH_METRICS` to set metrics env vars
    let mut metrics =
        Config::builder().add_source(Environment::with_prefix("IROH_METRICS").try_parsing(true));

    // allow custom `IROH_INSTANCE_ID` env var
    if let Ok(instance_id) = std::env::var("IROH_INSTANCE_ID") {
        metrics = metrics.set_override("instance_id", instance_id)?;
    }
    // allow custom `IROH_ENV` env var
    if let Ok(service_env) = std::env::var("IROH_ENV") {
        metrics = metrics.set_override("service_env", service_env)?;
    }
    let metrics = metrics.build().unwrap();

    builder = builder.add_source(MetricsSource { metrics });

    // finally, override any values
    for (flag, val) in flag_overrides.into_iter() {
        builder = builder.set_override(flag, val)?;
    }

    let cfg = builder.build()?;
    debug!("make_config:\n{:#?}\n", cfg);
    let cfg: T = cfg.try_deserialize()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iroh_home_path() {
        let got = iroh_home_path("foo.bar").unwrap();
        let got = got.to_str().unwrap().to_string();
        assert!(got.ends_with("/.iroh/foo.bar"));
    }
}
