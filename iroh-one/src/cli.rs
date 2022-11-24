/// CLI arguments support.
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Gateway
    #[clap(short = 'p', long = "gateway-port")]
    gateway_port: Option<u16>,
    #[clap(short, long)]
    writeable: Option<bool>,
    #[clap(short, long)]
    fetch: Option<bool>,
    #[clap(short, long)]
    cache: Option<bool>,
    #[clap(long)]
    metrics: bool,
    #[clap(long)]
    tracing: bool,
    #[clap(long)]
    denylist: bool,
    #[cfg(all(feature = "http-uds-gateway", unix))]
    #[clap(long = "gateway-uds-path")]
    pub gateway_uds_path: Option<PathBuf>,
    /// Path to the store
    #[clap(long = "store-path")]
    pub store_path: Option<PathBuf>,
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Args {
    pub fn make_overrides_map(&self) -> HashMap<&str, String> {
        let mut map: HashMap<&str, String> = HashMap::new();
        if let Some(port) = self.gateway_port {
            map.insert("gateway.port", port.to_string());
        }
        if let Some(writable) = self.writeable {
            map.insert("gateway.writable", writable.to_string());
        }
        if let Some(fetch) = self.fetch {
            map.insert("gateway.fetch", fetch.to_string());
        }
        if let Some(cache) = self.cache {
            map.insert("gateway.cache", cache.to_string());
        }
        map.insert("gateway.denylist", self.denylist.to_string());
        map.insert("metrics.collect", self.metrics.to_string());
        map.insert("metrics.tracing", self.tracing.to_string());
        if let Some(path) = self.store_path.clone() {
            map.insert("store.path", path.to_str().unwrap_or("").to_string());
        }
        #[cfg(all(feature = "http-uds-gateway", unix))]
        if let Some(path) = self.gateway_uds_path.clone() {
            map.insert("gateway_uds_path", path.to_str().unwrap_or("").to_string());
        }
        map
    }
}
