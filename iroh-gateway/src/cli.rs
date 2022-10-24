/// CLI arguments support.
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long)]
    port: Option<u16>,
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
    pub cfg: Option<PathBuf>,
    #[clap(long)]
    use_denylist: bool,
}

impl Args {
    pub fn make_overrides_map(&self) -> HashMap<&str, String> {
        let mut map: HashMap<&str, String> = HashMap::new();
        if let Some(port) = self.port {
            map.insert("port", port.to_string());
        }
        if let Some(writable) = self.writeable {
            map.insert("writable", writable.to_string());
        }
        if let Some(fetch) = self.fetch {
            map.insert("fetch", fetch.to_string());
        }
        if let Some(cache) = self.cache {
            map.insert("cache", cache.to_string());
        }
        map.insert("use_denylist", self.use_denylist.to_string());
        map.insert("metrics.collect", self.metrics.to_string());
        map.insert("metrics.tracing", self.tracing.to_string());
        map
    }
}
