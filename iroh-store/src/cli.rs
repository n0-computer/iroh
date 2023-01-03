use std::{collections::HashMap, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
pub struct Args {
    /// Path to the store
    #[clap(long, short)]
    pub path: Option<PathBuf>,
    /// Enable metrics export
    #[clap(long = "metrics")]
    metrics: bool,
    #[clap(long = "tracing")]
    tracing: bool,
    /// Print the iRPC listening address to stdout as IRPC_LISTENING_ADDR=xxx
    #[clap(long)]
    print_address: bool,
    /// Path to the config file
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Args {
    pub fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        if let Some(path) = self.path.clone() {
            map.insert("path".to_string(), path.to_str().unwrap_or("").to_string());
        }
        map.insert("metrics.collect".to_string(), self.metrics.to_string());
        map.insert("metrics.tracing".to_string(), self.tracing.to_string());
        map.insert(
            "server.print_address".to_string(),
            self.print_address.to_string(),
        );
        map
    }
}
