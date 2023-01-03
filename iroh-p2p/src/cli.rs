use std::{collections::HashMap, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Enable metrics export
    #[clap(long = "metrics")]
    metrics: bool,
    /// Enable tracing
    #[clap(long = "tracing")]
    tracing: bool,
    /// Print the listening address to stdout as LISTENING_ADDR=xxx
    #[clap(long)]
    print_address: bool,
    /// Path to the config file
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Args {
    pub fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.collect".to_string(), self.metrics.to_string());
        map.insert("metrics.tracing".to_string(), self.tracing.to_string());
        map.insert(
            "server.print_address".to_string(),
            self.print_address.to_string(),
        );
        map
    }
}
