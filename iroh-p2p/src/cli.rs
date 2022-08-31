use std::{collections::HashMap, path::PathBuf};

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(long = "metrics")]
    metrics: bool,
    #[clap(long = "tracing")]
    tracing: bool,
    #[clap(long)]
    pub cfg: Option<PathBuf>,
}

impl Args {
    pub fn make_overrides_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("metrics.collect".to_string(), self.metrics.to_string());
        map.insert("metrics.tracing".to_string(), self.tracing.to_string());
        map
    }
}
