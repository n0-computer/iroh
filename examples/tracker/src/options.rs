//! Options for the tracker
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Options {
    // time after which an announce is considered stale
    #[serde(with = "serde_duration")]
    pub announce_timeout: Duration,
    // time after which a probe is considered stale
    #[serde(with = "serde_duration")]
    pub probe_timeout: Duration,
    // interval between probing peers
    #[serde(with = "serde_duration")]
    pub probe_interval: Duration,
    // max hash seq size in bytes
    pub max_hash_seq_size: u64,
    // log file for dial attempts
    pub dial_log: Option<PathBuf>,
    // log file for probe attempts
    pub probe_log: Option<PathBuf>,
    // path to the file where announce data is persisted
    // this is used to restore the announce data on startup
    // can use either toml, json or postcard
    pub announce_data_path: Option<PathBuf>,
    // number of peers to probe in parallel
    pub probe_parallelism: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            announce_timeout: Duration::from_secs(60 * 60 * 12),
            probe_timeout: Duration::from_secs(30),
            probe_interval: Duration::from_secs(10),
            // max hash seq size is 16 * 1024 hashes of 32 bytes each
            max_hash_seq_size: 1024 * 16 * 32,
            dial_log: Some("dial.log".into()),
            probe_log: Some("probe.log".into()),
            announce_data_path: Some("announce.data.toml".into()),
            probe_parallelism: 4,
        }
    }
}

impl Options {
    /// Make the paths in the options relative to the given base path.
    pub fn make_paths_relative(&mut self, base: &Path) {
        if let Some(path) = &mut self.dial_log {
            *path = base.join(&path);
        }
        if let Some(path) = &mut self.probe_log {
            *path = base.join(&path);
        }
        if let Some(path) = &mut self.announce_data_path {
            *path = base.join(&path);
        }
    }
}
mod serde_duration {
    use super::*;
    use serde::de::Deserializer;
    use serde::ser::Serializer;

    pub fn serialize<S: Serializer>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(humantime::Duration::from(*duration).to_string().as_str())
        } else {
            duration.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            humantime::parse_duration(&s).map_err(serde::de::Error::custom)
        } else {
            Duration::deserialize(deserializer)
        }
    }
}
