//! Anything related to local IO, including logging, file formats, and file locations.
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    io::Write,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use iroh_bytes::{get::Stats, HashAndFormat};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing_subscriber::{prelude::*, EnvFilter};

use crate::{protocol::AnnounceKind, tracker::ProbeKind, NodeId};

/// Data format of the announce data file.
///
/// This should be easy to edit manually when serialized as json or toml.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnnounceData(pub BTreeMap<HashAndFormat, BTreeMap<AnnounceKind, BTreeSet<NodeId>>>);

pub fn save_to_file(data: impl Serialize, path: &Path) -> anyhow::Result<()> {
    let data_dir = path.parent().context("non absolute data file")?;
    let ext = path
        .extension()
        .context("no extension")?
        .to_str()
        .context("not utf8")?
        .to_ascii_lowercase();
    let mut temp = tempfile::NamedTempFile::new_in(data_dir)?;
    match ext.as_str() {
        "toml" => {
            let data = toml::to_string_pretty(&data)?;
            temp.write_all(&data.as_bytes())?;
        }
        "json" => {
            let data = serde_json::to_string_pretty(&data)?;
            temp.write_all(&data.as_bytes())?;
        }
        "postcard" => {
            let data = postcard::to_stdvec(&data)?;
            temp.write_all(&data)?;
        }
        _ => anyhow::bail!("unsupported extension"),
    }
    std::fs::rename(temp.into_temp_path(), path)?;
    Ok(())
}

pub fn load_from_file<T: DeserializeOwned + Default>(path: &Path) -> anyhow::Result<T> {
    anyhow::ensure!(path.is_absolute(), "non absolute data file");
    let ext = path
        .extension()
        .context("no extension")?
        .to_str()
        .context("not utf8")?
        .to_ascii_lowercase();
    if !path.exists() {
        return Ok(T::default());
    }
    match ext.as_str() {
        "toml" => {
            let data = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&data)?)
        }
        "json" => {
            let data = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&data)?)
        }
        "postcard" => {
            let data = std::fs::read(path)?;
            Ok(postcard::from_bytes(&data)?)
        }
        _ => anyhow::bail!("unsupported extension"),
    }
}

pub fn log_connection_attempt(
    path: &Option<PathBuf>,
    host: &NodeId,
    t0: Instant,
    outcome: &anyhow::Result<quinn::Connection>,
) -> anyhow::Result<()> {
    if let Some(path) = path {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let outcome = match outcome {
            Ok(_) => "ok",
            Err(_) => "err",
        };
        let line = format!(
            "{:.6},{},{:.6},{}\n",
            now,
            host,
            t0.elapsed().as_secs_f64(),
            outcome
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        file.write_all(line.as_bytes())?;
    }
    Ok(())
}

pub fn log_probe_attempt(
    path: &Option<PathBuf>,
    host: &NodeId,
    content: &HashAndFormat,
    kind: ProbeKind,
    t0: Instant,
    outcome: &anyhow::Result<Stats>,
) -> anyhow::Result<()> {
    if let Some(path) = path {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let outcome = match outcome {
            Ok(_) => "ok",
            Err(_) => "err",
        };
        let line = format!(
            "{:.6},{},{},{:?},{:.6},{}\n",
            now,
            host,
            content,
            kind,
            t0.elapsed().as_secs_f64(),
            outcome
        );
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap();
        file.write_all(line.as_bytes())?;
    }
    Ok(())
}

// set the RUST_LOG env var to one of {debug,info,warn} to see logging info
pub fn setup_logging() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(EnvFilter::from_default_env())
        .try_init()
        .ok();
}

pub fn tracker_home() -> anyhow::Result<PathBuf> {
    Ok(if let Some(val) = env::var_os("IROH_TRACKER_HOME") {
        PathBuf::from(val)
    } else {
        dirs_next::data_dir()
            .ok_or_else(|| {
                anyhow::anyhow!("operating environment provides no directory for application data")
            })?
            .join("iroh_tracker")
    })
}

pub fn tracker_path(file_name: impl AsRef<Path>) -> anyhow::Result<PathBuf> {
    Ok(tracker_home()?.join(file_name))
}
