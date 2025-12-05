use std::{io::BufWriter, path::PathBuf};

use n0_future::time::{Instant, SystemTime};
use quinn::{QlogConfig, QlogFactory};
use tracing::{debug, warn};

/// Enables writing qlog traces to a directory.
#[derive(Debug)]
pub struct QlogFileFactory {
    dir: Option<PathBuf>,
    prefix: Option<String>,
    start_instant: Option<Instant>,
}

impl QlogFileFactory {
    /// Creates a new qlog factory that writes files into the specified directory.
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir: Some(dir),
            prefix: None,
            start_instant: None,
        }
    }

    /// Creates a new qlog factory that writes files into `QLOGDIR`, if set.
    ///
    /// If the environment variable `QLOGDIR` is set, qlog traces for all connections handled
    /// by this endpoint will be written into that directory.
    /// If the directory doesn't exist it will be created.
    ///
    /// By default, files will be prefixed with the name of the binary. Use [`Self::with_prefix]
    /// to override the prefix.
    pub fn from_env() -> Self {
        let dir = match std::env::var("QLOGDIR") {
            Ok(dir) => {
                if let Err(err) = std::fs::create_dir_all(&dir) {
                    warn!("qlog not enabled: failed to create qlog directory at {dir}: {err}",);
                    None
                } else {
                    Some(PathBuf::from(dir))
                }
            }
            Err(_) => None,
        };
        let prefix = std::env::args().next();
        Self {
            dir,
            prefix,
            start_instant: None,
        }
    }

    /// Sets a prefix to the filename of the generated files.
    pub fn with_prefix(mut self, prefix: impl ToString) -> Self {
        self.prefix = Some(prefix.to_string());
        self
    }

    /// Override the instant relative to which all events are recorded.
    ///
    /// If not set, events will be recorded relative to the start of the connection.
    pub fn with_start_instant(mut self, start: Instant) -> Self {
        self.start_instant = Some(start);
        self
    }
}

impl QlogFactory for QlogFileFactory {
    fn for_connection(
        &self,
        side: quinn::Side,
        _remote: std::net::SocketAddr,
        initial_dst_cid: quinn::ConnectionId,
        now: std::time::Instant,
    ) -> Option<quinn::QlogConfig> {
        let dir = self.dir.as_ref()?;
        let timestamp = {
            SystemTime::now()
                .checked_sub(Instant::now().duration_since(now.into()))?
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()?
                .as_millis()
        };
        let name = format!(
            "{prefix}{timestamp}-{initial_dst_cid}-{side}.qlog",
            prefix = self
                .prefix
                .as_ref()
                .map(|prefix| format!("{prefix}-"))
                .unwrap_or_default(),
            side = format!("{side:?}").to_lowercase()
        );
        let path = dir.join(name);
        let file = std::fs::File::create(&path)
            .inspect_err(|err| warn!("Failed to create qlog file at {}: {err}", path.display()))
            .ok()?;
        debug!(
            "Initialized qlog file for connection {initial_dst_cid} at {}",
            path.display()
        );
        let writer = BufWriter::new(file);
        let mut config = QlogConfig::new(Box::new(writer));
        if let Some(instant) = self.start_instant {
            config.start_time(instant.into_std());
        }
        Some(config)
    }
}
